use crate::pe::PE;
use crate::elf::ELF;

use capstone::Insn;
use capstone::prelude::*;

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<String>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub start_addr: u64,
    pub end_addr: u64,
    pub name: Option<String>,
    pub basic_blocks: Vec<BasicBlock>,
    pub calls_to: Vec<(u64, Option<String>)>,
    pub called_from: Vec<u64>,
    pub stack_frame_size: Option<i64>,
    pub is_leaf: bool,
}

#[derive(Debug, Clone)]
pub struct CrossReference {
    pub from_addr: u64,
    pub to_addr: u64,
    pub xref_type: XRefType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XRefType {
    Call,
    Jump,
    DataRead,
    DataWrite,
    StringReference,
}

pub fn is_padding_instruction(insn: &Insn) -> bool {
    match (insn.mnemonic(), insn.op_str()) {
        (Some("add"), Some("byte ptr [rax], al")) => true,
        (Some("nop"), _) => true,
        (Some("int3"), _) => true,
        (Some("ud2"), _) => true,
        (Some("hlt"), _) => true,
        (Some("mov"), Some("eax, eax")) => true,
        (Some("sub"), Some("rsp, 0")) => true,
        _ => false,
    }
}

/// Build a map of RVA addresses to import function names
fn build_import_map(pe: &PE) -> HashMap<u64, String> {
    let mut map = HashMap::new();

    if let (Some(idt), Some(hnt)) = (&pe.import_directory_table, &pe.hint_name_table) {
        for (idx, entry) in idt.entries.iter().enumerate() {
            if idx >= hnt.entries.len() {
                break;
            }

            let dll_name = &hnt.entries[idx].dll_name;
            let iat_rva = entry.import_address_table_rva as u64;

            for (func_idx, func_entry) in hnt.entries[idx].entries.iter().enumerate() {
                let func_rva = iat_rva + (func_idx * if pe.is_32_bits() { 4 } else { 8 }) as u64;
                let full_name = format!("{}!{}", dll_name, func_entry.name);
                map.insert(func_rva, full_name);
            }
        }
    }

    return map;
}

/// Extract string references from code
fn find_string_references(code: &[u8], base_addr: u64, pe: &PE) -> HashMap<u64, String> {
    let mut strings = HashMap::new();

    for (section_name, section) in &pe.sections {
        if section_name.contains("data") || section_name.contains("rdata") {
            let mut current_string = Vec::new();
            let mut string_start = 0;

            for (i, &byte) in section.data.iter().enumerate() {
                if byte >= 0x20 && byte <= 0x7E {
                    if current_string.is_empty() {
                        string_start = i;
                    }

                    current_string.push(byte);
                } else if byte == 0 && current_string.len() >= 4 {
                    let s = String::from_utf8_lossy(&current_string).to_string();
                    let addr = section.header.virtual_address as u64 + string_start as u64;
                    strings.insert(addr, s);
                    current_string.clear();
                } else {
                    current_string.clear();
                }
            }
        }
    }

    return strings;
}

/// Analyze stack frame setup and teardown
fn analyze_stack_frame(instructions: &[&Insn]) -> Option<i64> {
    for insn in instructions.iter().take(10) {
        if let (Some("sub"), Some(op_str)) = (insn.mnemonic(), insn.op_str()) {
            if op_str.starts_with("rsp,") || op_str.starts_with("esp,") {
                let parts: Vec<&str> = op_str.split(',').collect();

                if parts.len() == 2 {
                    let size_str = parts[1].trim().trim_start_matches("0x");
                    if let Ok(size) = i64::from_str_radix(size_str, 16) {
                        return Some(size);
                    }
                }
            }
        }
    }

    return None;
}

/// Detect function boundaries using heuristics
fn detect_functions(instructions: &[Insn]) -> Vec<u64> {
    let mut function_starts = Vec::new();
    let mut seen_starts = HashSet::new();

    // Entry point is always a function
    if let Some(first) = instructions.first() {
        function_starts.push(first.address());
        seen_starts.insert(first.address());
    }

    for insn in instructions {
        let addr = insn.address();

        // Pattern 1: push rbp/ebp; mov rbp/ebp, rsp/esp (function prologue)
        if let (Some("push"), Some(op)) = (insn.mnemonic(), insn.op_str()) {
            if op == "rbp" || op == "ebp" {
                if !seen_starts.contains(&addr) {
                    function_starts.push(addr);
                    seen_starts.insert(addr);
                }
            }
        }

        // Pattern 2: After a return, next instruction likely starts a function
        if let Some("ret") = insn.mnemonic() {
            // Check if there's padding after ret
            let next_addr = addr + insn.bytes().len() as u64;
            if !seen_starts.contains(&next_addr) {
                function_starts.push(next_addr);
                seen_starts.insert(next_addr);
            }
        }
    }

    function_starts.sort();

    return function_starts;
}

/// Build control flow graph for basic blocks
fn build_cfg(instructions: &[Insn]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let mut block_starts = HashSet::new();

    // First pass: identify block boundaries
    block_starts.insert(instructions[0].address());

    for (i, insn) in instructions.iter().enumerate() {
        if let Some(mnemonic) = insn.mnemonic() {
            // After control flow instruction, next insn starts a new block
            if is_control_flow(mnemonic) || mnemonic == "ret" {
                if i + 1 < instructions.len() {
                    block_starts.insert(instructions[i + 1].address());
                }
            }

            // Target of jump/call starts a new block
            if mnemonic.starts_with('j') || mnemonic == "call" {
                if let Some(op_str) = insn.op_str() {
                    if let Ok(target) = parse_hex_address(op_str) {
                        block_starts.insert(target);
                    }
                }
            }
        }
    }

    // Second pass: build basic blocks
    let mut current_block_start = instructions[0].address();
    let mut current_instrs = Vec::new();

    for insn in instructions {
        let addr = insn.address();

        // Start new block if we hit a boundary
        if block_starts.contains(&addr) && addr != current_block_start {
            if !current_instrs.is_empty() {
                blocks.push(BasicBlock {
                    start_addr: current_block_start,
                    end_addr: addr - 1,
                    instructions: current_instrs.clone(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                });
            }
            current_block_start = addr;
            current_instrs.clear();
        }

        current_instrs.push(format!(
            "{:08X}  {} {}",
            addr,
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        ));

        // End block on control flow instruction
        if let Some(mnemonic) = insn.mnemonic() {
            if is_control_flow(mnemonic) || mnemonic == "ret" {
                blocks.push(BasicBlock {
                    start_addr: current_block_start,
                    end_addr: addr,
                    instructions: current_instrs.clone(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                });
                current_instrs.clear();

                if let Some(next_insn) =
                    instructions.get((addr - instructions[0].address()) as usize + 1)
                {
                    current_block_start = next_insn.address();
                }
            }
        }
    }

    // Add final block if any
    if !current_instrs.is_empty() {
        blocks.push(BasicBlock {
            start_addr: current_block_start,
            end_addr: instructions.last().unwrap().address(),
            instructions: current_instrs,
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
    }

    return blocks;
}

/// Build cross-reference table
fn build_xrefs(instructions: &[Insn], string_refs: &HashMap<u64, String>) -> Vec<CrossReference> {
    let mut xrefs = Vec::new();

    for insn in instructions {
        let from = insn.address();

        if let Some(mnemonic) = insn.mnemonic() {
            if let Some(op_str) = insn.op_str() {
                // Call/Jump xrefs
                if mnemonic == "call" {
                    if let Ok(target) = parse_hex_address(op_str) {
                        xrefs.push(CrossReference {
                            from_addr: from,
                            to_addr: target,
                            xref_type: XRefType::Call,
                        });
                    }
                } else if mnemonic.starts_with('j') {
                    if let Ok(target) = parse_hex_address(op_str) {
                        xrefs.push(CrossReference {
                            from_addr: from,
                            to_addr: target,
                            xref_type: XRefType::Jump,
                        });
                    }
                }

                // Data references
                if op_str.contains('[') {
                    if let Some(addr_start) = op_str.find("0x") {
                        let addr_part = &op_str[addr_start..];
                        let addr_end = addr_part
                            .find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
                            .unwrap_or(addr_part.len());

                        if let Ok(addr) = parse_hex_address(&addr_part[..addr_end]) {
                            let xref_type =
                                if mnemonic.starts_with("mov") && op_str.starts_with('[') {
                                    XRefType::DataRead
                                } else if mnemonic.starts_with("mov") {
                                    XRefType::DataWrite
                                } else {
                                    XRefType::DataRead
                                };

                            // Check if it's a string reference
                            if string_refs.contains_key(&addr) {
                                xrefs.push(CrossReference {
                                    from_addr: from,
                                    to_addr: addr,
                                    xref_type: XRefType::StringReference,
                                });
                            } else {
                                xrefs.push(CrossReference {
                                    from_addr: from,
                                    to_addr: addr,
                                    xref_type,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    return xrefs;
}

/// Build a map of addresses that are targets of jumps/calls (for labeling)
fn build_label_map(instructions: &[Insn]) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let mut label_counter = 0 as usize;

    for insn in instructions {
        if let Some(mnemonic) = insn.mnemonic() {
            // Check for control flow instructions
            if mnemonic.starts_with('j') || mnemonic == "call" {
                if let Some(op_str) = insn.op_str() {
                    // Try to parse the target address
                    if let Ok(target) = parse_hex_address(op_str) {
                        if !map.contains_key(&target) {
                            label_counter += 1;
                            map.insert(target, format!("label_{}", label_counter));
                        }
                    }
                }
            }
        }
    }

    return map;
}

/// Parse hex address from operand string
fn parse_hex_address(op_str: &str) -> Result<u64, ()> {
    let cleaned = op_str.trim().trim_start_matches("0x");

    return u64::from_str_radix(cleaned, 16).map_err(|_| ());
}

/// Parse a hex address from a memory reference
fn parse_hex_address_from_memory_ref(op_str: &str) -> Result<u64, ()> {
    if let Some(addr_start) = op_str.find("0x") {
        let addr_part = &op_str[addr_start..];
        let addr_end = addr_part
            .find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
            .unwrap_or(addr_part.len());

        return parse_hex_address(&addr_part[..addr_end]);
    }

    return Err(());
}

/// Parse a hex address from a rip memory reference
fn parse_hex_address_from_rip_memory_reference(op_str: &str, insn_addr: u64) -> Result<u64, ()> {
    let offset = parse_hex_address_from_memory_ref(op_str)?;

    return Ok(offset + insn_addr);
}

/// Check if instruction is a call or jump
fn is_control_flow(mnemonic: &str) -> bool {
    return mnemonic == "call" || mnemonic.starts_with('j');
}

/// Format instruction with imports and labels
fn format_instruction(
    insn: &Insn,
    import_map: &HashMap<u64, String>,
    label_map: &HashMap<u64, String>,
    string_refs: &HashMap<u64, String>,
    xrefs_to: &HashMap<u64, Vec<CrossReference>>,
) -> String {
    let mnemonic = insn.mnemonic().unwrap_or("");
    let op_str = insn.op_str().unwrap_or("");
    let addr = insn.address();

    // Build xref comments
    let mut comments = Vec::new();

    // Check if this is a call/jump to a known location
    if is_control_flow(mnemonic) {
        if op_str.contains("[rip") {
            if let Ok(target) = parse_hex_address_from_rip_memory_reference(op_str, addr) {
                let offset = target + insn.bytes().len() as u64;

                if let Some(import_name) = import_map.get(&offset) {
                    comments.push(import_name.clone());
                }
            }
        } else if let Ok(target) = parse_hex_address_from_memory_ref(op_str) {
            if let Some(import_name) = import_map.get(&target) {
                comments.push(import_name.clone());
            } else if let Some(label) = label_map.get(&target) {
                return format!("    {:<8} {}  ; {}", mnemonic, label, comments.join(" | "));
            }
        }
    }

    // Add xrefs to this location as comments
    if let Some(refs) = xrefs_to.get(&addr) {
        if !refs.is_empty() {
            let xref_addrs: Vec<String> = refs
                .iter()
                .take(3)
                .map(|xref| format!("{:08X}", xref.from_addr))
                .collect();
            let more = if refs.len() > 3 {
                format!(", +{} more", refs.len() - 3)
            } else {
                String::new()
            };
            comments.push(format!("XREF from: {}{}", xref_addrs.join(", "), more));
        }
    }

    // Check for memory references
    if op_str.contains('[') && op_str.contains(']') {
        if let Some(addr_start) = op_str.find("0x") {
            let addr_part = &op_str[addr_start..];
            let addr_end = addr_part
                .find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
                .unwrap_or(addr_part.len());

            if let Ok(addr) = parse_hex_address(&addr_part[..addr_end]) {
                // Check for string reference
                if let Some(string) = string_refs.get(&addr) {
                    let truncated = if string.len() > 40 {
                        format!("{}...", &string[..40])
                    } else {
                        string.clone()
                    };
                    comments.push(format!("\"{}\"", truncated));
                }
                // Check for import
                else if let Some(import_name) = import_map.get(&addr) {
                    comments.push(format!("-> {}", import_name));
                }
            }
        }
    }

    // Format with comments
    if comments.is_empty() {
        format!("    {:<8} {}", mnemonic, op_str)
    } else {
        format!(
            "    {:<8} {:<30}  ; {}",
            mnemonic,
            op_str,
            comments.join(" | ")
        )
    }
}

pub fn disasm_pe_code(
    pe: &PE,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .expect("Failed to initialize Capstone disasm");

    let instructions = cs.disasm_all(code, addr).expect("Failed to disassemble");

    let import_map = build_import_map(pe);
    let string_refs = find_string_references(code, addr, pe);
    let label_map = build_label_map(instructions.as_ref());
    let xrefs = build_xrefs(instructions.as_ref(), &string_refs);

    let mut xrefs_to: HashMap<u64, Vec<CrossReference>> = HashMap::new();

    for xref in &xrefs {
        xrefs_to
            .entry(xref.to_addr)
            .or_insert_with(Vec::new)
            .push(xref.clone());
    }

    let function_starts = detect_functions(instructions.as_ref());

    output.push(format!("; Entry: 0x{:X}", addr));

    let mut current_function_idx = 0;

    for insn in instructions.as_ref() {
        if is_padding_instruction(&insn) {
            continue;
        }

        let insn_addr = insn.address();

        if current_function_idx < function_starts.len()
            && insn_addr == function_starts[current_function_idx]
        {
            output.push(String::new());
            output.push(format!("; {}", "─".repeat(40)));
            output.push(format!("; FUNC_{:08x}", insn_addr));

            // Analyze stack frame for this function
            let remaining_insns: Vec<&Insn> = instructions
                .as_ref()
                .iter()
                .skip_while(|i| i.address() < insn_addr)
                .collect();

            if let Some(stack_size) = analyze_stack_frame(remaining_insns.as_slice()) {
                output.push(format!("; Stack frame size: 0x{:X} bytes", stack_size));
            }

            output.push(format!("; {}", "─".repeat(40)));
            output.push(String::new());

            current_function_idx += 1;
        }

        if let Some(label) = label_map.get(&insn_addr) {
            output.push(String::new());
            output.push(format!("{}:", label));
        }

        let formatted = format_instruction(&insn, &import_map, &label_map, &string_refs, &xrefs_to);

        let line = format!("{:08x}  {}", insn_addr, formatted);
        output.push(line);

        if let Some(mnemonic) = insn.mnemonic() {
            if mnemonic == "ret" {
                output.push(String::new());
            }
        }
    }

    output.push(String::new());
    output.push(format!("; End"));

    return Ok(output);
}

pub fn disasm_elf_code(
    elf: &ELF,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .expect("Failed to initialize Capstone disasm");

    let instructions = cs.disasm_all(code, addr).expect("Failed to disassemble");

    output.push(format!("; Entry: 0x{:X}", addr));

    for insn in instructions.as_ref() {
        if is_padding_instruction(&insn) {
            continue;
        }

        output.push(insn.to_string());

        if let Some(mnemonic) = insn.mnemonic() {
            if mnemonic == "ret" {
                output.push(String::new());
            }
        }
    }

    output.push(String::new());
    output.push(format!("; End"));

    return Ok(output);
}
