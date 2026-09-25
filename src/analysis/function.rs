/*
 * Function and control flow graph recovery (recursive descent)
 */

use crate::analysis::insn::{Aarch64Tracker, Decoded, Decoder, Flow, Instruction, Operand};
use crate::disasm::Architecture;
use crate::program::{Program, SeedSource};

use capstone::arch::x86::X86Reg;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Maximum number of instructions decoded for a single function
const MAX_FUNCTION_INSNS: usize = 200_000;

/// Maximum number of entries read from a jump table
const MAX_JUMP_TABLE_ENTRIES: u64 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Unconditional jump
    Jump,
    /// Conditional branch taken
    True,
    /// Conditional branch not taken
    False,
    /// Block split without a branch (the next block is a jump target)
    Fallthrough,
    /// Jump table entry
    Switch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    pub to: u64,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub insns: Vec<Instruction>,
    pub succs: Vec<Edge>,
    pub preds: Vec<u64>,
}

impl BasicBlock {
    pub fn last(&self) -> &Instruction {
        return self.insns.last().expect("Basic blocks always contain at least one instruction");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CallTarget {
    /// Call to the function starting at this address
    Function(u64),
    /// Call through an import pointer slot
    Import(String),
    /// Unresolved indirect call
    Indirect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    /// Address of the call instruction
    pub addr: u64,
    pub target: CallTarget,
    /// Jump to another function instead of a call
    pub tail: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionSource {
    Seed(SeedSource),
    Call,
    TailCall,
    Reference,
}

impl FunctionSource {
    pub fn name(&self) -> &'static str {
        match self {
            FunctionSource::Seed(seed) => seed.name(),
            FunctionSource::Call => "call",
            FunctionSource::TailCall => "tail call",
            FunctionSource::Reference => "reference",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Function {
    pub addr: u64,
    pub name: String,
    pub source: FunctionSource,
    pub blocks: BTreeMap<u64, BasicBlock>,
    pub calls: Vec<CallSite>,
    /// (instruction address, referenced address) pairs, for the addresses computed or loaded by the code
    pub refs: Vec<(u64, u64)>,
    /// Name of the imported function if this function only jumps to it (PLT entry, stub, import thunk)
    pub thunk: Option<String>,
    /// Function never returns to its caller
    pub noreturn: bool,
    /// Function contains indirect jumps that could not be resolved
    pub unresolved_jumps: usize,
}

impl Function {
    pub fn num_insns(&self) -> usize {
        return self.blocks.values().map(|b| b.insns.len()).sum();
    }

    pub fn size(&self) -> u64 {
        return self.blocks.values().map(|b| b.end - b.start).sum();
    }

    /// Returns the highest address covered by the function
    pub fn end(&self) -> u64 {
        return self.blocks.values().map(|b| b.end).max().unwrap_or(self.addr);
    }

    pub fn block_containing(&self, addr: u64) -> Option<&BasicBlock> {
        let (_, block) = self.blocks.range(..=addr).next_back()?;

        if addr < block.end {
            return Some(block);
        }

        return None;
    }

    pub fn contains(&self, addr: u64) -> bool {
        return self.block_containing(addr).is_some();
    }
}

/// Well known functions that never return
pub fn is_noreturn_name(name: &str) -> bool {
    let name = name.rsplit('!').next().unwrap_or(name);
    let name = name.split('@').next().unwrap_or(name);
    let name = name.trim_start_matches('_');

    return matches!(
        name,
        "exit" | "Exit" | "abort" | "stack_chk_fail" | "assert_fail" | "assert_rtn" | "libc_start_main" |
        "cxa_throw" | "cxa_rethrow" | "cxa_bad_cast" | "cxa_bad_typeid" | "Unwind_Resume" | "longjmp" | "siglongjmp" |
        "longjmp_chk" | "pthread_exit" | "fortify_fail" | "chk_fail" | "err" | "errx" | "verr" | "verrx" |
        "ExitProcess" | "ExitThread" | "FatalExit" | "FatalAppExitA" | "FatalAppExitW" | "RaiseFailFastException" |
        "invalid_parameter_noinfo_noreturn" | "report_gsfailure" | "report_rangecheckfailure" | "CxxThrowException" |
        "ZSt9terminatev" | "ZSt17__throw_bad_allocv" | "ZSt20__throw_length_errorPKc" | "ZSt24__throw_out_of_range_fmtPKcz" |
        "ZSt19__throw_logic_errorPKc" | "ZSt20__throw_out_of_rangePKc" | "ZSt25__throw_bad_function_callv" |
        "ZSt28__throw_bad_array_new_lengthv" | "ZSt16__throw_bad_castv" | "ZSt21__throw_bad_variant_accessPKc"
    ) || name.starts_with("ZN4core9panicking") || name.starts_with("ZN3std7process4exit") || name.starts_with("ZN5alloc5alloc18handle_alloc_error")
      || name.starts_with("rust_panic") || name.starts_with("rust_begin_unwind") || name.starts_with("ZN3std9panicking")
}

/// Context shared by all function recoveries
pub struct RecoveryContext<'a> {
    pub program: &'a Program,
    pub decoder: &'a Decoder,
    /// Known function starts (seeds and already discovered functions)
    pub known_starts: &'a BTreeSet<u64>,
    /// Functions known to never return
    pub noreturn: &'a HashSet<u64>,
    /// Function sizes known from the metadata (symbols, unwind information)
    pub sizes: &'a HashMap<u64, u64>,
}

impl RecoveryContext<'_> {
    fn import_name(&self, slot: Option<u64>) -> Option<&String> {
        return slot.and_then(|s| self.program.import_slots.get(&s));
    }

    fn call_is_noreturn(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::Function(addr) => {
                self.noreturn.contains(addr) || self.program.symbol_at(*addr).map_or(false, |s| is_noreturn_name(&s.name))
            }
            CallTarget::Import(name) => is_noreturn_name(name),
            CallTarget::Indirect => false,
        }
    }

    fn decode(&self, addr: u64) -> Option<Decoded> {
        if !self.program.is_executable(addr) {
            return None;
        }

        return self.decoder.decode(self.program.bytes_from(addr)?, addr);
    }
}

struct Recovery<'a, 'b> {
    ctx: &'b RecoveryContext<'a>,
    start: u64,
    insns: BTreeMap<u64, Instruction>,
    leaders: BTreeSet<u64>,
    /// Addresses after which execution does not continue (noreturn calls)
    stops: HashSet<u64>,
    /// Resolved jump table targets, by jump instruction address
    switches: BTreeMap<u64, Vec<u64>>,
    calls: Vec<CallSite>,
    refs: Vec<(u64, u64)>,
    unresolved_jumps: usize,
}

impl Recovery<'_, '_> {
    fn is_other_function(&self, addr: u64) -> bool {
        return addr != self.start && self.ctx.known_starts.contains(&addr);
    }

    /// A jump leaves the function if it targets another function, non executable memory,
    /// or an address outside of the function bounds when they are known
    fn is_tail_jump(&self, target: u64) -> bool {
        if self.is_other_function(target) || !self.ctx.program.is_executable(target) {
            return true;
        }

        if let Some(&size) = self.ctx.sizes.get(&self.start) {
            return target < self.start || target >= self.start + size;
        }

        return false;
    }

    fn add_refs(&mut self, insn: &Instruction) {
        for r in [insn.mem_ref, insn.imm_ref].into_iter().flatten() {
            if self.ctx.program.region_at(r).is_some() {
                self.refs.push((insn.addr, r));
            }
        }
    }

    /// Walks the instructions from addr until the end of the linear run
    fn walk(&mut self, addr: u64, work: &mut Vec<u64>) {
        let mut pc = addr;
        let mut tracker = Aarch64Tracker::default();

        loop {
            if self.insns.contains_key(&pc) {
                // Already visited, make sure it starts a block since two paths join here
                self.leaders.insert(pc);
                return;
            }

            if self.is_other_function(pc) || self.insns.len() >= MAX_FUNCTION_INSNS {
                return;
            }

            let Some(mut decoded) = self.ctx.decode(pc) else {
                return;
            };

            if self.ctx.decoder.arch() == Architecture::Aarch64 {
                tracker.step(&mut decoded);
            }

            let insn = decoded.insn;

            self.insns.insert(pc, insn);
            self.add_refs(&insn);

            match insn.flow {
                Flow::Seq => {}
                Flow::Call(target) => {
                    let target = CallTarget::Function(target);
                    let noreturn = self.ctx.call_is_noreturn(&target);

                    self.calls.push(CallSite { addr: pc, target, tail: false });

                    if noreturn {
                        self.stops.insert(pc);
                        return;
                    }
                }
                Flow::IndirectCall => {
                    let target = self.ctx.import_name(insn.mem_ref).map_or(CallTarget::Indirect, |n| CallTarget::Import(n.clone()));
                    let noreturn = self.ctx.call_is_noreturn(&target);

                    self.calls.push(CallSite { addr: pc, target, tail: false });

                    if noreturn {
                        self.stops.insert(pc);
                        return;
                    }
                }
                Flow::Jump(target) => {
                    // Unconditional jumps before the function start are tail calls to the previous function
                    if self.is_tail_jump(target) || target < self.start {
                        self.calls.push(CallSite { addr: pc, target: CallTarget::Function(target), tail: true });
                    } else {
                        self.leaders.insert(target);
                        work.push(target);
                    }

                    return;
                }
                Flow::CondJump(target) => {
                    if self.is_tail_jump(target) {
                        self.calls.push(CallSite { addr: pc, target: CallTarget::Function(target), tail: true });
                    } else {
                        self.leaders.insert(target);
                        work.push(target);
                    }

                    self.leaders.insert(insn.end());
                }
                Flow::IndirectJump => {
                    if let Some(name) = self.ctx.import_name(insn.mem_ref) {
                        self.calls.push(CallSite { addr: pc, target: CallTarget::Import(name.clone()), tail: true });
                    } else if let Some(targets) = self.resolve_jump_table(&decoded) {
                        for &target in targets.iter() {
                            self.leaders.insert(target);
                            work.push(target);
                        }

                        self.switches.insert(pc, targets);
                    } else {
                        self.unresolved_jumps += 1;
                    }

                    return;
                }
                Flow::Ret | Flow::Trap => return,
            }

            pc = insn.end();
        }
    }

    /// Previous instructions in address order, closest first
    fn previous_insns(&self, addr: u64, count: usize) -> Vec<Decoded> {
        let mut res = Vec::new();
        let mut expected = addr;

        for (_, insn) in self.insns.range(..addr).rev().take(count) {
            if insn.end() != expected {
                break;
            }

            if let Some(decoded) = self.ctx.decode(insn.addr) {
                res.push(decoded);
            }

            expected = insn.addr;
        }

        return res;
    }

    /// Looks for a "cmp reg, imm ; ja/jae" bound check before a jump table
    fn jump_table_bound(previous: &[Decoded]) -> Option<u64> {
        let mut inclusive = true;

        for decoded in previous.iter() {
            let mnemonic = decoded.base_mnemonic();

            match mnemonic {
                "ja" | "jnbe" => inclusive = true,
                "jae" | "jnb" | "jnc" => inclusive = false,
                "cmp" => {
                    if let Operand::Imm(imm) = decoded.operand(1) {
                        if imm < 0 {
                            return None;
                        }

                        let count = if inclusive { (imm as u64).saturating_add(1) } else { imm as u64 };
                        return Some(count.min(MAX_JUMP_TABLE_ENTRIES));
                    }

                    return None;
                }
                _ => {}
            }
        }

        return None;
    }

    fn table_target_valid(&self, target: u64) -> bool {
        return self.ctx.program.is_executable(target) && !self.is_other_function(target);
    }

    /// Resolves the common x86 jump table patterns:
    ///   jmp qword ptr [reg*8 + table]                          (absolute table)
    ///   lea rB, [rip + table] ; movsxd rX, dword ptr [rB + rI*4] ; add rX, rB ; jmp rX   (relative table)
    fn resolve_jump_table(&self, jump: &Decoded) -> Option<Vec<u64>> {
        if !matches!(self.ctx.decoder.arch(), Architecture::X86 | Architecture::X86_64) {
            return None;
        }

        let program = self.ctx.program;
        let previous = self.previous_insns(jump.insn.addr, 16);
        let bound = Self::jump_table_bound(&previous);
        let pointer_size = program.pointer_size as u64;

        let mut targets = Vec::new();

        match jump.operand(0) {
            Operand::Mem { base: 0, index, scale, disp } if index != 0 && scale as u64 == pointer_size => {
                let table = disp as u64;

                for i in 0..bound.unwrap_or(MAX_JUMP_TABLE_ENTRIES) {
                    let Some(target) = program.read_pointer(table.wrapping_add(i * pointer_size)) else {
                        break;
                    };

                    if !self.table_target_valid(target) {
                        break;
                    }

                    targets.push(target);
                }
            }
            Operand::Reg(jump_reg) => {
                // Find the table load and the table base computation
                let mut base_reg = None;
                let mut table = None;

                for decoded in previous.iter() {
                    match (decoded.base_mnemonic(), decoded.operand(0), decoded.operand(1)) {
                        ("movsxd" | "movslq", Operand::Reg(dst), Operand::Mem { base, index, scale: 4, .. }) if index != 0 && base_reg.is_none() => {
                            if dst == jump_reg || Self::same_x86_reg(dst, jump_reg) {
                                base_reg = Some(base);
                            }
                        }
                        ("lea", Operand::Reg(dst), Operand::Mem { base, .. }) if Some(dst) == base_reg && base == X86Reg::X86_REG_RIP as u16 => {
                            table = decoded.insn.imm_ref;
                            break;
                        }
                        _ => {}
                    }
                }

                let table = table?;

                for i in 0..bound.unwrap_or(MAX_JUMP_TABLE_ENTRIES) {
                    let Some(offset) = program.read_u32(table.wrapping_add(i * 4)) else {
                        break;
                    };

                    let target = table.wrapping_add(offset as i32 as i64 as u64);

                    if !self.table_target_valid(target) {
                        break;
                    }

                    targets.push(target);
                }
            }
            _ => return None,
        }

        if targets.is_empty() {
            return None;
        }

        targets.sort_unstable();
        targets.dedup();

        return Some(targets);
    }

    fn same_x86_reg(a: u16, b: u16) -> bool {
        // movsxd writes the 64-bit register, the jump uses the same one
        return a == b;
    }

    fn build_blocks(&self) -> BTreeMap<u64, BasicBlock> {
        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
        let mut current: Option<BasicBlock> = None;

        let close = |block: BasicBlock, blocks: &mut BTreeMap<u64, BasicBlock>| {
            blocks.insert(block.start, block);
        };

        for (&addr, insn) in self.insns.iter() {
            if let Some(block) = current.take() {
                if self.leaders.contains(&addr) || block.end != addr {
                    let mut block = block;

                    if block.end == addr {
                        block.succs.push(Edge { to: addr, kind: EdgeKind::Fallthrough });
                    }

                    close(block, &mut blocks);
                } else {
                    current = Some(block);
                }
            }

            let block = current.get_or_insert_with(|| BasicBlock { start: addr, end: addr, insns: Vec::new(), succs: Vec::new(), preds: Vec::new() });

            block.insns.push(*insn);
            block.end = insn.end();

            let ends = insn.flow.ends_block() || self.stops.contains(&addr);

            if ends {
                let mut block = current.take().unwrap();

                match insn.flow {
                    Flow::Jump(target) if !self.is_tail_jump(target) && target >= self.start => {
                        block.succs.push(Edge { to: target, kind: EdgeKind::Jump });
                    }
                    Flow::CondJump(target) => {
                        if !self.is_tail_jump(target) {
                            block.succs.push(Edge { to: target, kind: EdgeKind::True });
                        }

                        block.succs.push(Edge { to: insn.end(), kind: EdgeKind::False });
                    }
                    Flow::IndirectJump => {
                        if let Some(targets) = self.switches.get(&addr) {
                            for &target in targets.iter() {
                                block.succs.push(Edge { to: target, kind: EdgeKind::Switch });
                            }
                        }
                    }
                    _ => {}
                }

                close(block, &mut blocks);
            }
        }

        if let Some(block) = current {
            close(block, &mut blocks);
        }

        // Remove edges to addresses that do not start a block (jumps in the middle of an instruction)
        let starts: HashSet<u64> = blocks.keys().copied().collect();
        let mut preds: Vec<(u64, u64)> = Vec::new();

        for block in blocks.values_mut() {
            block.succs.retain(|e| starts.contains(&e.to));
            block.succs.dedup_by_key(|e| e.to);

            for edge in block.succs.iter() {
                preds.push((edge.to, block.start));
            }
        }

        for (to, from) in preds {
            if let Some(block) = blocks.get_mut(&to) {
                if !block.preds.contains(&from) {
                    block.preds.push(from);
                }
            }
        }

        return blocks;
    }
}

/// Recovers the function starting at addr
pub fn recover_function(ctx: &RecoveryContext, addr: u64, name: String, source: FunctionSource) -> Function {
    let mut recovery = Recovery {
        ctx,
        start: addr,
        insns: BTreeMap::new(),
        leaders: BTreeSet::from([addr]),
        stops: HashSet::new(),
        switches: BTreeMap::new(),
        calls: Vec::new(),
        refs: Vec::new(),
        unresolved_jumps: 0,
    };

    let mut work = vec![addr];

    while let Some(target) = work.pop() {
        recovery.walk(target, &mut work);
    }

    let blocks = recovery.build_blocks();

    // Thunks: a single block ending with a jump through an import slot, or an import stub symbol
    let thunk = if let Some(symbol) = ctx.program.symbol_at(addr).filter(|s| s.kind == crate::program::SymbolKind::Import) {
        Some(symbol.name.clone())
    } else if blocks.len() == 1 && recovery.calls.len() == 1 && recovery.calls[0].tail {
        match &recovery.calls[0].target {
            CallTarget::Import(name) => Some(name.clone()),
            _ => None,
        }
    } else {
        None
    };

    let mut function = Function {
        addr,
        name,
        source,
        blocks,
        calls: recovery.calls,
        refs: recovery.refs,
        thunk,
        noreturn: false,
        unresolved_jumps: recovery.unresolved_jumps,
    };

    function.noreturn = compute_noreturn(ctx, &function);

    return function;
}

/// A function does not return if no path ends with a return (or a tail call to a returning function)
fn compute_noreturn(ctx: &RecoveryContext, function: &Function) -> bool {
    if let Some(name) = &function.thunk {
        return is_noreturn_name(name);
    }

    if ctx.program.symbol_at(function.addr).map_or(false, |s| is_noreturn_name(&s.name)) {
        return true;
    }

    if function.blocks.is_empty() || function.unresolved_jumps > 0 {
        return false;
    }

    for block in function.blocks.values() {
        let last = block.last();

        match last.flow {
            Flow::Ret => return false,
            Flow::Jump(_) | Flow::CondJump(_) | Flow::IndirectJump => {
                let tail = function.calls.iter().find(|c| c.addr == last.addr && c.tail);

                if let Some(call) = tail {
                    if !ctx.call_is_noreturn(&call.target) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{Perms, Region};

    fn program(arch: Architecture, code: &[u8]) -> Program {
        let mut program = Program::default();

        program.arch = Some(arch);
        program.pointer_size = 8;
        program.regions.push(Region {
            name: ".text".to_string(),
            vaddr: 0x1000,
            size: code.len() as u64,
            data: code.to_vec(),
            perms: Perms { read: true, write: false, exec: true },
        });

        return program;
    }

    fn recover(program: &Program, known: &[u64]) -> Function {
        let decoder = Decoder::new(program.architecture()).unwrap();
        let known_starts: BTreeSet<u64> = known.iter().copied().collect();
        let noreturn = HashSet::new();
        let sizes = HashMap::new();
        let ctx = RecoveryContext { program, decoder: &decoder, known_starts: &known_starts, noreturn: &noreturn, sizes: &sizes };

        return recover_function(&ctx, 0x1000, "f".to_string(), FunctionSource::Call);
    }

    #[test]
    fn if_else_diamond() {
        // 0x1000: test edi, edi
        // 0x1002: je 0x1009
        // 0x1004: mov eax, 1
        //         (falls into 0x1009 is avoided with a jmp)
        // 0x1009: ...
        let code = [
            0x85, 0xff,                   // 1000 test edi, edi
            0x74, 0x07,                   // 1002 je 100b
            0xb8, 0x01, 0x00, 0x00, 0x00, // 1004 mov eax, 1
            0xeb, 0x05,                   // 1009 jmp 1010
            0xb8, 0x02, 0x00, 0x00, 0x00, // 100b mov eax, 2
            0xc3,                         // 1010 ret
        ];

        let function = recover(&program(Architecture::X86_64, &code), &[]);

        assert_eq!(function.blocks.keys().copied().collect::<Vec<_>>(), vec![0x1000, 0x1004, 0x100b, 0x1010]);

        let entry = &function.blocks[&0x1000];
        assert_eq!(entry.succs, vec![Edge { to: 0x100b, kind: EdgeKind::True }, Edge { to: 0x1004, kind: EdgeKind::False }]);

        assert_eq!(function.blocks[&0x1004].succs, vec![Edge { to: 0x1010, kind: EdgeKind::Jump }]);
        assert_eq!(function.blocks[&0x100b].succs, vec![Edge { to: 0x1010, kind: EdgeKind::Fallthrough }]);
        assert_eq!(function.blocks[&0x1010].preds.len(), 2);
        assert!(!function.noreturn);
    }

    #[test]
    fn loop_back_edge() {
        let code = [
            0x31, 0xc0,       // 1000 xor eax, eax
            0xff, 0xc0,       // 1002 inc eax
            0x39, 0xf8,       // 1004 cmp eax, edi
            0x7c, 0xfa,       // 1006 jl 1002
            0xc3,             // 1008 ret
        ];

        let function = recover(&program(Architecture::X86_64, &code), &[]);

        assert_eq!(function.blocks.keys().copied().collect::<Vec<_>>(), vec![0x1000, 0x1002, 0x1008]);
        assert!(function.blocks[&0x1002].succs.contains(&Edge { to: 0x1002, kind: EdgeKind::True }));
    }

    #[test]
    fn tail_call_and_noreturn() {
        let code = [
            0xe9, 0x0b, 0x00, 0x00, 0x00, // 1000 jmp 1010 (another function)
        ];

        let mut code = code.to_vec();
        code.resize(0x10, 0x90);
        code.extend_from_slice(&[0x0f, 0x0b]); // 1010 ud2

        let program = program(Architecture::X86_64, &code);
        let function = recover(&program, &[0x1010]);

        assert_eq!(function.blocks.len(), 1);
        assert_eq!(function.calls, vec![CallSite { addr: 0x1000, target: CallTarget::Function(0x1010), tail: true }]);
    }

    #[test]
    fn absolute_jump_table() {
        let mut code = vec![
            0x83, 0xff, 0x01,                                     // 1000 cmp edi, 1
            0x77, 0x0e,                                           // 1003 ja 1013
            0x89, 0xf8,                                           // 1005 mov eax, edi
            0xff, 0x24, 0xc5, 0x20, 0x10, 0x00, 0x00,             // 1007 jmp qword ptr [rax*8 + 0x1020]
            0x90, 0x90, 0x90, 0x90, 0x90,                         // 100e nops
            0xc3,                                                 // 1013 ret
            0xc3,                                                 // 1014 ret
            0xc3,                                                 // 1015 ret
        ];

        code.resize(0x20, 0xcc);
        code.extend_from_slice(&0x1014u64.to_le_bytes());
        code.extend_from_slice(&0x1015u64.to_le_bytes());

        let function = recover(&program(Architecture::X86_64, &code), &[]);
        let switch = &function.blocks[&0x1005];

        assert_eq!(switch.succs, vec![Edge { to: 0x1014, kind: EdgeKind::Switch }, Edge { to: 0x1015, kind: EdgeKind::Switch }]);
        assert_eq!(function.unresolved_jumps, 0);
    }
}
