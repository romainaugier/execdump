/*
 * Program analysis: function discovery, control flow graphs, call graph and strings
 */

pub mod dot;
pub mod function;
pub mod insn;
pub mod strings;

use crate::analysis::function::{recover_function, CallTarget, Function, FunctionSource, RecoveryContext};
use crate::analysis::insn::{Decoder, Flow, Instruction};
use crate::program::{Program, SymbolKind};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of noreturn propagation passes
const MAX_NORETURN_PASSES: usize = 3;

#[derive(Clone, Debug, Default)]
pub struct Analysis {
    pub functions: BTreeMap<u64, Function>,
    /// Callers of each function (function address -> caller function addresses)
    pub callers: HashMap<u64, Vec<u64>>,
    pub strings: BTreeMap<u64, String>,
}

fn function_name(program: &Program, addr: u64) -> String {
    if let Some(symbol) = program.symbol_at(addr) {
        return symbol.demangled.clone();
    }

    return format!("sub_{:x}", addr);
}

/// Runs the whole analysis, progress is incremented for each function recovered
pub fn analyze(program: &Program, progress: Option<&AtomicUsize>) -> Result<Analysis, Box<dyn std::error::Error>> {
    let decoder = Decoder::new(program.architecture())?;

    let mut analysis = Analysis::default();
    analysis.strings = strings::extract_strings(program);

    let mut known_starts: BTreeSet<u64> = program.seeds.iter().map(|s| s.addr).collect();
    known_starts.extend(program.symbols.values().filter(|s| s.kind == SymbolKind::Import && program.is_executable(s.addr)).map(|s| s.addr));

    let mut queue: VecDeque<(u64, FunctionSource)> = program.seeds.iter().map(|s| (s.addr, FunctionSource::Seed(s.source))).collect();
    let mut noreturn: HashSet<u64> = HashSet::new();

    let mut sizes: HashMap<u64, u64> = HashMap::new();

    for seed in program.seeds.iter() {
        if let Some(size) = seed.size.filter(|&s| s > 0) {
            sizes.entry(seed.addr).or_insert(size);
        }
    }

    discover(program, &decoder, &mut analysis, &mut known_starts, &mut noreturn, &sizes, &mut queue, progress);

    // Code referenced by address (callbacks, main passed to __libc_start_main, vtables entries...)
    loop {
        let mut referenced = BTreeSet::new();

        for function in analysis.functions.values() {
            for &(_, target) in function.refs.iter() {
                if program.is_executable(target) && !analysis.functions.contains_key(&target) {
                    referenced.insert(target);
                }
            }
        }

        // Only keep references to code that is not already part of a function
        let covered = coverage(&analysis);
        referenced.retain(|addr| !covered.contains(addr) && !is_padding(program, &decoder, *addr));

        if referenced.is_empty() {
            break;
        }

        for addr in referenced {
            known_starts.insert(addr);
            queue.push_back((addr, FunctionSource::Reference));
        }

        discover(program, &decoder, &mut analysis, &mut known_starts, &mut noreturn, &sizes, &mut queue, progress);
    }

    // Noreturn propagation: functions calling newly found noreturn functions must be recovered again
    for _ in 0..MAX_NORETURN_PASSES {
        noreturn.extend(analysis.functions.values().filter(|f| f.noreturn).map(|f| f.addr));

        let dirty: Vec<(u64, String, FunctionSource)> = analysis.functions.values()
            .filter(|f| f.calls.iter().any(|c| !c.tail && matches!(c.target, CallTarget::Function(t) if noreturn.contains(&t)) && !is_block_end(f, c.addr)))
            .map(|f| (f.addr, f.name.clone(), f.source))
            .collect();

        if dirty.is_empty() {
            break;
        }

        let ctx = RecoveryContext { program, decoder: &decoder, known_starts: &known_starts, noreturn: &noreturn, sizes: &sizes };

        for (addr, name, source) in dirty {
            let function = recover_function(&ctx, addr, name, source);
            analysis.functions.insert(addr, function);
        }
    }

    // Name thunks after the import they jump to
    for function in analysis.functions.values_mut() {
        if let Some(import) = &function.thunk {
            if program.symbol_at(function.addr).map_or(true, |s| s.kind == SymbolKind::Import) {
                function.name = crate::demangle::demangle(import).unwrap_or(import.clone());
            }
        }
    }

    analysis.build_callers();

    return Ok(analysis);
}

fn is_block_end(function: &Function, addr: u64) -> bool {
    return function.block_containing(addr).map_or(true, |b| b.last().addr == addr && b.succs.is_empty());
}

fn is_padding(program: &Program, decoder: &Decoder, addr: u64) -> bool {
    let Some(text) = program.bytes_from(addr).and_then(|b| decoder.text(b, addr)) else {
        return true;
    };

    return matches!(text.mnemonic.as_str(), "nop" | "int3" | "udf" | "hlt") || (text.mnemonic == "add" && text.operands == "byte ptr [rax], al");
}

fn coverage(analysis: &Analysis) -> HashSet<u64> {
    let mut covered = HashSet::new();

    for function in analysis.functions.values() {
        for block in function.blocks.values() {
            for insn in block.insns.iter() {
                covered.insert(insn.addr);
            }
        }
    }

    return covered;
}

fn discover(
    program: &Program,
    decoder: &Decoder,
    analysis: &mut Analysis,
    known_starts: &mut BTreeSet<u64>,
    noreturn: &mut HashSet<u64>,
    sizes: &HashMap<u64, u64>,
    queue: &mut VecDeque<(u64, FunctionSource)>,
    progress: Option<&AtomicUsize>,
) {
    while let Some((addr, source)) = queue.pop_front() {
        if analysis.functions.contains_key(&addr) || !program.is_executable(addr) {
            continue;
        }

        let function = {
            let ctx = RecoveryContext { program, decoder, known_starts, noreturn, sizes };
            recover_function(&ctx, addr, function_name(program, addr), source)
        };

        if function.blocks.is_empty() {
            continue;
        }

        if function.noreturn {
            noreturn.insert(addr);
        }

        for call in function.calls.iter() {
            if let CallTarget::Function(target) = call.target {
                if program.is_executable(target) && !analysis.functions.contains_key(&target) {
                    let source = if call.tail { FunctionSource::TailCall } else { FunctionSource::Call };

                    known_starts.insert(target);
                    queue.push_back((target, source));
                }
            }
        }

        analysis.functions.insert(addr, function);

        if let Some(progress) = progress {
            progress.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Analysis {
    fn build_callers(&mut self) {
        self.callers.clear();

        for function in self.functions.values() {
            for call in function.calls.iter() {
                if let CallTarget::Function(target) = call.target {
                    let callers = self.callers.entry(target).or_default();

                    if !callers.contains(&function.addr) {
                        callers.push(function.addr);
                    }
                }
            }
        }
    }

    /// Returns the function containing the address, preferring the one starting there
    pub fn function_containing(&self, addr: u64) -> Option<&Function> {
        if let Some(function) = self.functions.get(&addr) {
            return Some(function);
        }

        // Functions can be interleaved, check the closest ones before the address
        return self.functions.range(..=addr).rev().take(64).map(|(_, f)| f).find(|f| f.contains(addr));
    }

    pub fn function_by_name(&self, name: &str) -> Option<&Function> {
        return self.functions.values().find(|f| f.name == name)
            .or_else(|| self.functions.values().find(|f| f.name.trim_start_matches('_') == name.trim_start_matches('_')));
    }

    /// Name of a call target, for display
    pub fn call_target_name(&self, target: &CallTarget) -> String {
        match target {
            CallTarget::Function(addr) => self.functions.get(addr).map_or(format!("sub_{:x}", addr), |f| f.name.clone()),
            CallTarget::Import(name) => crate::demangle::demangle(name).unwrap_or(name.clone()),
            CallTarget::Indirect => "<indirect>".to_string(),
        }
    }

    /// Distinct callees of a function, in call order
    pub fn callees(&self, function: &Function) -> Vec<(CallTarget, bool)> {
        let mut seen = HashSet::new();
        let mut res = Vec::new();

        for call in function.calls.iter() {
            if call.target == CallTarget::Indirect {
                continue;
            }

            // Calls to thunks are shown as calls to the import
            let target = match &call.target {
                CallTarget::Function(addr) => match self.functions.get(addr).and_then(|f| f.thunk.clone()) {
                    Some(import) => CallTarget::Import(import),
                    None => call.target.clone(),
                },
                other => other.clone(),
            };

            if seen.insert(target.clone()) {
                res.push((target, call.tail));
            }
        }

        return res;
    }

    /// Short description of what lives at an address (function, import, string, symbol)
    pub fn describe(&self, program: &Program, addr: u64) -> Option<String> {
        if let Some(function) = self.functions.get(&addr) {
            return Some(function.name.clone());
        }

        if let Some(import) = program.import_slots.get(&addr) {
            return Some(format!("[{}]", crate::demangle::demangle(import).unwrap_or(import.clone())));
        }

        if let Some(string) = self.strings.get(&addr) {
            return Some(format!("\"{}\"", strings::escape(string, 48)));
        }

        if let Some((symbol, offset)) = program.symbol_near(addr) {
            if offset == 0 {
                return Some(symbol.demangled.clone());
            }

            return Some(format!("{}+{:#x}", symbol.demangled, offset));
        }

        return None;
    }

    /// Text of an instruction with the call/jump targets replaced by names, and a comment for the references
    pub fn insn_text(&self, program: &Program, decoder: &Decoder, insn: &Instruction) -> (String, String, Option<String>) {
        let Some(text) = program.bytes_from(insn.addr).and_then(|b| decoder.text(b, insn.addr)) else {
            return ("???".to_string(), String::new(), None);
        };

        let mut operands = text.operands;
        let mut comment = None;

        match insn.flow {
            Flow::Call(target) | Flow::Jump(target) | Flow::CondJump(target) => {
                if let Some(function) = self.functions.get(&target) {
                    if function.addr != self.function_containing(insn.addr).map_or(0, |f| f.addr) || matches!(insn.flow, Flow::Call(_)) {
                        operands = function.name.clone();
                    }
                }
            }
            _ => {}
        }

        for r in [insn.mem_ref, insn.imm_ref].into_iter().flatten() {
            if let Some(description) = self.describe(program, r) {
                comment = Some(description);
                break;
            }
        }

        return (text.mnemonic, operands, comment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::parse_elf;
    use crate::exec::Exec;
    use crate::macho::parse_macho;
    use crate::pe::parse_pe;
    use crate::program::programs_from_exec;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    }

    #[test]
    fn elf_x86_64_dyn() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_dyn")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        let entry = &analysis.functions[&program.entry.unwrap()];
        assert!(!entry.blocks.is_empty());

        // The call to lib_add goes through the PLT, which must be recognized as a thunk
        assert!(analysis.functions.values().any(|f| f.thunk.as_deref() == Some("lib_add")));
    }

    #[test]
    fn elf_aarch64_static() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_aarch64_static")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        let start = analysis.function_by_name("_start").unwrap();
        assert_eq!(start.addr, program.entry.unwrap());
    }

    #[test]
    fn elf_aarch64_dyn() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_aarch64_dyn")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        assert!(analysis.functions.values().any(|f| f.thunk.as_deref() == Some("lib_add")));
    }

    #[test]
    fn pe_arm64() {
        let program = programs_from_exec(&Exec::PE(parse_pe(&fixture("pe_arm64.exe")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        assert!(analysis.functions.len() >= 2);
        assert!(analysis.functions.contains_key(&program.entry.unwrap()));
    }

    #[test]
    fn macho_x86_64() {
        let program = programs_from_exec(&Exec::MachO(parse_macho(&fixture("macho_x86_64")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        let main = analysis.function_by_name("_main").unwrap();
        let callees: Vec<String> = analysis.callees(main).iter().map(|(t, _)| analysis.call_target_name(t)).collect();

        assert!(!callees.is_empty(), "{:?}", callees);
    }
}
