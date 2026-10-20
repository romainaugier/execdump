/*
 * Program analysis: function discovery, control flow graphs, call graph and strings
 */

pub mod dot;
pub mod function;
pub mod insn;
mod pointers;
pub mod strings;

use crate::analysis::function::{recover_function, CallTarget, Function, FunctionSource, RecoveryContext};
use crate::analysis::insn::{Decoder, Flow, Instruction};
use execdump_core::program::{Program, SymbolKind};

use anyhow::Result;

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
pub fn analyze(program: &Program, progress: Option<&AtomicUsize>) -> Result<Analysis> {
    let decoder = Decoder::new(program.architecture())?;

    let mut analysis = Analysis::default();
    analysis.strings = strings::extract_strings(program);

    // The strings of the (pointer, length) pairs are exact, they replace the text read up to a NUL
    for (&addr, &len) in program.sized_strings.iter() {
        if let Some(bytes) = program.sized_string(addr, len) {
            analysis.strings.insert(addr, String::from_utf8_lossy(bytes).to_string());
        }
    }

    let mut known_starts: HashSet<u64> = program.seeds.iter().map(|s| s.addr).collect();
    known_starts.extend(program.symbols.values().filter(|s| s.kind == SymbolKind::Import && program.is_executable(s.addr)).map(|s| s.addr));

    let queue: VecDeque<(u64, FunctionSource)> = program.seeds.iter().map(|s| (s.addr, FunctionSource::Seed(s.source))).collect();
    let noreturn: HashSet<u64> = HashSet::default();

    let mut sizes: HashMap<u64, u64> = HashMap::default();

    for seed in program.seeds.iter() {
        if let Some(size) = seed.size.filter(|&s| s > 0) {
            sizes.entry(seed.addr).or_insert(size);
        }
    }

    let mut discovery = Discovery { known_starts, noreturn, sizes: &sizes, bounds: Bounds::new(&sizes), covered: HashSet::default(), queue };
    discovery.run(program, &decoder, &mut analysis, progress);

    // Code referenced by address (callbacks, main passed to __libc_start_main, vtables entries...)
    loop {
        let mut referenced = BTreeSet::new();

        for function in analysis.functions.values() {
            for &(_, target) in function.refs.iter() {
                if program.is_executable(target) && !program.is_data(target) && !analysis.functions.contains_key(&target) {
                    referenced.insert(target);
                }
            }
        }

        // Only keep references to code that is not already part of a function
        referenced.retain(|addr| !discovery.covered.contains(addr) && !is_padding(program, &decoder, *addr));

        if referenced.is_empty() {
            break;
        }

        for addr in referenced {
            discovery.known_starts.insert(addr);
            discovery.queue.push_back((addr, FunctionSource::Reference));
        }

        discovery.run(program, &decoder, &mut analysis, progress);
    }

    let Discovery { known_starts, mut noreturn, bounds, mut covered, .. } = discovery;

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

        for (addr, name, source) in dirty {
            // Fragments still stop at the code of the others
            let fragment = source == FunctionSource::TailCall && bounds.inside(addr);

            if fragment {
                for insn in analysis.functions[&addr].blocks.values().flat_map(|b| b.insns.iter()) {
                    covered.remove(&insn.addr);
                }
            }

            let ctx = RecoveryContext { program, decoder: &decoder, known_starts: &known_starts, noreturn: &noreturn, sizes: &sizes, covered: fragment.then_some(&covered) };
            let function = recover_function(&ctx, addr, name, source);

            covered.extend(function.blocks.values().flat_map(|b| b.insns.iter().map(|i| i.addr)));
            analysis.functions.insert(addr, function);
        }
    }

    // Name thunks after the import they jump to
    for function in analysis.functions.values_mut() {
        if let Some(import) = &function.thunk {
            if program.symbol_at(function.addr).map_or(true, |s| s.kind == SymbolKind::Import) {
                function.name = execdump_core::demangle::demangle(import).unwrap_or(import.clone());
            }
        }
    }

    pointers::resolve(program, &decoder, &mut analysis);
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

/// Address ranges of the functions whose size is known (symbols, unwind information)
struct Bounds(Vec<(u64, u64)>);

impl Bounds {
    fn new(sizes: &HashMap<u64, u64>) -> Self {
        let mut ranges: Vec<(u64, u64)> = sizes.iter().map(|(&start, &size)| (start, start.saturating_add(size))).collect();
        ranges.sort();
        return Bounds(ranges);
    }

    /// The address is in the body of a function (not at its start). The parts of a function split by
    /// the compiler (hot and cold) jump into each other: these jumps are not calls of new functions,
    /// which would copy the rest of the other part.
    fn inside(&self, addr: u64) -> bool {
        let index = self.0.partition_point(|&(start, _)| start <= addr);
        return index > 0 && self.0[..index].iter().rev().take(4).any(|&(start, end)| start < addr && addr < end);
    }
}

struct Discovery<'a> {
    known_starts: HashSet<u64>,
    noreturn: HashSet<u64>,
    sizes: &'a HashMap<u64, u64>,
    bounds: Bounds,
    /// Instructions of the functions recovered so far
    covered: HashSet<u64>,
    queue: VecDeque<(u64, FunctionSource)>,
}

impl Discovery<'_> {
    fn run(&mut self, program: &Program, decoder: &Decoder, analysis: &mut Analysis, progress: Option<&AtomicUsize>) {
        while let Some((addr, source)) = self.queue.pop_front() {
            if analysis.functions.contains_key(&addr) || !program.is_executable(addr) {
                continue;
            }

            // A jump into the body of another function: the code that is not recovered yet is a fragment of
            // that function (reached through jumps the analysis could not follow), which stops at the code
            // already recovered instead of copying it
            let fragment = source == FunctionSource::TailCall && self.bounds.inside(addr);

            if fragment && self.covered.contains(&addr) {
                continue;
            }

            if fragment {
                self.known_starts.insert(addr);
            }

            let function = {
                let covered = fragment.then_some(&self.covered);
                let ctx = RecoveryContext { program, decoder, known_starts: &self.known_starts, noreturn: &self.noreturn, sizes: self.sizes, covered };
                recover_function(&ctx, addr, function_name(program, addr), source)
            };

            if function.blocks.is_empty() {
                continue;
            }

            if function.noreturn {
                self.noreturn.insert(addr);
            }

            for call in function.calls.iter() {
                if let CallTarget::Function(target) = call.target {
                    if program.is_executable(target) && !program.is_data(target) && !analysis.functions.contains_key(&target) {
                        let source = if call.tail { FunctionSource::TailCall } else { FunctionSource::Call };

                        // A fragment is a start once it is recovered: the code it jumps to may be in a function
                        if !(call.tail && self.bounds.inside(target)) {
                            self.known_starts.insert(target);
                        }

                        self.queue.push_back((target, source));
                    }
                }
            }

            self.covered.extend(function.blocks.values().flat_map(|b| b.insns.iter().map(|i| i.addr)));
            analysis.functions.insert(addr, function);

            if let Some(progress) = progress {
                progress.fetch_add(1, Ordering::Relaxed);
            }
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
            CallTarget::Import(name) => execdump_core::demangle::demangle(name).unwrap_or(name.clone()),
            CallTarget::Indirect => "<indirect>".to_string(),
        }
    }

    /// Distinct callees of a function, in call order
    pub fn callees(&self, function: &Function) -> Vec<(CallTarget, bool)> {
        let mut seen = HashSet::default();
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

    /// Functions in post order of the call graph (callees before their callers), thunks left out
    pub fn callees_first(&self, starts: impl IntoIterator<Item = u64>) -> Vec<u64> {
        let starts: Vec<u64> = starts.into_iter().collect();
        let wanted: HashSet<u64> = starts.iter().copied().filter(|a| self.functions.get(a).is_some_and(|f| f.thunk.is_none())).collect();
        let mut visited = HashSet::default();
        let mut order = Vec::with_capacity(wanted.len());

        for start in starts {
            let mut stack = vec![(start, false)];

            while let Some((addr, done)) = stack.pop() {
                if done {
                    if wanted.contains(&addr) {
                        order.push(addr);
                    }

                    continue;
                }

                if !visited.insert(addr) {
                    continue;
                }

                stack.push((addr, true));

                if let Some(function) = self.functions.get(&addr) {
                    for call in function.calls.iter() {
                        if let CallTarget::Function(callee) = call.target {
                            stack.push((callee, false));
                        }
                    }
                }
            }
        }

        return order;
    }

    /// Short description of what lives at an address (function, import, string, symbol)
    pub fn describe(&self, program: &Program, addr: u64) -> Option<String> {
        if let Some(function) = self.functions.get(&addr) {
            return Some(function.name.clone());
        }

        if let Some(import) = program.import_slots.get(&addr) {
            return Some(format!("[{}]", execdump_core::demangle::demangle(import).unwrap_or(import.clone())));
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
    use execdump_core::elf::parse_elf;
    use execdump_core::exec::Exec;
    use execdump_core::macho::parse_macho;
    use execdump_core::pe::parse_pe;
    use execdump_core::program::programs_from_exec;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data").join(name);
    }

    #[test]
    fn split_functions() {
        use execdump_core::disasm::Architecture;
        use execdump_core::program::{FunctionSeed, Perms, Region, SeedSource};

        // Hot part at 0x1000 (unwind information: 0xe bytes), cold part at 0x1100 (0xa bytes) jumping back
        let mut code = vec![0xcc; 0x10a];
        code[..0xe].copy_from_slice(&[
            0x85, 0xff,                         // 1000 test edi, edi
            0x0f, 0x84, 0xf8, 0x00, 0x00, 0x00, // 1002 je 1100
            0xb8, 0x01, 0x00, 0x00, 0x00,       // 1008 mov eax, 1
            0xc3,                               // 100d ret
        ]);
        code[0x100..].copy_from_slice(&[
            0xbf, 0x02, 0x00, 0x00, 0x00,       // 1100 mov edi, 2
            0xe9, 0xfe, 0xfe, 0xff, 0xff,       // 1105 jmp 1008
        ]);

        let mut program = Program::default();
        program.arch = Some(Architecture::X86_64);
        program.pointer_size = 8;
        program.regions.push(Region { name: ".text".to_string(), vaddr: 0x1000, size: code.len() as u64, data: code, perms: Perms { read: true, write: false, exec: true } });
        program.seeds.push(FunctionSeed { addr: 0x1000, size: Some(0xe), source: SeedSource::EhFrame });
        program.seeds.push(FunctionSeed { addr: 0x1100, size: Some(0xa), source: SeedSource::EhFrame });

        let analysis = analyze(&program, None).unwrap();

        // The jump back is not a new function, the hot part keeps its code
        assert_eq!(analysis.functions.keys().copied().collect::<Vec<_>>(), vec![0x1000, 0x1100]);
        assert!(analysis.functions[&0x1000].blocks.contains_key(&0x1008));
        assert!(analysis.functions[&0x1100].calls.iter().any(|c| c.tail && c.target == CallTarget::Function(0x1008)));
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
    fn elf_x86_64_analysis() {
        use crate::analysis::function::EdgeKind;

        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_analysis")).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        // The switch is compiled to a jump table with one entry per case
        let classify = analysis.function_by_name("classify").unwrap();
        let switch_edges: usize = classify.blocks.values().map(|b| b.succs.iter().filter(|e| e.kind == EdgeKind::Switch).count()).sum();
        assert_eq!(switch_edges, 7);
        assert_eq!(classify.unresolved_jumps, 0);

        let fatal = analysis.function_by_name("fatal").unwrap();
        assert!(fatal.noreturn);

        let main = analysis.function_by_name("main").unwrap();
        let callees: Vec<String> = analysis.callees(main).iter().map(|(t, _)| analysis.call_target_name(t)).collect();

        for name in ["classify", "count_chars", "fatal", "lib_add"] {
            assert!(callees.iter().any(|c| c == name), "{} not in {:?}", name, callees);
        }

        // The loop in count_chars has a back edge
        let count_chars = analysis.function_by_name("count_chars").unwrap();
        assert!(count_chars.blocks.values().any(|b| b.succs.iter().any(|e| e.to <= b.start)));

        // String references are annotated
        let decoder = Decoder::new(program.architecture()).unwrap();
        let comments: Vec<String> = main.blocks.values()
            .flat_map(|b| b.insns.iter())
            .filter_map(|i| analysis.insn_text(&program, &decoder, i).2)
            .collect();

        assert!(comments.iter().any(|c| c.contains("hello from the analysis fixture")), "{:?}", comments);
        assert!(analysis.callers[&classify.addr].contains(&main.addr));
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
