/*
 * Decompiler: lifts the recovered functions to LLVM IR and optimizes them
 *
 * Signatures come from the type database (imports, statically linked libc), from the demangler
 * (C++), or are discovered: the function is lifted with every argument register as a parameter,
 * optimized, and the parameters and return registers that are actually used are kept.
 */

use crate::analysis::function::CallTarget;
use crate::analysis::Analysis;
use crate::cxx;
use crate::lift::regs::{Abi, RegisterFile};
use crate::lift::{self, analyze_frame, discovery_signature, guessed_signature, refine, text_at, Env, LType, Loc, Signature, Value};
use crate::typedb::{Platform, TypeDb};
use crate::analysis::insn::Decoder;
use crate::c::{self, ast::CFunction};
use crate::llm::{self, Assistant, LlmConfig, Renames};
use crate::types::{CType, DataModel, FuncType, Param, Prototype};

use execdump_core::demangle::demangle_symbol;
use execdump_core::disasm::Architecture;
use execdump_core::program::{Format, Program};

use inkwell::context::Context;
use inkwell::module::Module;
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, InitializationConfig, RelocMode, Target, TargetMachine, TargetTriple};
use inkwell::values::BasicValue;
use inkwell::OptimizationLevel;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Cleanup passes, chosen to keep the code readable: no loop transformations, no vectorization,
/// no switch to lookup table conversion and no jump threading (they duplicate or obfuscate code)
const PASSES: &str = "function(sroa,mem2reg,early-cse,instcombine<no-verify-fixpoint>,simplifycfg,sccp,gvn,dse,adce,instcombine<no-verify-fixpoint>,simplifycfg)";

pub struct Decompiler<'a> {
    pub program: &'a Program,
    pub analysis: &'a Analysis,
    pub regs: RegisterFile,
    pub abi: Abi,
    pub model: DataModel,
    pub typedb: TypeDb,
    classes: HashSet<String>,
    signatures: RefCell<HashMap<u64, Signature>>,
    in_progress: RefCell<HashSet<u64>>,
    /// Names given to the globals, and the C prototypes of the functions, for the C backend
    globals: RefCell<HashMap<String, u64>>,
    prototypes: RefCell<HashMap<String, Prototype>>,
    decoder: Decoder,
    /// LLM improvement pass and the names it gave to the functions
    assistant: Option<Assistant>,
    renames: RefCell<Renames>,
}

impl<'a> Decompiler<'a> {
    pub fn new(program: &'a Program, analysis: &'a Analysis) -> Result<Self, String> {
        let arch = program.architecture();

        if arch == Architecture::Unsupported {
            return Err("unsupported architecture".to_string());
        }

        let windows = program.format == Format::Pe;
        let regs = RegisterFile::new(arch);
        let abi = Abi::new(&regs, windows);
        let model = DataModel::new(arch, windows);
        let typedb = TypeDb::bundled(if windows { Platform::Windows } else { Platform::Unix }, model);

        let symbols: Vec<_> = program.symbols.values().filter_map(|s| demangle_symbol(&s.name)).collect();
        let classes = cxx::known_classes(symbols.iter());

        return Ok(Decompiler {
            program,
            analysis,
            regs,
            abi,
            model,
            typedb,
            classes,
            signatures: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(HashSet::new()),
            globals: RefCell::new(HashMap::new()),
            prototypes: RefCell::new(HashMap::new()),
            decoder: Decoder::new(arch).map_err(|e| e.to_string())?,
            assistant: None,
            renames: RefCell::new(Renames::new()),
        });
    }

    /// Enables the LLM improvement pass of the C code
    pub fn with_assistant(mut self, config: &LlmConfig) -> Result<Self, String> {
        self.assistant = Some(Assistant::new(config)?);
        return Ok(self);
    }

    pub fn has_assistant(&self) -> bool {
        return self.assistant.is_some();
    }

    /// The C function improved by the LLM (names, types and a summary), the function rename is
    /// remembered for the functions decompiled afterwards
    pub fn c_function_improved(&self, addr: u64) -> Result<CFunction, String> {
        let mut function = self.c_function(addr)?;
        let assistant = self.assistant.as_ref().ok_or("no LLM configured")?;

        let mut suggestions = assistant.suggest(&function.print().text)?;

        // Names from the symbols are authoritative, only the unnamed functions are renamed
        if !function.name.starts_with("sub_") {
            suggestions.function_name = None;
        }

        let mut taken: HashSet<String> = self.prototypes.borrow().keys().cloned().collect();
        taken.extend(self.globals.borrow().keys().cloned());
        taken.extend(self.renames.borrow().values().cloned());

        if let Some((old, new)) = llm::apply(&mut function, &suggestions, &self.typedb, &taken) {
            self.renames.borrow_mut().insert(old, new);
        }

        return Ok(function);
    }

    /// The optimized LLVM IR of a function
    pub fn llvm_ir(&self, addr: u64) -> Result<String, String> {
        let cx = Context::create();
        let module = self.lift_function(&cx, addr)?;

        // The instruction addresses are metadata for the C backend
        let text = module.print_to_string().to_string();
        let text: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('!'))
            .map(|l| l.split(", !execdump.addr").next().unwrap_or(l).to_string())
            .collect();

        return Ok(text.join("\n"));
    }

    /// The C code of a function
    pub fn c_code(&self, addr: u64) -> Result<String, String> {
        let function = self.c_function(addr)?;
        return Ok(function.print().text);
    }

    /// The C function of a function, with the address of each statement
    pub fn c_function(&self, addr: u64) -> Result<CFunction, String> {
        let cx = Context::create();
        let module = self.lift_function(&cx, addr)?;
        let sig = self.signature(addr);
        let function = module.get_function(&sig.name).ok_or("the lifted function is missing")?;
        let prototype = self.prototypes.borrow().get(&sig.name).cloned();

        let ctx = c::Context {
            program: self.program,
            typedb: &self.typedb,
            globals: self.globals.borrow().clone(),
            prototypes: self.prototypes.borrow().clone(),
            noreturn: self
                .signatures
                .borrow()
                .values()
                .filter(|s| s.noreturn)
                .map(|s| s.name.clone())
                .chain(self.prototypes.borrow().keys().filter(|n| crate::analysis::function::is_noreturn_name(n)).cloned())
                .collect(),
            instruction: Box::new(|a| self.instruction_text(a)),
        };

        let mut function = c::decompile(&module, function, &ctx, prototype.as_ref(), addr);
        llm::apply_renames(&mut function, &self.renames.borrow());

        return Ok(function);
    }

    fn instruction_text(&self, addr: u64) -> String {
        let text = self.program.bytes_from(addr).and_then(|bytes| self.decoder.text(bytes, addr));
        return text.map_or(String::new(), |t| format!("{} {}", t.mnemonic, t.operands).trim().to_string());
    }

    /// Lifts a function with its final signature into a new module and optimizes it
    pub fn lift_function<'ctx>(&self, cx: &'ctx Context, addr: u64) -> Result<Module<'ctx>, String> {
        let function = self.analysis.functions.get(&addr).ok_or_else(|| format!("no function at {:#x}", addr))?;
        let sig = self.signature(addr);

        let module = self.module(cx, &function.name)?;
        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);

        let frame = analyze_frame(&env, function)?;
        lift::lift(cx, &module, &env, function, &frame, sig, false)?;

        self.optimize(&module)?;

        return Ok(module);
    }

    fn env<'e>(&'e self, signature: &'e dyn Fn(&CallTarget) -> Signature, global_name: &'e dyn Fn(u64) -> String) -> Env<'e> {
        return Env { program: self.program, analysis: self.analysis, regs: &self.regs, abi: &self.abi, signature, global_name };
    }

    fn module<'ctx>(&self, cx: &'ctx Context, name: &str) -> Result<Module<'ctx>, String> {
        let module = cx.create_module(name);
        let machine = self.target_machine()?;

        module.set_triple(&machine.get_triple());
        module.set_data_layout(&machine.get_target_data().get_data_layout());

        return Ok(module);
    }

    fn target_machine(&self) -> Result<TargetMachine, String> {
        let config = InitializationConfig::default();

        let triple = match (self.program.architecture(), self.program.format) {
            (Architecture::X86_64, Format::Pe) => "x86_64-pc-windows-msvc",
            (Architecture::X86_64, Format::MachO) => "x86_64-apple-macosx",
            (Architecture::X86_64, _) => "x86_64-pc-linux-gnu",
            (Architecture::X86, Format::Pe) => "i686-pc-windows-msvc",
            (Architecture::X86, _) => "i686-pc-linux-gnu",
            (Architecture::Aarch64, Format::Pe) => "aarch64-pc-windows-msvc",
            (Architecture::Aarch64, Format::MachO) => "arm64-apple-macosx",
            (Architecture::Aarch64, _) => "aarch64-unknown-linux-gnu",
            (Architecture::Unsupported, _) => return Err("unsupported architecture".to_string()),
        };

        match self.program.architecture() {
            Architecture::Aarch64 => Target::initialize_aarch64(&config),
            _ => Target::initialize_x86(&config),
        }

        let triple = TargetTriple::create(triple);
        let target = Target::from_triple(&triple).map_err(|e| e.to_string())?;

        return target
            .create_target_machine(&triple, "generic", "", OptimizationLevel::Default, RelocMode::Default, CodeModel::Default)
            .ok_or_else(|| "cannot create the target machine".to_string());
    }

    fn optimize(&self, module: &Module) -> Result<(), String> {
        module.verify().map_err(|e| format!("invalid IR: {}", e.to_string()))?;

        let machine = self.target_machine()?;
        module.run_passes(PASSES, &machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;

        // Helpers and globals the optimizations made useless
        for function in module.get_functions().filter(|f| f.count_basic_blocks() == 0 && f.as_global_value().as_pointer_value().get_first_use().is_none()).collect::<Vec<_>>() {
            unsafe { function.delete() };
        }

        for global in module.get_globals().filter(|g| g.as_pointer_value().get_first_use().is_none()).collect::<Vec<_>>() {
            unsafe { global.delete() };
        }

        return Ok(());
    }

    /*
     * Names
     */

    /// C name of a function: the C identifier of its demangled name, its symbol or sub_ADDRESS
    pub fn function_name(&self, addr: u64) -> String {
        let function = self.analysis.functions.get(&addr);

        if let Some(import) = function.and_then(|f| f.thunk.as_ref()) {
            return import_name(import);
        }

        if let Some(symbol) = self.program.symbol_at(addr) {
            if let Some(prototype) = demangle_symbol(&symbol.name).and_then(|s| cxx::prototype(&s, &self.model, &self.classes)) {
                return prototype.name;
            }

            return sanitize(&symbol.name);
        }

        return function.map_or_else(|| format!("sub_{:x}", addr), |f| sanitize(&f.name));
    }

    /// Name of a global: its symbol, s_ADDRESS for strings, g_ADDRESS otherwise
    pub fn global_name(&self, addr: u64) -> String {
        let mut name = self.name_global(addr);

        // Symbols of different addresses can have the same name (versions, copy relocations)
        if self.globals.borrow().get(&name).is_some_and(|&a| a != addr) {
            name = format!("{}_{:x}", name, addr);
        }

        self.globals.borrow_mut().insert(name.clone(), addr);
        return name;
    }

    fn name_global(&self, addr: u64) -> String {
        if let Some(symbol) = self.program.symbol_at(addr) {
            if let Some(demangled) = demangle_symbol(&symbol.name) {
                return cxx::identifier(&demangled.name);
            }

            return sanitize(&symbol.name);
        }

        if text_at(self.program, addr).is_some() && !self.program.region_at(addr).is_some_and(|r| r.perms.write) {
            return format!("s_{:x}", addr);
        }

        return format!("g_{:x}", addr);
    }

    /*
     * Signatures
     */

    fn call_signature(&self, target: &CallTarget) -> Signature {
        return match target {
            CallTarget::Function(addr) => self.signature(*addr),
            CallTarget::Import(name) => self.import_signature(name),
            CallTarget::Indirect => guessed_signature("indirect", &self.abi),
        };
    }

    fn import_signature(&self, name: &str) -> Signature {
        let clean = import_name(name);

        if let Some(prototype) = self.typedb.function(name) {
            return self.signature_from_prototype(&prototype, &clean);
        }

        if let Some(prototype) = demangle_symbol(name).and_then(|s| cxx::prototype(&s, &self.model, &self.classes)) {
            return self.signature_from_prototype(&prototype, &prototype.name);
        }

        let noreturn = crate::analysis::function::is_noreturn_name(name);
        return Signature { noreturn, ..guessed_signature(&clean, &self.abi) };
    }

    /// Signature of a function of the program (cached)
    pub fn signature(&self, addr: u64) -> Signature {
        if let Some(sig) = self.signatures.borrow().get(&addr) {
            return sig.clone();
        }

        // Recursive calls see a provisional signature
        if !self.in_progress.borrow_mut().insert(addr) {
            return self.call_signature(&CallTarget::Indirect);
        }

        let sig = self.compute_signature(addr);
        let prototype = self.prototype_of(&sig);
        self.prototypes.borrow_mut().entry(sig.name.clone()).or_insert(prototype);

        self.in_progress.borrow_mut().remove(&addr);
        self.signatures.borrow_mut().insert(addr, sig.clone());

        return sig;
    }

    fn compute_signature(&self, addr: u64) -> Signature {
        let name = self.function_name(addr);
        let function = self.analysis.functions.get(&addr);
        let noreturn = function.is_some_and(|f| f.noreturn);

        if let Some(import) = function.and_then(|f| f.thunk.as_ref()) {
            return Signature { noreturn, ..self.import_signature(import) };
        }

        let symbol = self.program.symbol_at(addr).map(|s| s.name.clone()).unwrap_or_default();
        let known = self.typedb.function(&symbol).filter(|_| !symbol.is_empty());
        let demangled = demangle_symbol(&symbol).and_then(|s| cxx::prototype(&s, &self.model, &self.classes));

        // Fully known prototypes are used as they are
        if let Some(prototype) = known.or(demangled.clone().filter(|p| !p.ty.ret.is_unknown())) {
            return Signature { noreturn, ..self.signature_from_prototype(&prototype, &name) };
        }

        let mut discovered = self.discover(addr, &name).unwrap_or_else(|_| self.call_signature(&CallTarget::Indirect));

        // A result nobody reads is a leftover in the return register
        if discovered.ret.is_some() && !self.result_read_by_callers(addr) {
            discovered.ret = None;
        }

        // Itanium encodes the parameters but not the return type
        if let Some(prototype) = demangled {
            let sig = self.signature_from_prototype(&prototype, &name);
            return Signature { ret: discovered.ret, noreturn, ..sig };
        }

        return Signature { name, noreturn, ..discovered };
    }

    /// Whether one of the direct callers reads the return register (true when there is none)
    fn result_read_by_callers(&self, addr: u64) -> bool {
        let Some(callers) = self.analysis.callers.get(&addr) else {
            return true;
        };

        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);
        let mut sites = 0;

        for caller in callers.iter().filter_map(|c| self.analysis.functions.get(c)) {
            for call in caller.calls.iter().filter(|c| c.target == CallTarget::Function(addr)) {
                sites += 1;

                if call.tail || lift::result_used(&env, caller, call.addr, self.abi.int_ret) {
                    return true;
                }
            }
        }

        return sites == 0;
    }

    /// Lifts the function with every argument register as a parameter, optimizes it and keeps what is used
    fn discover(&self, addr: u64, name: &str) -> Result<Signature, String> {
        let function = &self.analysis.functions[&addr];

        let cx = Context::create();
        let module = self.module(&cx, name)?;
        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);

        let frame = analyze_frame(&env, function)?;
        let discovery = discovery_signature(name, &self.abi, &self.regs, &frame.stack_params);
        let llvm = lift::lift(&cx, &module, &env, function, &frame, discovery.clone(), true)?;

        self.optimize(&module)?;

        return Ok(refine(&module, llvm, &discovery, &self.abi));
    }

    /// C prototype of a discovered signature: integers and floats of the register widths
    fn prototype_of(&self, sig: &Signature) -> Prototype {
        let ctype = |ty: LType| match ty {
            LType::Int(bits) => CType::int(bits as u16),
            LType::Float(bits) => CType::Float { bits: bits as u16 },
            LType::Ptr => CType::ptr(CType::Void),
        };

        let params = sig.params.iter().map(|p| Param { name: p.name.clone(), ty: ctype(p.ty) }).collect();
        let ret = sig.ret.as_ref().map_or(CType::Void, |r| ctype(r.ty));

        return Prototype { name: sig.name.clone(), ty: FuncType { ret, params, variadic: sig.variadic } };
    }

    /// Machine level signature of a C prototype: parameters in the ABI registers, then on the stack
    pub fn signature_from_prototype(&self, prototype: &Prototype, name: &str) -> Signature {
        let abi = &self.abi;
        let (mut next_int, mut next_float, mut next_stack) = (0usize, 0usize, 0i64);
        let mut params = Vec::new();

        for (index, param) in prototype.ty.params.iter().enumerate() {
            let ty = self.ltype(&param.ty).unwrap_or(LType::Int(self.model.pointer_bits as u32));
            let float = matches!(ty, LType::Float(_));

            let reg = if abi.positional {
                if float { abi.float_args.get(index) } else { abi.int_args.get(index) }
            } else if float {
                next_float += 1;
                abi.float_args.get(next_float - 1)
            } else {
                next_int += 1;
                abi.int_args.get(next_int - 1)
            };

            let loc = match reg {
                Some(&reg) => Loc::Reg(reg),
                None => {
                    next_stack += 1;
                    Loc::Stack(abi.stack_args + (next_stack - 1) * abi.slot_size)
                }
            };

            params.push(Value { loc, ty, name: param.name.clone() });
        }

        let ret = self.ltype(&prototype.ty.ret).map(|ty| {
            let reg = if matches!(ty, LType::Float(_)) { abi.float_ret } else { abi.int_ret };
            Value { loc: Loc::Reg(reg), ty, name: None }
        });

        self.prototypes.borrow_mut().entry(name.to_string()).or_insert_with(|| Prototype { name: name.to_string(), ty: prototype.ty.clone() });

        return Signature { name: name.to_string(), params, ret, variadic: prototype.ty.variadic, noreturn: false, guessed: false };
    }

    /// Machine level type of a C type, None for void
    fn ltype(&self, ty: &CType) -> Option<LType> {
        let pointer = LType::Int(self.model.pointer_bits as u32);

        return Some(match self.typedb.resolve(ty) {
            CType::Void => return None,
            CType::Pointer(_) | CType::Array(..) | CType::Function(_) => LType::Ptr,
            CType::Bool | CType::Char => LType::Int(8),
            CType::Int { bits, .. } => LType::Int(*bits as u32),
            CType::Float { bits: 32 } => LType::Float(32),
            CType::Float { .. } => LType::Float(64),
            CType::Enum(_) => LType::Int(32),
            CType::Const(inner) => return self.ltype(inner),
            CType::Struct(_) | CType::Union(_) => match self.typedb.size_of(ty) {
                Some(size @ (1 | 2 | 4 | 8)) => LType::Int(size as u32 * 8),
                _ => LType::Ptr,
            },
            CType::Unknown(0) | CType::Typedef(_) => pointer,
            CType::Unknown(bits) => LType::Int(*bits as u32),
        });
    }
}

/// Import name without its decorations (__imp_, symbol versions, stdcall suffixes)
fn import_name(name: &str) -> String {
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    let name = name.split('@').next().unwrap_or(name);

    if let Some(demangled) = demangle_symbol(name) {
        return cxx::identifier(&demangled.name);
    }

    return sanitize(name);
}

fn sanitize(name: &str) -> String {
    let name = name.split('@').next().unwrap_or(name);
    let mut out: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();

    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }

    return out;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analysis::analyze;
    use execdump_core::elf::parse_elf;
    use execdump_core::exec::Exec;
    use execdump_core::program::programs_from_exec;

    use std::path::PathBuf;

    fn fixture(name: &str) -> Program {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data").join(name);
        return programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0);
    }

    fn function<'a>(analysis: &'a Analysis, name: &str) -> u64 {
        return analysis.function_by_name(name).unwrap_or_else(|| panic!("no function {}", name)).addr;
    }

    #[test]
    fn lifts_every_function() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();

        for &addr in analysis.functions.keys() {
            if let Err(error) = decompiler.llvm_ir(addr) {
                panic!("{} ({:#x}): {}", analysis.functions[&addr].name, addr, error);
            }
        }
    }

    #[test]
    fn discovered_signatures() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();

        let classify = decompiler.signature(function(&analysis, "classify"));
        assert_eq!(classify.params.len(), 1);
        assert_eq!(classify.params[0].ty, LType::Int(32));
        assert_eq!(classify.ret.as_ref().map(|r| r.ty), Some(LType::Int(32)));

        let count_chars = decompiler.signature(function(&analysis, "count_chars"));
        assert_eq!(count_chars.params.len(), 1);
        assert_eq!(count_chars.params[0].ty, LType::Int(64));

        // argv is not used by the fixture
        let main = decompiler.signature(function(&analysis, "main"));
        assert_eq!(main.params.len(), 1);
    }

    #[test]
    fn conditions_are_folded() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();

        let ir = decompiler.llvm_ir(function(&analysis, "count_chars")).unwrap();
        assert!(ir.contains("icmp"), "{}", ir);
        assert!(!ir.contains("alloca"), "{}", ir);
    }

    #[test]
    fn aarch64_syscalls() {
        let program = fixture("elf_aarch64_static");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();

        let ir = decompiler.llvm_ir(program.entry.unwrap()).unwrap();
        assert!(ir.contains("@__syscall3(i64 64, i64 1, i64 ptrtoint (ptr @msg to i64), i64 13)"), "{}", ir);
        assert!(ir.contains("@__syscall1(i64 93, i64 0)"), "{}", ir);
    }

    #[test]
    fn c_output() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let code = |name: &str| decompiler.c_code(function(&analysis, name)).unwrap();

        let classify = code("classify");
        assert!(classify.starts_with("int classify(int a1)"), "{}", classify);
        assert!(classify.contains("switch (a1)") && classify.contains("case 6:"), "{}", classify);
        assert!(classify.contains("return lib_add(0, 1);"), "{}", classify);

        let main = code("main");
        assert!(main.contains("messages[a1 % 3]"), "{}", main);
        assert!(main.contains("do {") && main.contains("classify("), "{}", main);
        assert!(main.contains("fatal();\n    }\n    return lib_add("), "{}", main);

        let count_chars = code("count_chars");
        assert!(count_chars.starts_with("int count_chars(char *a1)"), "{}", count_chars);
    }
}
