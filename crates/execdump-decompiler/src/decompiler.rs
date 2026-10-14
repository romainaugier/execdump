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
use crate::lift::{self, analyze_frame, discovery_signature, guessed_signature, refine, text_at, Env, Frame, LType, Loc, Signature, Value};
use crate::typedb::{Platform, TypeDb};
use crate::analysis::insn::{Decoder, Flow};
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

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

/// Bytes a stack argument takes (a double is two slots on 32-bit targets)
pub(crate) fn stack_bytes(ty: LType, slot_size: i64, pointer_bits: u16) -> i64 {
    let bits = match ty {
        LType::Int(bits) | LType::Float(bits) => bits as i64,
        LType::Ptr => pointer_bits as i64,
    };

    return ((bits / 8 + slot_size - 1) / slot_size).max(1) * slot_size;
}

/// Frames kept for the final lift after the discovery of the signature
const FRAMES: usize = 64;

/// Cleanup passes, chosen to keep the code readable: no loop transformations, no vectorization,
/// no switch to lookup table conversion and no jump threading (they duplicate or obfuscate code)
const PASSES: &str = "function(sroa,mem2reg,early-cse,instcombine<no-verify-fixpoint>,simplifycfg,sccp,gvn,dse,adce,instcombine<no-verify-fixpoint>,simplifycfg)";

/// Signatures shared by the decompilers of a program (one per thread): a signature is discovered once
#[derive(Clone, Default)]
pub struct SharedSignatures(Arc<Mutex<SharedState>>);

#[derive(Default)]
struct SharedState {
    /// Incremented when the annotations change: signatures computed before are not published
    epoch: u64,
    entries: HashMap<u64, (Signature, Option<Prototype>)>,
}

impl SharedSignatures {
    /// Forgets every signature (the names or prototypes given by the user changed), returns the new epoch
    pub fn invalidate(&self) -> u64 {
        let mut state = self.0.lock().unwrap();
        state.epoch += 1;
        state.entries.clear();
        return state.epoch;
    }

    fn get(&self, addr: u64) -> Option<(Signature, Option<Prototype>)> {
        return self.0.lock().unwrap().entries.get(&addr).cloned();
    }

    fn publish(&self, epoch: u64, addr: u64, sig: Signature, prototype: Option<Prototype>) {
        let mut state = self.0.lock().unwrap();

        if state.epoch == epoch {
            state.entries.insert(addr, (sig, prototype));
        }
    }
}

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
    /// Names of the functions that do not return (from their signature or their name)
    noreturn: RefCell<HashSet<String>>,
    decoder: Decoder,
    /// Capstone with the instruction details, for the frames and the call sites
    cs: capstone::Capstone,
    /// Decoded instructions and stack frames of the latest functions (lifted for the discovery, then for the C code)
    frames: RefCell<(HashMap<u64, Rc<Frame>>, VecDeque<u64>)>,
    /// Created once: a target machine is expensive to set up (and caches its subtargets)
    machine: TargetMachine,
    /// LLM improvement pass and the names it gave to the functions
    assistant: Option<Assistant>,
    renames: RefCell<Renames>,
    /// Names and prototypes given by the user, by address (functions and globals share the names)
    user_names: RefCell<HashMap<u64, String>>,
    user_prototypes: RefCell<HashMap<u64, Prototype>>,
    shared: Option<SharedSignatures>,
    epoch: Cell<u64>,
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
            noreturn: RefCell::new(HashSet::new()),
            decoder: Decoder::new(arch).map_err(|e| e.to_string())?,
            cs: lift::capstone(arch)?,
            frames: RefCell::new((HashMap::new(), VecDeque::new())),
            machine: target_machine(program)?,
            assistant: None,
            renames: RefCell::new(Renames::new()),
            user_names: RefCell::new(HashMap::new()),
            user_prototypes: RefCell::new(HashMap::new()),
            shared: None,
            epoch: Cell::new(0),
        });
    }

    /// Shares the signatures with the other decompilers of the program
    pub fn with_shared_signatures(mut self, shared: SharedSignatures) -> Self {
        self.epoch.set(shared.0.lock().unwrap().epoch);
        self.shared = Some(shared);
        return self;
    }

    /// Annotations up to this epoch of the shared signatures are applied
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.set(epoch);
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
        // Named values: the IR is read by people
        let cx = Context::create();
        let module = self.lift_function(&cx, addr)?;

        // LLVM prints the constant expressions as trees
        if printed_constants_size(&module) > MAX_PRINTED_CONSTANTS {
            return Err("the constant expressions of the function are too large to be printed".to_string());
        }

        // The instruction addresses are debug locations for the C backend
        let text = module.print_to_string().to_string();
        let text: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('!'))
            .map(|l| without_debug_locations(l))
            .collect();

        return Ok(text.join("\n"));
    }

    /// The C code of a function
    pub fn c_code(&self, addr: u64) -> Result<String, String> {
        let function = self.c_function(addr)?;
        return Ok(function.print().text);
    }

    /// The return instruction of a function that has only one
    fn single_return(&self, addr: u64) -> Option<u64> {
        let function = self.analysis.functions.get(&addr)?;
        let mut rets = function.blocks.values().filter_map(|b| b.insns.last()).filter(|i| i.flow == Flow::Ret);
        let ret = rets.next()?;
        return rets.next().is_none().then_some(ret.addr);
    }

    /// The C function of a function, with the address of each statement
    pub fn c_function(&self, addr: u64) -> Result<CFunction, String> {
        let cx = anonymous_context();
        let module = self.lift_function(&cx, addr)?;
        let sig = self.signature(addr);
        let function = module.get_function(&sig.name).ok_or("the lifted function is missing")?;
        let prototype = self.prototypes.borrow().get(&sig.name).cloned();

        let (globals, prototypes, noreturn) = (self.globals.borrow(), self.prototypes.borrow(), self.noreturn.borrow());

        let ctx = c::Context {
            program: self.program,
            typedb: &self.typedb,
            globals: &globals,
            prototypes: &prototypes,
            noreturn: &noreturn,
            instruction: Box::new(|a| self.instruction_text(a)),
            ret: self.single_return(addr),
            function: Box::new(|a| self.analysis.functions.contains_key(&a).then(|| self.function_name(a))),
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

        let frame = self.frame(&env, function)?;
        lift::lift(cx, &module, &env, function, &frame, sig, false)?;

        self.optimize(&module)?;

        return Ok(module);
    }

    fn env<'e>(&'e self, signature: &'e dyn Fn(&CallTarget) -> Signature, global_name: &'e dyn Fn(u64) -> String) -> Env<'e> {
        return Env { program: self.program, analysis: self.analysis, regs: &self.regs, abi: &self.abi, signature, global_name };
    }

    fn module<'ctx>(&self, cx: &'ctx Context, name: &str) -> Result<Module<'ctx>, String> {
        let module = cx.create_module(name);
        module.set_triple(&self.machine.get_triple());
        module.set_data_layout(&self.machine.get_target_data().get_data_layout());

        return Ok(module);
    }

    fn optimize(&self, module: &Module) -> Result<(), String> {
        module.verify().map_err(|e| format!("invalid IR: {}", e.to_string()))?;

        module.run_passes(PASSES, &self.machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;

        // Stack protector checks removed, frames kept whole by an escaping address split into variables,
        // then optimized again
        let mut again = false;

        for function in module.get_functions().filter(|f| f.count_basic_blocks() > 0) {
            lift::fold_frame_addresses(function);
            let protector = lift::remove_stack_protector(function);
            again |= protector.changed;
            again |= lift::split_frame(module, function, &protector.slots);
        }

        if again {
            module.verify().map_err(|e| format!("invalid IR after the stack protector removal and the split of the stack frame: {}", e.to_string()))?;
            module.run_passes(PASSES, &self.machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;
        }

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
     * User annotations
     */

    /// Names a function or a global, None restores the name from the symbols. The functions decompiled
    /// afterwards use the new name, in their body as well as in their callers.
    pub fn rename(&self, addr: u64, name: Option<String>) {
        match name {
            Some(name) => self.user_names.borrow_mut().insert(addr, name),
            None => self.user_names.borrow_mut().remove(&addr),
        };

        self.globals.borrow_mut().retain(|_, a| *a != addr);

        let Some(mut sig) = self.signatures.borrow_mut().remove(&addr) else {
            return;
        };

        let new = self.function_name(addr);
        let old = std::mem::replace(&mut sig.name, new.clone());

        let prototype = self.prototypes.borrow_mut().remove(&old);

        if let Some(mut prototype) = prototype {
            prototype.name = new.clone();
            self.prototypes.borrow_mut().insert(new.clone(), prototype);
        }

        let noreturn = self.noreturn.borrow_mut().remove(&old);

        if noreturn {
            self.noreturn.borrow_mut().insert(new);
        }

        self.signatures.borrow_mut().insert(addr, sig);
    }

    /// Gives a function a prototype (parameters and result), None goes back to the recovered one.
    /// Its callers pass the arguments of the new prototype once they are decompiled again.
    pub fn set_prototype(&self, addr: u64, prototype: Option<Prototype>) {
        let sig = self.signatures.borrow_mut().remove(&addr);

        if let Some(sig) = sig {
            self.prototypes.borrow_mut().remove(&sig.name);
        }

        match prototype {
            Some(prototype) => self.user_prototypes.borrow_mut().insert(addr, prototype),
            None => self.user_prototypes.borrow_mut().remove(&addr),
        };
    }

    /// C prototype of a function or import, by C name (known once a function using it was decompiled)
    pub fn prototype(&self, name: &str) -> Option<Prototype> {
        return self.prototypes.borrow().get(name).cloned();
    }

    /// Address of a global, by C name (known once a function using it was decompiled)
    pub fn global_address(&self, name: &str) -> Option<u64> {
        return self.globals.borrow().get(name).copied();
    }

    /*
     * Names
     */

    /// C name of a function: the name given by the user, the C identifier of its demangled name, its
    /// symbol or sub_ADDRESS
    pub fn function_name(&self, addr: u64) -> String {
        if let Some(name) = self.user_names.borrow().get(&addr) {
            return name.clone();
        }

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
        if let Some(name) = self.user_names.borrow().get(&addr) {
            return name.clone();
        }

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

        if let Some((sig, prototype)) = self.shared.as_ref().and_then(|s| s.get(addr)) {
            if let Some(prototype) = prototype {
                self.add_prototype(prototype);
            }

            if sig.noreturn {
                self.noreturn.borrow_mut().insert(sig.name.clone());
            }

            self.signatures.borrow_mut().insert(addr, sig.clone());
            return sig;
        }

        // Recursive calls see a provisional signature
        if !self.in_progress.borrow_mut().insert(addr) {
            return self.call_signature(&CallTarget::Indirect);
        }

        let sig = self.compute_signature(addr);
        let prototype = self.prototype_of(&sig);
        self.add_prototype(prototype);

        if sig.noreturn {
            self.noreturn.borrow_mut().insert(sig.name.clone());
        }

        self.in_progress.borrow_mut().remove(&addr);
        self.signatures.borrow_mut().insert(addr, sig.clone());

        if let Some(shared) = self.shared.as_ref() {
            shared.publish(self.epoch.get(), addr, sig.clone(), self.prototypes.borrow().get(&sig.name).cloned());
        }

        return sig;
    }

    fn compute_signature(&self, addr: u64) -> Signature {
        let name = self.function_name(addr);
        let function = self.analysis.functions.get(&addr);
        let noreturn = function.is_some_and(|f| f.noreturn);

        if let Some(import) = function.and_then(|f| f.thunk.as_ref()) {
            return Signature { noreturn, ..self.import_signature(import) };
        }

        if let Some(prototype) = self.user_prototypes.borrow().get(&addr).cloned() {
            return Signature { noreturn, ..self.signature_from_prototype(&prototype, &name) };
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

                if call.tail || lift::result_used(&env, &self.cs, caller, call.addr, self.abi.int_ret) {
                    return true;
                }
            }
        }

        return sites == 0;
    }

    /// Lifts the function with every argument register as a parameter, optimizes it and keeps what is used
    fn discover(&self, addr: u64, name: &str) -> Result<Signature, String> {
        let function = self.analysis.functions.get(&addr).ok_or_else(|| format!("no function at {:#x}", addr))?;

        let cx = anonymous_context();
        let module = self.module(&cx, name)?;
        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);

        let frame = self.frame(&env, function)?;
        let discovery = discovery_signature(name, &self.abi, &self.regs, &frame.stack_params);
        let llvm = lift::lift(&cx, &module, &env, function, &frame, discovery.clone(), true)?;

        self.optimize(&module)?;

        return Ok(refine(&module, llvm, &discovery, &self.abi));
    }

    /// Stack frame of a function, decoded once for its discovery and its final lift
    fn frame(&self, env: &Env, function: &crate::analysis::function::Function) -> Result<Rc<Frame>, String> {
        if let Some(frame) = self.frames.borrow().0.get(&function.addr) {
            return Ok(frame.clone());
        }

        let frame = Rc::new(analyze_frame(env, &self.cs, function)?);
        let mut frames = self.frames.borrow_mut();

        if frames.1.len() >= FRAMES {
            if let Some(old) = frames.1.pop_front() {
                frames.0.remove(&old);
            }
        }

        frames.0.insert(function.addr, frame.clone());
        frames.1.push_back(function.addr);

        return Ok(frame);
    }

    /// Keeps the first prototype given to a name
    fn add_prototype(&self, prototype: Prototype) {
        if crate::analysis::function::is_noreturn_name(&prototype.name) {
            self.noreturn.borrow_mut().insert(prototype.name.clone());
        }

        self.prototypes.borrow_mut().entry(prototype.name.clone()).or_insert(prototype);
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
                    let offset = abi.stack_args + next_stack;
                    next_stack += stack_bytes(ty, abi.slot_size, self.model.pointer_bits);
                    Loc::Stack(offset)
                }
            };

            params.push(Value { loc, ty, name: param.name.clone() });
        }

        let ret = self.ltype(&prototype.ty.ret).map(|ty| {
            let reg = if matches!(ty, LType::Float(_)) { abi.float_ret } else { abi.int_ret };
            Value { loc: Loc::Reg(reg), ty, name: None }
        });

        if !self.prototypes.borrow().contains_key(name) {
            self.add_prototype(Prototype { name: name.to_string(), ty: prototype.ty.clone() });
        }

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

/// Line of LLVM IR without its debug attachments (", !dbg !12" on instructions, " !dbg !4" on definitions)
const MAX_PRINTED_CONSTANTS: u64 = 1 << 20;

/// Number of constant expressions LLVM prints for the operands of the instructions of a module
fn printed_constants_size(module: &Module) -> u64 {
    use inkwell::llvm_sys::core::{LLVMGetNumOperands, LLVMGetOperand, LLVMIsAConstantExpr};
    use inkwell::llvm_sys::prelude::LLVMValueRef;
    use inkwell::values::AsValueRef;

    fn size(value: LLVMValueRef, sizes: &mut HashMap<LLVMValueRef, u64>) -> u64 {
        if let Some(&size) = sizes.get(&value) {
            return size;
        }

        // Constant expressions are DAGs, their size is counted once per node
        let total = unsafe {
            if LLVMIsAConstantExpr(value).is_null() {
                1
            } else {
                (0..LLVMGetNumOperands(value) as u32).fold(1u64, |total, i| total.saturating_add(size(LLVMGetOperand(value, i), sizes)))
            }
        };

        sizes.insert(value, total);
        return total;
    }

    let mut sizes = HashMap::new();
    let mut total = 0u64;

    for function in module.get_functions() {
        for block in function.get_basic_blocks() {
            for instruction in block.get_instructions() {
                for i in 0..instruction.get_num_operands() {
                    let raw = unsafe { LLVMGetOperand(instruction.as_value_ref(), i) };

                    if !raw.is_null() {
                        total = total.saturating_add(size(raw, &mut sizes));
                    }
                }
            }
        }
    }

    return total;
}

fn without_debug_locations(line: &str) -> String {
    let mut out = line.to_string();

    while let Some(start) = out.find(" !dbg !") {
        let digits = out[start + 7..].chars().take_while(|c| c.is_ascii_digit()).count();
        let from = if out[..start].ends_with(',') { start - 1 } else { start };
        out.replace_range(from..start + 7 + digits, "");
    }

    return out;
}

/// LLVM context dropping the names of the values (nothing reads them, naming them is costly)
fn anonymous_context() -> Context {
    let cx = Context::create();
    unsafe { inkwell::llvm_sys::core::LLVMContextSetDiscardValueNames(cx.raw(), 1) };
    return cx;
}

/// Target machine of the program (its triple and data layout for the modules, its cost model for the passes)
fn target_machine(program: &Program) -> Result<TargetMachine, String> {
    let config = InitializationConfig::default();

    let triple = match (program.architecture(), program.format) {
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

    match program.architecture() {
        Architecture::Aarch64 => Target::initialize_aarch64(&config),
        _ => Target::initialize_x86(&config),
    }

    let triple = TargetTriple::create(triple);
    let target = Target::from_triple(&triple).map_err(|e| e.to_string())?;

    return target
        .create_target_machine(&triple, "generic", "", OptimizationLevel::Default, RelocMode::Default, CodeModel::Default)
        .ok_or_else(|| "cannot create the target machine".to_string());
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

    #[test]
    fn stack_frame_variables() {
        let program = fixture("elf_i386_frame");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let check = decompiler.c_code(function(&analysis, "check")).unwrap();

        // The buffers are arrays, the scalars below them are values
        assert!(check.contains("char dest[44];") && check.contains("strcpy(dest, src);"), "{}", check);
        assert!(check.contains("for (i = 0; i <= 3; i++) {") && check.contains("+= dest[i];"), "{}", check);

        // The buffer is read after the call that wrote it
        let strcpy = check.find("strcpy(").unwrap();
        assert!(check[strcpy..].contains("if (dest[1] == 'x') {"), "{}", check);

        // A string written four bytes at a time, stack arguments after a double
        assert!(check.contains("memcpy(v2, \"libsrty ko!\", 12);"), "{}", check);
        assert!(check.contains("printf(\"%s %d %f\\n\", v2, v1, 2.5);"), "{}", check);
    }

    #[test]
    fn conditional_tail_calls() {
        let program = fixture("elf_x86_64_quality");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let code = decompiler.c_code(function(&analysis, "length_of")).unwrap();

        // gcc moves the unlikely path to a cold part reached by a conditional jump, the rest follows it
        assert!(code.contains("if (") && code.contains("length_of_cold();") && code.contains("strlen("), "{}", code);
    }

    #[test]
    fn stack_protector() {
        // The thread canary (fs:0x28, gs:0x14) and __stack_chk_guard (aarch64)
        for (name, buffer) in [("elf_x86_64_quality", 72), ("elf_i386_quality", 64), ("elf_aarch64_quality", 64)] {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();

            for function_name in ["length_of", "parse_opt"] {
                let code = decompiler.c_code(function(&analysis, function_name)).unwrap();

                for canary in ["__readfsqword", "__readgsdword", "__stack_chk_fail", "__stack_chk_guard"] {
                    assert!(!code.contains(canary), "{}: {}", name, code);
                }
            }

            // The buffer ends at the slot of the canary
            let code = decompiler.c_code(function(&analysis, "length_of")).unwrap();
            assert!(code.contains(&format!("char dest[{}];", buffer)) && code.contains("strcpy(dest, src);"), "{}: {}", name, code);
        }
    }

    #[test]
    fn switches_split_by_the_compiler() {
        // gcc: a test of the sparse values then a range check before a jump table, clang: a search tree
        for name in ["elf_x86_64_quality", "elf_i386_quality", "elf_aarch64_quality"] {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();
            let code = decompiler.c_code(function(&analysis, "parse_opt")).unwrap();

            assert_eq!(code.matches("switch (").count(), 1, "{}: {}", name, code);
            assert!(!code.contains("if ("), "{}: {}", name, code);

            for case in ["case 97:", "case 99:", "case 112:", "case 0x1000003:", "case 0x1000005:", "default:\n            return 7;"] {
                assert!(code.contains(case), "{}: {} is missing: {}", name, case, code);
            }
        }
    }

    #[test]
    fn printed_constants() {
        let cx = Context::create();
        let module = cx.create_module("constants");
        let i64_type = cx.i64_type();
        let global = module.add_global(i64_type, None, "g");
        let function = module.add_function("f", i64_type.fn_type(&[], false), None);
        let builder = cx.create_builder();
        builder.position_at_end(cx.append_basic_block(function, "entry"));

        let mut value = global.as_pointer_value().const_to_int(i64_type);

        for _ in 0..60 {
            value = value.const_add(value);
        }

        builder.build_return(Some(&value)).unwrap();
        assert!(printed_constants_size(&module) > MAX_PRINTED_CONSTANTS);
    }

    #[test]
    fn line_addresses() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let (mut statements, mut located) = (0, 0);

        for (&addr, function) in analysis.functions.iter() {
            let Ok(c) = decompiler.c_function(addr) else { continue };
            let printed = c.print();
            let insns: std::collections::HashSet<u64> = function.blocks.values().flat_map(|b| b.insns.iter().map(|i| i.addr)).collect();

            for (line, addr) in printed.text.lines().zip(printed.lines.iter()) {
                if let Some(addr) = addr {
                    assert!(insns.contains(addr), "{:#x} is not an instruction of {}: {}", addr, function.name, line);
                }

                let line = line.trim();
                let statement = line.ends_with(';') && !line.starts_with('}') && !line.starts_with("//") && line.contains(['=', '(']) || line.starts_with("return") || line.starts_with("if (");

                if statement && !printed.text.starts_with(line) {
                    statements += 1;
                    located += addr.is_some() as usize;
                }
            }
        }

        assert!(statements > 20 && located * 100 >= statements * 95, "{} of {} statements have an address", located, statements);
    }

    #[test]
    fn user_names_and_prototypes() {
        let program = fixture("elf_x86_64_analysis");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let (main, classify, count_chars) = (function(&analysis, "main"), function(&analysis, "classify"), function(&analysis, "count_chars"));

        // Renamed after its signature was computed: the cached signature follows
        assert!(decompiler.c_code(main).unwrap().contains("classify("));
        decompiler.rename(classify, Some("classify_value".to_string()));
        assert!(decompiler.c_code(classify).unwrap().starts_with("int classify_value(int a1)"));
        assert!(decompiler.c_code(main).unwrap().contains("classify_value("));
        assert!(decompiler.prototype("classify_value").is_some());

        let prototype = crate::notes::parse_prototype("int count(const char *text)", &decompiler.typedb).unwrap();
        decompiler.set_prototype(count_chars, Some(prototype));
        let code = decompiler.c_code(count_chars).unwrap();
        assert!(code.starts_with("int count_chars(const char *text)"), "{}", code);

        decompiler.rename(classify, None);
        assert!(decompiler.c_code(main).unwrap().contains("classify("));
    }
}
