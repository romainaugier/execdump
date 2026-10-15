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
use crate::lift::regs::{Abi, Reg, RegisterFile};
use crate::lift::{self, analyze_frame, discovery_signature, guessed_signature, refine, text_at, Env, Frame, LType, Loc, Signature, Value};
use crate::typedb::{Aggregate, Platform, TypeDb};
use crate::analysis::insn::{Decoder, Flow};
use crate::c::{self, ast::CFunction, inline::Trivial};
use crate::llm::{self, Assistant, LlmConfig, Renames};
use crate::storage;
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
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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

/// Instructions of the functions looked at to be inlined in their callers (trivial ones are a few)
const MAX_TRIVIAL_INSNS: usize = 32;

fn typing_pointee(ty: &CType) -> Option<&CType> {
    return match ty {
        CType::Pointer(inner) => Some(inner.unqualified()),
        CType::Const(inner) => typing_pointee(inner),
        _ => None,
    };
}

/// Names of the structs a type names (through its pointers)
fn struct_names(ty: &CType) -> Vec<String> {
    return match ty {
        CType::Struct(name) if name.starts_with("st_") => vec![name.clone()],
        CType::Pointer(inner) | CType::Const(inner) | CType::Array(inner, _) => struct_names(inner),
        _ => Vec::new(),
    };
}

/// Callers followed up the call graph to know whether a result is read (the ones that return it)
const MAX_RESULT_DEPTH: usize = 8;

/// Optimizations of a function after its stack frame was split (a split can make another one possible)
const MAX_SPLIT_ROUNDS: usize = 3;

/// Prototypes of the functions the C runtime links in the programs
const CRT_PROTOTYPES: &[(&str, &str)] = &[
    ("__libc_csu_init", "void __libc_csu_init(int argc, char **argv, char **envp)"),
    ("__libc_csu_fini", "void __libc_csu_fini(void)"),
    ("_init", "void _init(void)"),
    ("_fini", "void _fini(void)"),
    ("frame_dummy", "void frame_dummy(void)"),
    ("register_tm_clones", "void register_tm_clones(void)"),
    ("deregister_tm_clones", "void deregister_tm_clones(void)"),
    ("__do_global_dtors_aux", "void __do_global_dtors_aux(void)"),
    ("__do_global_ctors_aux", "void __do_global_ctors_aux(void)"),
];

/// Cleanup passes, chosen to keep the code readable: no loop transformations, no vectorization,
/// no switch to lookup table conversion and no jump threading (they duplicate or obfuscate code)
pub(crate) const PASSES: &str = "function(sroa,mem2reg,early-cse,instcombine<no-verify-fixpoint>,simplifycfg,sccp,gvn,dse,adce,instcombine<no-verify-fixpoint>,simplifycfg)";

/// Signatures shared by the decompilers of a program (one per thread): a signature is discovered once
#[derive(Clone, Default)]
pub struct SharedSignatures(Arc<Mutex<SharedState>>);

#[derive(Default)]
struct SharedState {
    /// Incremented when the annotations change: signatures computed before are not published
    epoch: u64,
    entries: HashMap<u64, (Signature, Option<Prototype>)>,
    /// Prototypes of the decompiled functions, for their callers
    decompiled: HashMap<u64, Option<Arc<CPrototype>>>,
}

/// A function as the code of its callers sees it once decompiled: its C prototype (the structs it takes and
/// returns, a boolean or nothing returned) and the structs the prototype names
#[derive(Clone, Debug)]
pub struct CPrototype {
    pub prototype: Prototype,
    pub structs: Vec<(String, Aggregate)>,
}

impl SharedSignatures {
    /// Forgets every signature (the names or prototypes given by the user changed), returns the new epoch
    pub fn invalidate(&self) -> u64 {
        let mut state = self.0.lock().unwrap();
        state.epoch += 1;
        state.entries.clear();
        state.decompiled.clear();
        return state.epoch;
    }

    fn get(&self, addr: u64) -> Option<(Signature, Option<Prototype>)> {
        return self.0.lock().unwrap().entries.get(&addr).cloned();
    }

    fn decompiled(&self, addr: u64) -> Option<Option<Arc<CPrototype>>> {
        return self.0.lock().unwrap().decompiled.get(&addr).cloned();
    }

    fn publish_decompiled(&self, epoch: u64, addr: u64, prototype: Option<Arc<CPrototype>>) {
        let mut state = self.0.lock().unwrap();

        if state.epoch == epoch {
            state.decompiled.insert(addr, prototype);
        }
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
    /// C names of the functions with a mangled symbol
    demangled: HashMap<u64, String>,
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
    /// Statement of the trivial functions (None for the others), their callers show it instead of the call
    trivial: RefCell<HashMap<u64, Option<Rc<Trivial>>>>,
    /// Functions whose calls are being inlined (a trivial function calling itself stays a call)
    inlining: RefCell<HashSet<u64>>,
    /// Registers each function may write, for its callers
    clobbered: RefCell<HashMap<u64, u128>>,
    /// Prototypes of the functions passed to known ones as callbacks (qsort, signal, atexit...)
    callbacks: std::cell::OnceCell<HashMap<u64, FuncType>>,
    /// Prototypes of the decompiled functions for their callers (None when the decompilation failed), and the
    /// functions being decompiled
    decompiled: RefCell<HashMap<u64, Option<Arc<CPrototype>>>>,
    decompiling: RefCell<HashSet<u64>>,
    /// The functions decompiled for their callers, until they are asked for (they are not decompiled twice)
    ready: RefCell<HashMap<u64, CFunction>>,
    /// Component of each function in the call graph (the functions that call each other are one)
    components: std::cell::OnceCell<HashMap<u64, usize>>,
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
        let demangled = demangled_names(program, analysis, &model, &classes);

        return Ok(Decompiler {
            program,
            analysis,
            regs,
            abi,
            model,
            typedb,
            classes,
            demangled,
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
            trivial: RefCell::new(HashMap::new()),
            inlining: RefCell::new(HashSet::new()),
            clobbered: RefCell::new(HashMap::new()),
            callbacks: std::cell::OnceCell::new(),
            decompiled: RefCell::new(HashMap::new()),
            decompiling: RefCell::new(HashSet::new()),
            ready: RefCell::new(HashMap::new()),
            components: std::cell::OnceCell::new(),
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
        self.trivial.borrow_mut().clear();
        self.decompiled.borrow_mut().clear();
        self.ready.borrow_mut().clear();
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
        if let Some(function) = self.ready.borrow_mut().remove(&addr) {
            return Ok(function);
        }

        self.decompiling.borrow_mut().insert(addr);
        let result = self.c_function_with_callees(addr);
        self.decompiling.borrow_mut().remove(&addr);

        let prototype = result.as_ref().ok().map(|(function, imported)| Arc::new(self.c_prototype(addr, function, imported)));

        if let Some(shared) = self.shared.as_ref() {
            shared.publish_decompiled(self.epoch.get(), addr, prototype.clone());
        }

        self.decompiled.borrow_mut().insert(addr, prototype);
        return result.map(|(function, _)| function);
    }

    /// The C function, the structs of its callees it uses
    fn c_function_with_callees(&self, addr: u64) -> Result<(CFunction, BTreeMap<String, Aggregate>), String> {
        let (callees, imported) = self.callee_prototypes(addr);
        let cx = anonymous_context();
        let (module, lifted) = self.lift(&cx, addr, true)?;
        let sig = self.signature(addr);
        let function = module.get_function(&sig.name).ok_or("the lifted function is missing")?;
        let prototype = self.prototypes.borrow().get(&sig.name).cloned();

        let mut function = {
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
                structs: Default::default(),
                callees,
                imported: imported.clone(),
            };

            c::decompile(&module, function, &ctx, prototype.as_ref(), addr)
        };

        self.storage(addr, &mut function, &lifted);

        let first = self.inlining.borrow_mut().insert(addr);
        self.inline_trivial(&mut function);

        if first {
            self.inlining.borrow_mut().remove(&addr);
        }

        let trivial = Trivial::of(&function).map(Rc::new);
        function.inlined = trivial.is_some();
        self.trivial.borrow_mut().insert(addr, trivial);

        llm::apply_renames(&mut function, &self.renames.borrow());

        return Ok((function, imported));
    }

    /// The prototype of a decompiled function for its callers, with the structs it names (and the ones they
    /// point to)
    fn c_prototype(&self, addr: u64, function: &CFunction, imported: &BTreeMap<String, Aggregate>) -> CPrototype {
        let name = self.signature(addr).name;
        let discovered = self.prototypes.borrow().get(&name).cloned();

        // A struct of the headers the function guessed from its uses is not one for its callers (the pointer may
        // point to a bigger object starting with it): they keep the discovered type
        let guessed = |ty: &CType| match typing_pointee(ty) {
            Some(CType::Struct(n) | CType::Union(n)) => !n.starts_with("st_"),
            _ => false,
        };

        let params = function
            .params
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let ty = &function.vars[p].ty;
                let declared = discovered.as_ref().and_then(|d| d.ty.params.get(i)).map(|d| d.ty.clone());

                // The callers take the structs the function recovered, the other types stay the discovered or
                // declared ones (what the function guessed from its uses is its own)
                let ty = match declared {
                    Some(declared) if struct_names(ty).is_empty() || guessed(ty) => declared,
                    _ => ty.clone(),
                };

                Param { name: Some(function.vars[p].name.clone()), ty }
            })
            .collect();

        // A boolean, nothing or a recovered struct returned are what the callers get, a pointer guessed is not
        let ret = match (&function.ret, discovered.as_ref().map(|d| d.ty.ret.clone())) {
            (CType::Bool | CType::Void, _) => function.ret.clone(),
            (ret, _) if !struct_names(ret).is_empty() => ret.clone(),
            (_, Some(declared)) => declared,
            (ret, None) => ret.clone(),
        };

        let prototype = Prototype { name, ty: FuncType { ret, params, variadic: function.variadic } };

        let known = |name: &str| function.structs.iter().find(|(n, _)| n == name).map(|(_, a)| a.clone()).or_else(|| imported.get(name).cloned());
        let mut structs: Vec<(String, Aggregate)> = Vec::new();
        let mut pending: Vec<String> = prototype.ty.params.iter().map(|p| &p.ty).chain([&prototype.ty.ret]).flat_map(struct_names).collect();

        while let Some(name) = pending.pop() {
            if structs.iter().any(|(n, _)| *n == name) {
                continue;
            }

            if let Some(aggregate) = known(&name) {
                pending.extend(aggregate.fields.iter().flat_map(|f| struct_names(&f.ty)));
                structs.push((name, aggregate));
            }
        }

        structs.sort_by(|(a, _), (b, _)| a.cmp(b));
        return CPrototype { prototype, structs };
    }

    /// Component of each function in the call graph (Tarjan's strongly connected components, iterative)
    fn components(&self) -> &HashMap<u64, usize> {
        return self.components.get_or_init(|| {
            let callees = |addr: u64| -> Vec<u64> {
                self.analysis.functions.get(&addr).map_or(Vec::new(), |f| {
                    f.calls.iter().filter_map(|c| match c.target {
                        CallTarget::Function(t) if self.analysis.functions.contains_key(&t) => Some(t),
                        _ => None,
                    }).collect()
                })
            };

            let mut index: HashMap<u64, (usize, usize)> = HashMap::new();
            let mut component: HashMap<u64, usize> = HashMap::new();
            let mut stack: Vec<u64> = Vec::new();
            let mut on_stack: HashSet<u64> = HashSet::new();
            let mut next = 0;

            for &root in self.analysis.functions.keys() {
                if index.contains_key(&root) {
                    continue;
                }

                // (function, its callees, the next one to visit)
                let mut work: Vec<(u64, Vec<u64>, usize)> = vec![(root, callees(root), 0)];
                index.insert(root, (next, next));
                next += 1;
                stack.push(root);
                on_stack.insert(root);

                while let Some((node, targets, position)) = work.last_mut() {
                    let node = *node;

                    if let Some(&target) = targets.get(*position) {
                        *position += 1;

                        match index.get(&target).copied() {
                            None => {
                                index.insert(target, (next, next));
                                next += 1;
                                stack.push(target);
                                on_stack.insert(target);
                                work.push((target, callees(target), 0));
                            }
                            Some((target_index, _)) if on_stack.contains(&target) => {
                                let entry = index.get_mut(&node).unwrap();
                                entry.1 = entry.1.min(target_index);
                            }
                            _ => {}
                        }

                        continue;
                    }

                    work.pop();
                    let (node_index, low) = index[&node];

                    if let Some((parent, _, _)) = work.last() {
                        let parent = *parent;
                        let entry = index.get_mut(&parent).unwrap();
                        entry.1 = entry.1.min(low);
                    }

                    if node_index == low {
                        while let Some(member) = stack.pop() {
                            on_stack.remove(&member);
                            component.insert(member, node_index);

                            if member == node {
                                break;
                            }
                        }
                    }
                }
            }

            component
        });
    }

    /// The decompiled prototype of a function, decompiling it when needed (None when it failed or is being
    /// decompiled)
    fn decompiled_prototype(&self, addr: u64) -> Option<Arc<CPrototype>> {
        if let Some(known) = self.decompiled.borrow().get(&addr) {
            return known.clone();
        }

        if let Some(known) = self.shared.as_ref().and_then(|s| s.decompiled(addr)) {
            self.decompiled.borrow_mut().insert(addr, known.clone());
            return known;
        }

        if self.decompiling.borrow().contains(&addr) {
            return None;
        }

        if let Ok(function) = self.c_function(addr) {
            self.ready.borrow_mut().insert(addr, function);
        }

        return self.decompiled.borrow().get(&addr).cloned().flatten();
    }

    /// The decompiled prototypes of the callees of a function (decompiled first, callees before their callers)
    /// and the structs they name. The callees calling the function back are left out: what each function of a
    /// cycle sees would depend on the one decompiled first.
    fn callee_prototypes(&self, addr: u64) -> (HashMap<String, Prototype>, BTreeMap<String, Aggregate>) {
        let components = self.components();
        let outside = |caller: u64, callee: u64| components.get(&caller) != components.get(&callee);

        let direct = |addr: u64| -> Vec<u64> {
            let mut found = Vec::new();

            for call in self.analysis.functions.get(&addr).into_iter().flat_map(|f| f.calls.iter()) {
                if let CallTarget::Function(target) = call.target {
                    let function = self.analysis.functions.get(&target);

                    if function.is_some_and(|f| f.thunk.is_none()) && outside(addr, target) && !found.contains(&target) {
                        found.push(target);
                    }
                }
            }

            found
        };

        // Callees first, without recursing: each one finds its own callees decompiled
        let known = |addr: u64| self.decompiled.borrow().contains_key(&addr) || self.decompiling.borrow().contains(&addr);
        let mut order: Vec<u64> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut work: Vec<(u64, Vec<u64>, usize)> = vec![(addr, direct(addr), 0)];
        visited.insert(addr);

        while let Some((node, targets, position)) = work.last_mut() {
            let node = *node;

            match targets.get(*position).copied() {
                Some(target) => {
                    *position += 1;

                    if !known(target) && visited.insert(target) {
                        work.push((target, direct(target), 0));
                    }
                }
                None => {
                    work.pop();

                    if node != addr {
                        order.push(node);
                    }
                }
            }
        }

        for callee in order {
            let _ = self.decompiled_prototype(callee);
        }

        let mut prototypes = HashMap::new();
        let mut structs = BTreeMap::new();

        for callee in direct(addr) {
            if let Some(decompiled) = self.decompiled_prototype(callee) {
                structs.extend(decompiled.structs.iter().cloned());
                prototypes.insert(decompiled.prototype.name.clone(), decompiled.prototype.clone());
            }
        }

        return (prototypes, structs);
    }

    /// The calls to trivial functions show their statement, with the name of the function as a note when
    /// it has one (a symbol, or a name given by the user)
    fn inline_trivial(&self, function: &mut CFunction) {
        let names: HashMap<String, u64> = self.signatures.borrow().iter().map(|(addr, sig)| (sig.name.clone(), *addr)).collect();

        let lookup = |name: &str| -> Option<(Rc<Trivial>, Option<String>)> {
            let addr = *names.get(name)?;
            let trivial = self.trivial(addr)?;
            let named = self.program.symbol_at(addr).is_some() || self.user_names.borrow().contains_key(&addr);
            Some((trivial, named.then(|| name.to_string())))
        };

        c::inline::inline(function, &lookup);
    }

    /// The statement of a trivial function of the program, decompiled to know (the small ones only)
    fn trivial(&self, addr: u64) -> Option<Rc<Trivial>> {
        if let Some(known) = self.trivial.borrow().get(&addr) {
            return known.clone();
        }

        let function = self.analysis.functions.get(&addr)?;

        if function.thunk.is_some() || function.num_insns() > MAX_TRIVIAL_INSNS || self.inlining.borrow().contains(&addr) {
            return None;
        }

        // Decompiling it records whether it is trivial
        if self.c_function(addr).is_err() {
            self.trivial.borrow_mut().insert(addr, None);
        }

        return self.trivial.borrow().get(&addr).cloned().flatten();
    }

    /// Whether the callers of a function show its only statement instead of calling it (known once it was
    /// decompiled)
    pub fn is_inlined(&self, addr: u64) -> bool {
        return self.trivial.borrow().get(&addr).is_some_and(|t| t.is_some());
    }

    fn instruction_text(&self, addr: u64) -> String {
        let text = self.program.bytes_from(addr).and_then(|bytes| self.decoder.text(bytes, addr));
        return text.map_or(String::new(), |t| format!("{} {}", t.mnemonic, t.operands).trim().to_string());
    }

    /// Lifts a function with its final signature into a new module and optimizes it
    pub fn lift_function<'ctx>(&self, cx: &'ctx Context, addr: u64) -> Result<Module<'ctx>, String> {
        return self.lift(cx, addr, false).map(|(module, _)| module);
    }

    /// Lifts and optimizes a function, with the notes of the storage of its values for the C code
    fn lift<'ctx>(&self, cx: &'ctx Context, addr: u64, storage: bool) -> Result<(Module<'ctx>, Lifted), String> {
        let function = self.analysis.functions.get(&addr).ok_or_else(|| format!("no function at {:#x}", addr))?;
        let sig = self.signature(addr);

        let module = self.module(cx, &function.name)?;
        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);

        let frame = self.frame(&env, function)?;
        let (_, slot_writes) = lift::lift(cx, &module, &env, function, &frame, sig, false, storage)?;

        let saved = frame.saved_slots(function.addr, self.abi.slot_size as i64);
        let canaries = self.optimize(&module, storage, &saved)?.into_iter().map(|index| index as i64 + frame.low).collect();

        return Ok((module, Lifted { frame, slot_writes, canaries }));
    }

    /// Ranges of the locations of the variables of a C function, from the notes of the backend and the
    /// instructions of the function (what they write, what the calls clobber)
    fn storage(&self, addr: u64, function: &mut CFunction, lifted: &Lifted) {
        let Some(analysis) = self.analysis.functions.get(&addr) else {
            return;
        };

        let callee_saved = self.abi.callee_saved.iter().fold(0u128, |mask, &r| mask | 1 << r);
        let results = 1u128 << self.abi.int_ret | 1u128 << self.abi.float_ret;
        let index: HashMap<u64, usize> = analysis.blocks.keys().enumerate().map(|(i, &a)| (a, i)).collect();

        let blocks: Vec<storage::Block> = analysis
            .blocks
            .values()
            .map(|block| {
                let insns = lifted.frame.blocks.get(&block.start).map_or(&[][..], |i| i.as_slice());
                let steps = insns
                    .iter()
                    .map(|insn| {
                        let call = analysis.calls.iter().find(|c| c.addr == insn.addr() && !c.tail);
                        let clobbered = call.map_or(0, |c| (self.call_signature(&c.target).clobbers & !callee_saved) | results);
                        storage::Step { end: insn.end(), kills: insn.written(&self.regs) | clobbered }
                    })
                    .collect();

                storage::Block { start: block.start, end: block.end, preds: block.preds.iter().filter_map(|p| index.get(p).copied()).collect(), steps }
            })
            .collect();

        let mut used = vec![false; function.vars.len()];
        c::ast::mark_used(&function.body, &mut used);
        function.params.iter().for_each(|&p| used[p] = true);

        let notes = std::mem::take(&mut function.storage.notes);
        let mut vars = storage::ranges(addr, &blocks, &notes, &lifted.slot_writes);

        // The variables of the frame are in their slot from the start to the end of the function
        let start = blocks.iter().map(|b| b.start.wrapping_sub(addr) as u32).min().unwrap_or(0);
        let end = blocks.iter().map(|b| b.end.wrapping_sub(addr) as u32).max().unwrap_or(0);

        for (var, loc) in std::mem::take(&mut function.storage.frame_vars) {
            vars.retain(|(v, _)| *v != var);
            vars.push((var, vec![storage::Range { start, end, loc }]));
        }

        vars.sort_by_key(|(var, _)| *var);
        vars.retain(|(var, _)| used.get(*var).copied().unwrap_or(false));

        function.storage.vars = vars;
        function.storage.canaries = lifted.canaries.iter().filter_map(|&offset| storage::Loc::stack(offset)).map(|l| l.canary()).collect();
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

    /// Optimizes a lifted module, returns the frame offsets the stack canary was stored at. The saved slots are
    /// the offsets from the stack pointer at the entry the prologue saves registers to.
    fn optimize(&self, module: &Module, storage: bool, saved: &[i64]) -> Result<Vec<u64>, String> {
        module.verify().map_err(|e| format!("invalid IR: {}", e.to_string()))?;

        module.run_passes(PASSES, &self.machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;

        // Stack protector checks removed, frames kept whole by an escaping address split into variables,
        // then optimized again
        let mut again = false;
        let mut canaries = Vec::new();

        for function in module.get_functions().filter(|f| f.count_basic_blocks() > 0) {
            lift::fold_frame_addresses(function);
            let protector = lift::remove_stack_protector(function);
            again |= protector.changed;
            let split = lift::split_frame(module, function, &protector.slots, saved);
            again |= split;
            canaries.extend(protector.slots.iter().map(|(_, offset)| *offset));

            if split && storage {
                lift::declare_slots(module, function);
            }
        }

        // A buffer whose address only escaped through a store the split made dead (the arguments of a realigned
        // frame, their address saved by the prologue) is split once that store is gone
        for round in 0..MAX_SPLIT_ROUNDS {
            if !again {
                break;
            }

            module.verify().map_err(|e| format!("invalid IR after the stack protector removal and the split of the stack frame: {}", e.to_string()))?;
            module.run_passes(PASSES, &self.machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;

            again = false;

            for function in module.get_functions().filter(|f| f.count_basic_blocks() > 0 && round + 1 < MAX_SPLIT_ROUNDS) {
                let split = lift::split_frame(module, function, &[], saved);
                again |= split;

                if split && storage {
                    lift::declare_slots(module, function);
                }
            }
        }

        // Helpers and globals the optimizations made useless
        for function in module.get_functions().filter(|f| f.count_basic_blocks() == 0 && f.as_global_value().as_pointer_value().get_first_use().is_none()).collect::<Vec<_>>() {
            unsafe { function.delete() };
        }

        for global in module.get_globals().filter(|g| g.as_pointer_value().get_first_use().is_none()).collect::<Vec<_>>() {
            unsafe { global.delete() };
        }

        canaries.sort();
        canaries.dedup();

        return Ok(canaries);
    }

    /*
     * User annotations
     */

    /// Names a function or a global, None restores the name from the symbols. The functions decompiled
    /// afterwards use the new name, in their body as well as in their callers.
    pub fn rename(&self, addr: u64, name: Option<String>) {
        self.trivial.borrow_mut().clear();
        self.decompiled.borrow_mut().clear();
        self.ready.borrow_mut().clear();

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
        self.trivial.borrow_mut().clear();
        self.decompiled.borrow_mut().clear();
        self.ready.borrow_mut().clear();
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

        if let Some(name) = self.demangled.get(&addr) {
            return name.clone();
        }

        if let Some(symbol) = self.program.symbol_at(addr) {
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
        let sig = self.compute_signature_without_clobbers(addr);
        return Signature { clobbers: self.clobbers(addr), ..sig };
    }

    /// Registers a function of the program may write: its instructions and its callees (the ones that are
    /// not known may write anything)
    fn clobbers(&self, addr: u64) -> u128 {
        if let Some(&known) = self.clobbered.borrow().get(&addr) {
            return known;
        }

        // In a cycle of calls, the callers seen first may write anything (as the compiler assumes for the
        // functions it did not compile yet)
        self.clobbered.borrow_mut().insert(addr, lift::CLOBBERS_ALL);

        let mut mask = 0u128;

        match self.analysis.functions.get(&addr).filter(|f| f.thunk.is_none()) {
            None => mask = lift::CLOBBERS_ALL,
            Some(function) => {
                for insn in function.blocks.values().flat_map(|b| b.insns.iter()) {
                    let written = self.program.read(insn.addr, insn.size as usize).and_then(|bytes| lift::written_registers(&self.regs, &self.cs, bytes, insn.addr));
                    mask |= written.unwrap_or(lift::CLOBBERS_ALL);
                }

                for call in function.calls.iter() {
                    mask |= match call.target {
                        CallTarget::Function(callee) if callee != addr => self.clobbers(callee),
                        CallTarget::Function(_) => 0,
                        _ => lift::CLOBBERS_ALL,
                    };
                }
            }
        }

        self.clobbered.borrow_mut().insert(addr, mask);
        return mask;
    }

    fn compute_signature_without_clobbers(&self, addr: u64) -> Signature {
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

        // The functions the C runtime links in return nothing (what is left in the return register is not a
        // result, they have no caller in the program)
        if let Some((_, text)) = CRT_PROTOTYPES.iter().find(|(n, _)| *n == name) {
            if let Ok(prototype) = crate::notes::parse_prototype(text, &self.typedb) {
                return Signature { noreturn, ..self.signature_from_prototype(&prototype, &name) };
            }
        }

        if let Some(ty) = self.callbacks().get(&addr) {
            return Signature { noreturn, ..self.signature_from_prototype(&Prototype { name: name.clone(), ty: ty.clone() }, &name) };
        }

        let mut discovered = self.discover(addr, &name).unwrap_or_else(|_| self.call_signature(&CallTarget::Indirect));

        // A result nobody reads is a leftover in the return register
        if discovered.ret.is_some() && !self.result_read_by_callers(addr) {
            discovered.ret = None;
        }

        // main has its standard parameters, as many as it reads
        if name == "main" && discovered.params.len() <= 3 {
            let names = ["argc", "argv", "envp"];
            let types = [CType::int(32), CType::ptr(CType::ptr(CType::Char)), CType::ptr(CType::ptr(CType::Char))];
            let params = names.iter().zip(types).take(discovered.params.len()).map(|(n, ty)| Param { name: Some(n.to_string()), ty }).collect();
            let prototype = Prototype { name: name.clone(), ty: FuncType { ret: CType::int(32), params, variadic: false } };
            return Signature { noreturn, ..self.signature_from_prototype(&prototype, &name) };
        }

        // Itanium encodes the parameters but not the return type
        if let Some(prototype) = demangled {
            let sig = self.signature_from_prototype(&prototype, &name);
            return Signature { ret: discovered.ret, noreturn, ..sig };
        }

        return Signature { name, noreturn, ..discovered };
    }

    /// The functions of the program whose address is passed to a parameter of a known function that is a
    /// pointer to a function, with its type (the ones passed to parameters of different types are left out)
    fn callbacks(&self) -> &HashMap<u64, FuncType> {
        return self.callbacks.get_or_init(|| {
            let signature = |target: &CallTarget| self.call_signature(target);
            let global_name = |addr: u64| self.global_name(addr);
            let env = self.env(&signature, &global_name);
            let mut found: HashMap<u64, Option<FuncType>> = HashMap::new();

            for caller in self.analysis.functions.values() {
                for call in caller.calls.iter() {
                    let import = match &call.target {
                        CallTarget::Import(name) => Some(name.as_str()),
                        CallTarget::Function(addr) => self.analysis.functions.get(addr).and_then(|f| f.thunk.as_deref()),
                        CallTarget::Indirect => None,
                    };

                    let Some(prototype) = import.and_then(|name| self.typedb.function(name)) else {
                        continue;
                    };

                    let callbacks: Vec<(usize, FuncType)> = prototype
                        .ty
                        .params
                        .iter()
                        .enumerate()
                        .filter_map(|(i, p)| match self.typedb.resolve(&p.ty) {
                            CType::Pointer(to) => match self.typedb.resolve(to) {
                                CType::Function(ty) => Some((i, (**ty).clone())),
                                _ => None,
                            },
                            _ => None,
                        })
                        .collect();

                    if callbacks.is_empty() {
                        continue;
                    }

                    let params = self.signature_from_prototype(&prototype, &prototype.name).params;

                    for (index, ty) in callbacks {
                        let Some(Loc::Reg(reg)) = params.get(index).map(|p| p.loc) else {
                            continue;
                        };

                        let Some(target) = lift::argument_address(&env, &self.cs, caller, call.addr, reg).filter(|t| self.analysis.functions.contains_key(t)) else {
                            continue;
                        };

                        let known = found.entry(target).or_insert_with(|| Some(ty.clone()));

                        if known.as_ref() != Some(&ty) {
                            *known = None;
                        }
                    }
                }
            }

            found.into_iter().filter_map(|(addr, ty)| Some((addr, ty?))).collect()
        });
    }

    /// Whether a caller reads the result of a function: after the call, or as its own result read by its callers
    /// (a function without callers in the program is called from elsewhere)
    fn result_read_by_callers(&self, addr: u64) -> bool {
        let mut visited = HashSet::new();
        return self.result_read(addr, self.abi.int_ret, true, &mut visited, MAX_RESULT_DEPTH);
    }

    /// Whether a caller reads a return register of a function, unknown is the answer for the functions whose callers
    /// are not known
    fn result_read(&self, addr: u64, reg: Reg, unknown: bool, visited: &mut HashSet<u64>, depth: usize) -> bool {
        if !visited.insert(addr) {
            return false;
        }

        let Some(callers) = self.analysis.callers.get(&addr).filter(|_| depth > 0) else {
            return unknown;
        };

        let signature = |target: &CallTarget| self.call_signature(target);
        let global_name = |addr: u64| self.global_name(addr);
        let env = self.env(&signature, &global_name);
        let mut sites = 0;

        for caller in callers.iter().filter_map(|c| self.analysis.functions.get(c)) {
            for call in caller.calls.iter().filter(|c| c.target == CallTarget::Function(addr)) {
                sites += 1;

                // The return register is read when unsure, the high half of a result only when it is seen read
                let unsure = if unknown { lift::ResultUse::Read } else { lift::ResultUse::Unused };
                let used = if call.tail { lift::ResultUse::Returned } else { lift::result_used(&env, &self.cs, caller, call.addr, reg, unsure) };

                let read = match used {
                    lift::ResultUse::Read => true,
                    lift::ResultUse::Returned => self.result_read(caller.addr, reg, unknown, visited, depth - 1),
                    lift::ResultUse::Unused => false,
                };

                if read {
                    return true;
                }
            }
        }

        return sites == 0 && unknown;
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
        let (llvm, _) = lift::lift(&cx, &module, &env, function, &frame, discovery.clone(), true, false)?;

        let saved = frame.saved_slots(function.addr, self.abi.slot_size as i64);
        self.optimize(&module, false, &saved)?;

        let high_read = || self.abi.int_ret_high.is_some_and(|high| self.result_read(addr, high, false, &mut HashSet::new(), MAX_RESULT_DEPTH));
        return Ok(refine(&module, llvm, &discovery, &self.abi, &high_read));
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

    /// C prototype of a discovered signature: integers and floats of the register widths, pointers to
    /// what is not known (the function's own accesses give it)
    fn prototype_of(&self, sig: &Signature) -> Prototype {
        let ctype = |ty: LType| match ty {
            LType::Int(bits) => CType::int(bits as u16),
            LType::Float(bits) => CType::Float { bits: bits as u16 },
            LType::Ptr => CType::ptr(CType::Unknown(0)),
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

        return Signature { name: name.to_string(), params, ret, variadic: prototype.ty.variadic, noreturn: false, guessed: false, clobbers: lift::CLOBBERS_ALL };
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

/// A lifted function: its frame, the stack slots its instructions write, the offsets of the slots of
/// the stack canary
struct Lifted {
    frame: Rc<Frame>,
    slot_writes: Vec<lift::SlotWrite>,
    canaries: Vec<i64>,
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
/// C names of the functions with a mangled symbol: the name of their C++ prototype, or the C identifier of
/// their demangled name (core::fmt::Arguments::new_v1 is core_fmt_Arguments_new_v1). The names given to
/// several functions (the instances of a Rust generic function, C++ overloads) end with their address.
fn demangled_names(program: &Program, analysis: &Analysis, model: &DataModel, classes: &HashSet<String>) -> HashMap<u64, String> {
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut plain: HashSet<String> = HashSet::new();

    for function in analysis.functions.values().filter(|f| f.thunk.is_none()) {
        let Some(symbol) = program.symbol_at(function.addr) else {
            continue;
        };

        let Some(demangled) = demangle_symbol(&symbol.name) else {
            plain.insert(sanitize(&symbol.name));
            continue;
        };

        let name = match cxx::prototype(&demangled, model, classes) {
            Some(prototype) => prototype.name,
            None => cxx::identifier(&demangled.name),
        };

        if !name.is_empty() {
            names.insert(function.addr, name);
        }
    }

    let mut count: HashMap<&str, usize> = HashMap::new();

    for name in names.values() {
        *count.entry(name.as_str()).or_default() += 1;
    }

    let shared: HashSet<String> = count.into_iter().filter(|&(name, n)| n > 1 || plain.contains(name)).map(|(name, _)| name.to_string()).collect();

    for (addr, name) in names.iter_mut() {
        if shared.contains(name.as_str()) {
            *name = format!("{}_{:x}", name, addr);
        }
    }

    return names;
}

/// C names of the functions with a mangled symbol, for the tools that find a function by its C name
pub fn function_names(program: &Program, analysis: &Analysis) -> HashMap<u64, String> {
    let windows = program.format == Format::Pe;
    let model = DataModel::new(program.architecture(), windows);
    let symbols: Vec<_> = program.symbols.values().filter_map(|s| demangle_symbol(&s.name)).collect();

    return demangled_names(program, analysis, &model, &cxx::known_classes(symbols.iter()));
}

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

        // A string: the register is an address
        let count_chars = decompiler.signature(function(&analysis, "count_chars"));
        assert_eq!(count_chars.params.len(), 1);
        assert_eq!(count_chars.params[0].ty, LType::Ptr);

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
        assert!(main.starts_with("int main(int argc)") && main.contains("messages[argc % 3]"), "{}", main);
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

        // The buffers are arrays (up to the registers the prologue saves, the return address and the arguments
        // are above them), the scalars below them are values
        assert!(check.contains("char dest[32];") && check.contains("strcpy(dest, src);"), "{}", check);
        assert!(check.contains("for (i = 0; i <= 3; i++) {") && check.contains("+= dest[i];"), "{}", check);

        // The buffer is read after the call that wrote it
        let strcpy = check.find("strcpy(").unwrap();
        assert!(check[strcpy..].contains("if (dest[1] == 'x') {"), "{}", check);

        // A string written four bytes at a time, stack arguments after a double
        assert!(check.contains("memcpy(v2, \"libsrty ko!\", 12);"), "{}", check);
        assert!(check.contains("printf(\"%s %d %f\\n\", v2, v1, 2.5);"), "{}", check);
    }

    #[test]
    fn crt_prototypes() {
        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86, false));

        for (name, text) in CRT_PROTOTYPES {
            let prototype = crate::notes::parse_prototype(text, &typedb).unwrap();
            assert_eq!((prototype.name.as_str(), prototype.ty.ret.clone()), (*name, CType::Void));
        }
    }

    #[test]
    fn calls_through_a_global_holding_one_function() {
        let program = fixture("elf_i386_pointer");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let main = decompiler.c_code(function(&analysis, "main")).unwrap();

        // verify returns nothing: main clears eax after calling it (xor eax, eax does not read it)
        let verify = decompiler.c_code(function(&analysis, "verify")).unwrap();
        assert!(verify.starts_with("void verify(const char *s1, const char *s2)") && !verify.contains("return"), "{}", verify);

        // The pointer is only ever set to verify: the call is a call to verify, with its arguments
        assert!(main.contains("main_check = verify;") && main.contains("verify(dest, s);"), "{}", main);

        // main has its standard prototype, the format string is in a register before it is passed
        assert!(main.starts_with("int main(int argc, char **argv)"), "{}", main);
        assert!(main.contains("strcpy(dest, argv[1]);") && main.contains("printf(\"usage: %s password\\n\", *argv);"), "{}", main);
    }

    #[test]
    fn realigned_frame_of_gcc() {
        let program = fixture("elf_i386_pointer_gcc");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let main = decompiler.c_code(function(&analysis, "main")).unwrap();

        // The arguments are read through the address the realigned frame keeps of them (saved by the prologue)
        assert!(main.starts_with("int main(int argc, char **argv)") && main.contains("if (argc == 2) {") && main.contains("strcpy(dest, argv[1]);"), "{}", main);
        assert!(!main.contains(" *)"), "{}", main);

        // rep stosd clears the buffer, two overlapping stores write the string
        assert!(main.contains("memset(s2, 0, 100);") && main.contains("memcpy(s2, \"secret\", 7);") && main.contains("verify(dest, s2);"), "{}", main);
    }

    #[test]
    fn structs_between_functions() {
        let program = fixture("elf_x86_64_structs");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let code = |name: &str| decompiler.c_code(function(&analysis, name)).unwrap();

        // first uses only what sum knows of the node: it takes sum's struct
        let (sum, first) = (code("sum"), code("first"));
        let name = sum.split("int64_t sum(struct ").nth(1).and_then(|s| s.split(' ').next()).unwrap().to_string();
        assert!(first.starts_with(&format!("int64_t first(struct {} *a1)", name)) && !first.contains(" {\n    struct"), "{}\n{}", sum, first);

        // walk uses more: its struct has the fields of both of its callees and its own, the next pointer typed
        // with sum's struct
        let walk = code("walk");
        assert!(walk.contains(&format!("    struct {} *f0;", name)) && walk.contains("    int64_t f8;") && walk.contains("    const char *f18;"), "{}", walk);

        // named returns a test: a boolean for its callers
        assert!(code("named").contains("\nbool named(struct ") && walk.contains("if (!named(a1)) {"), "{}", walk);
    }

    #[test]
    fn code_hidden_behind_a_computed_jump() {
        let program = fixture("elf_i386_hidden");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let main = decompiler.c_code(function(&analysis, "main")).unwrap();

        // lea eax, [1f]; inc eax; jmp eax lands after the first byte of what reads as mov eax, imm32
        assert!(!main.contains("__indirect_jump") && main.contains("puts(\"hidden\");"), "{}", main);

        // The buffer fgets reads 9 bytes into ends there, the key after it is not part of it; its characters
        // compared are character literals
        assert!(main.contains("char s[9];") && main.contains("fgets(s, 9, stdin);") && main.contains("s[0] != 'd'"), "{}", main);
    }

    #[test]
    fn conditional_tail_calls() {
        let program = fixture("elf_x86_64_quality");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let code = decompiler.c_code(function(&analysis, "length_of")).unwrap();

        // gcc moves the unlikely path to a cold part reached by a conditional jump, the rest follows it (the
        // cold part only calls fatal, which only calls abort)
        assert!(code.contains("if (") && code.contains("abort(); // length_of_cold") && code.contains("strlen("), "{}", code);
    }

    #[test]
    fn rust_names_and_got_calls() {
        let program = fixture("elf_x86_64_rust");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let parse = function(&analysis, "rust::checks::parse");
        let scale = function(&analysis, "rust::checks::scale");
        let from_utf8 = function(&analysis, "core::str::converts::from_utf8");

        // The demangled paths joined with underscores, legacy (the crate) and v0 (core) manglings
        assert_eq!(decompiler.function_name(parse), "rust_checks_parse");
        assert_eq!(decompiler.function_name(from_utf8), "core_str_converts_from_utf8");
        assert_eq!(function_names(&program, &analysis).get(&scale).map(String::as_str), Some("rust_checks_scale"));

        // core is called through a GOT slot the loader fills with its address
        assert!(analysis.functions[&parse].calls.iter().any(|c| c.target == CallTarget::Function(from_utf8)));
        assert!(decompiler.c_code(parse).unwrap().contains("core_str_converts_from_utf8(&"));

        // A parameter only used to compute the result is a parameter
        let code = decompiler.c_code(scale).unwrap();
        assert!(code.contains("int64_t rust_checks_scale(int64_t a1)") && code.contains("return a1 * 7 + 3;"), "{}", code);

        // Option<u32> is returned in eax (some) and edx (the value), its caller reads both
        assert!(decompiler.c_code(parse).unwrap().contains("__int128 rust_checks_parse("));
        let start = decompiler.c_code(function(&analysis, "_start")).unwrap();
        assert!(start.contains("__int128 v1 = rust_checks_parse(") && start.contains("(int64_t)(v1 >> 64)"), "{}", start);
    }

    #[test]
    fn trivial_functions_inlined() {
        for (name, cold) in [("elf_x86_64_quality", "length_of_cold"), ("elf_i386_quality", "fatal"), ("elf_aarch64_quality", "fatal")] {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();
            let code = |function_name: &str| decompiler.c_code(function(&analysis, function_name)).unwrap();

            // Their callers show their statement, they are printed on one line
            assert_eq!(code("fatal"), "void fatal(void) { abort(); }\n", "{}", name);
            assert!(code("answer").ends_with(" answer(void) { return 42; }\n"), "{}: {}", name, code("answer"));
            assert!(decompiler.is_inlined(function(&analysis, "fatal")));

            let length_of = code("length_of");
            assert!(length_of.contains(&format!("abort(); // {}", cold)), "{}: {}", name, length_of);

            // The unused parameter of forward is dropped with its argument (on x86 the arguments it passes on
            // the stack are the ones it received), clang folds the result of answer
            let parse_opt = code("parse_opt");
            assert!(parse_opt.contains("return length_of(src); // forward"), "{}: {}", name, parse_opt);
            assert!(parse_opt.contains(if name == "elf_x86_64_quality" { "return 42; // answer" } else { "return 42;" }), "{}: {}", name, parse_opt);
        }
    }

    #[test]
    fn pointer_signatures() {
        // A register used as an address is a pointer, a result that is always one is too
        for name in ["elf_x86_64_quality", "elf_i386_quality", "elf_aarch64_quality"] {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();
            let skip_spaces = function(&analysis, "skip_spaces");

            let signature = decompiler.signature(skip_spaces);
            assert_eq!(signature.params.iter().map(|p| p.ty).collect::<Vec<_>>(), vec![LType::Ptr], "{}", name);
            assert_eq!(signature.ret.as_ref().map(|r| r.ty), Some(LType::Ptr), "{}", name);

            let code = decompiler.c_code(skip_spaces).unwrap();
            assert!(code.starts_with("char *skip_spaces(char *a1)"), "{}: {}", name, code);
        }
    }

    #[test]
    fn callback_prototypes() {
        // A function passed to qsort has the prototype of its parameter (the arguments in registers only)
        for name in ["elf_x86_64_quality", "elf_aarch64_quality"] {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();

            let code = decompiler.c_code(function(&analysis, "by_value")).unwrap();
            assert!(code.starts_with("int by_value(const void *a1, const void *a2)"), "{}: {}", name, code);
        }
    }

    #[test]
    fn storage_of_the_variables() {
        let location = |name: &str, function_name: &str, var: &str, at: u64| -> Option<storage::Loc> {
            let program = fixture(name);
            let analysis = analyze(&program, None).unwrap();
            let decompiler = Decompiler::new(&program, &analysis).unwrap();
            let addr = function(&analysis, function_name);
            let c = decompiler.c_function(addr).unwrap();
            let var = c.vars.iter().position(|v| v.name == var).unwrap_or_else(|| panic!("{}: no {} in {:?}", name, var, c.vars));
            let (_, ranges) = c.storage.vars.iter().find(|(v, _)| *v == var)?;
            storage::location_at(ranges, (at - addr) as u32)
        };

        let regs = RegisterFile::new(Architecture::X86_64);

        // The parameter in its register at the entry, the buffer in its slot
        assert_eq!(location("elf_x86_64_quality", "length_of", "src", 0x4010a0), storage::Loc::register(regs.reg("rdi"), 64, 0));
        assert_eq!(location("elf_x86_64_quality", "length_of", "dest", 0x4010d4), storage::Loc::stack(-0x58));
        assert_eq!(location("elf_x86_64_quality", "parse_opt", "a1", 0x401120), storage::Loc::register(regs.reg("rdi"), 32, 0));

        // Unoptimized code: the variables are in their stack slot, the loop counter at the start of the loop too
        assert_eq!(location("elf_i386_frame", "check", "i", 0x401319), storage::Loc::stack(-0x38));
        assert_eq!(location("elf_i386_frame", "check", "src", 0x401300), storage::Loc::stack(4));

        let regs = RegisterFile::new(Architecture::Aarch64);
        assert_eq!(location("elf_aarch64_quality", "length_of", "src", 0x10640), storage::Loc::register(regs.reg("x0"), 64, 0));

        // The slot of the canary is known
        let program = fixture("elf_x86_64_quality");
        let analysis = analyze(&program, None).unwrap();
        let decompiler = Decompiler::new(&program, &analysis).unwrap();
        let c = decompiler.c_function(function(&analysis, "length_of")).unwrap();
        assert_eq!(c.storage.canaries, vec![storage::Loc::stack(-0x10).unwrap().canary()]);
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
