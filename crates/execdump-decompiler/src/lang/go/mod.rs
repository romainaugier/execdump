// SPDX-License-Identifier: Apache-2.0
/*
 * Go: the runtime of Go and its calling conventions
 *
 * - the pclntab gives the functions, their source files and the size of their arguments and results
 *   (execdump_core::golang), the calling convention follows the version (abi.rs)
 * - the runtime functions with conventions of their own: the write barriers return their buffer in r11 (x25),
 *   runtime.deferproc of the stack ABI returns in rax and takes the arguments of the deferred function after its own
 * - the compiler zeroes and copies blocks with calls into runtime.duffzero and runtime.duffcopy, grows the stack with
 *   runtime.morestack before running the function again, and tests runtime.writeBarrier before the stores of pointers
 *   (barriers.rs)
 */

pub mod abi;
mod barriers;

use super::{Intrinsic, Language, Mapping};

use crate::analysis::function::CallTarget;
use crate::c::ast::CFunction;
use crate::lift::regs::{Abi, RegisterFile};
use crate::lift::{Env, Insn, LType, Lifter, Loc, Signature, Value, CLOBBERS_ALL};
use crate::types::{CType, Prototype};

use execdump_core::disasm::Architecture;
use execdump_core::golang::GoRuntime;
use execdump_core::program::{Language as Kind, Program};

pub struct Go;

/// Types of the runtime and prototypes of the runtime and of a few functions of the standard library
const DATABASE: &str = include_str!("../../../data/typedb/go.h");

/// Bytes of the arguments of a deferred function passed with it
const MAX_DEFERRED_ARGS: u64 = 256;

/// Instructions followed from an entry of a duff device to its return
const MAX_DUFF_INSNS: usize = 1024;

/// The runtime functions that do not return: the panics, the fatal errors, the exits, and the growth of the stack (it
/// runs the function again from its start, the jump back after the call is never taken). runtime.panicCheck1 returns
/// (it only throws in the runtime), runtime.exitsyscall too.
const NORETURN: &[&str] = &[
    "runtime.gopanic",
    "runtime.throw",
    "runtime.fatal",
    "runtime.fatalthrow",
    "runtime.fatalpanic",
    "runtime.goexit",
    "runtime.goexit0",
    "runtime.goexit1",
    "runtime.Goexit",
    "runtime.exit",
    "runtime.abort",
    "os.Exit",
    "syscall.Exit",
];

/// Prefixes of the families of panics (runtime.panicIndex, runtime.goPanicSliceB, runtime.panicdottypeE...)
const NORETURN_PREFIXES: &[&str] = &["runtime.goPanic", "runtime.panic", "runtime.morestack"];

pub fn noreturn(name: &str) -> bool {
    let name = name.strip_suffix(".abi0").unwrap_or(name);

    if NORETURN.contains(&name) {
        return true;
    }

    return NORETURN_PREFIXES.iter().any(|p| name.starts_with(p)) && !name.starts_with("runtime.panicCheck") && !name.contains(".func");
}

/// main.main and the init functions of the packages: the runtime starts them, they have no parameters nor results
fn is_started(name: &str) -> bool {
    let name = name.strip_suffix(".abi0").unwrap_or(name);
    let init = name.rsplit_once(".init").is_some_and(|(_, n)| n.is_empty() || n.strip_prefix('.').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())));
    return name == "main.main" || init;
}

/// The functions of the runtime given a buffer of the frame of their caller for a short result (tmpBuf: 32 bytes,
/// 32 runes for stringtoslicerune), its first argument
const TEMPORARY_BUFFERS: [(&str, u64); 10] = [
    ("runtime_stringtoslicebyte", 32),
    ("runtime_slicebytetostring", 32),
    ("runtime_concatstring2", 32),
    ("runtime_concatstring3", 32),
    ("runtime_concatstring4", 32),
    ("runtime_concatstring5", 32),
    ("runtime_concatstrings", 32),
    ("runtime_intstring", 4),
    ("runtime_rawstringtmp", 32),
    ("runtime_stringtoslicerune", 128),
];

/// The allocations of the runtime, given the type descriptor of what they allocate
const ALLOCATIONS: [&str; 6] = ["runtime_newobject", "runtime_newarray", "runtime_mallocgc", "runtime_makeslice", "runtime_growslice", "runtime_makeslicecopy"];

/// The C type of a Go type of a kind (reflect.Kind): the types of the database for the strings, slices and interfaces
fn go_ctype(kind: u8, name: &str) -> Option<CType> {
    let named = |name: &str| CType::Struct(name.to_string());

    return Some(match kind {
        1 => CType::Bool,
        2 | 6 => CType::int(64),
        3 => CType::int(8),
        4 => CType::int(16),
        5 => CType::int(32),
        7 | 11 | 12 => CType::uint(64),
        8 => CType::uint(8),
        9 => CType::uint(16),
        10 => CType::uint(32),
        13 => CType::Float { bits: 32 },
        14 => CType::Float { bits: 64 },
        18 | 19 | 21 | 22 | 26 => CType::ptr(CType::Void),
        20 if name == "interface {}" => named("go_eface"),
        20 => named("go_iface"),
        23 => named("go_slice"),
        24 => named("go_string"),
        _ => return None,
    });
}

/// C identifier of a type descriptor: type_slice_uint8 for []uint8, type_ptr_main_T for *main.T, type_array14_uint8
/// for [14]uint8, type_map_string_int for map[string]int
fn type_identifier(name: &str) -> String {
    let mut text = String::from("type_");
    let mut chars = name.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '*' => text.push_str("ptr_"),
            '[' if chars.peek() == Some(&']') => {
                chars.next();
                text.push_str("slice_");
            }
            '[' if chars.peek().is_some_and(|c| c.is_ascii_digit()) => {
                text.push_str("array");

                while let Some(digit) = chars.next_if(|c| c.is_ascii_digit()) {
                    text.push(digit);
                }

                text.push('_');
            }
            c if c.is_ascii_alphanumeric() => text.push(c),
            _ => text.push('_'),
        }
    }

    let mut collapsed = String::with_capacity(text.len());

    for c in text.chars() {
        if !(c == '_' && collapsed.ends_with('_')) {
            collapsed.push(c);
        }
    }

    return collapsed.trim_end_matches('_').to_string();
}

/// The function of the runtime a Go function calls from its prologue when its stack is too small: it grows the stack
/// and runs the function again, it is not code of the function
fn grows_stack(name: &str) -> bool {
    return name.starts_with("runtime.morestack");
}

impl Language for Go {
    fn kind(&self) -> Kind {
        return Kind::Go;
    }

    /// The functions of the pclntab (the other functions of a Go program are the C of cgo)
    fn owns(&self, program: &Program, addr: u64) -> bool {
        return GoRuntime::of(program).is_some_and(|r| r.functions.contains_key(&addr));
    }

    fn type_database(&self, program: &Program) -> Option<&'static str> {
        return (GoRuntime::of(program).is_some() && program.pointer_size == 8).then_some(DATABASE);
    }

    /// The parameters then the results laid out as the stack ABI does (each at its alignment, the results from the
    /// next word), in the registers of the register ABI: the size of the layout is the one the pclntab gives to the
    /// function when the prototype is the one of its version
    fn prototype_signature(&self, program: &Program, abi: &Abi, prototype: &Prototype, addr: u64, ltype: &dyn Fn(&CType) -> Option<LType>) -> Mapping {
        let Some(size) = GoRuntime::of(program).and_then(|r| r.args(addr)) else {
            return Mapping::Mismatch;
        };

        let outs = prototype.ty.params.iter().rev().take_while(|p| p.name.as_deref().is_some_and(|n| n.starts_with("ret_"))).count();
        let (inputs, outputs) = prototype.ty.params.split_at(prototype.ty.params.len() - outs);

        let pointee = |ty: &CType| match ty {
            CType::Pointer(to) => ltype(to),
            _ => None,
        };

        let params: Option<Vec<(LType, Option<String>)>> = inputs.iter().map(|p| Some((ltype(&p.ty).unwrap_or(LType::Int(64)), p.name.clone()))).collect();
        let results: Option<Vec<LType>> = ltype(&prototype.ty.ret).into_iter().map(Some).chain(outputs.iter().map(|p| pointee(&p.ty))).collect();

        let (Some(params), Some(results)) = (params, results) else {
            return Mapping::Mismatch;
        };

        if results.is_empty() && outs > 0 {
            return Mapping::Mismatch;
        }

        let slot = abi.slot_size;
        let bytes = |ty: LType| -> i64 {
            match ty {
                LType::Int(bits) | LType::Float(bits) => (bits as i64 / 8).max(1),
                LType::Ptr => slot,
            }
        };
        let align = |offset: i64, to: i64| (offset + to - 1) / to * to;

        // The stack layout: the offsets of the parameters, then of the results
        let mut offset = 0i64;
        let mut param_offsets = Vec::new();

        for &(ty, _) in params.iter() {
            offset = align(offset, bytes(ty).min(slot));
            param_offsets.push(offset);
            offset += bytes(ty);
        }

        offset = align(offset, slot);
        let params_end = offset;
        let mut result_offsets = Vec::new();

        for &ty in results.iter() {
            offset = align(offset, bytes(ty).min(slot));
            result_offsets.push(offset);
            offset += bytes(ty);
        }

        // The size of the register ABI is the one of the spill slots of the parameters, the results have none
        let end = if abi.register_results { params_end } else { align(offset, slot) };

        if end != align(size as i64, slot) {
            return Mapping::Mismatch;
        }

        let value = |loc: Loc, ty: LType, name: Option<String>| Value { loc, ty, name };
        let mut sig = Signature { name: prototype.name.clone(), params: Vec::new(), ret: None, outs: Vec::new(), variadic: false, noreturn: false, guessed: false, clobbers: CLOBBERS_ALL };

        if abi.stack_results {
            sig.params = params.into_iter().zip(param_offsets).map(|((ty, name), at)| value(Loc::Stack(abi.stack_args + at), ty, name)).collect();
            let mut results = results.into_iter().zip(result_offsets).map(|(ty, at)| value(Loc::Stack(abi.stack_args + at), ty, None));
            sig.ret = results.next();
            sig.outs = results.collect();
            return Mapping::Signature(sig);
        }

        // The integers and the floats take the next registers of their kind, the results start again from the first
        let (mut ints, mut floats) = (abi.int_args.iter(), abi.float_args.iter());

        for (ty, name) in params {
            let reg = if matches!(ty, LType::Float(_)) { floats.next() } else { ints.next() };

            let Some(&reg) = reg else {
                return Mapping::Mismatch;
            };

            sig.params.push(value(Loc::Reg(reg), ty, name));
        }

        if results.iter().any(|ty| matches!(ty, LType::Float(_))) && results.len() > 1 {
            return Mapping::Mismatch;
        }

        let mut registers = abi.int_args.iter();

        for (index, ty) in results.into_iter().enumerate() {
            let reg = match ty {
                LType::Float(_) => abi.float_ret,
                _ => match registers.next() {
                    Some(&reg) => reg,
                    None => return Mapping::Mismatch,
                },
            };

            if index == 0 {
                sig.ret = Some(value(Loc::Reg(reg), ty, None));
            } else {
                sig.outs.push(value(Loc::Reg(reg), ty, None));
            }
        }

        return Mapping::Signature(sig);
    }

    fn abi(&self, program: &Program, regs: &RegisterFile) -> Option<Abi> {
        let runtime = GoRuntime::of(program)?;

        if runtime.register_abi {
            return Some(abi::register_abi(regs).unwrap_or_else(|| abi::stack_abi(regs)));
        }

        return Some(abi::stack_abi(regs));
    }

    /// The write barriers return the buffer the caller writes the pointers to in r11 (x25 on aarch64), the registers of
    /// the arguments untouched. runtime.deferproc of the stack ABI returns in rax whether a deferred function recovered
    /// from a panic (the code after the call tests it), its arguments are on the stack.
    fn runtime_signature(&self, program: &Program, abi: &Abi, regs: &RegisterFile, symbol: &str, name: &str) -> Option<Signature> {
        GoRuntime::of(program)?;

        if abi.stack_results && matches!(symbol, "runtime.deferproc" | "runtime.deferprocStack") {
            let slot = LType::Int(abi.slot_size as u32 * 8);
            let mut params = vec![Value { loc: Loc::Stack(abi.stack_args), ty: slot, name: None }];

            if symbol == "runtime.deferproc" {
                params[0].ty = LType::Int(32);
                params.push(Value { loc: Loc::Stack(abi.stack_args + abi.slot_size), ty: LType::Ptr, name: None });
            }

            let ret = Value { loc: Loc::Reg(abi.int_ret), ty: LType::Int(32), name: None };
            return Some(Signature { name: name.to_string(), params, ret: Some(ret), outs: Vec::new(), variadic: false, noreturn: false, guessed: false, clobbers: CLOBBERS_ALL });
        }

        if !symbol.starts_with("runtime.gcWriteBarrier") {
            return None;
        }

        let buffer = regs.reg(if program.architecture() == Architecture::Aarch64 { "x25" } else { "r11" });
        let ret = Value { loc: Loc::Reg(buffer), ty: LType::Ptr, name: None };

        return Some(Signature { name: name.to_string(), params: Vec::new(), ret: Some(ret), outs: Vec::new(), variadic: false, noreturn: false, guessed: false, clobbers: 1 << buffer });
    }

    /// The pclntab gives the size of the arguments and results of the stack ABI: none means none (main.main), else as
    /// many words at most of each. The one of the register ABI bounds the parameters only.
    fn bound_signature(&self, program: &Program, abi: &Abi, addr: u64, sig: &mut Signature) {
        let Some(size) = GoRuntime::of(program).and_then(|r| r.args(addr)) else {
            return;
        };

        let words = (size as i64 / abi.slot_size) as usize;

        // The functions the runtime starts have nothing (the registers the stack ABI passes to the assembly are not
        // their parameters)
        if words == 0 && program.symbol_near(addr).is_some_and(|(s, off)| off == 0 && is_started(&s.name)) {
            sig.params.clear();
            sig.ret = None;
            sig.outs.clear();
            return;
        }

        // The size of the register ABI is the one of the spill slots of the parameters: the results have none
        if abi.register_results {
            sig.params.truncate(words);
            return;
        }

        if words == 0 {
            sig.ret = None;
        }

        sig.outs.truncate(words.saturating_sub(1));
    }

    /// The type descriptors and the itabs, named as the symbols of the itabs are (go:itab.*os.File,io.Writer)
    fn global_name(&self, program: &Program, addr: u64) -> Option<String> {
        let runtime = GoRuntime::of(program)?;

        if let Some(name) = runtime.type_name(program, addr) {
            return Some(type_identifier(&name));
        }

        let (interface, concrete) = runtime.itab(program, addr)?;
        let symbol = format!("go:itab.{},{}", concrete, interface);
        return Some(symbol.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect());
    }

    /// The allocations of the runtime return a pointer to the type of their descriptor (the elements of a slice for
    /// makeslice)
    fn returned_pointee(&self, program: &Program, callee: &str, globals: &[Option<u64>]) -> Option<CType> {
        if !ALLOCATIONS.contains(&callee) {
            return None;
        }

        let runtime = GoRuntime::of(program)?;
        let descriptor = globals.iter().flatten().find(|&&addr| runtime.kind(program, addr).is_some_and(|k| k != 0))?;
        return go_ctype(runtime.kind(program, *descriptor)?, &runtime.type_name(program, *descriptor)?);
    }

    fn argument_extent(&self, program: &Program, callee: &str, index: u32) -> Option<u64> {
        let (_, bytes) = TEMPORARY_BUFFERS.iter().find(|(name, _)| *name == callee).filter(|_| index == 0 && GoRuntime::of(program).is_some())?;
        return Some(*bytes);
    }

    fn result_read_elsewhere(&self, program: &Program, addr: u64) -> bool {
        let Some(runtime) = GoRuntime::of(program) else {
            return true;
        };

        return !(runtime.register_abi && runtime.args(addr) == Some(0));
    }

    /// A call into runtime.duffzero or runtime.duffcopy (x86_64): the compiler zeroes and copies blocks of memory by
    /// calling their code at the offset that leaves the right number of 16-byte moves before the return. The bytes are
    /// the ones the moves from the entry write through rdi.
    fn intrinsic(&self, env: &Env, target: u64) -> Option<Intrinsic> {
        let program = env.program;

        if GoRuntime::of(program).is_none() || program.architecture() != Architecture::X86_64 {
            return None;
        }

        let (symbol, _) = program.symbol_near(target)?;

        let copy = match symbol.name.as_str() {
            "runtime.duffzero" => false,
            "runtime.duffcopy" => true,
            _ => return None,
        };

        let (rdi, rsi) = (env.regs.reg("rdi"), env.regs.reg("rsi"));
        let mut at = target;
        let mut bytes = 0u64;

        for _ in 0..MAX_DUFF_INSNS {
            let code = program.bytes_from(at)?;
            let insn = Insn::decode(Architecture::X86_64, env.regs, env.cs, &code[..code.len().min(16)], at)?;

            if insn.is_return() {
                return match (bytes, copy) {
                    (0, _) => None,
                    (_, true) => Some(Intrinsic::Copy { dst: rdi, src: rsi, bytes }),
                    (_, false) => Some(Intrinsic::Zero { dst: rdi, bytes }),
                };
            }

            bytes += insn.bytes_written_through(rdi);
            at = insn.end();
        }

        return None;
    }

    /// runtime.deferproc(siz, fn) and runtime.newproc(siz, fn) of the stack ABI: the siz bytes of the arguments of the
    /// deferred function (or of the new goroutine) follow their own arguments, they are arguments of the call too
    /// (defer f(x, y) is runtime_deferproc(16, &f, x, y))
    fn call_signature(&self, lifter: &Lifter, target: &CallTarget, mut sig: Signature) -> Signature {
        let CallTarget::Function(addr) = target else {
            return sig;
        };

        let abi = lifter.env.abi;
        let name = lifter.env.program.symbol_at(*addr).map_or("", |s| s.name.as_str());

        if !abi.stack_results || !matches!(name, "runtime.deferproc" | "runtime.newproc") {
            return sig;
        }

        let Some(size) = lifter.stored_constant(abi.stack_args - abi.return_address).filter(|&s| s <= MAX_DEFERRED_ARGS) else {
            return sig;
        };

        let first = abi.stack_args + 2 * abi.slot_size;

        for word in 0..(size as i64 + abi.slot_size - 1) / abi.slot_size {
            sig.params.push(Value { loc: Loc::Stack(first + word * abi.slot_size), ty: LType::Int(abi.slot_size as u32 * 8), name: None });
        }

        return sig;
    }

    fn restarts_function(&self, callee: &str) -> bool {
        return grows_stack(callee);
    }

    fn rewrite_c(&self, function: &mut CFunction) {
        barriers::write_barriers(function);
    }

    /// The package of the function and its source file (runtime.gopark of /usr/lib/go/src/runtime/proc.go ->
    /// runtime/proc.go)
    fn source_module(&self, program: &Program, addr: u64) -> Option<String> {
        GoRuntime::of(program)?;
        let symbol = program.symbol_at(addr)?;
        return Some(module(&symbol.name, program.source_files.get(&addr).map(String::as_str)));
    }

    fn entry_points(&self) -> &'static [&'static str] {
        return &["main.main"];
    }

    fn steps_over(&self, callee: &str) -> bool {
        return grows_stack(callee);
    }
}

/// Package of a Go function: its path to the first dot after the last slash (internal/poll.(*FD).Write ->
/// internal/poll, example.com/app/sub.Run -> example.com/app/sub)
fn package(name: &str) -> &str {
    let last_slash = name.rfind('/').map_or(0, |i| i + 1);
    let end = name[last_slash..].find('.').map_or(name.len(), |i| last_slash + i);
    return &name[..end];
}

/// Module of a Go function: its package and the name of its source file (runtime/proc.go), the package alone without
/// a file
fn module(name: &str, file: Option<&str>) -> String {
    let clean = |text: &str| -> String { text.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/') { c } else { '_' }).collect() };
    let package = clean(package(name).trim_matches('/'));
    let package = if package.is_empty() { "go".to_string() } else { package };

    let stem = file.and_then(|f| f.rsplit(['/', '\\']).next()).map(|f| f.strip_suffix(".go").unwrap_or(f)).filter(|f| !f.is_empty());

    return match stem {
        Some(stem) => format!("{}/{}.go", package, clean(stem)),
        None => format!("{}.go", package),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_and_noreturn() {
        assert_eq!(module("runtime.gopark", Some("/usr/lib/go/src/runtime/proc.go")), "runtime/proc.go");
        assert_eq!(module("internal/poll.(*FD).Write", Some("internal/poll/fd_unix.go")), "internal/poll/fd_unix.go");
        assert_eq!(module("example.com/app/sub.Run", None), "example.com/app/sub.go");
        assert_eq!(module("main.main", Some("C:\\src\\app\\main.go")), "main/main.go");
        assert_eq!(module("type:.eq.main.T", None), "type_.go");

        assert!(noreturn("runtime.panicIndex") && noreturn("runtime.morestack_noctxt.abi0") && noreturn("runtime.exit"));
        assert!(!noreturn("runtime.panicCheck1") && !noreturn("runtime.exitsyscall") && !noreturn("runtime.panicwrap.func1"));
        assert_eq!(go_ctype(23, "[]uint8"), Some(CType::Struct("go_slice".to_string())));
        assert_eq!(go_ctype(20, "io.Writer"), Some(CType::Struct("go_iface".to_string())));
        assert_eq!(go_ctype(25, "main.T"), None);
        assert_eq!(type_identifier("[]uint8"), "type_slice_uint8");
        assert_eq!(type_identifier("*main.T"), "type_ptr_main_T");
        assert_eq!(type_identifier("[14]uint8"), "type_array14_uint8");
        assert_eq!(type_identifier("map[string]int"), "type_map_string_int");
        assert_eq!(type_identifier("interface {}"), "type_interface");
        assert!(is_started("main.main") && is_started("fmt.init") && is_started("main.init.0") && !is_started("main.initialize"));
    }

    #[test]
    fn prototypes_of_the_database() {
        use crate::types::{FuncType, Param};

        // void *runtime_stringtoslicebyte(void *buf, char *s, int64_t s_len, int64_t *ret_len, int64_t *ret_cap)
        let param = |name: &str, ty: CType| Param { name: Some(name.to_string()), ty };
        let words = CType::int(64);
        let params = vec![
            param("buf", CType::ptr(CType::Void)),
            param("s", CType::ptr(CType::Char)),
            param("s_len", words.clone()),
            param("ret_len", CType::ptr(words.clone())),
            param("ret_cap", CType::ptr(words.clone())),
        ];
        let prototype = Prototype { name: "runtime_stringtoslicebyte".to_string(), ty: FuncType { ret: CType::ptr(CType::Void), params, variadic: false } };
        let ltype = |ty: &CType| Some(if matches!(ty, CType::Pointer(_)) { LType::Ptr } else { LType::Int(64) });

        let regs = RegisterFile::new(Architecture::X86_64);
        let signature = |register_abi: bool, args: u32| {
            let mut program = Program { language: Kind::Go, pointer_size: 8, ..Default::default() };
            let runtime = GoRuntime { register_abi, functions: [(0x1000, Some(args))].into_iter().collect(), types: None };
            program.language_data = execdump_core::program::LanguageData::Go(Box::new(runtime));
            let abi = if register_abi { abi::register_abi(&regs).unwrap() } else { abi::stack_abi(&regs) };

            return match Go.prototype_signature(&program, &abi, &prototype, 0x1000, &ltype) {
                Mapping::Signature(sig) => Some(sig),
                _ => None,
            };
        };

        // Go 1.9: three words of arguments then three of results on the stack, above the return address
        let sig = signature(false, 48).unwrap();
        let locs: Vec<Loc> = sig.params.iter().map(|p| p.loc).collect();
        assert_eq!(locs, [Loc::Stack(8), Loc::Stack(16), Loc::Stack(24)]);
        assert_eq!(sig.ret.unwrap().loc, Loc::Stack(32));
        assert_eq!(sig.outs.iter().map(|o| o.loc).collect::<Vec<_>>(), [Loc::Stack(40), Loc::Stack(48)]);

        // Go 1.17 and after: the arguments in rax, rbx, rcx and the results too, the size is the one of the spill slots
        let sig = signature(true, 24).unwrap();
        let reg = |name: &str| Loc::Reg(regs.reg(name));
        assert_eq!(sig.params.iter().map(|p| p.loc).collect::<Vec<_>>(), [reg("rax"), reg("rbx"), reg("rcx")]);
        assert_eq!(sig.ret.unwrap().loc, reg("rax"));
        assert_eq!(sig.outs.iter().map(|o| o.loc).collect::<Vec<_>>(), [reg("rbx"), reg("rcx")]);

        // Another version of the runtime with other arguments
        assert!(signature(false, 40).is_none());
        assert!(signature(true, 16).is_none());
    }
}
