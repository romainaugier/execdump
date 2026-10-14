/*
 * C backend: optimized LLVM IR to C
 *
 * ir reads the LLVM function, typing infers the C types of its values, build turns them into
 * statements (out of SSA), structure gives them if/else, loops and switches, naming gives the
 * variables names from their use
 */

pub mod ast;
mod build;
mod coalesce;
#[cfg(test)]
mod differential;
pub mod inline;
pub mod ir;
mod naming;
pub mod quality;
mod reaching;
mod scope;
mod simplify;
mod structure;
mod typing;

use ast::CFunction;

use crate::lift::text_at;
use crate::typedb::TypeDb;
use crate::types::{CType, Prototype};

use execdump_core::program::Program;

use inkwell::module::Module;
use inkwell::values::FunctionValue;

use std::collections::{HashMap, HashSet};

/// What the C backend knows about the program
pub struct Context<'a> {
    pub program: &'a Program,
    pub typedb: &'a TypeDb,
    /// LLVM global name to its address
    pub globals: &'a HashMap<String, u64>,
    /// Prototypes of the functions, by C name
    pub prototypes: &'a HashMap<String, Prototype>,
    /// Functions that do not return
    pub noreturn: &'a HashSet<String>,
    /// Text of the instruction at an address (kept as inline assembly)
    pub instruction: Box<dyn Fn(u64) -> String + 'a>,
    /// The return instruction, when there is only one (the returns merged by LLVM have no address)
    pub ret: Option<u64>,
    /// Name of the function starting at an address
    pub function: Box<dyn Fn(u64) -> Option<String> + 'a>,
}

impl Context<'_> {
    pub fn resolve(&self, ty: &CType) -> CType {
        return self.typedb.resolve(ty).clone();
    }

    pub fn size_of(&self, ty: &CType) -> Option<u64> {
        return self.typedb.size_of(ty);
    }

    pub fn size_bits(&self, ty: &CType) -> u32 {
        return self.size_of(ty).map_or(0, |s| s as u32 * 8);
    }

    /// Text of a read-only string global
    pub fn string(&self, name: &str) -> Option<String> {
        let addr = *self.globals.get(name)?;

        if self.program.region_at(addr).is_some_and(|r| r.perms.write) {
            return None;
        }

        return text_at(self.program, addr);
    }

    /// String at an address of read-only data. Numbers are rarely mistaken for one: when the value is not
    /// known to be a pointer, the string has to start after a NUL or at the start of its section (linkers
    /// merge the strings that end another one, a pointer can point in the middle of one).
    pub fn string_at(&self, addr: u64, pointer: bool) -> Option<String> {
        if addr < 0x1000 {
            return None;
        }

        let region = self.program.region_at(addr).filter(|r| !r.perms.write && !r.perms.exec && !r.data.is_empty())?;

        if !pointer && addr != region.vaddr && self.program.read(addr - 1, 1) != Some(&[0][..]) {
            return None;
        }

        return text_at(self.program, addr);
    }

    pub fn instruction(&self, addr: u64) -> String {
        return (self.instruction)(addr);
    }
}

/// C function of an optimized LLVM function, with its known prototype (parameter names and types)
pub fn decompile(module: &Module, function: FunctionValue, ctx: &Context, prototype: Option<&Prototype>, addr: u64) -> CFunction {
    let f = ir::read(module, function);

    let declared: Vec<CType> = match prototype {
        Some(p) if p.ty.params.len() == f.params.len() => p.ty.params.iter().map(|p| p.ty.clone()).collect(),
        _ => Vec::new(),
    };

    let names: Vec<String> = (0..f.params.len())
        .map(|i| prototype.and_then(|p| p.ty.params.get(i)).and_then(|p| p.name.clone()).unwrap_or_default())
        .collect();

    let types = typing::infer(&f, ctx, &declared);
    let ret = return_type(&f, &types, prototype);
    let mut built = build::build(&f, ctx, types, &names);
    let body = structure::structure(built.blocks, &mut built.vars);

    let mut function = CFunction { name: f.name.clone(), ret, params: built.params, variadic: f.variadic, vars: built.vars, body, addr, globals: built.globals, inlined: false };
    simplify::simplify(&mut function);
    simplify::null_returns(&mut function);
    naming::name(&mut function, ctx);

    return function;
}

fn return_type(f: &ir::Func, types: &[CType], prototype: Option<&Prototype>) -> CType {
    let declared = prototype.map(|p| p.ty.ret.clone()).filter(|r| !r.is_unknown());

    // Discovered prototypes only know the width of the result or that it is a pointer, an inferred pointer
    // is better
    let discovered = |r: &CType| matches!(r, CType::Int { bits: 32 | 64, .. }) || typing::pointee(r).is_some_and(|p| p.is_unknown());

    if let Some(declared) = declared.as_ref().filter(|r| !discovered(r)) {
        return declared.clone();
    }

    let declared = declared.map(|r| if typing::pointee(&r).is_some_and(|p| p.is_unknown()) { CType::ptr(CType::Void) } else { r });

    // The type of the returned values (a pointer when one of them is)
    let returned: Vec<&CType> = f
        .blocks
        .iter()
        .filter_map(|b| b.insts.last())
        .filter_map(|&i| match f.inst(i) {
            Some((ir::Op::Ret, [value])) => Some(&types[*value]),
            _ => None,
        })
        .collect();

    if let Some(pointer) = returned.iter().find(|t| typing::is_pointer(t)) {
        return (*pointer).clone();
    }

    return declared.or(returned.first().map(|t| (*t).clone())).unwrap_or(CType::Void);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typedb::Platform;
    use crate::types::DataModel;
    use execdump_core::disasm::Architecture;
    use execdump_core::program::{Perms, Region};

    #[test]
    fn strings_in_read_only_data() {
        let mut program = Program::default();
        program.arch = Some(Architecture::X86_64);
        program.pointer_size = 8;

        let read_only = Perms { read: true, write: false, exec: false };
        program.regions.push(Region { name: ".rodata".to_string(), vaddr: 0x2000, size: 8, data: b"xx\0pi\0\x01\0".to_vec(), perms: read_only });
        program.regions.push(Region { name: ".data".to_string(), vaddr: 0x3000, size: 4, data: b"ab\0\0".to_vec(), perms: Perms { write: true, ..read_only } });

        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
        let (globals, prototypes, noreturn) = (HashMap::new(), HashMap::new(), HashSet::new());
        let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None) };

        assert_eq!(ctx.string_at(0x2000, false).as_deref(), Some("xx"));
        assert_eq!(ctx.string_at(0x2003, false).as_deref(), Some("pi"));
        // The end of another string is one only for pointers
        assert_eq!(ctx.string_at(0x2001, false), None);
        assert_eq!(ctx.string_at(0x2001, true).as_deref(), Some("x"));
        assert_eq!(ctx.string_at(0x2006, true), None);
        assert_eq!(ctx.string_at(0x3000, true), None);
    }

    /// C of a function given as LLVM IR text, without prototypes
    fn c_of_ir(ir: &str) -> String {
        let mut program = Program::default();
        program.arch = Some(Architecture::X86_64);
        program.pointer_size = 8;

        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
        let (globals, prototypes, noreturn) = (HashMap::new(), HashMap::new(), HashSet::new());
        let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None) };

        let llvm = inkwell::context::Context::create();
        let buffer = inkwell::memory_buffer::MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "test");
        let module = llvm.create_module_from_ir(buffer).unwrap();
        let function = module.get_first_function().unwrap();

        return decompile(&module, function, &ctx, None, 0).print().text;
    }

    #[test]
    fn index_side_of_byte_accesses() {
        // The counter indexes the integers it is added to, in either order
        let code = c_of_ir(
            "define i64 @copy(i64 %0, i64 %1) {
            entry:
              br label %loop
            loop:
              %i = phi i64 [ 0, %entry ], [ %next, %loop ]
              %src = add i64 %i, %0
              %p = inttoptr i64 %src to ptr
              %c = load i8, ptr %p
              %dst = add i64 %1, %i
              %q = inttoptr i64 %dst to ptr
              store i8 %c, ptr %q
              %next = add i64 %i, 1
              %z = icmp eq i8 %c, 0
              br i1 %z, label %done, label %loop
            done:
              ret i64 %i
            }",
        );

        assert!(code.contains("a1[") && code.contains("a2["), "{}", code);
        assert!(!code.contains("(char *)"), "{}", code);
    }
}
