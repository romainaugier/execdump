/*
 * C backend: optimized LLVM IR to C
 *
 * ir reads the LLVM function, typing infers the C types of its values, build turns them into
 * statements (out of SSA), structure gives them if/else, loops and switches, naming gives the
 * variables names from their use
 */

pub mod ast;
mod build;
pub mod ir;
mod naming;
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
    let built = build::build(&f, ctx, types, &names);
    let body = structure::structure(built.blocks);

    let mut function = CFunction { name: f.name.clone(), ret, params: built.params, variadic: f.variadic, vars: built.vars, body, addr };
    simplify::simplify(&mut function);
    simplify::null_returns(&mut function);
    naming::name(&mut function, ctx);

    return function;
}

fn return_type(f: &ir::Func, types: &[CType], prototype: Option<&Prototype>) -> CType {
    let declared = prototype.map(|p| p.ty.ret.clone()).filter(|r| !r.is_unknown());

    // Discovered prototypes only know the width of the result, an inferred pointer is better
    if let Some(declared) = declared.as_ref().filter(|r| !matches!(r, CType::Int { bits: 32 | 64, .. })) {
        return declared.clone();
    }

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
