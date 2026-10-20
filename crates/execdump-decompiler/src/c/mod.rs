/*
 * C backend: optimized LLVM IR to C
 *
 * ir reads the LLVM function, typing infers the C types of its values, build turns them into
 * statements (out of SSA), structure gives them if/else, loops and switches, naming gives the
 * variables names from their use. golang removes the write barriers of the Go compiler.
 */

pub mod ast;
mod build;
mod coalesce;
mod conditions;
#[cfg(test)]
mod differential;
mod golang;
pub mod inline;
pub mod ir;
mod naming;
pub mod quality;
mod reaching;
mod scope;
mod simplify;
mod structs;
mod structure;
mod typing;

use ast::CFunction;

use crate::lift::text_at;
use crate::typedb::{Aggregate, TypeDb};
use crate::types::{CType, Prototype};

use execdump_core::program::Program;

use inkwell::module::Module;
use inkwell::values::FunctionValue;

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Structs recovered from the accesses of the function
    pub structs: RefCell<BTreeMap<String, Aggregate>>,
    /// Prototypes of the functions it calls as they were decompiled (the structs they take and return), before
    /// the discovered ones
    pub callees: HashMap<String, Prototype>,
    /// Structs of those prototypes, recovered by other functions
    pub imported: BTreeMap<String, Aggregate>,
    /// Strings the function passes or returns with their length (address -> length)
    pub sized: RefCell<HashMap<u64, u64>>,
}

impl Context<'_> {
    pub fn resolve(&self, ty: &CType) -> CType {
        return self.typedb.resolve(ty).clone();
    }

    pub fn size_of(&self, ty: &CType) -> Option<u64> {
        if let CType::Struct(name) = self.resolve(ty).unqualified() {
            if let Some(aggregate) = self.structs.borrow().get(name).or(self.imported.get(name)) {
                return Some(aggregate.size);
            }
        }

        return self.typedb.size_of(ty);
    }

    /// A struct or union of the headers, recovered from the accesses of the function or by its callees
    pub fn aggregate(&self, name: &str) -> Option<Aggregate> {
        return self.typedb.aggregates.get(name).or(self.structs.borrow().get(name)).or(self.imported.get(name)).cloned();
    }

    /// Prototype of a function: as its code was decompiled, else as it was discovered or declared
    pub fn prototype(&self, name: &str) -> Option<&Prototype> {
        return self.callees.get(name).or(self.prototypes.get(name));
    }

    pub fn size_bits(&self, ty: &CType) -> u32 {
        return self.size_of(ty).map_or(0, |s| s as u32 * 8);
    }

    /// Text of a read-only string global
    pub fn string(&self, name: &str) -> Option<String> {
        let addr = *self.globals.get(name)?;

        if let Some(text) = self.sized_text(addr) {
            return Some(text);
        }

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

        if let Some(text) = self.sized_text(addr) {
            return Some(text);
        }

        let region = self.program.region_at(addr).filter(|r| !r.perms.write && !r.perms.exec && !r.data.is_empty())?;

        if !pointer && addr != region.vaddr && self.program.read(addr - 1, 1) != Some(&[0][..]) {
            return None;
        }

        return text_at(self.program, addr);
    }

    /// Text of a string whose length is known (a pointer and a length, the strings of Rust and Go are not NUL
    /// terminated: they are the start of the strings laid out after them)
    fn sized_text(&self, addr: u64) -> Option<String> {
        let len = self.sized.borrow().get(&addr).copied().or_else(|| self.program.sized_strings.get(&addr).copied())?;
        return self.program.sized_string(addr, len).map(crate::lift::literal);
    }

    /// Address a constant value is: an integer, a global, through casts and constant offsets
    fn constant_address(&self, f: &ir::Func, id: ir::ValueId) -> Option<u64> {
        return match &f.values[id].kind {
            ir::ValueKind::Int(value) => u64::try_from(*value).ok(),
            ir::ValueKind::Global(name) => self.globals.get(name).copied(),
            ir::ValueKind::Inst { op: ir::Op::PtrToInt | ir::Op::IntToPtr | ir::Op::BitCast | ir::Op::ZExt, operands, .. } => self.constant_address(f, operands[0]),
            ir::ValueKind::Inst { op: ir::Op::Gep, operands, scales, .. } => {
                let base = self.constant_address(f, operands[0])?;
                let offset = operands[1..].iter().zip(scales.iter()).try_fold(0i128, |sum, (&index, &scale)| Some(sum + f.int(index)? * scale as i128))?;
                base.checked_add_signed(i64::try_from(offset).ok()?)
            }
            _ => None,
        };
    }

    /// The (address, length) pairs a pointer and a length are: two constants, the same arms of two selects on one
    /// condition, the values two phis of one block get from the same block
    /// The length is shifted left by shift bits (the high half of an i128)
    fn sized_pairs(&self, f: &ir::Func, pointer: ir::ValueId, length: ir::ValueId, shift: u32, depth: usize, out: &mut Vec<(u64, u64)>) {
        let low = (1u128 << shift) - 1;
        let len = f.int(length).filter(|&l| l >= 0 && l as u128 & low == 0).and_then(|l| u64::try_from(l as u128 >> shift).ok());

        if let (Some(addr), Some(len)) = (self.constant_address(f, pointer), len) {
            out.push((addr, len));
            return;
        }

        if depth == 0 {
            return;
        }

        use ir::{Op, ValueKind};

        let uncast = |mut id: ir::ValueId| {
            while let Some((Op::ZExt | Op::PtrToInt | Op::IntToPtr | Op::BitCast | Op::Freeze, [inner])) = f.inst(id) {
                id = *inner;
            }

            id
        };

        let (pointer, length) = (uncast(pointer), uncast(length));

        match (&f.values[pointer].kind, &f.values[length].kind) {
            (ValueKind::Inst { op: Op::Select, operands: p, .. }, ValueKind::Inst { op: Op::Select, operands: l, .. }) if p[0] == l[0] => {
                self.sized_pairs(f, p[1], l[1], shift, depth - 1, out);
                self.sized_pairs(f, p[2], l[2], shift, depth - 1, out);
            }
            (ValueKind::Inst { op: Op::Phi, operands: p, blocks: from, block: a, .. }, ValueKind::Inst { op: Op::Phi, operands: l, blocks: other, block: b, .. }) if a == b => {
                for (index, block) in from.iter().enumerate() {
                    if let Some(position) = other.iter().position(|o| o == block) {
                        self.sized_pairs(f, p[index], l[position], shift, depth - 1, out);
                    }
                }
            }
            // One length for every pointer a select or a phi chooses (a NULL one has no string), and the reverse
            (ValueKind::Inst { op: Op::Select, operands: p, .. }, _) => p[1..].iter().for_each(|&arm| self.sized_pairs(f, arm, length, shift, depth - 1, out)),
            (ValueKind::Inst { op: Op::Phi, operands: p, .. }, _) => p.iter().for_each(|&arm| self.sized_pairs(f, arm, length, shift, depth - 1, out)),
            (_, ValueKind::Inst { op: Op::Select, operands: l, .. }) => l[1..].iter().for_each(|&arm| self.sized_pairs(f, pointer, arm, shift, depth - 1, out)),
            (_, ValueKind::Inst { op: Op::Phi, operands: l, .. }) => l.iter().for_each(|&arm| self.sized_pairs(f, pointer, arm, shift, depth - 1, out)),
            _ => {}
        }
    }

    /// Strings with their length in the function: a pointer to text then its length in the arguments of a call or
    /// stored next to each other (the fields of a &str), a pointer and a length returned in a pair of registers
    /// (low and high halves of an i128) or as a result and the first result after it
    fn note_sized_strings(&self, f: &ir::Func) {
        if !self.program.language.has_sized_strings() {
            return;
        }

        let pointer_size = self.program.pointer_size.max(4) as i128;
        let mut found: Vec<(u64, u64)> = Vec::new();

        for value in f.values.iter() {
            let ir::ValueKind::Inst { op, operands, .. } = &value.kind else {
                continue;
            };

            match op {
                ir::Op::Call => {
                    for pair in operands.windows(2) {
                        self.sized_pairs(f, pair[0], pair[1], 0, 4, &mut found);
                    }
                }
                ir::Op::Or if value.ty == ir::Ty::Int(128) => {
                    self.sized_pairs(f, operands[0], operands[1], 64, 4, &mut found);
                    self.sized_pairs(f, operands[1], operands[0], 64, 4, &mut found);
                }
                _ => {}
            }
        }

        for block in f.blocks.iter() {
            let stores: Vec<(ir::ValueId, i128, ir::ValueId)> = block
                .insts
                .iter()
                .filter_map(|&id| match f.inst(id) {
                    Some((ir::Op::Store, [value, address])) => {
                        let (base, offset) = f.base_offset(*address);
                        Some((base, offset, *value))
                    }
                    _ => None,
                })
                .collect();

            for &(base, offset, pointer) in stores.iter() {
                if let Some(&(_, _, length)) = stores.iter().find(|(b, o, _)| *b == base && *o == offset + pointer_size) {
                    self.sized_pairs(f, pointer, length, 0, 4, &mut found);
                }
            }
        }

        // A pointer returned with its length written to the first pointer to a result (Go returns a string in two
        // registers, the second one is the first result written through a pointer)
        for (index, block) in f.blocks.iter().enumerate() {
            let Some(Some((ir::Op::Ret, [returned]))) = block.insts.last().map(|&id| f.inst(id)) else {
                continue;
            };

            // The value returned from each block (the arms of the phi of the block of the return)
            let returns: Vec<(ir::ValueId, usize)> = match &f.values[*returned].kind {
                ir::ValueKind::Inst { op: ir::Op::Phi, operands, blocks, block: Some(at), .. } if *at == index => operands.iter().copied().zip(blocks.iter().copied()).collect(),
                _ => vec![(*returned, index)],
            };

            for (value, from) in returns {
                for &id in f.blocks[from].insts.iter().chain(block.insts.iter()) {
                    if let Some((ir::Op::Store, [stored, address])) = f.inst(id) {
                        if f.params.contains(address) {
                            self.sized_pairs(f, value, *stored, 0, 4, &mut found);
                        }
                    }
                }
            }
        }

        let mut sized = self.sized.borrow_mut();

        for (addr, len) in found {
            if self.program.sized_string(addr, len).is_some() {
                let known = sized.entry(addr).or_insert(len);
                *known = (*known).max(len);
            }
        }
    }

    pub fn instruction(&self, addr: u64) -> String {
        return (self.instruction)(addr);
    }
}

/// C function of an optimized LLVM function, with its known prototype (parameter names and types)
pub fn decompile(module: &Module, function: FunctionValue, ctx: &Context, prototype: Option<&Prototype>, addr: u64) -> CFunction {
    let mut f = ir::read(module, function);
    f.sink();
    ctx.note_sized_strings(&f);

    let declared: Vec<CType> = match prototype {
        Some(p) if p.ty.params.len() == f.params.len() => p.ty.params.iter().map(|p| p.ty.clone()).collect(),
        _ => Vec::new(),
    };

    let names: Vec<String> = (0..f.params.len())
        .map(|i| prototype.and_then(|p| p.ty.params.get(i)).and_then(|p| p.name.clone()).unwrap_or_default())
        .collect();

    let mut types = typing::infer(&f, ctx, &declared);
    structs::recover(&f, ctx, &mut types, &declared, addr);

    let ret = return_type(&f, &types, prototype);
    let mut built = build::build(&f, ctx, types, &names);
    let body = structure::structure(built.blocks, &mut built.vars);

    let storage = crate::storage::Storage { notes: built.notes, frame_vars: built.frame_vars, ..Default::default() };
    let mut structs: Vec<(String, Aggregate)> = ctx.structs.borrow().iter().map(|(name, aggregate)| (name.clone(), aggregate.clone())).collect();
    structs.sort_by(|(a, _), (b, _)| (a.len(), a).cmp(&(b.len(), b)));
    let mut function = CFunction { name: f.name.clone(), ret, params: built.params, variadic: f.variadic, vars: built.vars, body, addr, globals: built.globals, inlined: false, storage, structs };

    if ctx.program.language == execdump_core::program::Language::Go {
        golang::write_barriers(&mut function);
    }

    simplify::simplify(&mut function);
    structure::loops_and_exits(&mut function.body);

    if conditions::simplify(&mut function) {
        simplify::simplify(&mut function);
        structure::loops_and_exits(&mut function.body);
    }

    simplify::null_returns(&mut function);
    simplify::void_returns(&mut function);
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

    // Only 0, 1 and conditions returned, both values: a boolean
    let values: Vec<ir::ValueId> = f.blocks.iter().filter_map(|b| b.insts.last()).filter_map(|&i| match f.inst(i) {
        Some((ir::Op::Ret, [value])) => Some(*value),
        _ => None,
    }).collect();

    let mut seen = (false, false, false);

    if f.name != "main" && declared.as_ref().is_none_or(|d| matches!(d, CType::Int { .. })) && !values.is_empty() && values.iter().all(|&v| boolean(f, v, &mut seen, MAX_BOOLEAN_DEPTH)) && (seen.2 || seen.0 && seen.1) {
        return CType::Bool;
    }

    return declared.or(returned.first().map(|t| (*t).clone())).unwrap_or(CType::Void);
}

/// Phis followed to know whether a returned value is a boolean
const MAX_BOOLEAN_DEPTH: usize = 4;

/// A value that is 0 or 1: the constants (seen: a 0, a 1, a condition), a condition extended, the phis of them
fn boolean(f: &ir::Func, v: ir::ValueId, seen: &mut (bool, bool, bool), depth: usize) -> bool {
    match f.int(v) {
        Some(0) => {
            seen.0 = true;
            return true;
        }
        Some(1) => {
            seen.1 = true;
            return true;
        }
        Some(_) => return false,
        None => {}
    }

    return match f.inst(v) {
        _ if f.values[v].ty == ir::Ty::Int(1) => {
            seen.2 = true;
            true
        }
        Some((ir::Op::ZExt, [x])) if f.values[*x].ty == ir::Ty::Int(1) => {
            seen.2 = true;
            true
        }
        Some((ir::Op::Phi, incoming)) if depth > 0 => incoming.iter().all(|&x| boolean(f, x, seen, depth - 1)),
        // A bit of a value: (flags >> 2) & 1
        Some((ir::Op::And, [_, one])) if f.int(*one) == Some(1) => {
            seen.2 = true;
            true
        }
        _ => false,
    };
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
        let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None), structs: Default::default(), callees: Default::default(), imported: Default::default(), sized: Default::default() };

        assert_eq!(ctx.string_at(0x2000, false).as_deref(), Some("xx"));
        assert_eq!(ctx.string_at(0x2003, false).as_deref(), Some("pi"));
        // The end of another string is one only for pointers
        assert_eq!(ctx.string_at(0x2001, false), None);
        assert_eq!(ctx.string_at(0x2001, true).as_deref(), Some("x"));
        assert_eq!(ctx.string_at(0x2006, true), None);
        assert_eq!(ctx.string_at(0x3000, true), None);
    }

    /// C of the first function given as LLVM IR text, the functions it declares have the prototypes of the
    /// headers
    fn c_of_ir(ir: &str) -> String {
        let mut program = Program::default();
        program.arch = Some(Architecture::X86_64);
        program.pointer_size = 8;

        let llvm = inkwell::context::Context::create();
        let buffer = inkwell::memory_buffer::MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "test");
        let module = llvm.create_module_from_ir(buffer).unwrap();
        let function = module.get_first_function().unwrap();

        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
        let prototypes: HashMap<String, Prototype> =
            module.get_functions().filter_map(|f| f.get_name().to_str().ok().and_then(|name| Some((name.to_string(), typedb.function(name)?)))).collect();
        let (globals, noreturn) = (HashMap::new(), HashSet::new());
        let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None), structs: Default::default(), callees: Default::default(), imported: Default::default(), sized: Default::default() };

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

    #[test]
    fn pointers_to_pointers_are_not_structs() {
        // argv: its elements are strings, the first one only passed to printf (a variadic argument, a number in the
        // IR) for a %s. A pointer to pointers stays one, not a struct of a number and a pointer.
        let code = c_of_ir(
            "define i32 @usage(ptr %0) {
            entry:
              %first = load i64, ptr %0
              %sp = getelementptr i8, ptr %0, i64 8
              %second = load ptr, ptr %sp
              %r = call i32 (ptr, ...) @printf(ptr @fmt, i64 %first)
              %s = call i32 @puts(ptr %second)
              ret i32 %s
            }
            @fmt = private constant [11 x i8] c\"usage: %s\\0A\\00\"
            declare i32 @printf(ptr, ...)
            declare i32 @puts(ptr)",
        );

        assert!(!code.contains("struct") && !code.contains(" *)"), "{}", code);
        assert!(code.starts_with("int usage(const char **a1)") && code.contains("printf(\"usage: %s\\n\", *a1);") && code.contains("= a1[1];"), "{}", code);
    }

    #[test]
    fn pointers_of_several_types_are_an_array() {
        // A string read as const char *, another one freed (void *): still the elements of one array
        let code = c_of_ir(
            "define i64 @lengths(ptr %0) {
            entry:
              %first = load ptr, ptr %0
              %sp = getelementptr i8, ptr %0, i64 8
              %second = load ptr, ptr %sp
              %n = call i64 @strlen(ptr %first)
              call void @free(ptr %second)
              ret i64 %n
            }
            declare i64 @strlen(ptr)
            declare void @free(ptr)",
        );

        assert!(!code.contains("struct") && !code.contains(" *)") && code.contains("a1[1]"), "{}", code);
    }

    #[test]
    fn structs_of_the_accesses() {
        // A pointer accessed at several offsets and a buffer of the frame accessed with several types are
        // structs, the address of a field is passed on
        let code = c_of_ir(
            "define i64 @walk(ptr %0) {
            entry:
              %buf = alloca [16 x i8]
              %len = load i64, ptr %0
              %fp = getelementptr i8, ptr %0, i64 8
              %next = load ptr, ptr %fp
              %cp = getelementptr i8, ptr %0, i64 16
              %c = load i32, ptr %cp
              store i64 %len, ptr %buf
              %b8 = getelementptr i8, ptr %buf, i64 8
              store i32 %c, ptr %b8
              %r = call i32 @use(ptr %buf)
              %sp = getelementptr i8, ptr %0, i64 24
              %s = call i32 @fstat(i32 0, ptr %sp)
              %zp = getelementptr i8, ptr %0, i64 72
              %size = load i64, ptr %zp
              %nx = ptrtoint ptr %next to i64
              %sum = add i64 %size, %nx
              ret i64 %sum
            }
            declare i32 @use(ptr)
            declare i32 @fstat(i32, ptr)",
        );

        assert!(code.contains("struct st_0_0 {") && code.contains("struct st_0_1 {") && code.contains("struct stat f18;"), "{}", code);
        assert!(code.contains("a1->f0") && code.contains("a1->f8") && code.contains("a1->f10"), "{}", code);
        assert!(code.contains("fstat(0, &a1->f18)") && code.contains("a1->f18.st_size"), "{}", code);
        assert!(code.contains(".f0 = ") && code.contains(".f8 = ") && code.contains("use(&v"), "{}", code);
        assert!(!code.contains(" *)"), "{}", code);
    }
}
