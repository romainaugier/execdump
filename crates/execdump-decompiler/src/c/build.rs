/*
 * Out of SSA: IR values become C expressions and statements, block by block
 *
 * A value is inlined into its single use when it is safe: pure values anywhere their operands
 * are still valid, loads and calls only into a use in the same block with no side effect in
 * between. Phis are variables assigned on the edges that lead to them, and the blocks that only
 * return a phi are folded into their predecessors (return x instead of v = x; goto ret).
 */

use super::ast::{BinaryOp, Expr, Stmt, StmtKind, UnaryOp, Var, VarId};
use super::ir::{Allocated, FloatCmp, Func, Op, Pred, Ty, ValueId, ValueKind};
use super::typing::{base_type, is_pointer, pointee};
use crate::storage::{Loc, Place, VarNote};
use super::Context;

use crate::types::CType;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Clone, Debug, PartialEq)]
pub enum Term {
    Return(Option<Expr>),
    Jump(usize),
    Branch(Expr, usize, usize),
    Switch(Expr, Vec<(Vec<i128>, usize)>, usize),
    Unreachable,
}

#[derive(Clone, Debug)]
pub struct SBlock {
    pub stmts: Vec<Stmt>,
    pub term: Term,
    pub addr: Option<u64>,
}

/// The tests of one value that lead from a block to the blocks after them, as one switch: an edge
/// (from the last test to a block after them) for each value and the edge of the others
struct Decision {
    value: ValueId,
    cases: Vec<(i128, (usize, usize))>,
    default: (usize, usize),
    blocks: Vec<usize>,
}

/// Blocks of a decision, values of a switch
const MAX_DECISION_BLOCKS: usize = 64;
const MAX_CASES: usize = 4096;

/// Type of a value of a smaller type in an operation of C: an int
fn promoted(ty: CType) -> CType {
    return match ty.unqualified() {
        CType::Int { bits, .. } if *bits < 32 => CType::int(32),
        CType::Bool | CType::Char => CType::int(32),
        _ => ty,
    };
}

pub struct Built {
    pub blocks: Vec<SBlock>,
    pub vars: Vec<Var>,
    pub params: Vec<VarId>,
    pub globals: Vec<(String, Option<CType>)>,
    pub notes: Vec<VarNote>,
    pub frame_vars: Vec<(VarId, Loc)>,
}

struct Builder<'a> {
    f: &'a Func,
    ctx: &'a Context<'a>,
    types: Vec<CType>,
    var_of: Vec<Option<VarId>>,
    /// Variables of the stack frame (allocas): the alloca is their address
    storage: Vec<Option<VarId>>,
    vars: Vec<Var>,
    /// Inlined expressions that read memory (loads and calls, directly or through their operands)
    reads_memory: Vec<bool>,
    /// Constant expressions computed once at the start of the function, operands first
    constants: Vec<ValueId>,
    /// Type each global is accessed with, None when the accesses disagree
    globals: RefCell<BTreeMap<String, Option<CType>>>,
}

/// Size of an inlined constant expression above which it gets a variable when it is used more than once
const SHARED_CONSTANT_SIZE: usize = 24;

fn has_side_effects(f: &Func, id: ValueId) -> bool {
    return matches!(f.op(id), Some(Op::Store | Op::Call));
}

/// Calls to these helpers have no effect on the C code
fn is_ignored_call(name: &str) -> bool {
    return name.starts_with("llvm.lifetime") || name.starts_with("llvm.assume") || name.starts_with("llvm.dbg") || name.starts_with("llvm.experimental.noalias");
}

impl<'a> Builder<'a> {
    fn new_var(&mut self, name: String, ty: CType) -> VarId {
        self.vars.push(Var { name, ty });
        return self.vars.len() - 1;
    }

    /// Position of an instruction in its block
    fn position(&self, id: ValueId) -> Option<(usize, usize)> {
        let block = self.f.block_of(id)?;
        let index = self.f.blocks[block].insts.iter().position(|&i| i == id)?;
        return Some((block, index));
    }

    /// No store or call between two instructions of the same block (exclusive)
    fn nothing_between(&self, from: ValueId, to: ValueId) -> bool {
        let (Some((block, start)), Some((other, end))) = (self.position(from), self.position(to)) else {
            return false;
        };

        if block != other || end < start {
            return false;
        }

        return self.f.blocks[block].insts[start + 1..end].iter().all(|&i| !has_side_effects(self.f, i));
    }

    /// Which values become variables, the others are inlined in their use
    fn decide(&mut self) {
        let f = self.f;
        let mut order: Vec<ValueId> = f.blocks.iter().flat_map(|b| b.insts.iter().copied()).collect();

        // Loads and calls first, the pure values look at what their operands read
        order.sort_by_key(|&id| !matches!(f.op(id), Some(Op::Load | Op::Call | Op::Phi)));

        for id in order {
            let value = &f.values[id];
            let Some((op, operands)) = f.inst(id) else {
                continue;
            };

            if value.ty == Ty::Void || value.uses.is_empty() {
                continue;
            }

            if op == Op::Alloca {
                let ty = self.storage_type(id);
                self.storage[id] = Some(self.new_var(String::new(), ty));
                continue;
            }

            let memory = matches!(op, Op::Load | Op::Call) || operands.iter().any(|&o| self.var_of[o].is_none() && self.reads_memory[o]);
            self.reads_memory[id] = memory;

            let single = value.uses.len() == 1;
            let user = value.uses[0];
            let user_is_phi = f.op(user) == Some(Op::Phi);

            let inline = match op {
                Op::Phi => false,
                _ if single && user_is_phi => !memory,
                _ if single && memory => self.nothing_between(id, user),
                _ if single => true,
                // Casts can be repeated in every use
                Op::ZExt | Op::SExt | Op::Trunc | Op::IntToPtr | Op::PtrToInt | Op::BitCast | Op::Freeze => !memory,
                _ => false,
            };

            if !inline {
                let ty = self.types[id].clone();
                let var = self.new_var(String::new(), ty);
                self.var_of[id] = Some(var);
            }
        }
    }

    /// Constant expressions are DAGs that LLVM folds from straight code (x = x + x...): inlined
    /// everywhere they are used, their text would grow exponentially
    fn share_constants(&mut self) {
        let f = self.f;
        let mut parents = vec![0usize; f.values.len()];

        for value in f.values.iter() {
            if let ValueKind::Inst { operands, .. } = &value.kind {
                for &operand in operands.iter() {
                    parents[operand] += 1;
                }
            }
        }

        let mut sizes: Vec<Option<usize>> = vec![None; f.values.len()];

        for id in 0..f.values.len() {
            self.constant_size(id, &parents, &mut sizes);
        }
    }

    /// Expanded size of a constant expression, the shared big ones become variables (operands first)
    fn constant_size(&mut self, id: ValueId, parents: &[usize], sizes: &mut Vec<Option<usize>>) -> usize {
        if let Some(size) = sizes[id] {
            return size;
        }

        let f = self.f;
        let ValueKind::Inst { block: None, operands, .. } = &f.values[id].kind else {
            sizes[id] = Some(1);
            return 1;
        };

        // A placeholder against cycles (there are none in constants)
        sizes[id] = Some(1);
        let mut size = 1usize;

        for &operand in operands.iter() {
            size = size.saturating_add(self.constant_size(operand, parents, sizes));
        }

        if size > SHARED_CONSTANT_SIZE && parents[id] > 1 && self.var_of[id].is_none() {
            let var = self.new_var(String::new(), self.types[id].clone());
            self.var_of[id] = Some(var);
            self.constants.push(id);
            size = 1;
        }

        sizes[id] = Some(size);
        return size;
    }

    /*
     * Expressions
     */

    fn ty(&self, id: ValueId) -> &CType {
        return &self.types[id];
    }

    fn pointee_size(&self, id: ValueId) -> i64 {
        return pointee(self.ty(id)).and_then(|t| self.ctx.size_of(t)).filter(|&s| s > 0).unwrap_or(1) as i64;
    }

    pub fn expr(&self, id: ValueId) -> Expr {
        if let Some(var) = self.var_of[id] {
            return Expr::Var(var);
        }

        // Arrays are their address
        if let Some(var) = self.storage[id] {
            return if self.is_array(var) { Expr::Var(var) } else { Expr::unary(UnaryOp::AddrOf, Expr::Var(var)) };
        }

        let f = self.f;

        return match &f.values[id].kind {
            ValueKind::Param(index) => Expr::Var(*index),
            ValueKind::Int(0) if is_pointer(self.ty(id)) => Expr::Name("NULL".to_string()),
            // Addresses of strings and functions in constants (non position independent code)
            ValueKind::Int(value) => {
                let addr = u64::try_from(*value).ok().filter(|&a| a >= 0x1000);
                let pointer_sized = f.values[id].ty.bits() == self.ctx.program.pointer_size.max(4) as u32 * 8 || is_pointer(self.ty(id));

                if let Some(text) = addr.and_then(|a| self.ctx.string_at(a, is_pointer(self.ty(id)))) {
                    Expr::Str(text)
                } else if let Some(name) = addr.filter(|_| pointer_sized).and_then(|a| (self.ctx.function)(a)) {
                    Expr::Name(name)
                } else {
                    Expr::Int(*value)
                }
            }
            ValueKind::Float(value) => Expr::Float(*value),
            ValueKind::Undef => Expr::Int(0),
            ValueKind::Function(name) => Expr::Name(name.clone()),
            ValueKind::Global(name) => self.global(name),
            ValueKind::Inst { .. } => self.inst(id),
        };
    }

    /// Type of a variable of the stack frame: an array of chars, or its scalar type from its accesses
    fn storage_type(&self, id: ValueId) -> CType {
        return match self.f.allocated.get(&id) {
            Some(Allocated::Scalar(ty)) => {
                let bits = if *ty == Ty::Ptr { self.ctx.program.pointer_size.max(4) as u32 * 8 } else { ty.bits() };

                match pointee(&self.types[id]) {
                    Some(known) if !known.is_unknown() && self.ctx.size_bits(known) == bits => known.clone(),
                    _ => base_type(*ty),
                }
            }
            // A struct of the buffer's size (recovered from its accesses, or one of the headers) or the type of
            // the whole buffer
            Some(Allocated::Bytes(size)) => match pointee(&self.types[id]) {
                Some(ty) if !matches!(ty, CType::Char) && !ty.is_unknown() && self.ctx.size_of(ty) == Some(*size) => ty.clone(),
                _ => CType::Array(Box::new(CType::Char), Some(*size)),
            },
            None => CType::Unknown(0),
        };
    }

    /// A global accessed with a type (unknown: only its address is used). Accessed as a pointer and as
    /// an integer of its size, it is a pointer.
    fn accessed(&self, name: &str, ty: CType) {
        let mut globals = self.globals.borrow_mut();
        let known = globals.entry(name.to_string()).or_insert_with(|| Some(ty.clone()));
        let pointer_sized = |t: &CType| is_pointer(t) || matches!(t, CType::Int { .. }) && self.ctx.size_of(t) == self.ctx.size_of(&CType::ptr(CType::Void));

        *known = match known.take() {
            _ if ty.is_unknown() => None,
            Some(k) if k == ty => Some(k),
            Some(k) if pointer_sized(&k) && pointer_sized(&ty) && (is_pointer(&k) || is_pointer(&ty)) => match (is_pointer(&k), is_pointer(&ty)) {
                (true, true) if pointee(&k) == Some(&CType::Void) => Some(ty),
                (true, _) => Some(k),
                _ => Some(ty),
            },
            _ => None,
        };
    }

    fn is_array(&self, var: VarId) -> bool {
        return matches!(self.vars[var].ty, CType::Array(..));
    }

    /// Access to a variable of the stack frame: the variable, an element, or bytes of it
    fn storage_access(&self, var: VarId, offset: i128, terms: &[(ValueId, i128)], ty: &CType, size: i128) -> Option<Expr> {
        let var_size = self.ctx.size_of(&self.vars[var].ty).unwrap_or(0) as i128;

        if !self.is_array(var) {
            let whole = !matches!(self.ctx.resolve(&self.vars[var].ty).unqualified(), CType::Struct(_)) || self.ctx.resolve(ty).unqualified() == self.ctx.resolve(&self.vars[var].ty).unqualified();

            return match (offset, terms.is_empty()) {
                (0, true) if size == var_size && whole => Some(self.reinterpreted(Expr::Var(var), ty)),
                (_, true) => match self.member(Expr::Var(var), &self.vars[var].ty, offset, size, false) {
                    Some(member) => Some(self.reinterpreted(member, ty)),
                    None if offset == 0 && size == var_size => Some(Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), Expr::unary(UnaryOp::AddrOf, Expr::Var(var))))),
                    None => self.from_field(Expr::Var(var), &self.vars[var].ty, offset, ty, false),
                },
                _ => None,
            };
        }

        let index = match terms {
            [] => Expr::Int(offset),
            [(term, 1)] => self.index_expr(*term, offset),
            _ => return None,
        };

        let element = Expr::Index(Box::new(Expr::Var(var)), Box::new(index));

        if size == 1 && matches!(ty.unqualified(), CType::Char | CType::Int { bits: 8, .. }) {
            return Some(element);
        }

        // Bytes of the buffer read as a wider value: *(int *)&buf[4]
        return Some(Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), Expr::unary(UnaryOp::AddrOf, element))));
    }

    /// Value of a load from a constant address in read-only memory: a number, a string or a function
    fn constant_load(&self, address: ValueId, id: ValueId) -> Option<Expr> {
        let f = self.f;
        let (base, offset, terms) = self.decompose(address);

        if !terms.is_empty() {
            return None;
        }

        let start = match &f.values[base].kind {
            ValueKind::Global(name) => *self.ctx.globals.get(name)?,
            ValueKind::Int(value) => u64::try_from(*value).ok()?,
            _ => return None,
        };

        let addr = start.checked_add_signed(i64::try_from(offset).ok()?)?;
        let region = self.ctx.program.region_at(addr)?;

        if region.perms.write || region.perms.exec || region.data.is_empty() {
            return None;
        }

        let ty = self.types[id].clone();
        let size = self.ctx.size_of(&ty).filter(|s| matches!(s, 1 | 2 | 4 | 8))? as usize;
        let bytes = self.ctx.program.read(addr, size)?;
        let mut raw = [0u8; 8];
        raw[..size].copy_from_slice(bytes);
        let value = u64::from_le_bytes(raw);
        let pointer_size = self.ctx.program.pointer_size.max(4) as usize;

        return Some(match ty.unqualified() {
            CType::Float { bits: 32 } => Expr::Float(f32::from_bits(value as u32) as f64),
            CType::Float { bits: 64 } => Expr::Float(f64::from_bits(value)),
            CType::Pointer(_) if value == 0 => Expr::Name("NULL".to_string()),
            _ if size == pointer_size && value != 0 => {
                if let Some(text) = self.ctx.string_at(value, is_pointer(&ty)) {
                    Expr::Str(text)
                } else if let Some(name) = (self.ctx.function)(value) {
                    Expr::Name(name)
                } else {
                    Expr::Int(value as i128)
                }
            }
            CType::Int { signed: true, .. } => Expr::Int(((value << (64 - 8 * size)) as i64 >> (64 - 8 * size)) as i128),
            _ => Expr::Int(value as i128),
        });
    }

    /// Text of a global string: from the binary, or made by the optimizations
    fn string_global(&self, name: &str) -> Option<String> {
        return self.ctx.string(name).or_else(|| self.f.data.get(name).map(|bytes| crate::lift::literal(bytes.strip_suffix(&[0]).unwrap_or(bytes))));
    }

    /// Strings are literals, other globals are addressed
    fn global(&self, name: &str) -> Expr {
        if let Some(text) = self.string_global(name) {
            return Expr::Str(text);
        }

        return Expr::unary(UnaryOp::AddrOf, Expr::Name(name.to_string()));
    }

    /// Operand of an unsigned or signed operation, cast when its type has the other signedness
    /// The operand is cast when the expression written for it has the other signedness in C (an inlined
    /// expression has the type C gives it from its variables, not always the one inferred for the value)
    fn signed_operand(&self, id: ValueId, signed: bool) -> Expr {
        let expr = self.expr(id);
        let written = self.written_type(&expr).map(promoted).unwrap_or_else(|| self.ty(id).clone());

        let bits = match self.ty(id) {
            CType::Int { bits, .. } => *bits,
            _ => self.f.values[id].ty.bits() as u16,
        };

        return match written {
            CType::Int { signed: s, .. } if s != signed && !matches!(expr, Expr::Int(_)) && bits > 0 => Expr::cast(CType::Int { bits, signed }, expr),
            ty if is_pointer(&ty) && bits > 0 => Expr::cast(CType::Int { bits, signed }, expr),
            _ => expr,
        };
    }

    /// Operand of an integer operation: a value typed as a pointer is cast to the integer it is
    fn integer(&self, id: ValueId) -> Expr {
        let expr = self.expr(id);

        return match self.f.values[id].ty {
            Ty::Int(bits) if is_pointer(self.ty(id)) || self.written_type(&expr).is_some_and(|ty| is_pointer(&ty)) => Expr::cast(CType::int(bits as u16), expr),
            _ => expr,
        };
    }

    /// C type of an expression as written: from its variables and casts, with the conversions of C (None
    /// for literals and what is not known)
    fn written_type(&self, e: &Expr) -> Option<CType> {
        return match e {
            Expr::Var(v) => Some(self.vars[*v].ty.clone()),
            Expr::Cast(ty, _) => Some(ty.clone()),
            Expr::Index(base, _) | Expr::Unary(UnaryOp::Deref, base) => self.written_type(base).and_then(|ty| pointee(&ty).cloned()),
            Expr::Name(name) => self.globals.borrow().get(name).cloned().flatten(),
            Expr::Member(base, field, arrow) => {
                let base = self.written_type(base)?;
                let aggregate = if *arrow { pointee(&base)?.clone() } else { base };

                let (CType::Struct(name) | CType::Union(name)) = self.ctx.resolve(&aggregate).unqualified().clone() else {
                    return None;
                };

                self.ctx.aggregate(&name)?.fields.into_iter().find(|f| f.name == *field).map(|f| f.ty)
            }
            Expr::Unary(UnaryOp::Neg | UnaryOp::Not, inner) => self.written_type(inner).map(promoted),
            Expr::Unary(UnaryOp::LogicalNot, _) => Some(CType::int(32)),
            Expr::Binary(op, ..) if op.is_comparison() || matches!(op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr) => Some(CType::int(32)),
            Expr::Binary(BinaryOp::Shl | BinaryOp::Shr, a, _) => self.written_type(a).map(promoted),
            Expr::Binary(_, a, b) | Expr::Ternary(_, a, b) => match (self.written_type(a).map(promoted), self.written_type(b).map(promoted)) {
                (Some(CType::Int { bits: x, signed: s }), Some(CType::Int { bits: y, signed: t })) => {
                    let signed = if x == y { s && t } else if x > y { s } else { t };
                    Some(CType::Int { bits: x.max(y), signed })
                }
                (Some(ty), None) | (None, Some(ty)) => Some(ty),
                _ => None,
            },
            _ => None,
        };
    }

    fn inst(&self, id: ValueId) -> Expr {
        if let Some(idiom) = self.division_idiom(id) {
            return idiom;
        }

        let f = self.f;
        let ValueKind::Inst { op, operands, pred, callee, scales, .. } = &f.values[id].kind else {
            return Expr::Int(0);
        };

        let o = operands.as_slice();
        let boolean = f.values[id].ty == Ty::Int(1);

        let binary = |op: BinaryOp| Expr::binary(op, self.integer(o[0]), self.integer(o[1]));

        return match (op, o) {
            (Op::Add | Op::Sub, [x, y]) if is_pointer(self.ty(id)) && (is_pointer(self.ty(*x)) || is_pointer(self.ty(*y))) => {
                let (base, offset) = if is_pointer(self.ty(*x)) { (*x, *y) } else { (*y, *x) };
                let offset = if *op == Op::Sub { Expr::unary(UnaryOp::Neg, self.integer(offset)) } else { self.integer(offset) };
                self.pointer_add(base, offset)
            }
            (Op::Add, [x, y]) => match f.int(*y) {
                Some(c) if c < 0 => Expr::binary(BinaryOp::Sub, self.integer(*x), Expr::Int(-c)),
                _ => binary(BinaryOp::Add),
            },
            (Op::Sub, [x, y]) if f.int(*x) == Some(0) => Expr::unary(UnaryOp::Neg, self.integer(*y)),
            // The difference of two pointers to bytes is in bytes, other pointers are subtracted as integers
            (Op::Sub, [x, y]) if self.pointee_size(*x) == 1 && is_pointer(self.ty(*x)) && self.ty(*x) == self.ty(*y) => Expr::binary(BinaryOp::Sub, self.expr(*x), self.expr(*y)),
            (Op::Sub, _) => binary(BinaryOp::Sub),
            (Op::Mul, _) => binary(BinaryOp::Mul),
            (Op::Shl, _) => binary(BinaryOp::Shl),
            (Op::And, _) if boolean => binary(BinaryOp::LogicalAnd),
            (Op::Or, _) if boolean => binary(BinaryOp::LogicalOr),
            (Op::Xor, [x, y]) if boolean && f.int(*y) == Some(-1) => self.expr(*x).not(),
            (Op::Xor, _) if boolean => binary(BinaryOp::Ne),
            (Op::Xor, [x, y]) if f.int(*y) == Some(-1) => Expr::unary(UnaryOp::Not, self.integer(*x)),
            (Op::And, _) => binary(BinaryOp::And),
            (Op::Or, _) => binary(BinaryOp::Or),
            (Op::Xor, _) => binary(BinaryOp::Xor),
            (Op::UDiv | Op::URem | Op::LShr, [x, y]) => {
                let op = match op {
                    Op::UDiv => BinaryOp::Div,
                    Op::URem => BinaryOp::Rem,
                    _ => BinaryOp::Shr,
                };
                Expr::binary(op, self.signed_operand(*x, false), self.signed_operand(*y, false))
            }
            (Op::SDiv | Op::SRem | Op::AShr, [x, y]) => {
                let op = match op {
                    Op::SDiv => BinaryOp::Div,
                    Op::SRem => BinaryOp::Rem,
                    _ => BinaryOp::Shr,
                };
                Expr::binary(op, self.signed_operand(*x, true), self.integer(*y))
            }
            (Op::FAdd, _) => binary(BinaryOp::Add),
            (Op::FSub, _) => binary(BinaryOp::Sub),
            (Op::FMul, _) => binary(BinaryOp::Mul),
            (Op::FDiv, _) => binary(BinaryOp::Div),
            (Op::FRem, [x, y]) => Expr::Call(Box::new(Expr::Name("fmod".to_string())), vec![self.expr(*x), self.expr(*y)]),
            (Op::FNeg, [x]) => Expr::unary(UnaryOp::Neg, self.expr(*x)),

            // Integer conversions are implicit in C, except the narrowing ones and the sign changes
            (Op::Trunc, [x]) => Expr::cast(self.ty(id).clone(), self.expr(*x)),
            (Op::ZExt, [x]) => match self.ty(*x) {
                CType::Int { bits, signed: true } => Expr::cast(CType::uint(*bits), self.expr(*x)),
                CType::Char => Expr::cast(CType::uint(8), self.expr(*x)),
                _ => self.expr(*x),
            },
            (Op::SExt, [x]) => match self.ty(*x) {
                CType::Int { bits, signed: false } => Expr::cast(CType::int(*bits), self.expr(*x)),
                CType::Bool => Expr::unary(UnaryOp::Neg, self.expr(*x)),
                _ => self.expr(*x),
            },
            (Op::FPTrunc | Op::FPExt | Op::SIToFP | Op::UIToFP | Op::FPToSI | Op::FPToUI, [x]) => Expr::cast(self.ty(id).clone(), self.expr(*x)),
            (Op::PtrToInt | Op::IntToPtr | Op::BitCast | Op::Freeze, [x]) => self.expr(*x),

            (Op::ICmp, [x, y]) => self.compare(pred.unwrap_or(Pred::Eq), *x, *y),
            (Op::FCmp, [x, y]) => match pred {
                Some(Pred::True) => Expr::Int(1),
                Some(Pred::False) => Expr::Int(0),
                Some(Pred::Float { op: FloatCmp::Uno, .. }) => Expr::Call(Box::new(Expr::Name("isnan".to_string())), vec![self.expr(*x)]),
                Some(Pred::Float { op: FloatCmp::Ord, .. }) => Expr::Call(Box::new(Expr::Name("isnan".to_string())), vec![self.expr(*x)]).not(),
                Some(Pred::Float { op, .. }) => {
                    let op = match op {
                        FloatCmp::Eq => BinaryOp::Eq,
                        FloatCmp::Ne => BinaryOp::Ne,
                        FloatCmp::Gt => BinaryOp::Gt,
                        FloatCmp::Ge => BinaryOp::Ge,
                        FloatCmp::Lt => BinaryOp::Lt,
                        _ => BinaryOp::Le,
                    };
                    Expr::binary(op, self.expr(*x), self.expr(*y))
                }
                _ => Expr::Int(0),
            },
            (Op::Select, [c, a, b]) if boolean && f.int(*a) == Some(-1) => Expr::binary(BinaryOp::LogicalOr, self.expr(*c), self.expr(*b)),
            (Op::Select, [c, a, b]) if boolean && f.int(*b) == Some(0) => Expr::binary(BinaryOp::LogicalAnd, self.expr(*c), self.expr(*a)),
            (Op::Select, [c, a, b]) => Expr::Ternary(Box::new(self.expr(*c)), Box::new(self.expr(*a)), Box::new(self.expr(*b))),
            // A pointer loaded from memory typed otherwise and used in the expressions of its users is
            // converted to its own type (the one they use it with)
            (Op::Load, [address]) => {
                let loaded = self.constant_load(*address, id).unwrap_or_else(|| self.deref(*address, &self.types[id].clone()));
                let ty = self.ty(id);
                let converted = |written: &CType| !pointee(ty).is_some_and(|p| matches!(p.unqualified(), CType::Void)) && written.unqualified() != ty.unqualified();

                let address = f.values[id].uses.iter().any(|&u| matches!(f.op(u), Some(Op::IntToPtr | Op::Gep | Op::Load | Op::Store | Op::Add | Op::Sub)));

                match self.written_type(&loaded) {
                    Some(written) if self.var_of[id].is_none() && is_pointer(ty) && (is_pointer(&written) || address) && converted(&written) => Expr::cast(ty.clone(), loaded),
                    _ => loaded,
                }
            }
            (Op::Gep, [base, indices @ ..]) => {
                let mut offset: Option<Expr> = None;

                for (index, scale) in indices.iter().zip(scales.iter()) {
                    let term = match (f.int(*index), *scale) {
                        (Some(c), s) => Expr::Int(c * s as i128),
                        (None, 1) => self.expr(*index),
                        (None, s) => Expr::binary(BinaryOp::Mul, self.expr(*index), Expr::Int(s as i128)),
                    };

                    offset = Some(match offset {
                        Some(previous) => Expr::binary(BinaryOp::Add, previous, term),
                        None => term,
                    });
                }

                self.pointer_add(*base, offset.unwrap_or(Expr::Int(0)))
            }
            (Op::Call, args) => self.call(callee.as_deref().unwrap_or(""), args, id),
            (Op::ExtractValue, [aggregate]) => {
                let index = scales.first().copied().unwrap_or(0);
                Expr::Call(Box::new(Expr::Name(format!("__extract{}", index))), vec![self.expr(*aggregate)])
            }
            _ => Expr::Name(format!("/* {:?} */ 0", op)),
        };
    }

    /// Divisions and remainders by constants that compilers turn into multiplications by a magic
    /// number: the expression is evaluated for test inputs and compared with x / d and x % d
    fn division_idiom(&self, id: ValueId) -> Option<Expr> {
        let f = self.f;
        let Ty::Int(bits @ (32 | 64)) = f.values[id].ty else {
            return None;
        };

        if !matches!(f.op(id), Some(Op::Trunc | Op::Add | Op::Sub | Op::AShr | Op::LShr)) {
            return None;
        }

        // A single variable input, through arithmetic with a large multiplier
        let mut leaves = Vec::new();
        let mut magic = false;
        let mut stack = vec![id];

        while let Some(v) = stack.pop() {
            match f.inst(v) {
                Some((op @ (Op::Add | Op::Sub | Op::Mul | Op::Shl | Op::LShr | Op::AShr | Op::And | Op::ZExt | Op::SExt | Op::Trunc), operands)) if f.block_of(v).is_some() => {
                    magic |= op == Op::Mul && operands.iter().any(|&o| f.int(o).is_some_and(|c| c.unsigned_abs() > 0xffff));
                    stack.extend(operands.iter().filter(|&&o| f.int(o).is_none()));
                }
                _ => {
                    if !leaves.contains(&v) {
                        leaves.push(v);
                    }
                }
            }
        }

        let [x] = leaves.as_slice() else {
            return None;
        };

        let input_bits = f.values[*x].ty.bits();

        if !magic || !(input_bits == 32 || input_bits == 64) {
            return None;
        }

        let signed = |v: i128, b: u32| if (v >> (b - 1)) & 1 == 1 { v - (1i128 << b) } else { v };
        let at = |input: i128| self.evaluate(id, *x, input & ((1i128 << input_bits) - 1)).map(|v| signed(v, bits));

        let tests: [i128; 14] = [0, 1, 2, 3, 7, 100, 12345, 1000003, -1, -2, -7, -100, -1000003, (1i128 << (input_bits - 1)) - 1];

        // Division: d from a large input, remainder: the first positive input giving 0
        let large = 1i128 << (input_bits - 2);
        let quotient = at(large)?;
        let mut candidates = Vec::new();

        if quotient > 0 {
            candidates.push(((large / quotient), false));
            candidates.push(((large / quotient) + 1, false));
        }

        if let Some(d) = (2..=4096i128).find(|&d| at(d) == Some(0)) {
            candidates.push((d, true));
        }

        for (d, remainder) in candidates.into_iter().filter(|(d, _)| *d >= 2) {
            for unsigned in [false, true] {
                let expected = |v: i128| -> i128 {
                    let v = if unsigned { v & ((1i128 << input_bits) - 1) } else { v };
                    let r = if remainder { v % d } else { v / d };
                    signed(r & ((1i128 << bits) - 1), bits)
                };

                if tests.iter().all(|&t| at(t) == Some(expected(t))) {
                    let op = if remainder { BinaryOp::Rem } else { BinaryOp::Div };
                    let input = if unsigned { self.signed_operand(*x, false) } else { self.signed_operand(*x, true) };
                    return Some(Expr::binary(op, input, Expr::Int(d)));
                }
            }
        }

        return None;
    }

    fn compare(&self, pred: Pred, x: ValueId, y: ValueId) -> Expr {
        let (op, signed) = match pred {
            Pred::Eq => (BinaryOp::Eq, None),
            Pred::Ne => (BinaryOp::Ne, None),
            Pred::Slt => (BinaryOp::Lt, Some(true)),
            Pred::Sle => (BinaryOp::Le, Some(true)),
            Pred::Sgt => (BinaryOp::Gt, Some(true)),
            Pred::Sge => (BinaryOp::Ge, Some(true)),
            Pred::Ult => (BinaryOp::Lt, Some(false)),
            Pred::Ule => (BinaryOp::Le, Some(false)),
            Pred::Ugt => (BinaryOp::Gt, Some(false)),
            Pred::Uge => (BinaryOp::Ge, Some(false)),
            _ => (BinaryOp::Eq, None),
        };

        let operand = |id: ValueId, other: ValueId| -> Expr {
            // Pointers are compared with NULL
            let pointer = |v: ValueId| is_pointer(self.ty(v)) || self.written_type(&self.expr(v)).is_some_and(|t| is_pointer(&t));

            if self.f.int(id) == Some(0) && !matches!(self.f.values[other].kind, ValueKind::Int(_)) && pointer(other) {
                return Expr::Name("NULL".to_string());
            }

            // Characters compared with printable constants are character literals
            if let (Some(c), CType::Char) = (self.f.int(id), self.ty(other)) {
                if (0x20..0x7f).contains(&c) {
                    return Expr::Char(c as u8);
                }
            }

            match signed {
                Some(signed) if !is_pointer(self.ty(id)) => self.signed_operand(id, signed),
                _ => self.expr(id),
            }
        };

        let (a, b) = (operand(x, y), operand(y, x));

        // Booleans compared with zero or one are the boolean itself
        if self.ty(x) == &CType::Bool && !matches!(a, Expr::Int(_)) {
            match (op, &b) {
                (BinaryOp::Ne, Expr::Int(0)) | (BinaryOp::Eq, Expr::Int(1)) => return a,
                (BinaryOp::Eq, Expr::Int(0)) | (BinaryOp::Ne, Expr::Int(1)) => return a.not(),
                _ => {}
            }
        }

        return Expr::binary(op, a, b);
    }

    /// base + offset bytes, in elements of the pointee when the offset allows it
    fn pointer_add(&self, base: ValueId, offset: Expr) -> Expr {
        let size = self.pointee_size(base);
        let base_expr = self.expr(base);

        // Address in a buffer of the frame: &buf[i], &v.f8
        if let Some(var) = self.storage[base] {
            if self.is_array(var) {
                return Expr::unary(UnaryOp::AddrOf, Expr::Index(Box::new(Expr::Var(var)), Box::new(offset)));
            }

            if let Expr::Int(c @ 1..) = offset {
                if let Some(field) = self.field_at(Expr::Var(var), &self.vars[var].ty, c, false) {
                    return Expr::unary(UnaryOp::AddrOf, field);
                }
            }
        }

        // Address of a field of a struct: &p->f58
        if let (Expr::Int(c @ 1..), Some(pointee)) = (&offset, pointee(self.ty(base))) {
            if let Some(field) = self.field_at(base_expr.clone(), pointee, *c, true) {
                return Expr::unary(UnaryOp::AddrOf, field);
            }
        }

        let elements = match &offset {
            Expr::Int(0) => return base_expr,
            Expr::Int(c) if *c % size as i128 == 0 => Some(Expr::Int(*c / size as i128)),
            Expr::Binary(BinaryOp::Mul, index, scale) if **scale == Expr::Int(size as i128) => Some((**index).clone()),
            _ if size == 1 => Some(offset.clone()),
            _ => None,
        };

        return match elements {
            Some(Expr::Int(c)) if c < 0 => Expr::binary(BinaryOp::Sub, base_expr, Expr::Int(-c)),
            Some(Expr::Unary(UnaryOp::Neg, inner)) => Expr::binary(BinaryOp::Sub, base_expr, *inner),
            Some(elements) => Expr::binary(BinaryOp::Add, base_expr, elements),
            None => Expr::binary(BinaryOp::Add, Expr::cast(CType::ptr(CType::Char), base_expr), offset),
        };
    }

    /// Splits an address into a base value, a constant byte offset and scaled index terms
    fn decompose(&self, mut id: ValueId) -> (ValueId, i128, Vec<(ValueId, i128)>) {
        let f = self.f;
        let mut offset = 0i128;
        let mut terms = Vec::new();

        loop {
            if self.var_of[id].is_some() {
                break;
            }

            match f.inst(id) {
                Some((Op::IntToPtr | Op::PtrToInt | Op::Freeze, [x])) => id = *x,
                Some((Op::Add, [x, y])) => match (f.int(*y), is_pointer(self.ty(*x)), is_pointer(self.ty(*y))) {
                    (Some(c), _, _) => {
                        offset += c;
                        id = *x;
                    }
                    (None, false, true) => {
                        terms.push(self.scaled(*x));
                        id = *y;
                    }
                    _ => {
                        terms.push(self.scaled(*y));
                        id = *x;
                    }
                },
                Some((Op::Sub, [x, y])) if f.int(*y).is_some() => {
                    offset -= f.int(*y).unwrap();
                    id = *x;
                }
                Some((Op::Gep, [base, indices @ ..])) => {
                    let ValueKind::Inst { scales, .. } = &f.values[id].kind else {
                        break;
                    };

                    for (index, scale) in indices.iter().zip(scales.iter()) {
                        match f.int(*index) {
                            Some(c) => offset += c * *scale as i128,
                            None => {
                                let (value, inner) = self.scaled(*index);
                                terms.push((value, inner * *scale as i128));
                            }
                        }
                    }

                    id = *base;
                }
                _ => break,
            }
        }

        return (id, offset, terms);
    }

    /// x << 3 is x * 8, extensions of indices are invisible in C
    fn scaled(&self, id: ValueId) -> (ValueId, i128) {
        if self.var_of[id].is_some() {
            return (id, 1);
        }

        return match self.f.inst(id) {
            Some((Op::Shl, [x, y])) if self.f.int(*y).is_some() => {
                let (inner, scale) = self.scaled(*x);
                (inner, scale << self.f.int(*y).unwrap())
            }
            Some((Op::Mul, [x, y])) if self.f.int(*y).is_some() => {
                let (inner, scale) = self.scaled(*x);
                (inner, scale * self.f.int(*y).unwrap())
            }
            Some((Op::SExt | Op::ZExt, [x])) => self.scaled(*x),
            _ => (id, 1),
        };
    }

    /// Memory access of a type at an address: *p, p[i], or *(T *)((char *)p + offset)
    fn deref(&self, address: ValueId, ty: &CType) -> Expr {
        let size = self.ctx.size_of(ty).unwrap_or(1).max(1) as i128;
        let (base, offset, terms) = self.decompose(address);

        // Globals at a constant address are accessed by name, import slots hold their function
        if let ValueKind::Global(name) = &self.f.values[base].kind {
            if let (Some(import), 0, true) = (name.strip_prefix("__imp_"), offset, terms.is_empty()) {
                let function = self.ctx.prototypes.contains_key(import) || self.ctx.typedb.function(import).is_some();
                let name = Expr::Name(import.to_string());

                if function {
                    return name;
                }

                self.accessed(import, CType::Unknown(0));
                return Expr::unary(UnaryOp::AddrOf, name);
            }

            if offset == 0 && terms.is_empty() && self.string_global(name).is_none() {
                self.accessed(name, ty.clone());
                return Expr::Name(name.clone());
            }

            if terms.is_empty() && offset % size == 0 && self.string_global(name).is_none() {
                self.accessed(name, CType::Array(Box::new(ty.clone()), None));
                return Expr::Index(Box::new(Expr::Name(name.clone())), Box::new(Expr::Int(offset / size)));
            }

            if terms.len() == 1 && terms[0].1 == size && offset % size == 0 {
                self.accessed(name, CType::Array(Box::new(ty.clone()), None));
                let index = self.index_expr(terms[0].0, offset / size);
                return Expr::Index(Box::new(Expr::Name(name.clone())), Box::new(index));
            }
        }

        if let Some(access) = self.storage[base].and_then(|var| self.storage_access(var, offset, &terms, ty, size)) {
            return access;
        }

        let base_pointee = pointee(self.ty(base)).cloned();

        // Fields of known structs: p->field
        if let (Some(pointee), true) = (&base_pointee, terms.is_empty()) {
            if let Some(member) = self.member(self.expr(base), pointee, offset, size, true) {
                return self.reinterpreted(member, ty);
            }

            if let Some(access) = self.from_field(self.expr(base), pointee, offset, ty, true) {
                return access;
            }
        }

        // An access of the size of a struct is not the struct (its fields did not match)
        let aggregate = |p: &CType| matches!(self.ctx.resolve(p).unqualified(), CType::Struct(_) | CType::Union(_)) && !matches!(ty.unqualified(), CType::Struct(_) | CType::Union(_));
        let same_type = base_pointee.as_ref().is_some_and(|p| self.ctx.size_of(p).map(|s| s as i128) == Some(size) && !aggregate(p));
        let base_expr = self.expr(base);

        if same_type && offset % size == 0 && terms.iter().all(|(_, scale)| *scale == size) {
            let index = match terms.as_slice() {
                [] => None,
                [(term, _)] => Some(self.index_expr(*term, offset / size)),
                _ => None,
            };

            match (index, terms.len()) {
                (None, 0) if offset == 0 => return Expr::unary(UnaryOp::Deref, base_expr),
                (None, 0) => return Expr::Index(Box::new(base_expr), Box::new(Expr::Int(offset / size))),
                (Some(index), _) => return Expr::Index(Box::new(base_expr), Box::new(index)),
                _ => {}
            }
        }

        // Byte arithmetic with a cast to the accessed type
        let mut bytes: Option<Expr> = None;

        for (term, scale) in terms.iter() {
            let term = if *scale == 1 { self.expr(*term) } else { Expr::binary(BinaryOp::Mul, self.expr(*term), Expr::Int(*scale)) };
            bytes = Some(match bytes {
                Some(previous) => Expr::binary(BinaryOp::Add, previous, term),
                None => term,
            });
        }

        let bytes_of = |e: Expr| if is_pointer(self.ty(base)) && pointee(self.ty(base)) == Some(&CType::Char) { e } else { Expr::cast(CType::ptr(CType::Char), e) };
        let mut pointer = if bytes.is_none() && offset == 0 && *ty != CType::Char { base_expr } else { bytes_of(base_expr) };

        // A char is an element of the bytes: ((char *)p)[5]
        if *ty == CType::Char {
            let index = match (bytes, offset) {
                (None, offset) => Expr::Int(offset),
                (Some(bytes), 0) => bytes,
                (Some(bytes), offset) if offset < 0 => Expr::binary(BinaryOp::Sub, bytes, Expr::Int(-offset)),
                (Some(bytes), offset) => Expr::binary(BinaryOp::Add, bytes, Expr::Int(offset)),
            };

            return Expr::Index(Box::new(pointer), Box::new(index));
        }

        if let Some(bytes) = bytes {
            pointer = Expr::binary(BinaryOp::Add, pointer, bytes);
        }

        if offset != 0 {
            pointer = if offset < 0 { Expr::binary(BinaryOp::Sub, pointer, Expr::Int(-offset)) } else { Expr::binary(BinaryOp::Add, pointer, Expr::Int(offset)) };
        }

        return Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), pointer));
    }

    /// A field read as a float when it holds an integer or a pointer (or the reverse): *(double *)&p->f8
    fn reinterpreted(&self, member: Expr, ty: &CType) -> Expr {
        let float = |t: &CType| matches!(self.ctx.resolve(t).unqualified(), CType::Float { .. });

        return match self.written_type(&member) {
            Some(field) if float(&field) != float(ty) => Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), Expr::unary(UnaryOp::AddrOf, member))),
            _ => member,
        };
    }

    /// The field of a struct that starts at an offset
    fn field_at(&self, base: Expr, ty: &CType, offset: i128, arrow: bool) -> Option<Expr> {
        let (CType::Struct(name) | CType::Union(name)) = self.ctx.resolve(ty).unqualified().clone() else {
            return None;
        };

        let aggregate = self.ctx.aggregate(&name)?;
        let field = aggregate.fields.into_iter().filter(|f| f.bits.is_none() && !f.name.is_empty()).find(|f| {
            let start = f.offset as i128;
            start == offset || offset > start && offset < start + self.ctx.size_of(&f.ty).unwrap_or(0) as i128
        })?;

        let member = Expr::Member(Box::new(base), field.name, arrow);

        // Inside a nested struct: its field there
        return match field.offset as i128 {
            start if start == offset => Some(member),
            start => self.field_at(member, &field.ty, offset - start, false),
        };
    }

    /// An access over several fields from the first one: *(int128_t *)&p->f8
    fn from_field(&self, base: Expr, aggregate: &CType, offset: i128, ty: &CType, arrow: bool) -> Option<Expr> {
        let field = self.field_at(base, aggregate, offset, arrow)?;
        return Some(Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), Expr::unary(UnaryOp::AddrOf, field))));
    }

    /// Access of a field at an offset of a struct (through nested structs and arrays)
    fn member(&self, base: Expr, ty: &CType, offset: i128, size: i128, arrow: bool) -> Option<Expr> {
        let resolved = self.ctx.resolve(ty);
        let (CType::Struct(name) | CType::Union(name)) = resolved.unqualified() else {
            return None;
        };

        let aggregate = self.ctx.aggregate(name)?;

        for field in aggregate.fields.iter().filter(|f| f.bits.is_none()) {
            let field_size = self.ctx.size_of(&field.ty).unwrap_or(0) as i128;
            let start = field.offset as i128;

            if offset < start || offset >= start + field_size.max(1) {
                continue;
            }

            let access = if field.name.is_empty() { base.clone() } else { Expr::Member(Box::new(base.clone()), field.name.clone(), arrow) };
            let inner = offset - start;

            // An array (the padding too) or a struct is not read or written whole as a number, its elements are
            let whole = !matches!(self.ctx.resolve(&field.ty).unqualified(), CType::Array(..) | CType::Struct(_) | CType::Union(_));

            if inner == 0 && field_size == size && whole {
                return Some(access);
            }

            // Nested struct or array element
            if let CType::Array(element, _) = self.ctx.resolve(&field.ty) {
                let element_size = self.ctx.size_of(&element).unwrap_or(1) as i128;

                if element_size == size && inner % element_size == 0 {
                    return Some(Expr::Index(Box::new(access), Box::new(Expr::Int(inner / element_size))));
                }
            }

            return self.member(access, &field.ty, inner, size, false);
        }

        return None;
    }

    fn index_expr(&self, term: ValueId, add: i128) -> Expr {
        let expr = self.expr(term);

        return match add {
            0 => expr,
            c if c < 0 => Expr::binary(BinaryOp::Sub, expr, Expr::Int(-c)),
            c => Expr::binary(BinaryOp::Add, expr, Expr::Int(c)),
        };
    }

    fn call(&self, callee: &str, args: &[ValueId], id: ValueId) -> Expr {
        let f = self.f;
        let arg = |i: usize| self.expr(args[i]);
        let call = |name: &str, args: Vec<Expr>| Expr::Call(Box::new(Expr::Name(name.to_string())), args);

        // Indirect calls: the target is the last operand
        if callee.is_empty() {
            let (target, rest) = args.split_last().map(|(t, r)| (*t, r)).unwrap_or((id, &[]));
            return Expr::Call(Box::new(self.expr(target)), rest.iter().map(|&a| self.expr(a)).collect());
        }

        if callee == "asm" {
            let text = f.addr(id).map(|a| self.ctx.instruction(a)).unwrap_or_default();
            return call("__asm__", vec![Expr::Str(text)]);
        }

        if let Some(intrinsic) = callee.strip_prefix("llvm.") {
            let family = intrinsic.split('.').next().unwrap_or("");
            let bits = f.values[id].ty.bits();

            return match family {
                "memset" => call("memset", vec![arg(0), arg(1), arg(2)]),
                "memcpy" => call("memcpy", vec![arg(0), arg(1), arg(2)]),
                "memmove" => call("memmove", vec![arg(0), arg(1), arg(2)]),
                // The comparison has the signedness of the intrinsic
                "smax" | "umax" | "smin" | "umin" => {
                    let signed = family.starts_with('s');
                    let op = if family.ends_with("max") { BinaryOp::Gt } else { BinaryOp::Lt };
                    let condition = Expr::binary(op, self.signed_operand(args[0], signed), self.signed_operand(args[1], signed));
                    Expr::Ternary(Box::new(condition), Box::new(arg(0)), Box::new(arg(1)))
                }
                "maxnum" => Expr::Ternary(Box::new(Expr::binary(BinaryOp::Gt, arg(0), arg(1))), Box::new(arg(0)), Box::new(arg(1))),
                "minnum" => Expr::Ternary(Box::new(Expr::binary(BinaryOp::Lt, arg(0), arg(1))), Box::new(arg(0)), Box::new(arg(1))),
                "abs" => call("abs", vec![arg(0)]),
                "fabs" => call(if bits == 32 { "fabsf" } else { "fabs" }, vec![arg(0)]),
                "sqrt" => call(if bits == 32 { "sqrtf" } else { "sqrt" }, vec![arg(0)]),
                "ctpop" => call(if bits == 64 { "__builtin_popcountll" } else { "__builtin_popcount" }, vec![arg(0)]),
                "ctlz" => call(if bits == 64 { "__builtin_clzll" } else { "__builtin_clz" }, vec![arg(0)]),
                "cttz" => call(if bits == 64 { "__builtin_ctzll" } else { "__builtin_ctz" }, vec![arg(0)]),
                "bswap" => call(&format!("__builtin_bswap{}", bits), vec![arg(0)]),
                "fshl" if args[0] == args[1] => call(&format!("__builtin_rotateleft{}", bits), vec![arg(0), arg(2)]),
                "fshr" if args[0] == args[1] => call(&format!("__builtin_rotateright{}", bits), vec![arg(0), arg(2)]),
                "trap" => call("__builtin_trap", Vec::new()),
                _ => call(&format!("__builtin_{}", family.replace('.', "_")), args.iter().map(|&a| self.expr(a)).collect()),
            };
        }

        // System calls: __syscallN(number, args...)
        if callee.starts_with("__syscall") {
            return call("syscall", args.iter().map(|&a| self.expr(a)).collect());
        }

        return call(callee, args.iter().map(|&a| self.argument(a)).collect());
    }

    /// An argument of the size of a pointer that points to a string is one (the strings that end another
    /// one are merged by linkers, a pointer to one does not follow a NUL)
    fn argument(&self, id: ValueId) -> Expr {
        let pointer_bits = self.ctx.program.pointer_size.max(4) as u32 * 8;

        if let (ValueKind::Int(value), None) = (&self.f.values[id].kind, self.var_of[id]) {
            if self.f.values[id].ty.bits() == pointer_bits {
                if let Some(text) = u64::try_from(*value).ok().and_then(|a| self.ctx.string_at(a, true)) {
                    return Expr::Str(text);
                }
            }
        }

        return self.expr(id);
    }

    /*
     * Statements
     */

    fn stmt(&self, kind: StmtKind, id: ValueId) -> Stmt {
        return Stmt::new(kind, self.f.addr(id));
    }

    fn block_stmts(&self, block: usize) -> Vec<Stmt> {
        let f = self.f;
        let mut stmts = Vec::new();

        if block == 0 {
            let addr = f.blocks[0].insts.iter().find_map(|&i| f.addr(i));

            for &id in self.constants.iter() {
                let var = self.var_of[id].expect("shared constants have a variable");
                stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(var), self.inst(id)), addr));
            }
        }

        for &id in f.blocks[block].insts.iter() {
            let Some((op, operands)) = f.inst(id) else {
                continue;
            };

            match op {
                Op::Phi | Op::Br | Op::Switch | Op::Ret | Op::Unreachable => {}
                Op::Store => {
                    let ty = self.types[operands[0]].clone();
                    let ty = if ty == CType::Bool { CType::uint(8) } else { ty };

                    // Printable characters stored in chars are character literals
                    let value = match (f.int(operands[0]), &ty) {
                        (Some(c), CType::Char) if (0x20..0x7f).contains(&c) || matches!(c, 9 | 10 | 13) => Expr::Char(c as u8),
                        _ => self.expr(operands[0]),
                    };

                    stmts.push(self.stmt(StmtKind::Assign(self.deref(operands[1], &ty), value), id));
                }
                _ => match self.var_of[id] {
                    Some(var) => stmts.push(self.stmt(StmtKind::Assign(Expr::Var(var), self.inst(id)), id)),
                    None if op == Op::Call && f.values[id].uses.is_empty() => {
                        let ValueKind::Inst { callee, .. } = &f.values[id].kind else {
                            continue;
                        };

                        let name = callee.as_deref().unwrap_or("");

                        if self.ctx.noreturn.contains(name) {
                            stmts.push(self.stmt(StmtKind::NoReturn(self.inst(id)), id));
                        } else if !is_ignored_call(name) {
                            stmts.push(self.stmt(StmtKind::Expr(self.inst(id)), id));
                        }
                    }
                    None => {}
                },
            }
        }

        return stmts;
    }

    /// Jump table switches are on the target address: the cases come from evaluating the address
    /// for every index the range check before the switch allows
    fn jump_table(&self, block: usize) -> Option<(Expr, Vec<(i128, usize)>, usize)> {
        let f = self.f;
        let switch = *f.blocks[block].insts.last()?;
        let ValueKind::Inst { operands, blocks: targets, .. } = &f.values[switch].kind else {
            return None;
        };

        // Case values are addresses (the lifter switches on jump targets)
        if operands[1..].iter().any(|&c| f.int(c).is_none_or(|v| v < 0x100)) {
            return None;
        }

        let (index, count) = self.range_check(block)?;
        let mut table = Vec::new();

        for i in 0..count.min(4096) {
            let target = self.evaluate(operands[0], index, i)?;
            let case = operands[1..].iter().position(|&c| f.int(c) == Some(target));

            if let Some(case) = case {
                table.push((i, targets[case + 1]));
            }
        }

        // switch (x - 5) with case 0 is switch (x) with case 5
        let (value, bias) = match f.inst(index) {
            Some((Op::Add, [x, c])) if f.int(*c).is_some() && self.var_of[index].is_none() => (*x, -f.int(*c).unwrap()),
            _ => (index, 0),
        };

        let table = table.into_iter().map(|(i, t)| (i + bias, t)).collect();

        return Some((self.expr(value), table, targets[0]));
    }

    /// The value checked against a bound before a block, and the number of values in range
    fn range_check(&self, block: usize) -> Option<(ValueId, i128)> {
        let f = self.f;

        for &pred in f.blocks[block].preds.iter() {
            let branch = *f.blocks[pred].insts.last()?;
            let ValueKind::Inst { op: Op::Br, operands, blocks: targets, .. } = &f.values[branch].kind else {
                continue;
            };

            let Some(&condition) = operands.first() else {
                continue;
            };

            let ValueKind::Inst { op: Op::ICmp, operands: compared, pred: Some(predicate), .. } = &f.values[condition].kind else {
                continue;
            };

            let (Some(bound), index) = (f.int(compared[1]), compared[0]) else {
                continue;
            };

            let in_range_when_true = targets.first() == Some(&block);

            let count = match (predicate, in_range_when_true) {
                (Pred::Ugt, false) | (Pred::Ule, true) => bound + 1,
                (Pred::Uge, false) | (Pred::Ult, true) => bound,
                _ => continue,
            };

            return Some((index, count));
        }

        return None;
    }

    /// Value of an expression when a value is known, reading the constant memory of the program
    fn evaluate(&self, id: ValueId, known: ValueId, value: i128) -> Option<i128> {
        let f = self.f;

        if id == known {
            return Some(value);
        }

        let bits = f.values[id].ty.bits().max(1);
        let mask = |v: i128, b: u32| if b >= 128 { v } else { v & ((1i128 << b) - 1) };

        return match &f.values[id].kind {
            ValueKind::Int(c) => Some(*c),
            ValueKind::Global(name) => self.ctx.globals.get(name).map(|&a| a as i128),
            ValueKind::Inst { op, operands, scales, .. } => {
                let e = |i: usize| self.evaluate(operands[i], known, value);

                let result = match op {
                    // The arithmetic wraps as the machine's does, on 128 bits then masked to the width of the value
                    Op::Add => e(0)?.wrapping_add(e(1)?),
                    Op::Sub => e(0)?.wrapping_sub(e(1)?),
                    Op::Mul => e(0)?.wrapping_mul(e(1)?),
                    Op::Shl => e(0)? << (e(1)? as u32 & 127),
                    Op::LShr => (mask(e(0)?, bits) as u128 >> (e(1)? as u32 & 127)) as i128,
                    Op::AShr => e(0)? >> (e(1)? as u32 & 127),
                    Op::And => e(0)? & e(1)?,
                    Op::Or => e(0)? | e(1)?,
                    Op::Xor => e(0)? ^ e(1)?,
                    Op::ZExt => mask(e(0)?, f.values[operands[0]].ty.bits()),
                    Op::SExt => {
                        let from = f.values[operands[0]].ty.bits();
                        let v = mask(e(0)?, from);
                        if from > 0 && from < 128 && v >> (from - 1) & 1 == 1 { v - (1i128 << from) } else { v }
                    }
                    Op::Trunc | Op::IntToPtr | Op::PtrToInt | Op::Freeze | Op::BitCast => e(0)?,
                    Op::Gep => {
                        let mut address = e(0)?;

                        for (i, scale) in scales.iter().enumerate() {
                            address = address.wrapping_add(e(i + 1)?.wrapping_mul(*scale as i128));
                        }

                        address
                    }
                    Op::ICmp => {
                        let width = f.values[operands[0]].ty.bits().max(1);
                        let (a, b) = (mask(e(0)?, width), mask(e(1)?, width));
                        let signed = |v: i128| if width < 128 && v >> (width - 1) & 1 == 1 { v - (1i128 << width) } else { v };

                        let ValueKind::Inst { pred: Some(pred), .. } = &f.values[id].kind else {
                            return None;
                        };

                        let result = match pred {
                            Pred::Eq => a == b,
                            Pred::Ne => a != b,
                            Pred::Ugt => a > b,
                            Pred::Uge => a >= b,
                            Pred::Ult => a < b,
                            Pred::Ule => a <= b,
                            Pred::Sgt => signed(a) > signed(b),
                            Pred::Sge => signed(a) >= signed(b),
                            Pred::Slt => signed(a) < signed(b),
                            Pred::Sle => signed(a) <= signed(b),
                            Pred::True => true,
                            Pred::False => false,
                            Pred::Float { .. } => return None,
                        };

                        result as i128
                    }
                    Op::Select => {
                        if e(0)? & 1 == 1 {
                            e(1)?
                        } else {
                            e(2)?
                        }
                    }
                    // Only constant memory (jump tables) has a known value
                    Op::Load => {
                        let address = e(0)? as u64;

                        if self.ctx.program.region_at(address).is_none_or(|r| r.perms.write) {
                            return None;
                        }

                        let bytes = self.ctx.program.read(address, (bits / 8) as usize)?;
                        let mut raw = [0u8; 16];
                        raw[..bytes.len()].copy_from_slice(bytes);
                        u128::from_le_bytes(raw) as i128
                    }
                    _ => return None,
                };

                Some(mask(result, bits))
            }
            _ => None,
        };
    }

    /*
     * Switches split by the compilers: a range check before a jump table, sparse values tested before
     * it, search trees of comparisons (LLVM lowers switches this way). The blocks that only test the
     * same value after a first test are one decision, taken for every value of interest: the
     * boundaries of the comparisons, the cases, every value of the small ranges between them.
     */

    /// The decisions of the function by their first block, the blocks of one are not the start of another
    fn decisions(&self) -> HashMap<usize, Decision> {
        let f = self.f;
        let mut decisions = HashMap::new();
        let mut taken: HashSet<usize> = HashSet::new();

        // Reverse post order: the first test of a decision comes before the others
        let mut order = Vec::new();
        let mut visited = vec![false; f.blocks.len()];
        let mut stack = vec![(0usize, 0usize)];

        if f.blocks.is_empty() {
            return decisions;
        }

        visited[0] = true;

        while let Some((block, next)) = stack.pop() {
            match f.blocks[block].succs.get(next) {
                Some(&succ) => {
                    stack.push((block, next + 1));

                    if !visited[succ] {
                        visited[succ] = true;
                        stack.push((succ, 0));
                    }
                }
                None => order.push(block),
            }
        }

        for &block in order.iter().rev() {
            if taken.contains(&block) {
                continue;
            }

            if let Some(decision) = self.decision(block, &taken) {
                taken.extend(decision.blocks.iter().copied());
                decisions.insert(block, decision);
            }
        }

        return decisions;
    }

    /// Case values of the type of the switched expression: negative for a signed one, not for an unsigned
    /// one (the values are its bits, and stay what they are once promoted to int)
    fn case_values(&self, switched: &Expr, mut cases: Vec<(Vec<i128>, usize)>) -> Vec<(Vec<i128>, usize)> {
        let (bits, signed) = match self.written_type(switched).as_ref().map(|t| t.unqualified()) {
            Some(CType::Int { bits, signed }) => (*bits as u32, *signed),
            Some(CType::Char) => (8, true),
            _ => return cases,
        };

        let modulus = 1i128 << bits.clamp(1, 127);

        for (values, _) in cases.iter_mut() {
            for value in values.iter_mut() {
                let wrapped = value.rem_euclid(modulus);
                *value = if signed && wrapped >= modulus / 2 { wrapped - modulus } else { wrapped };
            }
        }

        return cases;
    }

    /// The value without the constant added to it: (x, c) for x + c (its extensions and truncations too)
    fn linear(&self, mut id: ValueId) -> (ValueId, i128) {
        let f = self.f;
        let mut offset = 0i128;

        loop {
            match f.inst(id) {
                Some((Op::Add, [x, c])) if f.int(*c).is_some() => {
                    offset += f.int(*c).unwrap();
                    id = *x;
                }
                Some((Op::Sub, [x, c])) if f.int(*c).is_some() => {
                    offset -= f.int(*c).unwrap();
                    id = *x;
                }
                Some((Op::ZExt | Op::SExt | Op::Trunc | Op::Freeze, [x])) => id = *x,
                _ => return (id, offset),
            }
        }
    }

    /// The value a block tests: the operand of its comparison with a constant, of its switch
    fn tested(&self, block: usize) -> Option<ValueId> {
        let f = self.f;
        let (op, operands) = f.inst(*f.blocks[block].insts.last()?)?;

        let operand = match (op, operands) {
            (Op::Br, [condition]) => match f.inst(*condition)? {
                (Op::ICmp, [x, y]) if f.int(*y).is_some() => *x,
                (Op::ICmp, [x, y]) if f.int(*x).is_some() => *y,
                _ => return None,
            },
            (Op::Switch, [value, ..]) => *value,
            _ => return None,
        };

        return Some(self.linear(operand).0);
    }

    /// A block that only tests the value: no effect, its values only used by the decision, a test of the value
    fn is_test(&self, block: usize, value: ValueId, region: &HashSet<usize>) -> bool {
        let f = self.f;
        let Some((&last, body)) = f.blocks[block].insts.split_last() else {
            return false;
        };

        if !matches!(f.op(last), Some(Op::Br | Op::Switch)) {
            return false;
        }

        for &id in body {
            if !matches!(f.op(id), Some(Op::Add | Op::Sub | Op::ICmp | Op::ZExt | Op::SExt | Op::Trunc | Op::Freeze | Op::Load | Op::Gep | Op::IntToPtr | Op::PtrToInt | Op::Shl | Op::Mul | Op::Select)) {
                return false;
            }

            if !region.is_empty() && f.values[id].uses.iter().any(|&u| f.block_of(u).is_none_or(|b| !region.contains(&b) && b != block)) {
                return false;
            }
        }

        // A jump instead of a test (a block only jumping to the next test)
        let condition = match f.inst(last) {
            Some((Op::Br, [])) => return true,
            Some((Op::Br, [condition])) => *condition,
            Some((_, [switched, ..])) => *switched,
            _ => return false,
        };

        return self.depends_only(condition, value, 12);
    }

    /// A value computed from another one, constants and constant memory only
    fn depends_only(&self, id: ValueId, value: ValueId, depth: usize) -> bool {
        let f = self.f;

        if id == value {
            return true;
        }

        return match &f.values[id].kind {
            ValueKind::Int(_) | ValueKind::Global(_) => true,
            ValueKind::Inst { op: Op::Phi | Op::Call | Op::Alloca, .. } => false,
            ValueKind::Inst { operands, .. } if depth > 0 => operands.iter().all(|&o| self.depends_only(o, value, depth - 1)),
            _ => false,
        };
    }

    /// What an edge does: the block it goes to, the phi assignments or the value it returns
    fn edge_key(&self, from: usize, to: usize) -> (usize, Vec<(VarId, Expr)>, Option<Option<Expr>>) {
        let f = self.f;

        if let Some(ret) = self.folded_return(from, to) {
            return (usize::MAX, Vec::new(), Some(ret));
        }

        let mut copies = Vec::new();

        for &id in f.blocks[to].insts.iter() {
            let ValueKind::Inst { op: Op::Phi, operands, blocks, .. } = &f.values[id].kind else {
                continue;
            };

            if let (Some(var), Some(position)) = (self.var_of[id], blocks.iter().position(|&b| b == from)) {
                copies.push((var, self.expr(operands[position])));
            }
        }

        return (to, copies, None);
    }

    /// The edge taken for a value of the tested value: the last test and the block after the decision
    fn route(&self, head: usize, region: &HashSet<usize>, value: ValueId, x: i128) -> Option<(usize, usize)> {
        let f = self.f;
        let mut block = head;

        for _ in 0..=region.len() {
            let terminator = *f.blocks[block].insts.last()?;
            let ValueKind::Inst { op, operands, blocks: targets, .. } = &f.values[terminator].kind else {
                return None;
            };

            let next = match (op, operands.as_slice()) {
                (Op::Br, []) => targets[0],
                (Op::Br, [condition]) => targets[if self.evaluate(*condition, value, x)? & 1 == 1 { 0 } else { 1 }],
                (Op::Switch, [switched, cases @ ..]) => {
                    let bits = f.values[*switched].ty.bits().clamp(1, 127);
                    let v = self.evaluate(*switched, value, x)? & ((1i128 << bits) - 1);
                    let case = cases.iter().position(|&c| f.int(c).is_some_and(|c| c & ((1i128 << bits) - 1) == v));
                    case.map_or(targets[0], |i| targets[i + 1])
                }
                _ => return None,
            };

            if !region.contains(&next) || next == head {
                return Some((block, next));
            }

            block = next;
        }

        return None;
    }

    /// The decision starting at a block (with at least a switch after a test, or two switches)
    fn decision(&self, head: usize, taken: &HashSet<usize>) -> Option<Decision> {
        let f = self.f;
        let value = self.tested(head)?;
        let bits = match f.values[value].ty {
            Ty::Int(bits @ 8..=64) => bits,
            _ => return None,
        };

        // The tests after the head whose predecessors are all tests
        let mut region: HashSet<usize> = HashSet::from([head]);
        let mut changed = true;

        while changed && region.len() < MAX_DECISION_BLOCKS {
            changed = false;
            let frontier: BTreeSet<usize> = region.iter().flat_map(|&b| f.blocks[b].succs.iter().copied()).filter(|b| !region.contains(b) && !taken.contains(b)).collect();

            for block in frontier {
                if f.blocks[block].preds.iter().all(|p| region.contains(p)) && self.is_test(block, value, &HashSet::new()) {
                    region.insert(block);
                    changed = true;
                }
            }
        }

        // Without the tests whose values are used after the decision, and the ones only they lead to
        loop {
            let kept: HashSet<usize> = region.iter().copied().filter(|&b| b == head || (self.is_test(b, value, &region) && f.blocks[b].preds.iter().all(|p| region.contains(p)))).collect();

            if kept.len() == region.len() {
                break;
            }

            region = kept;
        }

        let switches = region.iter().filter(|&&b| f.blocks[b].insts.last().is_some_and(|&t| f.op(t) == Some(Op::Switch))).count();

        if region.len() < 2 || switches == 0 || (switches == 1 && region.len() < 2) {
            return None;
        }

        // Values of interest: around the constants the tests compare with, the case values, where the
        // tested value plus its constants wraps, the extremes
        let modulus = 1i128 << bits;
        let wrap = |v: i128| v.rem_euclid(modulus);
        let mut points: BTreeSet<i128> = BTreeSet::from([0, 1, modulus - 1, modulus / 2 - 1, modulus / 2]);
        let add = |points: &mut BTreeSet<i128>, v: i128| {
            for d in [-1, 0, 1] {
                points.insert(wrap(v + d));
            }
        };

        for &block in region.iter() {
            for &id in f.blocks[block].insts.iter() {
                let Some((op, operands)) = f.inst(id) else { continue };

                match (op, operands) {
                    (Op::ICmp, [x, y]) => {
                        let (compared, constant) = match (f.int(*x), f.int(*y)) {
                            (None, Some(c)) => (*x, c),
                            (Some(c), None) => (*y, c),
                            _ => continue,
                        };

                        let (root, offset) = self.linear(compared);

                        if root == value {
                            add(&mut points, constant - offset);
                            add(&mut points, -offset);
                            add(&mut points, modulus / 2 - offset);
                        }
                    }
                    (Op::Switch, [switched, cases @ ..]) => {
                        let (root, offset) = self.linear(*switched);

                        if root == value {
                            cases.iter().filter_map(|&c| f.int(c)).for_each(|c| add(&mut points, c - offset));
                        }
                    }
                    _ => {}
                }
            }
        }

        // The edges that do the same thing are one (the same phi assignments to the same block)
        let mut keys: Vec<(usize, Vec<(VarId, Expr)>, Option<Option<Expr>>)> = Vec::new();
        let mut representatives: Vec<(usize, usize)> = Vec::new();
        let mut known: HashMap<(usize, usize), usize> = HashMap::new();

        let mut edge_of = |x: i128| -> Option<usize> {
            let edge = self.route(head, &region, value, x)?;

            if let Some(&id) = known.get(&edge) {
                return Some(id);
            }

            let key = self.edge_key(edge.0, edge.1);
            let id = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
                keys.push(key);
                representatives.push(edge);
                keys.len() - 1
            });

            known.insert(edge, id);
            return Some(id);
        };

        // The edge of each value, then of the ranges between them (each value when they are small)
        let mut edges: BTreeMap<i128, usize> = BTreeMap::new();
        let mut ranges: Vec<usize> = Vec::new();
        let points: Vec<i128> = points.into_iter().collect();

        for (i, &x) in points.iter().enumerate() {
            edges.insert(x, edge_of(x)?);

            let next = points.get(i + 1).copied().unwrap_or(points[0] + modulus);
            let gap = next - x - 1;

            if gap <= 0 {
                continue;
            }

            if gap <= MAX_CASES as i128 {
                for v in x + 1..next {
                    edges.insert(wrap(v), edge_of(wrap(v))?);
                }

                continue;
            }

            let samples: Vec<usize> = [x + 1, x + gap / 2, next - 1].iter().map(|&v| edge_of(wrap(v))).collect::<Option<_>>()?;

            if samples.iter().any(|s| *s != samples[0]) {
                return None;
            }

            ranges.push(samples[0]);
        }

        // The edge of the large ranges is the default, without them the most frequent one
        let default = match ranges.first() {
            Some(&edge) if ranges.iter().all(|&e| e == edge) => edge,
            Some(_) => return None,
            None => {
                let mut counts: HashMap<usize, usize> = HashMap::new();
                edges.values().for_each(|e| *counts.entry(*e).or_default() += 1);
                *counts.iter().max_by_key(|(e, c)| (**c, std::cmp::Reverse(**e)))?.0
            }
        };

        let cases: Vec<(i128, (usize, usize))> = edges.into_iter().filter(|(_, edge)| *edge != default).map(|(x, edge)| (x, representatives[edge])).collect();

        if cases.is_empty() || cases.len() > MAX_CASES {
            return None;
        }

        return Some(Decision { value, cases, default: representatives[default], blocks: region.into_iter().collect() });
    }

    /// Storage notes of the variables: a note on a value that is not a variable is for the variable it is
    /// an extension or a conversion of, for the variable that is its low bits (the register holds it), or
    /// for the variable of a phi it is assigned to
    fn notes(&self, params: &[VarId]) -> Vec<VarNote> {
        let f = self.f;
        let var = |id: ValueId| match f.values[id].kind {
            ValueKind::Param(index) => params.get(index).copied(),
            _ => self.var_of[id],
        };

        // The variable it is the low bits of, or the variable of the phi it is assigned to
        let low_bits = |id: ValueId| -> Option<ValueId> {
            f.values[id].uses.iter().copied().find(|&u| matches!(f.inst(u), Some((Op::Trunc | Op::BitCast | Op::IntToPtr | Op::PtrToInt | Op::Phi, _))) && var(u).is_some())
        };

        let mut notes = Vec::new();

        for note in f.notes.iter() {
            let mut id = note.value;

            for _ in 0..4 {
                if var(id).is_some() {
                    break;
                }

                id = match f.inst(id) {
                    Some((Op::ZExt | Op::SExt | Op::Freeze | Op::BitCast | Op::IntToPtr | Op::PtrToInt, [x])) => *x,
                    _ => match low_bits(id) {
                        Some(u) => u,
                        None => break,
                    },
                };
            }

            let Some(v) = var(id) else {
                continue;
            };

            let bits = match f.values[id].ty {
                Ty::Ptr => self.ctx.program.pointer_size.max(4) as u32 * 8,
                ty => ty.bits(),
            };

            let loc = match note.loc.place() {
                Place::Register { reg, bits: noted, offset } => Loc::register(reg, bits.min(noted), offset),
                _ => Some(note.loc),
            };

            if let Some(loc) = loc.filter(|_| bits > 0) {
                notes.push(VarNote { var: v, loc, start: note.start, entry: note.entry, bits });
            }
        }

        return notes;
    }

    /// Variables of the stack frame at a known place of it: they are there while the function runs
    fn frame_vars(&self) -> Vec<(VarId, Loc)> {
        let mut vars: Vec<(VarId, Loc)> = self.f.stack.iter().filter_map(|(&id, &offset)| Some((self.storage[id]?, Loc::stack(offset)?))).collect();
        vars.sort();
        return vars;
    }

    /// Phi assignments of an edge, in an order that reads every value before it is overwritten. They
    /// execute with the jump of the edge, they get its address.
    fn copies(&mut self, from: usize, to: usize, jump: Option<u64>) -> Vec<Stmt> {
        let f = self.f;
        let mut pending: Vec<(VarId, Expr, Option<u64>)> = Vec::new();

        for &id in f.blocks[to].insts.iter() {
            let ValueKind::Inst { op: Op::Phi, operands, blocks, .. } = &f.values[id].kind else {
                continue;
            };

            let Some(var) = self.var_of[id] else {
                continue;
            };

            let Some(position) = blocks.iter().position(|&b| b == from) else {
                continue;
            };

            let value = match self.expr(operands[position]) {
                Expr::Int(0) if is_pointer(&self.vars[var].ty) => Expr::Name("NULL".to_string()),
                value => value,
            };

            if value != Expr::Var(var) {
                pending.push((var, value, f.addr(id).or(jump)));
            }
        }

        let mut stmts = Vec::new();

        while !pending.is_empty() {
            // A copy whose variable no other pending copy reads
            let ready = (0..pending.len()).find(|&i| pending.iter().enumerate().all(|(j, (_, value, _))| j == i || !value.uses(pending[i].0)));

            match ready {
                Some(i) => {
                    let (var, value, addr) = pending.remove(i);
                    stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(var), value), addr));
                }
                None => {
                    // Cycle: the first variable is saved before being overwritten
                    let (var, _, addr) = pending[0].clone();
                    let saved = self.new_var(String::new(), self.vars[var].ty.clone());
                    stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(saved), Expr::Var(var)), addr));

                    for (_, value, _) in pending.iter_mut().skip(1) {
                        *value = replace_var(value, var, saved);
                    }

                    let (var, value, addr) = pending.remove(0);
                    stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(var), value), addr));
                }
            }
        }

        return stmts;
    }

    /// Return value when the block only returns (one of) its phis, for the edge coming from a predecessor
    fn folded_return(&self, from: usize, to: usize) -> Option<Option<Expr>> {
        let f = self.f;
        let insts = &f.blocks[to].insts;
        let (&last, phis) = insts.split_last()?;

        if f.op(last) != Some(Op::Ret) || phis.iter().any(|&p| f.op(p) != Some(Op::Phi)) {
            return None;
        }

        let (_, operands) = f.inst(last)?;

        let Some(&value) = operands.first() else {
            return Some(None);
        };

        if let ValueKind::Inst { op: Op::Phi, operands, blocks, .. } = &f.values[value].kind {
            if f.block_of(value) == Some(to) {
                let position = blocks.iter().position(|&b| b == from)?;
                return Some(Some(self.expr(operands[position])));
            }
        }

        return Some(Some(self.expr(value)));
    }
}

/// The blocks made for the edges (after the blocks of the function): a folded return, or the phi
/// assignments then a jump. The edges of a block that do the same thing are one block.
struct Edges {
    count: usize,
    blocks: Vec<SBlock>,
}

impl Edges {
    /// Target of an edge: the block it goes to, or a block made for it (the copies go to the statements
    /// of the block when it has one successor)
    fn edge(&mut self, builder: &mut Builder, from: usize, to: usize, addr: Option<u64>, multiple: bool, stmts: &mut Vec<Stmt>) -> usize {
        let made = match builder.folded_return(from, to) {
            Some(ret) => SBlock { stmts: Vec::new(), term: Term::Return(ret), addr },
            None => {
                let copies = builder.copies(from, to, addr);

                if copies.is_empty() {
                    return to;
                }

                if !multiple {
                    stmts.extend(copies);
                    return to;
                }

                SBlock { stmts: copies, term: Term::Jump(to), addr }
            }
        };

        let same = |b: &SBlock| b.term == made.term && b.stmts.len() == made.stmts.len() && b.stmts.iter().zip(made.stmts.iter()).all(|(x, y)| x.kind == y.kind);

        if let Some(existing) = self.blocks.iter().rposition(|b| b.addr == made.addr && same(b)) {
            return self.count + existing;
        }

        self.blocks.push(made);
        return self.count + self.blocks.len() - 1;
    }
}

pub fn replace_var(expr: &Expr, from: VarId, to: VarId) -> Expr {
    let r = |e: &Expr| Box::new(replace_var(e, from, to));

    return match expr {
        Expr::Var(v) if *v == from => Expr::Var(to),
        Expr::Unary(op, e) => Expr::Unary(*op, r(e)),
        Expr::Binary(op, a, b) => Expr::Binary(*op, r(a), r(b)),
        Expr::Cast(ty, e) => Expr::Cast(ty.clone(), r(e)),
        Expr::Index(a, b) => Expr::Index(r(a), r(b)),
        Expr::Member(e, name, arrow) => Expr::Member(r(e), name.clone(), *arrow),
        Expr::Call(callee, args) => Expr::Call(r(callee), args.iter().map(|a| replace_var(a, from, to)).collect()),
        Expr::Ternary(a, b, c) => Expr::Ternary(r(a), r(b), r(c)),
        other => other.clone(),
    };
}

/// Statements and terminators of the blocks, the variables of the function
pub fn build(f: &Func, ctx: &Context, types: Vec<CType>, param_names: &[String]) -> Built {
    let mut builder = Builder {
        f,
        ctx,
        var_of: vec![None; f.values.len()],
        storage: vec![None; f.values.len()],
        vars: Vec::new(),
        reads_memory: vec![false; f.values.len()],
        types,
        constants: Vec::new(),
        globals: RefCell::new(BTreeMap::new()),
    };

    // Parameters are the first variables
    let params: Vec<VarId> = f.params.iter().enumerate().map(|(i, &p)| builder.new_var(param_names[i].clone(), builder.types[p].clone())).collect();

    builder.decide();
    builder.share_constants();
    super::coalesce::coalesce(f, &mut builder.var_of, &builder.vars, &params);

    let count = f.blocks.len();
    let decisions = builder.decisions();
    let mut blocks: Vec<SBlock> = Vec::new();
    let mut edges = Edges { count, blocks: Vec::new() };

    for block in 0..count {
        let stmts = builder.block_stmts(block);
        let terminator = f.blocks[block].insts.last().copied();
        let mut addr = terminator.and_then(|t| f.addr(t));

        if let (None, Some((Op::Ret, operands))) = (addr, terminator.and_then(|t| f.inst(t))) {
            addr = operands.first().and_then(|&v| f.addr(v)).or(ctx.ret);
        }

        let addr = addr.or(stmts.first().and_then(|s| s.addr));

        let Some((op, operands)) = terminator.and_then(|t| f.inst(t)) else {
            blocks.push(SBlock { stmts, term: Term::Unreachable, addr });
            continue;
        };

        let succs = f.blocks[block].succs.clone();
        let multiple = succs.len() > 1 || decisions.contains_key(&block);
        let mut stmts = stmts;

        let term = match op {
            _ if decisions.contains_key(&block) => {
                let decision = &decisions[&block];
                let value = builder.expr(decision.value);
                let (from, to) = decision.default;
                let default = edges.edge(&mut builder, from, to, addr, true, &mut stmts);
                let mut cases: Vec<(Vec<i128>, usize)> = Vec::new();

                for &(case, (from, to)) in decision.cases.iter() {
                    let target = edges.edge(&mut builder, from, to, addr, true, &mut stmts);

                    match cases.iter_mut().find(|(_, t)| *t == target) {
                        Some((values, _)) => values.push(case),
                        None => cases.push((vec![case], target)),
                    }
                }

                Term::Switch(value.clone(), builder.case_values(&value, cases), default)
            }
            Op::Ret => Term::Return(operands.first().map(|&v| builder.expr(v))),
            Op::Br if succs.len() == 1 => {
                let target = edges.edge(&mut builder, block, succs[0], addr, multiple, &mut stmts);

                // A jump to a folded return is the return
                match target.checked_sub(count).map(|e| edges.blocks[e].clone()) {
                    Some(SBlock { stmts: s, term: Term::Return(ret), .. }) if s.is_empty() => Term::Return(ret),
                    _ => Term::Jump(target),
                }
            }
            Op::Br => {
                let condition = builder.expr(operands[0]);
                let on_true = edges.edge(&mut builder, block, succs[0], addr, multiple, &mut stmts);
                let on_false = edges.edge(&mut builder, block, succs[1], addr, multiple, &mut stmts);
                Term::Branch(condition, on_true, on_false)
            }
            Op::Switch if builder.jump_table(block).is_some() => {
                let (value, table, default_target) = builder.jump_table(block).unwrap();
                let default = edges.edge(&mut builder, block, default_target, addr, multiple, &mut stmts);
                let mut cases: Vec<(Vec<i128>, usize)> = Vec::new();

                for (case, target) in table {
                    let target = edges.edge(&mut builder, block, target, addr, multiple, &mut stmts);

                    match cases.iter_mut().find(|(_, t)| *t == target) {
                        Some((values, _)) => values.push(case),
                        None => cases.push((vec![case], target)),
                    }
                }

                Term::Switch(value.clone(), builder.case_values(&value, cases), default)
            }
            Op::Switch => {
                let value = builder.expr(operands[0]);
                let default = edges.edge(&mut builder, block, succs[0], addr, multiple, &mut stmts);
                let mut cases: Vec<(Vec<i128>, usize)> = Vec::new();

                for (i, &target) in succs[1..].iter().enumerate() {
                    let value = f.int(operands[i + 1]).unwrap_or(0);
                    let target = edges.edge(&mut builder, block, target, addr, multiple, &mut stmts);

                    match cases.iter_mut().find(|(_, t)| *t == target) {
                        Some((values, _)) => values.push(value),
                        None => cases.push((vec![value], target)),
                    }
                }

                Term::Switch(value.clone(), builder.case_values(&value, cases), default)
            }
            _ => Term::Unreachable,
        };

        blocks.push(SBlock { stmts, term, addr });
    }

    let edges = edges.blocks;
    blocks.extend(edges);

    let notes = builder.notes(&params);
    let frame_vars = builder.frame_vars();
    let vars = std::mem::take(&mut builder.vars);
    let globals = builder.globals.take().into_iter().collect();

    return Built { blocks, vars, params, globals, notes, frame_vars };
}
