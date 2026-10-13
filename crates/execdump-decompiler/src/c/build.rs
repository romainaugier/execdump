/*
 * Out of SSA: IR values become C expressions and statements, block by block
 *
 * A value is inlined into its single use when it is safe: pure values anywhere their operands
 * are still valid, loads and calls only into a use in the same block with no side effect in
 * between. Phis are variables assigned on the edges that lead to them, and the blocks that only
 * return a phi are folded into their predecessors (return x instead of v = x; goto ret).
 */

use super::ast::{BinaryOp, Expr, Stmt, StmtKind, UnaryOp, Var, VarId};
use super::ir::{FloatCmp, Func, Op, Pred, Ty, ValueId, ValueKind};
use super::typing::{is_pointer, pointee};
use super::Context;

use crate::types::CType;

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

pub struct Built {
    pub blocks: Vec<SBlock>,
    pub vars: Vec<Var>,
    pub params: Vec<VarId>,
}

struct Builder<'a> {
    f: &'a Func,
    ctx: &'a Context<'a>,
    types: Vec<CType>,
    var_of: Vec<Option<VarId>>,
    vars: Vec<Var>,
    /// Inlined expressions that read memory (loads and calls, directly or through their operands)
    reads_memory: Vec<bool>,
    /// Constant expressions computed once at the start of the function, operands first
    constants: Vec<ValueId>,
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

            let memory = matches!(op, Op::Load | Op::Call) || operands.iter().any(|&o| self.var_of[o].is_none() && self.reads_memory[o]);
            self.reads_memory[id] = memory;

            let single = value.uses.len() == 1;
            let user = value.uses[0];
            let user_is_phi = f.op(user) == Some(Op::Phi);

            let inline = match op {
                Op::Phi | Op::Alloca => false,
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

    /// A value assigned to a phi on the back edge shares the phi variable when the phi is not
    /// needed anymore once the value is computed (i = i + 1 instead of v = i + 1; i = v)
    fn coalesce(&mut self) {
        let f = self.f;

        for phi in 0..f.values.len() {
            let ValueKind::Inst { op: Op::Phi, operands, .. } = &f.values[phi].kind else {
                continue;
            };

            let Some(var) = self.var_of[phi] else {
                continue;
            };

            for &value in operands.iter() {
                let Some(own) = self.var_of[value] else {
                    continue;
                };

                if own == var || f.op(value) == Some(Op::Phi) || !self.dead_after(phi, value) {
                    continue;
                }

                // The value must not feed another phi of the same block (both would share the variable)
                let header = f.block_of(phi);
                if f.values[value].uses.iter().filter(|&&u| f.op(u) == Some(Op::Phi) && f.block_of(u) == header).count() > 1 {
                    continue;
                }

                self.var_of[value] = Some(var);
            }
        }
    }

    /// The phi is only used before the value, in the value's block (or by the value itself)
    fn dead_after(&self, phi: ValueId, value: ValueId) -> bool {
        let Some((block, position)) = self.position(value) else {
            return false;
        };

        return self.f.values[phi].uses.iter().all(|&u| {
            if self.f.op(u) == Some(Op::Phi) && self.f.block_of(u) == self.f.block_of(phi) {
                return true;
            }

            // Inlined uses are evaluated where their expression is
            let root = self.evaluated_at(u);
            root == value || matches!(self.position(root), Some((b, p)) if b == block && p < position)
        });
    }

    /// The statement an inlined value is evaluated in (the value itself when it is a variable)
    fn evaluated_at(&self, mut id: ValueId) -> ValueId {
        while self.var_of[id].is_none() {
            match self.f.values[id].uses.first() {
                Some(&user) if self.f.op(user) != Some(Op::Phi) => id = user,
                _ => break,
            }
        }

        return id;
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

        let f = self.f;

        return match &f.values[id].kind {
            ValueKind::Param(index) => Expr::Var(*index),
            ValueKind::Int(0) if is_pointer(self.ty(id)) => Expr::Name("NULL".to_string()),
            ValueKind::Int(value) => Expr::Int(*value),
            ValueKind::Float(value) => Expr::Float(*value),
            ValueKind::Undef => Expr::Int(0),
            ValueKind::Function(name) => Expr::Name(name.clone()),
            ValueKind::Global(name) => self.global(name),
            ValueKind::Inst { .. } => self.inst(id),
        };
    }

    /// Strings are literals, other globals are addressed
    fn global(&self, name: &str) -> Expr {
        if let Some(text) = self.ctx.string(name) {
            return Expr::Str(text);
        }

        return Expr::unary(UnaryOp::AddrOf, Expr::Name(name.to_string()));
    }

    /// Operand of an unsigned or signed operation, cast when its type has the other signedness
    fn signed_operand(&self, id: ValueId, signed: bool) -> Expr {
        let expr = self.expr(id);

        return match self.ty(id) {
            CType::Int { bits, signed: s } if *s != signed && !matches!(expr, Expr::Int(_)) => Expr::cast(CType::Int { bits: *bits, signed }, expr),
            _ => expr,
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

        let binary = |op: BinaryOp| Expr::binary(op, self.expr(o[0]), self.expr(o[1]));

        return match (op, o) {
            (Op::Add | Op::Sub, [x, y]) if is_pointer(self.ty(id)) && (is_pointer(self.ty(*x)) || is_pointer(self.ty(*y))) => {
                let (base, offset) = if is_pointer(self.ty(*x)) { (*x, *y) } else { (*y, *x) };
                let offset = if *op == Op::Sub { Expr::unary(UnaryOp::Neg, self.expr(offset)) } else { self.expr(offset) };
                self.pointer_add(base, offset)
            }
            (Op::Add, [x, y]) => match f.int(*y) {
                Some(c) if c < 0 => Expr::binary(BinaryOp::Sub, self.expr(*x), Expr::Int(-c)),
                _ => binary(BinaryOp::Add),
            },
            (Op::Sub, [x, y]) if f.int(*x) == Some(0) => Expr::unary(UnaryOp::Neg, self.expr(*y)),
            (Op::Sub, _) => binary(BinaryOp::Sub),
            (Op::Mul, _) => binary(BinaryOp::Mul),
            (Op::Shl, _) => binary(BinaryOp::Shl),
            (Op::And, _) if boolean => binary(BinaryOp::LogicalAnd),
            (Op::Or, _) if boolean => binary(BinaryOp::LogicalOr),
            (Op::Xor, [x, y]) if boolean && f.int(*y) == Some(-1) => self.expr(*x).not(),
            (Op::Xor, _) if boolean => binary(BinaryOp::Ne),
            (Op::Xor, [x, y]) if f.int(*y) == Some(-1) => Expr::unary(UnaryOp::Not, self.expr(*x)),
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
                Expr::binary(op, self.signed_operand(*x, true), self.expr(*y))
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
            (Op::Load, [address]) => self.deref(*address, &self.types[id].clone()),
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
                return if function { name } else { Expr::unary(UnaryOp::AddrOf, name) };
            }

            if offset == 0 && terms.is_empty() && self.ctx.string(name).is_none() {
                return Expr::Name(name.clone());
            }

            if terms.is_empty() && offset % size == 0 && self.ctx.string(name).is_none() {
                return Expr::Index(Box::new(Expr::Name(name.clone())), Box::new(Expr::Int(offset / size)));
            }

            if terms.len() == 1 && terms[0].1 == size && offset % size == 0 {
                let index = self.index_expr(terms[0].0, offset / size);
                return Expr::Index(Box::new(Expr::Name(name.clone())), Box::new(index));
            }
        }

        let base_pointee = pointee(self.ty(base)).cloned();

        // Fields of known structs: p->field
        if let (Some(pointee), true) = (&base_pointee, terms.is_empty()) {
            if let Some(member) = self.member(self.expr(base), pointee, offset, size, true) {
                return member;
            }
        }

        let same_type = base_pointee.as_ref().is_some_and(|p| self.ctx.size_of(p).map(|s| s as i128) == Some(size));
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

        let mut pointer = if is_pointer(self.ty(base)) && pointee(self.ty(base)) == Some(&CType::Char) { base_expr } else { Expr::cast(CType::ptr(CType::Char), base_expr) };

        if let Some(bytes) = bytes {
            pointer = Expr::binary(BinaryOp::Add, pointer, bytes);
        }

        if offset != 0 {
            pointer = if offset < 0 { Expr::binary(BinaryOp::Sub, pointer, Expr::Int(-offset)) } else { Expr::binary(BinaryOp::Add, pointer, Expr::Int(offset)) };
        }

        return Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(ty.clone()), pointer));
    }

    /// Access of a field at an offset of a struct (through nested structs and arrays)
    fn member(&self, base: Expr, ty: &CType, offset: i128, size: i128, arrow: bool) -> Option<Expr> {
        let resolved = self.ctx.resolve(ty);
        let (CType::Struct(name) | CType::Union(name)) = resolved.unqualified() else {
            return None;
        };

        let aggregate = self.ctx.typedb.aggregates.get(name)?;

        for field in aggregate.fields.iter().filter(|f| f.bits.is_none()) {
            let field_size = self.ctx.size_of(&field.ty).unwrap_or(0) as i128;
            let start = field.offset as i128;

            if offset < start || offset >= start + field_size.max(1) {
                continue;
            }

            let access = if field.name.is_empty() { base.clone() } else { Expr::Member(Box::new(base.clone()), field.name.clone(), arrow) };
            let inner = offset - start;

            if inner == 0 && field_size == size {
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
                "smax" | "umax" | "maxnum" => Expr::Ternary(Box::new(Expr::binary(BinaryOp::Gt, arg(0), arg(1))), Box::new(arg(0)), Box::new(arg(1))),
                "smin" | "umin" | "minnum" => Expr::Ternary(Box::new(Expr::binary(BinaryOp::Lt, arg(0), arg(1))), Box::new(arg(0)), Box::new(arg(1))),
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

        return call(callee, args.iter().map(|&a| self.expr(a)).collect());
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
                    stmts.push(self.stmt(StmtKind::Assign(self.deref(operands[1], &ty), self.expr(operands[0])), id));
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
                    Op::LShr => mask(e(0)?, bits) >> (e(1)? as u32 & 127),
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
                    Op::Load => {
                        let address = e(0)? as u64;
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

            let value = self.expr(operands[position]);

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
        vars: Vec::new(),
        reads_memory: vec![false; f.values.len()],
        types,
        constants: Vec::new(),
    };

    // Parameters are the first variables
    let params: Vec<VarId> = f.params.iter().enumerate().map(|(i, &p)| builder.new_var(param_names[i].clone(), builder.types[p].clone())).collect();

    builder.decide();
    builder.share_constants();
    builder.coalesce();

    let mut blocks: Vec<SBlock> = Vec::new();
    let mut edges: Vec<SBlock> = Vec::new();
    let count = f.blocks.len();

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
        let multiple = succs.len() > 1;

        // Edges to a successor: a folded return, the phi copies, or a direct jump
        let mut edge = |builder: &mut Builder, to: usize, stmts: &mut Vec<Stmt>| -> usize {
            if let Some(ret) = builder.folded_return(block, to) {
                edges.push(SBlock { stmts: Vec::new(), term: Term::Return(ret), addr });
                return count + edges.len() - 1;
            }

            let copies = builder.copies(block, to, addr);

            if copies.is_empty() {
                return to;
            }

            if multiple {
                edges.push(SBlock { stmts: copies, term: Term::Jump(to), addr });
                return count + edges.len() - 1;
            }

            stmts.extend(copies);
            to
        };

        let mut stmts = stmts;

        let term = match op {
            Op::Ret => Term::Return(operands.first().map(|&v| builder.expr(v))),
            Op::Br if succs.len() == 1 => {
                let target = edge(&mut builder, succs[0], &mut stmts);

                // A jump to a folded return is the return
                match target.checked_sub(count).map(|e| edges[e].clone()) {
                    Some(SBlock { stmts: s, term: Term::Return(ret), .. }) if s.is_empty() => Term::Return(ret),
                    _ => Term::Jump(target),
                }
            }
            Op::Br => {
                let condition = builder.expr(operands[0]);
                let on_true = edge(&mut builder, succs[0], &mut stmts);
                let on_false = edge(&mut builder, succs[1], &mut stmts);
                Term::Branch(condition, on_true, on_false)
            }
            Op::Switch if builder.jump_table(block).is_some() => {
                let (value, table, default_target) = builder.jump_table(block).unwrap();
                let default = edge(&mut builder, default_target, &mut stmts);
                let mut cases: Vec<(Vec<i128>, usize)> = Vec::new();

                for (case, target) in table {
                    let target = edge(&mut builder, target, &mut stmts);

                    match cases.iter_mut().find(|(_, t)| *t == target) {
                        Some((values, _)) => values.push(case),
                        None => cases.push((vec![case], target)),
                    }
                }

                Term::Switch(value, cases, default)
            }
            Op::Switch => {
                let value = builder.expr(operands[0]);
                let default = edge(&mut builder, succs[0], &mut stmts);
                let mut cases: Vec<(Vec<i128>, usize)> = Vec::new();

                for (i, &target) in succs[1..].iter().enumerate() {
                    let value = f.int(operands[i + 1]).unwrap_or(0);
                    let target = edge(&mut builder, target, &mut stmts);

                    match cases.iter_mut().find(|(_, t)| *t == target) {
                        Some((values, _)) => values.push(value),
                        None => cases.push((vec![value], target)),
                    }
                }

                Term::Switch(value, cases, default)
            }
            _ => Term::Unreachable,
        };

        blocks.push(SBlock { stmts, term, addr });
    }

    blocks.extend(edges);

    let vars = std::mem::take(&mut builder.vars);

    return Built { blocks, vars, params };
}
