/*
 * Quality counts of a decompiled function, to measure the effect of the changes to the decompiler:
 * fewer copies, gotos, casts, declarations, unlifted instructions and lines is more readable code
 */

use super::ast::{mark_used, CFunction, Expr, Stmt, StmtKind, UnaryOp};
use crate::types::CType;

use std::fmt;
use std::ops::{Add, AddAssign};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quality {
    pub lines: usize,
    /// v1 = v2;
    pub copies: usize,
    pub gotos: usize,
    /// Memory accesses through a cast pointer: *(int *)((char *)p + 8), ((char *)p)[3]
    pub casts: usize,
    /// Local variables
    pub declarations: usize,
    /// Instructions kept as inline assembly
    pub asm: usize,
}

impl Quality {
    pub const NAMES: [&'static str; 6] = ["lines", "copies", "gotos", "casts", "declarations", "asm"];

    pub fn values(&self) -> [usize; 6] {
        return [self.lines, self.copies, self.gotos, self.casts, self.declarations, self.asm];
    }

    pub fn from_values(values: &[usize]) -> Option<Self> {
        let [lines, copies, gotos, casts, declarations, asm] = values.try_into().ok()?;
        return Some(Quality { lines, copies, gotos, casts, declarations, asm });
    }
}

impl Add for Quality {
    type Output = Quality;

    fn add(self, other: Quality) -> Quality {
        let (a, b) = (self.values(), other.values());
        return Quality::from_values(&std::array::from_fn::<usize, 6, _>(|i| a[i] + b[i])).unwrap();
    }
}

impl AddAssign for Quality {
    fn add_assign(&mut self, other: Quality) {
        *self = *self + other;
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts: Vec<String> = Quality::NAMES.iter().zip(self.values()).map(|(name, value)| format!("{} {}", value, name)).collect();
        return write!(f, "{}", parts.join(", "));
    }
}

fn expr(e: &Expr, quality: &mut Quality) {
    e.visit(&mut |e| match e {
        Expr::Unary(UnaryOp::Deref, inner) | Expr::Index(inner, _) if matches!(&**inner, Expr::Cast(CType::Pointer(_), _)) => quality.casts += 1,
        Expr::Call(callee, _) if **callee == Expr::Name("__asm__".to_string()) => quality.asm += 1,
        _ => {}
    });
}

fn stmts(list: &[Stmt], quality: &mut Quality) {
    for stmt in list {
        match &stmt.kind {
            StmtKind::Assign(target, value) => {
                quality.copies += matches!((target, value), (Expr::Var(_), Expr::Var(_))) as usize;
                expr(target, quality);
                expr(value, quality);
            }
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => expr(e, quality),
            StmtKind::If(c, a, b) => {
                expr(c, quality);
                stmts(a, quality);
                stmts(b, quality);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                expr(c, quality);
                stmts(body, quality);
            }
            StmtKind::For(init, c, step, body) => {
                stmts(std::slice::from_ref(init), quality);
                expr(c, quality);
                stmts(std::slice::from_ref(step), quality);
                stmts(body, quality);
            }
            StmtKind::Switch(c, cases, default) => {
                expr(c, quality);
                cases.iter().for_each(|case| stmts(&case.body, quality));
                stmts(default, quality);
            }
            StmtKind::Goto(_) => quality.gotos += 1,
            _ => {}
        }
    }
}

impl CFunction {
    /// Quality counts of the function, its lines once printed
    pub fn quality(&self, lines: usize) -> Quality {
        let mut quality = Quality { lines, ..Quality::default() };
        stmts(&self.body, &mut quality);

        let mut used = vec![false; self.vars.len()];
        mark_used(&self.body, &mut used);
        quality.declarations = used.iter().enumerate().filter(|(id, used)| **used && !self.params.contains(id)).count();

        return quality;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c::ast::{BinaryOp, Var};

    #[test]
    fn counts() {
        let int = CType::int(32);
        let cast = Expr::unary(UnaryOp::Deref, Expr::cast(CType::ptr(int.clone()), Expr::binary(BinaryOp::Add, Expr::Var(0), Expr::Int(8))));
        let asm = Expr::Call(Box::new(Expr::Name("__asm__".to_string())), vec![Expr::Str("cpuid".to_string())]);

        let function = CFunction {
            name: "f".to_string(),
            ret: int.clone(),
            params: vec![0],
            variadic: false,
            vars: vec![Var { name: "a1".to_string(), ty: CType::ptr(CType::Char) }, Var { name: "v1".to_string(), ty: int.clone() }, Var { name: "v2".to_string(), ty: int.clone() }],
            body: vec![
                Stmt::new(StmtKind::Assign(Expr::Var(1), cast), None),
                Stmt::new(StmtKind::Expr(asm), None),
                Stmt::new(StmtKind::If(Expr::Var(1), vec![Stmt::new(StmtKind::Assign(Expr::Var(2), Expr::Var(1)), None), Stmt::new(StmtKind::Goto("label_1".to_string()), None)], Vec::new()), None),
                Stmt::new(StmtKind::Return(Some(Expr::Var(2))), None),
            ],
            addr: 0,
            globals: Vec::new(),
            inlined: false,
            storage: Default::default(),
        };

        let quality = function.quality(12);
        assert_eq!(quality, Quality { lines: 12, copies: 1, gotos: 1, casts: 1, declarations: 2, asm: 1 });
        assert_eq!(quality + quality, Quality { lines: 24, copies: 2, gotos: 2, casts: 2, declarations: 4, asm: 2 });
    }
}
