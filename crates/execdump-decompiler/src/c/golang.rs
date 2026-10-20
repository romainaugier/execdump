/*
 * Idioms of the Go compiler in the C of a Go program
 *
 * The write barriers of the garbage collector: a store of a pointer to the heap tests runtime.writeBarrier and
 * calls the runtime when it is enabled, the store itself is what the program does.
 * - Go 1.9: if (runtime_writeBarrier == 0) { *p = v; } else { runtime_writebarrierptr(p, v); }
 * - Go 1.10 to 1.20: the same with runtime_gcWriteBarrier (its arguments in registers)
 * - Go 1.21 and later: if (runtime_writeBarrier != 0) { b = runtime_gcWriteBarrier2(); b[0] = v; b[1] = *p; } *p = v;
 * The test and the calls go, the stores stay.
 */

use super::ast::{BinaryOp, CFunction, Expr, Stmt, StmtKind, UnaryOp, VarId};

const BARRIER_FLAG: &str = "runtime_writeBarrier";

/// Functions of the write barriers (the calls the compiler adds to the stores of pointers)
fn is_barrier(name: &str) -> bool {
    return ["runtime_writebarrierptr", "runtime_gcWriteBarrier", "runtime_wbZero", "runtime_wbMove", "runtime_writebarrierstring", "runtime_writebarrierslice", "runtime_writebarrieriface"]
        .iter()
        .any(|prefix| name.starts_with(prefix));
}

fn mentions_flag(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |e| found |= matches!(e, Expr::Name(name) if name == BARRIER_FLAG));
    return found;
}

/// Whether a condition tests that the write barriers are enabled (Some(true)) or disabled (Some(false))
fn barrier_test(cond: &Expr) -> Option<bool> {
    return match cond {
        Expr::Unary(UnaryOp::LogicalNot, inner) => barrier_test(inner).map(|enabled| !enabled),
        Expr::Binary(op @ (BinaryOp::Eq | BinaryOp::Ne), a, b) => {
            let (flag, zero) = if matches!(**b, Expr::Int(0)) { (a, true) } else if matches!(**a, Expr::Int(0)) { (b, true) } else { (a, false) };

            if !zero || !mentions_flag(flag) {
                return None;
            }

            Some(*op == BinaryOp::Ne)
        }
        e if mentions_flag(e) && matches!(e, Expr::Name(_) | Expr::Member(..) | Expr::Cast(..) | Expr::Unary(UnaryOp::Deref, _) | Expr::Index(..)) => Some(true),
        _ => None,
    };
}

fn barrier_call(e: &Expr) -> bool {
    return matches!(e, Expr::Call(callee, _) if matches!(&**callee, Expr::Name(name) if is_barrier(name)));
}

/// The variable a target of an assignment writes into (b[1], b->f8, *b)
fn base_var(e: &Expr) -> Option<VarId> {
    return match e {
        Expr::Var(var) => Some(*var),
        Expr::Index(base, _) | Expr::Member(base, ..) | Expr::Unary(UnaryOp::Deref, base) | Expr::Cast(_, base) => base_var(base),
        Expr::Binary(BinaryOp::Add | BinaryOp::Sub, base, _) => base_var(base),
        _ => None,
    };
}

/// A branch that only runs the barriers: calls to them, and the writes to the buffers they return
fn only_barriers(stmts: &[Stmt]) -> bool {
    let mut buffers: Vec<VarId> = Vec::new();

    for stmt in stmts.iter() {
        match &stmt.kind {
            StmtKind::Expr(e) if barrier_call(e) => {}
            StmtKind::Assign(Expr::Var(var), e) if barrier_call(e) => buffers.push(*var),
            StmtKind::Assign(target, _) if !matches!(target, Expr::Var(_)) && base_var(target).is_some_and(|v| buffers.contains(&v)) => {}
            StmtKind::Comment(_) => {}
            _ => return false,
        }
    }

    return !stmts.is_empty();
}

fn stmts(list: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    let mut index = 0;

    while index < list.len() {
        // Inner statements first
        match &mut list[index].kind {
            StmtKind::If(_, then, other) => {
                changed |= stmts(then);
                changed |= stmts(other);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => changed |= stmts(body),
            StmtKind::Switch(_, cases, default) => {
                for case in cases.iter_mut() {
                    changed |= stmts(&mut case.body);
                }

                changed |= stmts(default);
            }
            _ => {}
        }

        let replacement = match &list[index].kind {
            StmtKind::If(cond, then, other) => match barrier_test(cond) {
                Some(true) if only_barriers(then) => Some(other.clone()),
                Some(false) if only_barriers(other) => Some(then.clone()),
                _ => None,
            },
            _ => None,
        };

        match replacement {
            Some(kept) => {
                let count = kept.len();
                list.splice(index..index + 1, kept);
                index += count;
                changed = true;
            }
            None => index += 1,
        }
    }

    return changed;
}

/// Removes the write barriers of a Go function, its stores stay. Whether it changed.
pub fn write_barriers(function: &mut CFunction) -> bool {
    return stmts(&mut function.body);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(kind: StmtKind) -> Stmt {
        return Stmt::new(kind, None);
    }

    fn call(name: &str, args: Vec<Expr>) -> Expr {
        return Expr::Call(Box::new(Expr::Name(name.to_string())), args);
    }

    #[test]
    fn barriers_go() {
        let flag = || Expr::Name(BARRIER_FLAG.to_string());
        let store = || stmt(StmtKind::Assign(Expr::unary(UnaryOp::Deref, Expr::Var(0)), Expr::Var(1)));

        // Go 1.9
        let mut body = vec![stmt(StmtKind::If(
            Expr::binary(BinaryOp::Eq, flag(), Expr::Int(0)),
            vec![store()],
            vec![stmt(StmtKind::Expr(call("runtime_writebarrierptr", vec![Expr::Var(0), Expr::Var(1)])))],
        ))];
        assert!(stmts(&mut body));
        assert_eq!(body, vec![store()]);

        // Go 1.21: the buffer gets the values, the store follows
        let mut body = vec![
            stmt(StmtKind::If(
                Expr::binary(BinaryOp::Ne, flag(), Expr::Int(0)),
                vec![
                    stmt(StmtKind::Assign(Expr::Var(2), call("runtime_gcWriteBarrier2", vec![]))),
                    stmt(StmtKind::Assign(Expr::unary(UnaryOp::Deref, Expr::Var(2)), Expr::Var(1))),
                    stmt(StmtKind::Assign(Expr::Index(Box::new(Expr::Var(2)), Box::new(Expr::Int(1))), Expr::unary(UnaryOp::Deref, Expr::Var(0)))),
                ],
                vec![],
            )),
            store(),
        ];
        assert!(stmts(&mut body));
        assert_eq!(body, vec![store()]);

        // Something else in the branch: kept
        let mut body = vec![stmt(StmtKind::If(flag(), vec![stmt(StmtKind::Expr(call("f", vec![])))], vec![]))];
        assert!(!stmts(&mut body));
    }
}
