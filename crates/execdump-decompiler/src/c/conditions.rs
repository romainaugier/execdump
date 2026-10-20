/*
 * Conditions known where a statement runs
 *
 * After if (!c) break; the rest of the block runs with c true, the branches of if (c) with c true or false. The
 * conditions of the variables (no memory, no call) that are known make the tests of the same conditions constant:
 * if (c && d) is if (d), if (c) { x } is x. The optimizations of LLVM join the paths after a test and test it again
 * where the paths split, these tests go.
 *
 * Then the tests that follow each other with a first condition in common are one: if (a) { x } if (a && b) { y }
 * if (a) { z } is if (a) { x if (b) { y } z }.
 *
 * A fact holds until one of its variables is assigned, inside a loop only the facts on the variables the loop does not
 * assign hold, a label (the target of a goto) ends them all. The variables whose address is taken are never in a fact.
 */

use super::ast::{BinaryOp, CFunction, Expr, Stmt, StmtKind, UnaryOp, VarId};

use std::collections::HashSet;

/// Variables of a condition on variables only (comparisons, logic, arithmetic), None for the other conditions
fn condition_vars(e: &Expr, addressed: &HashSet<VarId>, vars: &mut Vec<VarId>) -> bool {
    return match e {
        Expr::Var(v) => {
            vars.push(*v);
            !addressed.contains(v)
        }
        Expr::Int(_) => true,
        Expr::Unary(UnaryOp::LogicalNot | UnaryOp::Neg | UnaryOp::Not, inner) | Expr::Cast(_, inner) => condition_vars(inner, addressed, vars),
        Expr::Binary(op, a, b) if !matches!(op, BinaryOp::Div | BinaryOp::Rem) => condition_vars(a, addressed, vars) && condition_vars(b, addressed, vars),
        _ => false,
    };
}

fn is_fact(e: &Expr, addressed: &HashSet<VarId>) -> bool {
    let mut vars = Vec::new();
    return condition_vars(e, addressed, &mut vars) && !vars.is_empty();
}

fn conjuncts(e: &Expr) -> Vec<Expr> {
    return match e {
        Expr::Binary(BinaryOp::LogicalAnd, a, b) => {
            let mut all = conjuncts(a);
            all.extend(conjuncts(b));
            all
        }
        other => vec![other.clone()],
    };
}

fn and_all(mut parts: Vec<Expr>) -> Option<Expr> {
    let first = (!parts.is_empty()).then(|| parts.remove(0))?;
    return Some(parts.into_iter().fold(first, |all, part| Expr::binary(BinaryOp::LogicalAnd, all, part)));
}

/// A condition with the known facts replaced by their value, folded
fn rewrite(e: &Expr, facts: &[Expr]) -> Expr {
    if facts.contains(e) {
        return Expr::Int(1);
    }

    if facts.iter().any(|f| f.clone().not() == *e) {
        return Expr::Int(0);
    }

    return match e {
        Expr::Binary(BinaryOp::LogicalAnd, a, b) => match (rewrite(a, facts), rewrite(b, facts)) {
            (Expr::Int(0), _) | (_, Expr::Int(0)) => Expr::Int(0),
            (Expr::Int(1), other) | (other, Expr::Int(1)) => other,
            (a, b) => Expr::binary(BinaryOp::LogicalAnd, a, b),
        },
        Expr::Binary(BinaryOp::LogicalOr, a, b) => match (rewrite(a, facts), rewrite(b, facts)) {
            (Expr::Int(1), _) | (_, Expr::Int(1)) => Expr::Int(1),
            (Expr::Int(0), other) | (other, Expr::Int(0)) => other,
            (a, b) => Expr::binary(BinaryOp::LogicalOr, a, b),
        },
        Expr::Unary(UnaryOp::LogicalNot, inner) => match rewrite(inner, facts) {
            Expr::Int(0) => Expr::Int(1),
            Expr::Int(1) => Expr::Int(0),
            other => other.not(),
        },
        other => other.clone(),
    };
}

/// Variables a list of statements assigns
fn assigned(stmts: &[Stmt], out: &mut HashSet<VarId>) {
    for stmt in stmts.iter() {
        match &stmt.kind {
            StmtKind::Assign(Expr::Var(v), _) => {
                out.insert(*v);
            }
            StmtKind::If(_, a, b) => {
                assigned(a, out);
                assigned(b, out);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) => assigned(body, out),
            StmtKind::For(init, _, step, body) => {
                assigned(std::slice::from_ref(&**init), out);
                assigned(std::slice::from_ref(&**step), out);
                assigned(body, out);
            }
            StmtKind::Switch(_, cases, default) => {
                cases.iter().for_each(|case| assigned(&case.body, out));
                assigned(default, out);
            }
            _ => {}
        }
    }
}

fn forget(facts: &mut Vec<Expr>, vars: &HashSet<VarId>) {
    facts.retain(|fact| !vars.iter().any(|&v| fact.uses(v)));
}

fn ends_with_jump(stmts: &[Stmt]) -> bool {
    return stmts.last().is_some_and(|s| s.is_jump());
}

/// Rewrites the tests of the statements with the facts known before them, whether something changed
fn known(stmts: &mut Vec<Stmt>, mut facts: Vec<Expr>, addressed: &HashSet<VarId>) -> bool {
    let mut changed = false;
    let mut index = 0;

    while index < stmts.len() {
        let mut replacement: Option<Vec<Stmt>> = None;

        // Inside a loop, the facts on the variables it assigns do not hold (nor after it)
        if matches!(stmts[index].kind, StmtKind::While(..) | StmtKind::DoWhile(..) | StmtKind::For(..)) {
            let mut written = HashSet::new();
            assigned(std::slice::from_ref(&stmts[index]), &mut written);
            forget(&mut facts, &written);

            if let StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) = &mut stmts[index].kind {
                changed |= known(body, facts.clone(), addressed);
            }

            index += 1;
            continue;
        }

        match &mut stmts[index].kind {
            StmtKind::Assign(Expr::Var(v), _) => {
                let v = *v;
                facts.retain(|fact| !fact.uses(v));
            }
            StmtKind::Label(_) => facts.clear(),
            StmtKind::If(cond, then, other) => {
                let rewritten = rewrite(cond, &facts);

                if rewritten != *cond {
                    *cond = rewritten;
                    changed = true;
                }

                match cond {
                    Expr::Int(0) => replacement = Some(std::mem::take(other)),
                    Expr::Int(1) => replacement = Some(std::mem::take(then)),
                    _ => {
                        let mut inside = facts.clone();
                        inside.extend(conjuncts(cond).into_iter().filter(|c| is_fact(c, addressed)));
                        changed |= known(then, inside, addressed);

                        let negated = cond.clone().not();
                        let mut outside = facts.clone();

                        if is_fact(&negated, addressed) {
                            outside.push(negated.clone());
                        }

                        changed |= known(other, outside, addressed);

                        let mut written = HashSet::new();
                        assigned(then, &mut written);
                        assigned(other, &mut written);

                        // Only one of the branches goes on: its condition holds after the test
                        let after = match (ends_with_jump(then), ends_with_jump(other)) {
                            (true, false) => conjuncts(&negated),
                            (false, true) => conjuncts(cond),
                            _ => Vec::new(),
                        };

                        forget(&mut facts, &written);
                        facts.extend(after.into_iter().filter(|c| is_fact(c, addressed) && !written.iter().any(|&v| c.uses(v))));
                    }
                }
            }
            StmtKind::Switch(_, cases, default) => {
                let mut written = HashSet::new();
                cases.iter().for_each(|case| assigned(&case.body, &mut written));
                assigned(default, &mut written);
                forget(&mut facts, &written);

                for case in cases.iter_mut() {
                    changed |= known(&mut case.body, facts.clone(), addressed);
                }

                changed |= known(default, facts.clone(), addressed);
            }
            _ => {}
        }

        match replacement {
            Some(kept) => {
                stmts.splice(index..index + 1, kept);
                changed = true;
            }
            None => index += 1,
        }
    }

    return changed;
}

/// if (a) { x } if (a && b) { y } if (a) { z } is if (a) { x if (b) { y } z }: the first condition is on variables
/// the bodies do not assign (the first test may have an else branch)
fn merge(stmts: &mut Vec<Stmt>, addressed: &HashSet<VarId>) -> bool {
    let mut changed = false;

    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::If(_, a, b) => {
                changed |= merge(a, addressed);
                changed |= merge(b, addressed);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => changed |= merge(body, addressed),
            StmtKind::Switch(_, cases, default) => {
                cases.iter_mut().for_each(|case| changed |= merge(&mut case.body, addressed));
                changed |= merge(default, addressed);
            }
            _ => {}
        }
    }

    let mut index = 0;

    while index + 1 < stmts.len() {
        let (StmtKind::If(first, x, other), StmtKind::If(second, _, other2)) = (&stmts[index].kind, &stmts[index + 1].kind) else {
            index += 1;
            continue;
        };

        let common = conjuncts(first);
        let parts = conjuncts(second);

        let mut written = HashSet::new();
        assigned(x, &mut written);
        assigned(other, &mut written);

        // The second test implies the first one: it runs in the first branch only
        let joinable = other2.is_empty()
            && !ends_with_jump(x)
            && parts.len() >= common.len()
            && parts[..common.len()] == common[..]
            && common.iter().all(|c| is_fact(c, addressed) && !written.iter().any(|&v| c.uses(v)));

        if !joinable {
            index += 1;
            continue;
        }

        let next = stmts.remove(index + 1);
        let StmtKind::If(_, y, _) = next.kind else {
            unreachable!("the statement is a test");
        };

        let StmtKind::If(_, x, _) = &mut stmts[index].kind else {
            unreachable!("the statement is a test");
        };

        match and_all(parts[common.len()..].to_vec()) {
            Some(rest) => x.push(Stmt { kind: StmtKind::If(rest, y, Vec::new()), addr: next.addr, note: next.note }),
            None => x.extend(y),
        }

        changed = true;
    }

    return changed;
}

/// Variables whose address an expression takes
fn addressed_in(e: &Expr, out: &mut HashSet<VarId>) {
    e.visit(&mut |e| {
        if let Expr::Unary(UnaryOp::AddrOf, inner) = e {
            let mut base = &**inner;

            while let Expr::Member(b, _, false) | Expr::Index(b, _) = base {
                base = b;
            }

            if let Expr::Var(v) = base {
                out.insert(*v);
            }
        }
    });
}

/// Variables whose address is taken (written through pointers)
fn addressed_vars(stmts: &[Stmt], out: &mut HashSet<VarId>) {
    for stmt in stmts.iter() {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::Return(Some(e)) | StmtKind::NoReturn(e) => addressed_in(e, out),
            StmtKind::Assign(a, b) => {
                addressed_in(a, out);
                addressed_in(b, out);
            }
            StmtKind::If(c, a, b) => {
                addressed_in(c, out);
                addressed_vars(a, out);
                addressed_vars(b, out);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                addressed_in(c, out);
                addressed_vars(body, out);
            }
            StmtKind::For(init, c, step, body) => {
                addressed_in(c, out);
                addressed_vars(std::slice::from_ref(&**init), out);
                addressed_vars(std::slice::from_ref(&**step), out);
                addressed_vars(body, out);
            }
            StmtKind::Switch(c, cases, default) => {
                addressed_in(c, out);
                cases.iter().for_each(|case| addressed_vars(&case.body, out));
                addressed_vars(default, out);
            }
            _ => {}
        }
    }
}

/// Removes the tests whose result is known, joins the tests that follow each other on the same condition
pub fn simplify(function: &mut CFunction) -> bool {
    let mut addressed = HashSet::new();
    addressed_vars(&function.body, &mut addressed);

    let mut changed = false;

    for _ in 0..4 {
        let round = known(&mut function.body, Vec::new(), &addressed) | merge(&mut function.body, &addressed);
        changed |= round;

        if !round {
            break;
        }
    }

    return changed;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(kind: StmtKind) -> Stmt {
        return Stmt::new(kind, None);
    }

    fn call(name: &str) -> Stmt {
        return stmt(StmtKind::Expr(Expr::Call(Box::new(Expr::Name(name.to_string())), Vec::new())));
    }

    #[test]
    fn known_conditions_and_joined_tests() {
        let (c, a, b) = (Expr::Var(0), Expr::Var(1), Expr::binary(BinaryOp::Lt, Expr::Var(2), Expr::Var(3)));
        let and = |x: &Expr, y: &Expr| Expr::binary(BinaryOp::LogicalAnd, x.clone(), y.clone());

        // while (1) { if (!c) break; if (a) { x } if (c && a && b) { y } if (c && a) { z } }
        let mut body = vec![stmt(StmtKind::While(
            Expr::Int(1),
            vec![
                stmt(StmtKind::If(c.clone().not(), vec![stmt(StmtKind::Break)], vec![])),
                stmt(StmtKind::If(a.clone(), vec![call("x")], vec![])),
                stmt(StmtKind::If(and(&and(&c, &a), &b), vec![call("y")], vec![])),
                stmt(StmtKind::If(and(&c, &a), vec![call("z")], vec![])),
            ],
        ))];

        let addressed = HashSet::new();
        assert!(known(&mut body, Vec::new(), &addressed));
        assert!(merge(&mut body, &addressed));

        let expected = vec![stmt(StmtKind::While(
            Expr::Int(1),
            vec![
                stmt(StmtKind::If(c.clone().not(), vec![stmt(StmtKind::Break)], vec![])),
                stmt(StmtKind::If(a.clone(), vec![call("x"), stmt(StmtKind::If(b.clone(), vec![call("y")], vec![])), call("z")], vec![])),
            ],
        ))];

        assert_eq!(body, expected);

        // A variable assigned between the test and the use: the fact is gone
        let mut body = vec![
            stmt(StmtKind::If(c.clone().not(), vec![stmt(StmtKind::Return(None))], vec![])),
            stmt(StmtKind::Assign(Expr::Var(0), Expr::Int(0))),
            stmt(StmtKind::If(c.clone(), vec![call("x")], vec![])),
        ];
        assert!(!known(&mut body, Vec::new(), &HashSet::new()));
    }
}
