/*
 * Statement level simplifications: temporaries used once in the next statement are inlined
 */

use super::ast::{CFunction, Expr, Stmt, StmtKind, VarId};


fn count(stmts: &[Stmt], uses: &mut [usize], assigns: &mut [usize]) {
    let expr = |e: &Expr, uses: &mut [usize]| {
        e.visit(&mut |e| {
            if let Expr::Var(v) = e {
                uses[*v] += 1;
            }
        })
    };

    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Assign(Expr::Var(v), value) => {
                assigns[*v] += 1;
                expr(value, uses);
            }
            StmtKind::Assign(target, value) => {
                expr(target, uses);
                expr(value, uses);
            }
            StmtKind::Expr(e) | StmtKind::Return(Some(e)) | StmtKind::NoReturn(e) => expr(e, uses),
            StmtKind::If(c, a, b) => {
                expr(c, uses);
                count(a, uses, assigns);
                count(b, uses, assigns);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                expr(c, uses);
                count(body, uses, assigns);
            }
            StmtKind::For(init, c, step, body) => {
                count(std::slice::from_ref(init), uses, assigns);
                expr(c, uses);
                count(std::slice::from_ref(step), uses, assigns);
                count(body, uses, assigns);
            }
            StmtKind::Switch(c, cases, default) => {
                expr(c, uses);
                cases.iter().for_each(|case| count(&case.body, uses, assigns));
                count(default, uses, assigns);
            }
            _ => {}
        }
    }
}

fn has_call(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |e| found |= matches!(e, Expr::Call(..)));
    return found;
}

fn substitute(e: &Expr, var: VarId, value: &Expr) -> Expr {
    let s = |e: &Expr| Box::new(substitute(e, var, value));

    return match e {
        Expr::Var(v) if *v == var => value.clone(),
        Expr::Unary(op, a) => Expr::Unary(*op, s(a)),
        Expr::Binary(op, a, b) => Expr::Binary(*op, s(a), s(b)),
        Expr::Cast(ty, a) => Expr::Cast(ty.clone(), s(a)),
        Expr::Index(a, b) => Expr::Index(s(a), s(b)),
        Expr::Member(a, field, arrow) => Expr::Member(s(a), field.clone(), *arrow),
        Expr::Call(callee, args) => Expr::Call(s(callee), args.iter().map(|a| substitute(a, var, value)).collect()),
        Expr::Ternary(a, b, c) => Expr::Ternary(s(a), s(b), s(c)),
        other => other.clone(),
    };
}

/// The expression of a statement evaluated first, where a temporary can be inlined
fn head_expr(stmt: &mut Stmt) -> Option<&mut Expr> {
    return match &mut stmt.kind {
        StmtKind::Assign(Expr::Var(_), value) => Some(value),
        StmtKind::Expr(e) | StmtKind::Return(Some(e)) | StmtKind::NoReturn(e) | StmtKind::If(e, ..) | StmtKind::Switch(e, ..) => Some(e),
        _ => None,
    };
}

/// Assignments immediately read once by the next statement, counted by variable
fn count_pairs(stmts: &mut Vec<Stmt>, pairs: &mut [usize]) {
    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::If(_, a, b) => {
                count_pairs(a, pairs);
                count_pairs(b, pairs);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => count_pairs(body, pairs),
            StmtKind::Switch(_, cases, default) => {
                cases.iter_mut().for_each(|case| count_pairs(&mut case.body, pairs));
                count_pairs(default, pairs);
            }
            _ => {}
        }
    }

    for i in 0..stmts.len().saturating_sub(1) {
        let StmtKind::Assign(Expr::Var(var), _) = &stmts[i].kind else {
            continue;
        };

        let var = *var;

        if let Some(next) = head_expr(&mut stmts[i + 1]) {
            let mut uses = 0;
            next.visit(&mut |e| uses += (*e == Expr::Var(var)) as usize);

            if uses == 1 {
                pairs[var] += 1;
            }
        }
    }
}

/// Inlines the variables whose every assignment is read once by the next statement only
fn inline_temporaries(stmts: &mut Vec<Stmt>, inline: &[bool]) {
    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::If(_, a, b) => {
                inline_temporaries(a, inline);
                inline_temporaries(b, inline);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => inline_temporaries(body, inline),
            StmtKind::Switch(_, cases, default) => {
                cases.iter_mut().for_each(|case| inline_temporaries(&mut case.body, inline));
                inline_temporaries(default, inline);
            }
            _ => {}
        }
    }

    let mut i = 0;

    while i + 1 < stmts.len() {
        let StmtKind::Assign(Expr::Var(var), value) = &stmts[i].kind else {
            i += 1;
            continue;
        };

        let (var, value) = (*var, value.clone());

        let Some(next) = head_expr(&mut stmts[i + 1]) else {
            i += 1;
            continue;
        };

        // Calls keep their order with the other calls of the statement
        if !inline[var] || !next.uses(var) || (has_call(&value) && has_call(next)) {
            i += 1;
            continue;
        }

        *next = substitute(next, var, &value);

        if stmts[i + 1].addr.is_none() {
            stmts[i + 1].addr = stmts[i].addr;
        }

        stmts.remove(i);
    }
}

/// Assignments to variables nobody reads, the calls in them stay as statements
fn remove_dead(stmts: &mut Vec<Stmt>, uses: &[usize]) {
    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::Assign(Expr::Var(v), value) if uses[*v] == 0 => {
                if let Expr::Call(..) = value {
                    stmt.kind = StmtKind::Expr(value.clone());
                }
            }
            StmtKind::If(_, a, b) => {
                remove_dead(a, uses);
                remove_dead(b, uses);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => remove_dead(body, uses),
            StmtKind::Switch(_, cases, default) => {
                cases.iter_mut().for_each(|case| remove_dead(&mut case.body, uses));
                remove_dead(default, uses);
            }
            _ => {}
        }
    }

    stmts.retain(|s| !matches!(&s.kind, StmtKind::Assign(Expr::Var(v), value) if uses[*v] == 0 && !has_call(value)));
}

pub fn simplify(function: &mut CFunction) {
    for _ in 0..3 {
        let mut uses = vec![0; function.vars.len()];
        let mut assigns = vec![0; function.vars.len()];
        count(&function.body, &mut uses, &mut assigns);

        remove_dead(&mut function.body, &uses);

        let mut pairs = vec![0; function.vars.len()];
        count_pairs(&mut function.body, &mut pairs);

        let inline: Vec<bool> = (0..function.vars.len()).map(|v| !function.params.contains(&v) && pairs[v] > 0 && pairs[v] == uses[v] && pairs[v] == assigns[v]).collect();
        inline_temporaries(&mut function.body, &inline);
    }
}

/// return 0 in a function returning a pointer is return NULL
pub fn null_returns(function: &mut CFunction) {
    fn walk(stmts: &mut [Stmt]) {
        for stmt in stmts.iter_mut() {
            match &mut stmt.kind {
                StmtKind::Return(Some(value @ Expr::Int(0))) => *value = Expr::Name("NULL".to_string()),
                StmtKind::If(_, a, b) => {
                    walk(a);
                    walk(b);
                }
                StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => walk(body),
                StmtKind::Switch(_, cases, default) => {
                    cases.iter_mut().for_each(|case| walk(&mut case.body));
                    walk(default);
                }
                _ => {}
            }
        }
    }

    if matches!(function.ret.unqualified(), crate::types::CType::Pointer(_)) {
        walk(&mut function.body);
    }
}
