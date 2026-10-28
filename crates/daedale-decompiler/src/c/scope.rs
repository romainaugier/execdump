// SPDX-License-Identifier: Apache-2.0
/*
 * Scope of the local variables: each one is declared at the start of the narrowest block that holds
 * all its uses, when entering that block always writes it before reading it (a value kept from one
 * entry to the next, a loop variable, needs the block around). Blocks with labels are left out (a goto
 * enters them past their start). A case of a switch that declares variables is printed as a block.
 */

use super::ast::{CFunction, Expr, Stmt, StmtKind, VarId};

use rustc_hash::{FxHashMap as HashMap};

/// Identity of a statement list: its address while the function is borrowed
pub type ListId = usize;

pub fn list_id(stmts: &[Stmt]) -> ListId {
    return stmts.as_ptr() as usize;
}

struct Walk<'a> {
    /// Narrowest list holding every use of a variable so far, as the lists from the body down
    common: HashMap<VarId, Vec<ListId>>,
    lists: HashMap<ListId, &'a [Stmt]>,
    path: Vec<ListId>,
}

impl<'a> Walk<'a> {
    fn uses(&mut self, e: &Expr) {
        let mut vars = Vec::new();
        e.visit(&mut |e| {
            if let Expr::Var(v) = e {
                vars.push(*v);
            }
        });

        for var in vars {
            self.used(var);
        }
    }

    fn used(&mut self, var: VarId) {
        match self.common.get_mut(&var) {
            Some(common) => {
                let same = common.iter().zip(self.path.iter()).take_while(|(a, b)| a == b).count();
                common.truncate(same);
            }
            None => {
                self.common.insert(var, self.path.clone());
            }
        }
    }

    fn list(&mut self, stmts: &'a [Stmt]) {
        self.path.push(list_id(stmts));
        self.lists.insert(list_id(stmts), stmts);

        for stmt in stmts {
            self.stmt(stmt);
        }

        self.path.pop();
    }

    fn stmt(&mut self, stmt: &'a Stmt) {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => self.uses(e),
            StmtKind::Assign(a, b) => {
                self.uses(a);
                self.uses(b);
            }
            StmtKind::If(c, a, b) => {
                self.uses(c);
                self.list(a);
                self.list(b);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                self.uses(c);
                self.list(body);
            }
            StmtKind::For(init, c, step, body) => {
                self.stmt(init);
                self.uses(c);
                self.stmt(step);
                self.list(body);
            }
            // A case declaring variables is a block of its own
            StmtKind::Switch(c, cases, default) => {
                self.uses(c);
                cases.iter().for_each(|case| self.list(&case.body));
                self.list(default);
            }
            _ => {}
        }
    }
}

fn has_label(stmts: &[Stmt]) -> bool {
    return stmts.iter().any(|s| match &s.kind {
        StmtKind::Label(_) => true,
        StmtKind::If(_, a, b) => has_label(a) || has_label(b),
        StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => has_label(body),
        StmtKind::Switch(_, cases, default) => cases.iter().any(|c| has_label(&c.body)) || has_label(default),
        _ => false,
    });
}

/// Whether a list may read the variable before writing it, when entered with it written or not. Returns
/// that, and whether the variable is written once the list is done.
fn exposed(stmts: &[Stmt], var: VarId, mut written: bool) -> (bool, bool) {
    let reads = |e: &Expr| e.uses(var);

    for stmt in stmts {
        let read = match &stmt.kind {
            StmtKind::Assign(Expr::Var(v), value) if *v == var => {
                let read = !written && reads(value);
                written = true;
                read
            }
            StmtKind::Assign(target, value) => !written && (reads(target) || reads(value)),
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => !written && reads(e),
            StmtKind::If(c, a, b) => {
                let (ea, wa) = exposed(a, var, written);
                let (eb, wb) = exposed(b, var, written);
                let read = (!written && reads(c)) || ea || eb;
                written |= wa && wb;
                read
            }
            StmtKind::While(c, body) => (!written && reads(c)) || exposed(body, var, written).0,
            StmtKind::DoWhile(body, c) => {
                let (e, w) = exposed(body, var, written);
                let read = e || (!(written || w) && reads(c));
                written |= w;
                read
            }
            StmtKind::For(init, c, step, body) => {
                let (ei, wi) = exposed(std::slice::from_ref(init), var, written);
                let after_init = written || wi;
                let (eb, wb) = exposed(body, var, after_init);
                let (es, _) = exposed(std::slice::from_ref(step), var, after_init || wb);
                let read = ei || (!after_init && reads(c)) || eb || es;
                written = after_init;
                read
            }
            StmtKind::Switch(c, cases, default) => (!written && reads(c)) || cases.iter().any(|case| exposed(&case.body, var, written).0) || exposed(default, var, written).0,
            _ => false,
        };

        if read {
            return (true, written);
        }
    }

    return (false, written);
}

/// The local variables to declare at the start of each list (the body of the function holds the ones
/// that cannot go deeper)
pub fn declarations(function: &CFunction, locals: &[VarId]) -> HashMap<ListId, Vec<VarId>> {
    let mut walk = Walk { common: HashMap::default(), lists: HashMap::default(), path: Vec::new() };
    walk.list(&function.body);

    let body = list_id(&function.body);
    let mut declared: HashMap<ListId, Vec<VarId>> = HashMap::default();

    for &var in locals {
        let mut path = walk.common.get(&var).cloned().unwrap_or_default();

        // Up from the narrowest list until one is always entered with the variable written before read
        while path.len() > 1 {
            let list = walk.lists[path.last().unwrap()];

            if !has_label(list) && !exposed(list, var, false).0 {
                break;
            }

            path.pop();
        }

        declared.entry(path.last().copied().unwrap_or(body)).or_default().push(var);
    }

    return declared;
}
