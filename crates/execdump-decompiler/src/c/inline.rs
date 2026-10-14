/*
 * Trivial functions: a body of one statement with no effect of its own (abort();, return f(a1, a2);,
 * return 42;, return &g;). Their callers show that statement instead of the call, with the arguments
 * in place of the parameters.
 */

use super::ast::{CFunction, Expr, Stmt, StmtKind, UnaryOp, VarId};

/// The statement of a trivial function, on its parameters
#[derive(Clone, Debug, PartialEq)]
pub struct Trivial {
    params: Vec<VarId>,
    body: Expr,
}

/// An expression that can be repeated or dropped: a variable, a constant, a global
fn is_simple(e: &Expr) -> bool {
    return match e {
        Expr::Var(_) | Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Char(_) | Expr::Name(_) => true,
        Expr::Unary(UnaryOp::AddrOf, inner) => matches!(**inner, Expr::Name(_) | Expr::Var(_)),
        Expr::Unary(UnaryOp::Neg, inner) => matches!(**inner, Expr::Int(_) | Expr::Float(_)),
        _ => false,
    };
}

/// Calls of these stay calls: what they do depends on where they are
fn is_opaque(name: &str) -> bool {
    return name == "__asm__" || name == "__indirect_jump" || name.starts_with("__read") || name.starts_with("__write");
}

impl Trivial {
    /// The statement of a function when it is trivial: a call whose arguments are its parameters or
    /// constants, or the return of a constant, a global or a parameter
    pub fn of(function: &CFunction) -> Option<Trivial> {
        if function.variadic {
            return None;
        }

        let [stmt] = function.body.as_slice() else {
            return None;
        };

        let body = match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => e,
            _ => return None,
        };

        let only_params = |e: &Expr| {
            let mut ok = true;
            e.visit(&mut |e| ok &= !matches!(e, Expr::Var(v) if !function.params.contains(v)));
            ok
        };

        let shape = match body {
            Expr::Call(callee, args) => match &**callee {
                Expr::Name(name) => *name != function.name && !is_opaque(name) && args.iter().all(is_simple),
                _ => false,
            },
            _ => matches!(stmt.kind, StmtKind::Return(_)) && is_simple(body),
        };

        return (shape && only_params(body)).then(|| Trivial { params: function.params.clone(), body: body.clone() });
    }

    /// Whether the statement is a call (it has an effect, a function only returning a value does not)
    pub fn is_call(&self) -> bool {
        return matches!(self.body, Expr::Call(..));
    }

    /// The statement for a call with these arguments: an argument used more than once, or not at all,
    /// has to be simple (its evaluation is repeated or dropped)
    pub fn apply(&self, args: &[Expr]) -> Option<Expr> {
        if args.len() != self.params.len() {
            return None;
        }

        for (&param, arg) in self.params.iter().zip(args.iter()) {
            let mut uses = 0;
            self.body.visit(&mut |e| uses += (*e == Expr::Var(param)) as usize);

            if uses != 1 && !is_simple(arg) {
                return None;
            }
        }

        return Some(substitute(&self.body, &self.params, args));
    }
}

fn substitute(e: &Expr, params: &[VarId], args: &[Expr]) -> Expr {
    let s = |e: &Expr| Box::new(substitute(e, params, args));

    return match e {
        Expr::Var(v) => params.iter().position(|p| p == v).map_or_else(|| e.clone(), |i| args[i].clone()),
        Expr::Unary(op, a) => Expr::Unary(*op, s(a)),
        Expr::Binary(op, a, b) => Expr::Binary(*op, s(a), s(b)),
        Expr::Cast(ty, a) => Expr::Cast(ty.clone(), s(a)),
        Expr::Index(a, b) => Expr::Index(s(a), s(b)),
        Expr::Member(a, field, arrow) => Expr::Member(s(a), field.clone(), *arrow),
        Expr::Call(callee, call_args) => Expr::Call(s(callee), call_args.iter().map(|a| substitute(a, params, args)).collect()),
        Expr::Ternary(a, b, c) => Expr::Ternary(s(a), s(b), s(c)),
        other => other.clone(),
    };
}

/// Trivial function called by name, with the note its call sites get (its name, when it has a symbol)
pub type Lookup<'a> = dyn Fn(&str) -> Option<(std::rc::Rc<Trivial>, Option<String>)> + 'a;

fn inline_expr(e: &mut Expr, lookup: &Lookup, notes: &mut Vec<String>) {
    match e {
        Expr::Unary(_, a) | Expr::Cast(_, a) | Expr::Member(a, ..) => inline_expr(a, lookup, notes),
        Expr::Binary(_, a, b) | Expr::Index(a, b) => {
            inline_expr(a, lookup, notes);
            inline_expr(b, lookup, notes);
        }
        Expr::Call(callee, args) => {
            args.iter_mut().for_each(|a| inline_expr(a, lookup, notes));

            let Expr::Name(name) = &**callee else {
                return;
            };

            if let Some((trivial, note)) = lookup(name) {
                if let Some(inlined) = trivial.apply(args) {
                    *e = inlined;
                    notes.extend(note);
                }
            }
        }
        Expr::Ternary(a, b, c) => {
            inline_expr(a, lookup, notes);
            inline_expr(b, lookup, notes);
            inline_expr(c, lookup, notes);
        }
        _ => {}
    }
}

fn has_call(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |e| found |= matches!(e, Expr::Call(..)));
    return found;
}

fn inline_stmts(stmts: &mut Vec<Stmt>, lookup: &Lookup) {
    for stmt in stmts.iter_mut() {
        let mut notes = Vec::new();

        match &mut stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => inline_expr(e, lookup, &mut notes),
            StmtKind::Assign(target, value) => {
                inline_expr(target, lookup, &mut notes);
                inline_expr(value, lookup, &mut notes);
            }
            StmtKind::If(c, a, b) => {
                inline_expr(c, lookup, &mut notes);
                inline_stmts(a, lookup);
                inline_stmts(b, lookup);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                inline_expr(c, lookup, &mut notes);
                inline_stmts(body, lookup);
            }
            StmtKind::For(init, c, step, body) => {
                for part in [&mut **init, &mut **step] {
                    match &mut part.kind {
                        StmtKind::Assign(target, value) => {
                            inline_expr(target, lookup, &mut notes);
                            inline_expr(value, lookup, &mut notes);
                        }
                        StmtKind::Expr(e) => inline_expr(e, lookup, &mut notes),
                        _ => {}
                    }
                }

                inline_expr(c, lookup, &mut notes);
                inline_stmts(body, lookup);
            }
            StmtKind::Switch(c, cases, default) => {
                inline_expr(c, lookup, &mut notes);
                cases.iter_mut().for_each(|case| inline_stmts(&mut case.body, lookup));
                inline_stmts(default, lookup);
            }
            _ => {}
        }

        if !notes.is_empty() {
            notes.dedup();
            stmt.note = Some(notes.join(", "));
        }
    }

    // A call to a function only returning a value does nothing
    stmts.retain(|s| !matches!(&s.kind, StmtKind::Expr(e) if !has_call(e)));
}

/// The calls to trivial functions become their statement
pub fn inline(function: &mut CFunction, lookup: &Lookup) {
    inline_stmts(&mut function.body, lookup);
}
