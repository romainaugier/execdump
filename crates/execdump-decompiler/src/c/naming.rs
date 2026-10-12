/*
 * Variable names from their use: loop counters, results of well known functions, and the names
 * of the parameters they are passed to (fputs(s, stream) names its arguments s and stream)
 */

use super::ast::{mark_used, CFunction, Expr, Stmt, StmtKind, VarId};
use super::Context;

use std::collections::{HashMap, HashSet};

/// Names of the results of well known functions
const RESULTS: &[(&str, &str)] = &[
    ("strlen", "len"),
    ("wcslen", "len"),
    ("malloc", "ptr"),
    ("calloc", "ptr"),
    ("realloc", "ptr"),
    ("strdup", "str"),
    ("fopen", "fp"),
    ("fdopen", "fp"),
    ("open", "fd"),
    ("openat", "fd"),
    ("socket", "sock"),
    ("accept", "client"),
    ("getenv", "env"),
    ("read", "count"),
    ("write", "count"),
    ("fork", "pid"),
    ("getpid", "pid"),
    ("time", "now"),
    ("opendir", "dir"),
    ("readdir", "entry"),
    ("CreateFileA", "file"),
    ("CreateFileW", "file"),
    ("GetProcAddress", "proc"),
    ("LoadLibraryA", "module"),
    ("LoadLibraryW", "module"),
    ("GetModuleHandleA", "module"),
    ("GetModuleHandleW", "module"),
    ("VirtualAlloc", "mem"),
    ("HeapAlloc", "mem"),
];

const KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "int", "long", "register", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "bool", "this", "new", "delete",
];

struct Hints {
    names: HashMap<VarId, String>,
    loop_depth: usize,
}

impl Hints {
    fn hint(&mut self, var: VarId, name: &str) {
        self.names.entry(var).or_insert_with(|| name.to_string());
    }

    fn expr(&mut self, e: &Expr, ctx: &Context) {
        e.visit(&mut |e| {
            if let Expr::Call(callee, args) = e {
                let Expr::Name(name) = &**callee else {
                    return;
                };

                let Some(prototype) = ctx.prototypes.get(name) else {
                    return;
                };

                for (arg, param) in args.iter().zip(prototype.ty.params.iter()) {
                    if let (Expr::Var(var), Some(param)) = (arg, &param.name) {
                        self.names.entry(*var).or_insert_with(|| param.clone());
                    }
                }
            }
        });
    }

    fn stmts(&mut self, stmts: &[Stmt], ctx: &Context) {
        for stmt in stmts {
            match &stmt.kind {
                StmtKind::Assign(Expr::Var(var), value) => {
                    if let Expr::Call(callee, _) = value {
                        if let Expr::Name(name) = &**callee {
                            if let Some((_, result)) = RESULTS.iter().find(|(f, _)| f == name) {
                                self.hint(*var, result);
                            }
                        }
                    }

                    self.expr(value, ctx);
                }
                StmtKind::Assign(target, value) => {
                    self.expr(target, ctx);
                    self.expr(value, ctx);
                }
                StmtKind::Expr(e) | StmtKind::Return(Some(e)) | StmtKind::NoReturn(e) => self.expr(e, ctx),
                StmtKind::If(c, a, b) => {
                    self.expr(c, ctx);
                    self.stmts(a, ctx);
                    self.stmts(b, ctx);
                }
                StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                    self.expr(c, ctx);
                    self.stmts(body, ctx);
                }
                StmtKind::For(init, c, _, body) => {
                    if let StmtKind::Assign(Expr::Var(var), _) = &init.kind {
                        let counter = ["i", "j", "k", "l", "m", "n"].get(self.loop_depth).copied().unwrap_or("idx");
                        self.names.insert(*var, counter.to_string());
                    }

                    self.expr(c, ctx);
                    self.loop_depth += 1;
                    self.stmts(body, ctx);
                    self.loop_depth -= 1;
                }
                StmtKind::Switch(c, cases, default) => {
                    self.expr(c, ctx);
                    cases.iter().for_each(|case| self.stmts(&case.body, ctx));
                    self.stmts(default, ctx);
                }
                _ => {}
            }
        }
    }
}

pub fn name(function: &mut CFunction, ctx: &Context) {
    let mut hints = Hints { names: HashMap::new(), loop_depth: 0 };
    hints.stmts(&function.body, ctx);

    let mut taken: HashSet<String> = KEYWORDS.iter().map(|k| k.to_string()).collect();
    taken.extend(ctx.prototypes.keys().cloned());
    taken.extend(ctx.globals.keys().cloned());
    taken.insert(function.name.clone());

    let unique = |base: &str, taken: &mut HashSet<String>| -> String {
        let mut name = base.to_string();
        let mut n = 2;

        while taken.contains(&name) {
            name = format!("{}{}", base, n);
            n += 1;
        }

        taken.insert(name.clone());
        name
    };

    // Parameters keep the names of their prototype
    for (position, &param) in function.params.iter().enumerate() {
        let var = &mut function.vars[param];

        if var.name.is_empty() {
            var.name = hints.names.get(&param).cloned().unwrap_or_else(|| format!("a{}", position + 1));
        }

        var.name = unique(&var.name, &mut taken);
    }

    let mut next = 1;
    let mut used = vec![false; function.vars.len()];
    mark_used(&function.body, &mut used);

    for id in 0..function.vars.len() {
        if function.params.contains(&id) || !used[id] {
            continue;
        }

        let base = match hints.names.get(&id) {
            Some(name) => name.clone(),
            None => {
                next += 1;
                format!("v{}", next - 1)
            }
        };

        function.vars[id].name = unique(&base, &mut taken);
    }
}
