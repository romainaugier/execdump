// SPDX-License-Identifier: Apache-2.0
/*
 * Variable names from their use: loop counters, results of well known functions, and the names
 * of the parameters they are passed to (fputs(s, stream) names its arguments s and stream)
 */

use super::ast::{mark_used, CFunction, Expr, Stmt, StmtKind, VarId};
use super::Context;

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

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
    /// Variables that are pointers (a for loop walking a list or a buffer moves a pointer, not a counter)
    pointers: HashSet<VarId>,
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

                let Some(prototype) = ctx.prototype(name) else {
                    return;
                };

                for (arg, param) in args.iter().zip(prototype.ty.params.iter()) {
                    if let (Expr::Var(var), Some(param)) = (arg, param.name.as_ref().filter(|n| !generated(n))) {
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
                        let counters: &[&str] = if self.pointers.contains(var) { &["p", "q", "r"] } else { &["i", "j", "k", "l", "m", "n"] };
                        let counter = counters.get(self.loop_depth).copied().unwrap_or("idx");
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

/// Names given when nothing better is known (a1, v3): they tell nothing about what is passed
fn generated(name: &str) -> bool {
    let digits = name.get(1..).unwrap_or_default();
    return (name.starts_with('a') || name.starts_with('v')) && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
}

pub fn name(function: &mut CFunction, ctx: &Context) {
    let pointers = function.vars.iter().enumerate().filter(|(_, v)| super::typing::is_pointer(&v.ty)).map(|(i, _)| i).collect();
    let mut hints = Hints { names: HashMap::default(), loop_depth: 0, pointers };
    hints.stmts(&function.body, ctx);

    // The names of the program (functions and globals) are looked up in place, they are too many to copy
    let mut taken: HashSet<String> = KEYWORDS.iter().map(|k| k.to_string()).collect();
    taken.insert(function.name.clone());

    let unique = |base: &str, taken: &mut HashSet<String>| -> String {
        let mut name = base.to_string();
        let mut n = 2;

        while taken.contains(&name) || ctx.prototype(&name).is_some() || ctx.globals.contains_key(&name) {
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
