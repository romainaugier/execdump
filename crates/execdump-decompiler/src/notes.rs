// SPDX-License-Identifier: Apache-2.0
/*
 * User annotations of the decompiled C code: names and types of the variables, summaries and
 * prototypes typed by the user. Like the LLM suggestions, they edit the syntax tree and are validated
 * before being applied.
 */

use crate::c::ast::{CFunction, Expr, Stmt, StmtKind};
use crate::llm::{parse_type, valid_identifier};
use crate::typedb::TypeDb;
use crate::types::{CType, FuncType, Param, Prototype};

use anyhow::{bail, Context, Result};

use std::collections::{BTreeMap, BTreeSet};
use rustc_hash::{FxHashSet as HashSet};

/// New name and type of a parameter or a local variable
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VarNote {
    pub name: Option<String>,
    pub ty: Option<String>,
}

/// Renames and retypes the variables (keyed by the name the decompiler gave them), returns the notes
/// that could not be applied
pub fn apply_vars(function: &mut CFunction, notes: &BTreeMap<String, VarNote>, typedb: &TypeDb) -> Vec<String> {
    let mut errors = Vec::new();
    let mut names: HashSet<String> = function.vars.iter().map(|v| v.name.clone()).collect();

    for (original, note) in notes.iter() {
        let Some(id) = function.vars.iter().position(|v| v.name == *original) else {
            errors.push(format!("{}: no such variable", original));
            continue;
        };

        if let Some(ty) = note.ty.as_deref() {
            match parse_type(ty, typedb) {
                Some(ty) if same_size(typedb, &ty, &function.vars[id].ty) => function.vars[id].ty = ty,
                Some(_) => errors.push(format!("{}: {} does not have the size of {}", original, ty, function.vars[id].ty)),
                None => errors.push(format!("{}: unknown type {}", original, ty)),
            }
        }

        if let Some(name) = note.name.as_deref().filter(|n| *n != original) {
            if !valid_identifier(name) || names.contains(name) {
                errors.push(format!("{}: {} is not a free C identifier", original, name));
                continue;
            }

            names.remove(original);
            names.insert(name.to_string());
            function.vars[id].name = name.to_string();
        }
    }

    return errors;
}

fn same_size(typedb: &TypeDb, a: &CType, b: &CType) -> bool {
    return match (typedb.size_of(a), typedb.size_of(b)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
}

/// Puts a summary comment at the top of the body
pub fn apply_summary(function: &mut CFunction, summary: &str) {
    for line in summary.lines().map(str::trim).filter(|l| !l.is_empty()).rev() {
        let line: String = line.chars().filter(|c| !c.is_control()).collect();
        function.body.insert(0, Stmt::new(StmtKind::Comment(line), None));
    }
}

/// Prototype typed by the user: "int parse(const char *text, size_t size)", parameters of the known
/// types only (builtins, typedefs and structs of the type database, with const and pointers)
pub fn parse_prototype(text: &str, typedb: &TypeDb) -> Result<Prototype> {
    let text = text.trim().trim_end_matches(';').trim();
    let open = text.find('(').context("expected a prototype such as int f(char *s)")?;
    let close = text.rfind(')').filter(|&c| c > open).context("missing )")?;

    let (ret, name) = split_declaration(&text[..open])?;
    let ret = if ret == "void" { CType::Void } else { parse_type(&ret, typedb).with_context(|| format!("unknown type {}", ret))? };

    let mut params = Vec::new();
    let mut variadic = false;
    let inside = text[open + 1..close].trim();

    if !inside.is_empty() && inside != "void" {
        for (index, param) in inside.split(',').map(str::trim).enumerate() {
            if param == "..." {
                variadic = true;
                continue;
            }

            // A parameter without a name is a type alone
            let (ty, name) = match split_declaration(param) {
                Ok((ty, name)) if parse_type(&ty, typedb).is_some() => (ty, Some(name)),
                _ => (param.to_string(), None),
            };

            let ty = parse_type(&ty, typedb).with_context(|| format!("parameter {}: unknown type {}", index + 1, ty))?;
            params.push(Param { name, ty });
        }
    }

    return Ok(Prototype { name, ty: FuncType { ret, params, variadic } });
}

/// "const char *name" to ("const char *", "name")
fn split_declaration(text: &str) -> Result<(String, String)> {
    let text = text.trim();
    let start = text.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |i| i + 1);
    let name = &text[start..];
    let ty = text[..start].trim();

    if ty.is_empty() || !valid_identifier(name) {
        bail!("expected a type and a name in \"{}\"", text);
    }

    return Ok((ty.to_string(), name.to_string()));
}

/// Names a function refers to: the functions it calls, and the other names (globals, functions taken by address)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsedNames {
    pub calls: BTreeSet<String>,
    pub others: BTreeSet<String>,
}

pub fn used_names(function: &CFunction) -> UsedNames {
    let mut used = UsedNames::default();

    fn expr(e: &Expr, used: &mut UsedNames) {
        match e {
            Expr::Call(callee, args) => {
                match &**callee {
                    Expr::Name(name) => {
                        used.calls.insert(name.clone());
                    }
                    other => expr(other, used),
                }

                args.iter().for_each(|a| expr(a, used));
            }
            Expr::Name(name) => {
                used.others.insert(name.clone());
            }
            Expr::Unary(_, a) | Expr::Cast(_, a) | Expr::Member(a, ..) => expr(a, used),
            Expr::Binary(_, a, b) | Expr::Index(a, b) => {
                expr(a, used);
                expr(b, used);
            }
            Expr::Ternary(a, b, c) => {
                expr(a, used);
                expr(b, used);
                expr(c, used);
            }
            _ => {}
        }
    }

    fn stmts(list: &[Stmt], used: &mut UsedNames) {
        for stmt in list {
            match &stmt.kind {
                StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => expr(e, used),
                StmtKind::Assign(a, b) => {
                    expr(a, used);
                    expr(b, used);
                }
                StmtKind::If(c, a, b) => {
                    expr(c, used);
                    stmts(a, used);
                    stmts(b, used);
                }
                StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                    expr(c, used);
                    stmts(body, used);
                }
                StmtKind::For(init, c, step, body) => {
                    stmts(std::slice::from_ref(init), used);
                    expr(c, used);
                    stmts(std::slice::from_ref(step), used);
                    stmts(body, used);
                }
                StmtKind::Switch(c, cases, default) => {
                    expr(c, used);
                    cases.iter().for_each(|case| stmts(&case.body, used));
                    stmts(default, used);
                }
                _ => {}
            }
        }
    }

    stmts(&function.body, &mut used);
    used.others.retain(|n| !used.calls.contains(n));

    return used;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::c::ast::Var;
    use crate::typedb::Platform;
    use crate::types::DataModel;

    use execdump_core::disasm::Architecture;

    fn typedb() -> TypeDb {
        return TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
    }

    fn function() -> CFunction {
        return CFunction {
            name: "sub_1000".to_string(),
            ret: CType::int(32),
            params: vec![0],
            variadic: false,
            vars: vec![Var { name: "a1".to_string(), ty: CType::int(64) }, Var { name: "v1".to_string(), ty: CType::int(32) }],
            body: vec![
                Stmt::new(StmtKind::Assign(Expr::Var(1), Expr::Call(Box::new(Expr::Name("sub_2000".to_string())), vec![Expr::Var(0), Expr::Name("g_4000".to_string())])), Some(0x1000)),
                Stmt::new(StmtKind::Return(Some(Expr::Var(1))), Some(0x1004)),
            ],
            addr: 0x1000,
            globals: Vec::new(),
            inlined: false,
            storage: Default::default(),
            structs: Vec::new(),
        };
    }

    #[test]
    fn variables() {
        let typedb = typedb();
        let mut f = function();

        let notes: BTreeMap<String, VarNote> = [
            ("a1".to_string(), VarNote { name: Some("text".to_string()), ty: Some("const char *".to_string()) }),
            ("v1".to_string(), VarNote { name: Some("text".to_string()), ty: Some("char".to_string()) }),
            ("v9".to_string(), VarNote { name: Some("x".to_string()), ty: None }),
        ].into_iter().collect();

        let errors = apply_vars(&mut f, &notes, &typedb);
        assert_eq!(errors.len(), 3, "{:?}", errors);
        assert_eq!(f.vars[0].name, "text");
        assert_eq!(f.vars[1].name, "v1");

        apply_summary(&mut f, "Counts things.");
        let printed = f.print().text;
        assert!(printed.starts_with("int sub_1000(const char *text)"), "{}", printed);
        assert!(printed.contains("// Counts things."), "{}", printed);
    }

    #[test]
    fn prototypes() {
        let typedb = typedb();

        let p = parse_prototype("size_t parse(const char *text, struct stat *, ...);", &typedb).unwrap();
        assert_eq!(p.to_string(), "size_t parse(const char *text, struct stat *, ...)");

        let p = parse_prototype("void run(void)", &typedb).unwrap();
        assert_eq!(p.to_string(), "void run(void)");

        assert!(parse_prototype("int f(my_type x)", &typedb).is_err());
        assert!(parse_prototype("int (x)", &typedb).is_err());
    }

    #[test]
    fn names() {
        let used = used_names(&function());
        assert_eq!(used.calls.into_iter().collect::<Vec<_>>(), ["sub_2000"]);
        assert_eq!(used.others.into_iter().collect::<Vec<_>>(), ["g_4000"]);
    }
}
