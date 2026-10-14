/*
 * C abstract syntax tree and printer, every statement keeps the address it comes from
 */

use super::scope::{self, list_id, ListId};
use crate::types::{CType, FuncType, Param, Prototype};

use std::collections::HashMap;
use std::fmt::Write;

pub type VarId = usize;

#[derive(Clone, Debug, PartialEq)]
pub struct Var {
    pub name: String,
    pub ty: CType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    LogicalNot,
    Deref,
    AddrOf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    And,
    Xor,
    Or,
    LogicalAnd,
    LogicalOr,
}

impl BinaryOp {
    pub fn symbol(self) -> &'static str {
        match self {
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Rem => "%",
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Shl => "<<",
            BinaryOp::Shr => ">>",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::And => "&",
            BinaryOp::Xor => "^",
            BinaryOp::Or => "|",
            BinaryOp::LogicalAnd => "&&",
            BinaryOp::LogicalOr => "||",
        }
    }

    /// C precedence, lower binds tighter
    fn precedence(self) -> u8 {
        match self {
            BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => 3,
            BinaryOp::Add | BinaryOp::Sub => 4,
            BinaryOp::Shl | BinaryOp::Shr => 5,
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => 6,
            BinaryOp::Eq | BinaryOp::Ne => 7,
            BinaryOp::And => 8,
            BinaryOp::Xor => 9,
            BinaryOp::Or => 10,
            BinaryOp::LogicalAnd => 11,
            BinaryOp::LogicalOr => 12,
        }
    }

    pub fn is_bitwise(self) -> bool {
        return matches!(self, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor | BinaryOp::Shl | BinaryOp::Shr);
    }

    pub fn is_comparison(self) -> bool {
        return matches!(self, BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge | BinaryOp::Eq | BinaryOp::Ne);
    }

    /// !(a < b) is a >= b
    pub fn negated(self) -> Option<BinaryOp> {
        return Some(match self {
            BinaryOp::Lt => BinaryOp::Ge,
            BinaryOp::Le => BinaryOp::Gt,
            BinaryOp::Gt => BinaryOp::Le,
            BinaryOp::Ge => BinaryOp::Lt,
            BinaryOp::Eq => BinaryOp::Ne,
            BinaryOp::Ne => BinaryOp::Eq,
            _ => return None,
        });
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Var(VarId),
    Int(i128),
    Float(f64),
    Str(String),
    Char(u8),
    /// Global variable or function
    Name(String),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    Cast(CType, Box<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Member(Box<Expr>, String, bool),
    Call(Box<Expr>, Vec<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

impl Expr {
    /// *&x is x, &*p is p
    pub fn unary(op: UnaryOp, e: Expr) -> Expr {
        return match (op, e) {
            (UnaryOp::Deref, Expr::Unary(UnaryOp::AddrOf, inner)) | (UnaryOp::AddrOf, Expr::Unary(UnaryOp::Deref, inner)) => *inner,
            (op, e) => Expr::Unary(op, Box::new(e)),
        };
    }

    pub fn binary(op: BinaryOp, a: Expr, b: Expr) -> Expr {
        return Expr::Binary(op, Box::new(a), Box::new(b));
    }

    pub fn cast(ty: CType, e: Expr) -> Expr {
        return Expr::Cast(ty, Box::new(e));
    }

    /// Logical negation, comparisons are inverted instead of wrapped
    pub fn not(self) -> Expr {
        match self {
            Expr::Unary(UnaryOp::LogicalNot, inner) => *inner,
            Expr::Binary(op, a, b) if op.negated().is_some() => Expr::Binary(op.negated().unwrap(), a, b),
            Expr::Binary(BinaryOp::LogicalAnd, a, b) => Expr::binary(BinaryOp::LogicalOr, a.not(), b.not()),
            Expr::Binary(BinaryOp::LogicalOr, a, b) => Expr::binary(BinaryOp::LogicalAnd, a.not(), b.not()),
            other => Expr::unary(UnaryOp::LogicalNot, other),
        }
    }

    fn precedence(&self) -> u8 {
        match self {
            Expr::Var(_) | Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Char(_) | Expr::Name(_) => 0,
            Expr::Index(..) | Expr::Member(..) | Expr::Call(..) => 1,
            Expr::Unary(..) | Expr::Cast(..) => 2,
            Expr::Binary(op, ..) => op.precedence(),
            Expr::Ternary(..) => 13,
        }
    }

    /// Calls the function on the expression and all its subexpressions
    pub fn visit(&self, f: &mut impl FnMut(&Expr)) {
        f(self);

        match self {
            Expr::Unary(_, e) | Expr::Cast(_, e) | Expr::Member(e, ..) => e.visit(f),
            Expr::Binary(_, a, b) | Expr::Index(a, b) => {
                a.visit(f);
                b.visit(f);
            }
            Expr::Call(callee, args) => {
                callee.visit(f);
                args.iter().for_each(|a| a.visit(f));
            }
            Expr::Ternary(a, b, c) => {
                a.visit(f);
                b.visit(f);
                c.visit(f);
            }
            _ => {}
        }
    }

    pub fn uses(&self, var: VarId) -> bool {
        let mut found = false;
        self.visit(&mut |e| found |= *e == Expr::Var(var));
        return found;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Case {
    pub values: Vec<i128>,
    pub body: Vec<Stmt>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StmtKind {
    Expr(Expr),
    Assign(Expr, Expr),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    While(Expr, Vec<Stmt>),
    DoWhile(Vec<Stmt>, Expr),
    For(Box<Stmt>, Expr, Box<Stmt>, Vec<Stmt>),
    Switch(Expr, Vec<Case>, Vec<Stmt>),
    Break,
    Continue,
    Return(Option<Expr>),
    Goto(String),
    Label(String),
    Comment(String),
    /// Call to a function that does not return
    NoReturn(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub addr: Option<u64>,
    /// Comment at the end of its first line
    pub note: Option<String>,
}

impl Stmt {
    pub fn new(kind: StmtKind, addr: Option<u64>) -> Self {
        return Stmt { kind, addr, note: None };
    }

    /// Statements after which the execution does not continue (calls to noreturn functions are NoReturn)
    pub fn is_jump(&self) -> bool {
        return matches!(self.kind, StmtKind::Break | StmtKind::Continue | StmtKind::Return(_) | StmtKind::Goto(_) | StmtKind::NoReturn(_));
    }
}

#[derive(Clone, Debug)]
pub struct CFunction {
    pub name: String,
    pub ret: CType,
    pub params: Vec<VarId>,
    pub variadic: bool,
    pub vars: Vec<Var>,
    pub body: Vec<Stmt>,
    pub addr: u64,
    /// Type each global is accessed with (an array of unknown size when indexed), None when the
    /// accesses do not agree
    pub globals: Vec<(String, Option<CType>)>,
    /// Its callers show its only statement instead of calling it, it is printed on one line
    pub inlined: bool,
}

/// Printed C code with the address of each line
pub struct Printed {
    pub text: String,
    pub lines: Vec<Option<u64>>,
}

struct Printer<'a> {
    function: &'a CFunction,
    out: String,
    lines: Vec<Option<u64>>,
    /// Note of the statement being printed, at the end of its first line
    note: Option<String>,
    /// Local variables declared at the start of the nested blocks
    declared: HashMap<ListId, Vec<VarId>>,
}

const INDENT: &str = "    ";

impl Printer<'_> {
    fn line(&mut self, depth: usize, text: &str, addr: Option<u64>) {
        for _ in 0..depth {
            self.out.push_str(INDENT);
        }

        self.out.push_str(text);

        if let Some(note) = self.note.take() {
            self.out.push_str(" // ");
            self.out.push_str(&note);
        }

        self.out.push('\n');
        self.lines.push(addr);
    }

    fn var(&self, id: VarId) -> &str {
        return &self.function.vars[id].name;
    }

    fn expr(&self, e: &Expr) -> String {
        let mut out = String::new();
        self.write_expr(&mut out, e, 15);
        return out;
    }

    /// Writes an expression, parenthesized when its precedence is looser than the context allows
    fn write_expr(&self, out: &mut String, e: &Expr, context: u8) {
        let parens = e.precedence() > context;

        if parens {
            out.push('(');
        }

        match e {
            Expr::Var(id) => out.push_str(self.var(*id)),
            Expr::Int(value) if *value > 255 && (*value & 0xff == 0 || *value > 0xffff) => {
                let _ = write!(out, "{:#x}", value);
            }
            Expr::Int(value) if *value < -0xffff => {
                let _ = write!(out, "-{:#x}", -value);
            }
            Expr::Int(value) => {
                let _ = write!(out, "{}", value);
            }
            Expr::Float(value) => {
                let _ = write!(out, "{:?}", value);
            }
            Expr::Str(text) => {
                out.push('"');
                out.push_str(&escape(text));
                out.push('"');
            }
            Expr::Char(c) => {
                let _ = write!(out, "'{}'", escape(&(*c as char).to_string()).replace('\'', "\\'"));
            }
            Expr::Name(name) => out.push_str(name),
            Expr::Unary(op, inner) => {
                out.push_str(match op {
                    UnaryOp::Neg => "-",
                    UnaryOp::Not => "~",
                    UnaryOp::LogicalNot => "!",
                    UnaryOp::Deref => "*",
                    UnaryOp::AddrOf => "&",
                });
                self.write_expr(out, inner, 2);
            }
            Expr::Binary(op, a, b) => {
                // Bitwise operations inside other operations keep their parentheses for clarity
                let context = |operand: &Expr, context: u8| match operand {
                    Expr::Binary(inner, ..) if inner != op && inner.is_bitwise() => 0,
                    _ => context,
                };

                self.write_expr(out, a, context(a, op.precedence()));
                let _ = write!(out, " {} ", op.symbol());
                // Left associative: a - (b - c) needs its parentheses
                self.write_expr(out, b, context(b, op.precedence() - 1));
            }
            Expr::Cast(ty, inner) => {
                let _ = write!(out, "({})", ty.declare(""));
                self.write_expr(out, inner, 2);
            }
            Expr::Index(base, index) => {
                self.write_expr(out, base, 1);
                out.push('[');
                self.write_expr(out, index, 15);
                out.push(']');
            }
            Expr::Member(base, field, arrow) => {
                self.write_expr(out, base, 1);
                out.push_str(if *arrow { "->" } else { "." });
                out.push_str(field);
            }
            Expr::Call(callee, args) => {
                self.write_expr(out, callee, 1);
                out.push('(');

                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }

                    self.write_expr(out, arg, 14);
                }

                out.push(')');
            }
            Expr::Ternary(c, a, b) => {
                self.write_expr(out, c, 12);
                out.push_str(" ? ");
                self.write_expr(out, a, 13);
                out.push_str(" : ");
                self.write_expr(out, b, 13);
            }
        }

        if parens {
            out.push(')');
        }
    }

    /// Statement without its terminating semicolon (for loops print them inline)
    fn simple(&self, stmt: &Stmt) -> String {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) => self.expr(e),
            StmtKind::Assign(target, value) => self.assignment(target, value),
            _ => String::new(),
        }
    }

    /// x = x + 1 is x += 1, x += 1 is x++
    fn assignment(&self, target: &Expr, value: &Expr) -> String {
        let target_text = self.expr(target);

        if let Expr::Binary(op, a, b) = value {
            let compound = matches!(op, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem | BinaryOp::Shl | BinaryOp::Shr | BinaryOp::And | BinaryOp::Or | BinaryOp::Xor);

            if compound && **a == *target {
                return match (op, &**b) {
                    (BinaryOp::Add, Expr::Int(1)) => format!("{}++", target_text),
                    (BinaryOp::Sub, Expr::Int(1)) => format!("{}--", target_text),
                    _ => format!("{} {}= {}", target_text, op.symbol(), self.expr(b)),
                };
            }
        }

        return format!("{} = {}", target_text, self.expr(value));
    }

    /// A case of a switch, in braces when it declares variables
    fn case(&mut self, mut labels: Vec<String>, body: &[Stmt], depth: usize) {
        let braces = !body.is_empty() && self.declared.get(&list_id(body)).is_some_and(|vars| !vars.is_empty());

        if braces {
            if let Some(last) = labels.last_mut() {
                last.push_str(" {");
            }
        }

        for label in labels {
            self.line(depth + 1, &label, None);
        }

        self.block(body, depth + 2);

        if braces {
            self.line(depth + 1, "}", None);
        }
    }

    /// The statements of a block, after the declarations of its variables: a variable first written by a
    /// statement of the block that does not read it is declared there (int v = ...;), the others at the start
    fn block(&mut self, stmts: &[Stmt], depth: usize) {
        let vars = self.declared.get(&list_id(stmts)).cloned().unwrap_or_default();
        let mut initialized: HashMap<usize, VarId> = HashMap::new();
        let mut declared_first = Vec::new();

        if !vars.is_empty() {
            let mentions: Vec<Vec<VarId>> = stmts.iter().map(|s| mentioned(std::slice::from_ref(s))).collect();

            for var in vars {
                let first = mentions.iter().position(|m| m.contains(&var));

                // A label is followed by a statement, not a declaration
                let after_label = |i: usize| i > 0 && matches!(stmts[i - 1].kind, StmtKind::Label(_));

                match first.map(|i| (i, &stmts[i].kind)) {
                    Some((i, StmtKind::Assign(Expr::Var(v), value))) if *v == var && !value.uses(var) && !initialized.contains_key(&i) && !after_label(i) => {
                        initialized.insert(i, var);
                    }
                    _ => declared_first.push(var),
                }
            }
        }

        for &var in declared_first.iter() {
            let text = format!("{};", self.function.vars[var].ty.declare(&self.function.vars[var].name));
            self.line(depth, &text, None);
        }

        if !declared_first.is_empty() && list_id(stmts) == list_id(&self.function.body) {
            self.line(0, "", None);
        }

        for (i, stmt) in stmts.iter().enumerate() {
            match (initialized.get(&i), &stmt.kind) {
                (Some(&var), StmtKind::Assign(_, value)) => {
                    self.note = stmt.note.clone();
                    let text = format!("{} = {};", self.function.vars[var].ty.declare(&self.function.vars[var].name), self.expr(value));
                    self.line(depth, &text, stmt.addr);
                }
                _ => self.stmt(stmt, depth),
            }
        }
    }

    fn stmt(&mut self, stmt: &Stmt, depth: usize) {
        let addr = stmt.addr;
        self.note = stmt.note.clone();

        match &stmt.kind {
            StmtKind::Expr(_) | StmtKind::Assign(..) | StmtKind::NoReturn(_) => {
                let text = format!("{};", self.simple(stmt));
                self.line(depth, &text, addr);
            }
            StmtKind::If(cond, then, otherwise) => {
                let text = format!("if ({}) {{", self.expr(cond));
                self.line(depth, &text, addr);
                self.block(then, depth + 1);

                // else if chains
                let mut otherwise = otherwise;

                while let ([Stmt { kind: StmtKind::If(cond, then, rest), addr, .. }], false) = (otherwise.as_slice(), self.declared.contains_key(&list_id(otherwise))) {
                    let text = format!("}} else if ({}) {{", self.expr(cond));
                    self.line(depth, &text, *addr);
                    self.block(then, depth + 1);
                    otherwise = rest;
                }

                if !otherwise.is_empty() {
                    self.line(depth, "} else {", None);
                    self.block(otherwise, depth + 1);
                }

                self.line(depth, "}", None);
            }
            StmtKind::While(cond, body) => {
                let text = format!("while ({}) {{", self.expr(cond));
                self.line(depth, &text, addr);
                self.block(body, depth + 1);
                self.line(depth, "}", None);
            }
            StmtKind::DoWhile(body, cond) => {
                self.line(depth, "do {", first_address(body).or(addr));
                self.block(body, depth + 1);
                let text = format!("}} while ({});", self.expr(cond));
                self.line(depth, &text, addr);
            }
            StmtKind::For(init, cond, step, body) => {
                let cond = if *cond == Expr::Int(1) { String::new() } else { format!(" {}", self.expr(cond)) };
                let text = format!("for ({};{}; {}) {{", self.simple(init), cond, self.simple(step));
                self.line(depth, &text, addr);
                self.block(body, depth + 1);
                self.line(depth, "}", None);
            }
            StmtKind::Switch(value, cases, default) => {
                let text = format!("switch ({}) {{", self.expr(value));
                self.line(depth, &text, addr);

                for case in cases {
                    // Runs of consecutive values are ranges (case 1 ... 9:, GNU C)
                    let mut values = case.values.clone();
                    values.sort();
                    values.dedup();
                    let mut labels = Vec::new();
                    let mut start = 0;

                    while start < values.len() {
                        let mut end = start;

                        while end + 1 < values.len() && values[end + 1] == values[end] + 1 {
                            end += 1;
                        }

                        let first = self.expr(&Expr::Int(values[start]));

                        if end - start >= 2 {
                            labels.push(format!("case {} ... {}:", first, self.expr(&Expr::Int(values[end]))));
                            start = end + 1;
                        } else {
                            labels.push(format!("case {}:", first));
                            start += 1;
                        }
                    }

                    self.case(labels, &case.body, depth);
                }

                if !default.is_empty() {
                    self.case(vec!["default:".to_string()], default, depth);
                }

                self.line(depth, "}", None);
            }
            StmtKind::Break => self.line(depth, "break;", addr),
            StmtKind::Continue => self.line(depth, "continue;", addr),
            StmtKind::Return(None) => self.line(depth, "return;", addr),
            StmtKind::Return(Some(e)) => {
                let text = format!("return {};", self.expr(e));
                self.line(depth, &text, addr);
            }
            StmtKind::Goto(label) => {
                let text = format!("goto {};", label);
                self.line(depth, &text, addr);
            }
            StmtKind::Label(label) => {
                let text = format!("{}:", label);
                self.line(depth.saturating_sub(1), &text, addr);
            }
            StmtKind::Comment(text) => {
                let text = format!("// {}", text);
                self.line(depth, &text, addr);
            }
        }
    }
}

fn first_address(stmts: &[Stmt]) -> Option<u64> {
    return stmts.iter().find_map(|s| s.addr);
}

/// Text of a C literal (one character per byte, see lift::literal), the bytes that are not printable
/// ASCII are hexadecimal escapes
fn escape(text: &str) -> String {
    let mut out = String::new();
    let mut hex = false;

    for c in text.chars() {
        // A hexadecimal escape takes every hexadecimal digit after it: the literal is split
        if hex && c.is_ascii_hexdigit() {
            out.push_str("\" \"");
        }

        hex = false;

        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\0' => out.push_str("\\0"),
            c if c.is_control() || ('\u{80}'..='\u{ff}').contains(&c) => {
                let _ = write!(out, "\\x{:02x}", c as u32);
                hex = true;
            }
            c => out.push(c),
        }
    }

    return out;
}

impl CFunction {
    pub fn signature(&self) -> String {
        let params = self.params.iter().map(|&p| Param { name: Some(self.vars[p].name.clone()), ty: self.vars[p].ty.clone() }).collect();
        return Prototype { name: self.name.clone(), ty: FuncType { ret: self.ret.clone(), params, variadic: self.variadic } }.to_string();
    }

    pub fn print(&self) -> Printed {
        let mut printer = Printer { function: self, out: String::new(), lines: Vec::new(), note: None, declared: HashMap::new() };

        let signature = self.signature();

        if let ([stmt], true) = (self.body.as_slice(), self.inlined) {
            let text = match &stmt.kind {
                StmtKind::Return(Some(e)) => format!("return {};", printer.expr(e)),
                _ => format!("{};", printer.simple(stmt)),
            };

            printer.line(0, &format!("{} {{ {} }}", signature, text), Some(self.addr));
            return Printed { text: printer.out, lines: printer.lines };
        }

        printer.line(0, &signature, Some(self.addr));
        printer.line(0, "{", None);

        // Local variables (the parameters are declared by the signature), in the narrowest block they can be
        let mut used = vec![false; self.vars.len()];
        mark_used(&self.body, &mut used);

        let locals: Vec<VarId> = (0..self.vars.len()).filter(|id| used[*id] && !self.params.contains(id)).collect();
        printer.declared = scope::declarations(self, &locals);
        printer.block(&self.body, 1);
        printer.line(0, "}", None);

        return Printed { text: printer.out, lines: printer.lines };
    }
}

/// The variables statements use, once each
pub(super) fn mentioned(stmts: &[Stmt]) -> Vec<VarId> {
    let mut vars = Vec::new();
    let expr = |e: &Expr, vars: &mut Vec<VarId>| {
        e.visit(&mut |e| {
            if let Expr::Var(v) = e {
                if !vars.contains(v) {
                    vars.push(*v);
                }
            }
        })
    };

    let mut stack: Vec<&Stmt> = stmts.iter().collect();

    while let Some(stmt) = stack.pop() {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => expr(e, &mut vars),
            StmtKind::Assign(a, b) => {
                expr(a, &mut vars);
                expr(b, &mut vars);
            }
            StmtKind::If(c, a, b) => {
                expr(c, &mut vars);
                stack.extend(a.iter().chain(b.iter()));
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                expr(c, &mut vars);
                stack.extend(body.iter());
            }
            StmtKind::For(init, c, step, body) => {
                expr(c, &mut vars);
                stack.push(init);
                stack.push(step);
                stack.extend(body.iter());
            }
            StmtKind::Switch(c, cases, default) => {
                expr(c, &mut vars);
                stack.extend(cases.iter().flat_map(|case| case.body.iter()).chain(default.iter()));
            }
            _ => {}
        }
    }

    return vars;
}

/// Marks the variables used by statements
pub fn mark_used(stmts: &[Stmt], used: &mut [bool]) {
    let expr = |e: &Expr, used: &mut [bool]| {
        e.visit(&mut |e| {
            if let Expr::Var(id) = e {
                used[*id] = true;
            }
        })
    };

    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) => expr(e, used),
            StmtKind::Assign(a, b) => {
                expr(a, used);
                expr(b, used);
            }
            StmtKind::If(c, a, b) => {
                expr(c, used);
                mark_used(a, used);
                mark_used(b, used);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                expr(c, used);
                mark_used(body, used);
            }
            StmtKind::For(init, c, step, body) => {
                mark_used(std::slice::from_ref(init), used);
                expr(c, used);
                mark_used(std::slice::from_ref(step), used);
                mark_used(body, used);
            }
            StmtKind::Switch(c, cases, default) => {
                expr(c, used);
                cases.iter().for_each(|case| mark_used(&case.body, used));
                mark_used(default, used);
            }
            StmtKind::Return(Some(e)) => expr(e, used),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence() {
        let function = CFunction {
            name: "f".to_string(),
            ret: CType::int(32),
            params: vec![0, 1],
            variadic: false,
            vars: vec![Var { name: "a".to_string(), ty: CType::int(32) }, Var { name: "b".to_string(), ty: CType::int(32) }],
            body: Vec::new(),
            addr: 0,
            globals: Vec::new(),
            inlined: false,
        };
        let printer = Printer { function: &function, out: String::new(), lines: Vec::new(), note: None, declared: HashMap::new() };
        let (a, b) = (Expr::Var(0), Expr::Var(1));

        let sum = Expr::binary(BinaryOp::Add, a.clone(), b.clone());
        assert_eq!(printer.expr(&Expr::binary(BinaryOp::Mul, sum.clone(), Expr::Int(2))), "(a + b) * 2");
        assert_eq!(printer.expr(&Expr::binary(BinaryOp::Sub, a.clone(), Expr::binary(BinaryOp::Sub, b.clone(), Expr::Int(1)))), "a - (b - 1)");
        assert_eq!(printer.expr(&Expr::binary(BinaryOp::Sub, Expr::binary(BinaryOp::Sub, a.clone(), b.clone()), Expr::Int(1))), "a - b - 1");
        assert_eq!(printer.expr(&Expr::unary(UnaryOp::Deref, Expr::binary(BinaryOp::Add, a.clone(), Expr::Int(1)))), "*(a + 1)");
        assert_eq!(printer.expr(&Expr::binary(BinaryOp::Lt, a.clone(), b.clone()).not()), "a >= b");
        assert_eq!(printer.expr(&Expr::cast(CType::ptr(CType::Char), a.clone())), "(char *)a");
        assert_eq!(printer.expr(&Expr::Str("hi\n".to_string())), "\"hi\\n\"");
        assert_eq!(printer.expr(&Expr::Str(crate::lift::literal("T3\u{c7}8x\u{c0}z".as_bytes()))), "\"T3\\xc3\\x87\" \"8x\\xc3\\x80z\"");
        assert_eq!(printer.expr(&Expr::Int(0x401000)), "0x401000");
    }

    #[test]
    fn narrowest_declarations() {
        let int = CType::int(32);
        let var = |name: &str| Var { name: name.to_string(), ty: int.clone() };
        let assign = |v: VarId, e: Expr| Stmt::new(StmtKind::Assign(Expr::Var(v), e), None);
        let call = |v: VarId| Stmt::new(StmtKind::Expr(Expr::Call(Box::new(Expr::Name("g".to_string())), vec![Expr::Var(v)])), None);

        // t is written then read in each iteration: in the loop; s is carried from one to the next: before it;
        // u is written in one branch only, then read after the if: declared first, at the start
        let body = vec![
            assign(2, Expr::Int(0)),
            Stmt::new(
                StmtKind::While(
                    Expr::Var(0),
                    vec![assign(1, Expr::binary(BinaryOp::Add, Expr::Var(0), Expr::Int(1))), call(1), assign(2, Expr::binary(BinaryOp::Add, Expr::Var(2), Expr::Var(1)))],
                ),
                None,
            ),
            Stmt::new(StmtKind::If(Expr::Var(0), vec![assign(3, Expr::Int(1))], Vec::new()), None),
            call(3),
            Stmt::new(StmtKind::Return(Some(Expr::Var(2))), None),
        ];

        let function = CFunction { name: "f".to_string(), ret: int.clone(), params: vec![0], variadic: false, vars: vec![var("n"), var("t"), var("s"), var("u")], body, addr: 0, globals: Vec::new(), inlined: false };
        let text = function.print().text;

        assert!(text.starts_with("int f(int n)\n{\n    int u;\n\n    int s = 0;\n    while (n) {\n        int t = n + 1;\n"), "{}", text);
    }

    #[test]
    fn statements() {
        let function = CFunction {
            name: "f".to_string(),
            ret: CType::int(32),
            params: vec![0],
            variadic: false,
            vars: vec![Var { name: "n".to_string(), ty: CType::int(32) }, Var { name: "i".to_string(), ty: CType::int(32) }],
            body: vec![
                Stmt::new(StmtKind::Assign(Expr::Var(1), Expr::Int(0)), Some(1)),
                Stmt::new(
                    StmtKind::While(
                        Expr::binary(BinaryOp::Lt, Expr::Var(1), Expr::Var(0)),
                        vec![Stmt::new(StmtKind::Assign(Expr::Var(1), Expr::binary(BinaryOp::Add, Expr::Var(1), Expr::Int(1))), Some(3))],
                    ),
                    Some(2),
                ),
                Stmt::new(StmtKind::Return(Some(Expr::Var(1))), Some(4)),
            ],
            addr: 0x1000,
            globals: Vec::new(),
            inlined: false,
        };

        let printed = function.print();
        assert_eq!(printed.text, "int f(int n)\n{\n    int i = 0;\n    while (i < n) {\n        i++;\n    }\n    return i;\n}\n");

        // Consecutive case values are a range
        let switch = Stmt::new(StmtKind::Switch(Expr::Var(0), vec![Case { values: vec![5, 1, 2, 3, 7], body: vec![Stmt::new(StmtKind::Return(Some(Expr::Int(1))), None)] }], Vec::new()), None);
        let function = CFunction { body: vec![switch], ..function };
        assert!(function.print().text.contains("case 1 ... 3:\n        case 5:\n        case 7:\n"), "{}", function.print().text);
        assert_eq!(printed.lines[0], Some(0x1000));
        assert_eq!(printed.lines[2], Some(1));
        assert_eq!(printed.lines[4], Some(3));
    }
}
