/*
 * LLM assistance: an improvement pass over the decompiled C code
 *
 * The model gets the C code of a function and answers with structured suggestions (names of
 * the function and of its variables, types of the variables, a summary). Suggestions are edits
 * of the C syntax tree: names must be valid and unique C identifiers, types must be known C
 * types, anything else is dropped.
 *
 * The improvement of the interface asks for the same suggestions and for the function rewritten as clear, documented C.
 * Each line of the code it gets ends with the address of its machine code (a marker, /*@4011a0*/), the rewritten
 * lines keep the markers of the lines they do the work of: the code keeps the addresses of its lines, so it can be
 * debugged. The code itself is only replaced by a rewrite the user accepts.
 *
 * The APIs are called by the clients of the chat module.
 */

use crate::c::ast::{CFunction, Expr, Stmt, StmtKind};
use crate::typedb::TypeDb;
use crate::types::CType;

use crate::chat::Chat;

use anyhow::{bail, Context, Result};

use serde::Deserialize;

use std::collections::{HashMap, HashSet};

const SYSTEM: &str = "You are a reverse engineer improving the output of a decompiler. You are given the C code of one \
function, decompiled from a binary. Suggest a descriptive name for the function and for its parameters and local variables \
(snake_case C identifiers), better C types for them when the code makes it clear (for example char * for strings, size_t \
for sizes), and a one sentence summary of what the function does. Only rename what you understand, keep the names you are \
unsure about. Answer with a JSON object only.";

/// The [llm] section of the configuration file
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct LlmConfig {
    /// openai, anthropic, google, deepseek, mistral, groq, xai, openrouter, ollama, openai-compatible
    pub backend: String,
    pub model: String,
    pub api_key: Option<String>,
    /// Environment variable holding the API key
    pub api_key_env: Option<String>,
    pub base_url: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout: u64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        return LlmConfig {
            backend: String::new(),
            model: String::new(),
            api_key: None,
            api_key_env: None,
            base_url: None,
            max_tokens: 2048,
            temperature: 0.2,
            timeout: 120,
        };
    }
}

impl LlmConfig {
    pub fn is_enabled(&self) -> bool {
        return !self.backend.is_empty() && !self.model.is_empty();
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct VariableSuggestion {
    pub name: String,
    pub new_name: Option<String>,
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Suggestions {
    pub function_name: Option<String>,
    pub summary: Option<String>,
    pub variables: Vec<VariableSuggestion>,
}

fn schema() -> serde_json::Value {
    return serde_json::json!({
        "type": "object",
        "properties": {
            "function_name": { "type": "string", "description": "New name of the function, or empty to keep it" },
            "summary": { "type": "string", "description": "What the function does, in one sentence" },
            "variables": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Current name of the parameter or variable" },
                        "new_name": { "type": "string", "description": "New name, or empty to keep it" },
                        "type": { "type": "string", "description": "New C type, or empty to keep it" }
                    },
                    "required": ["name", "new_name", "type"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["function_name", "summary", "variables"],
        "additionalProperties": false
    });
}

pub struct Assistant {
    chat: Chat,
    runtime: tokio::runtime::Runtime,
}

impl Assistant {
    /// Assistant improving the names and types of a function
    pub fn new(config: &LlmConfig) -> Result<Self> {
        return Assistant::for_task(config, SYSTEM, "suggestions", schema());
    }

    /// Assistant improving and documenting a function: the suggestions and the rewritten code
    pub fn improve(config: &LlmConfig) -> Result<Self> {
        return Assistant::for_task(config, IMPROVE_SYSTEM, "improve", improve_schema());
    }

    /// Asks the model to improve a function: its code with the markers of the addresses of its lines (see mark_lines),
    /// with the prototypes of what it uses. The code of the answer has the addresses of the markers it kept (the ones of
    /// the code given only).
    pub fn improve_code(&self, marked: &str, declarations: &[String]) -> Result<Improvement> {
        let prototypes = if declarations.is_empty() { String::new() } else { format!("Prototypes:\n\n```c\n{}\n```\n\n", declarations.join("\n")) };
        let text = self.ask(format!("{}Decompiled function:\n\n```c\n{}```", prototypes, marked))?;
        let start = text.find('{').context("no JSON object in the answer")?;
        let end = text.rfind('}').context("no JSON object in the answer")?;
        let answer: ImproveAnswer = serde_json::from_str(&text[start..=end])?;

        // Models wrap code in fences out of habit
        let code = answer.code.trim().trim_start_matches("```c").trim_start_matches("```").trim_end_matches("```").trim();
        let known = markers(marked).into_iter().flatten().collect();
        let code = (!code.is_empty()).then(|| unmark(&format!("{}\n", code), &known));
        let suggestions = Suggestions { function_name: answer.function_name, summary: answer.summary, variables: answer.variables };

        return Ok(Improvement { suggestions, code });
    }

    /// Assistant organizing functions into source files
    pub fn modules(config: &LlmConfig) -> Result<Self> {
        return Assistant::for_task(config, MODULES_SYSTEM, "files", modules_schema());
    }

    fn for_task(config: &LlmConfig, system: &str, name: &str, schema: serde_json::Value) -> Result<Self> {
        if !config.is_enabled() {
            bail!("the [llm] section of the configuration needs a backend and a model");
        }

        // An improvement is the whole function: more tokens than the suggestions
        let max_tokens = if name == "improve" { config.max_tokens.max(8192) } else { config.max_tokens };
        let chat = Chat::new(config, system, name, schema, max_tokens)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

        return Ok(Assistant { chat, runtime });
    }

    fn ask(&self, prompt: String) -> Result<String> {
        return self.runtime.block_on(self.chat.ask(&prompt));
    }

    /// Asks the model for suggestions on a function (its printed C code)
    pub fn suggest(&self, code: &str) -> Result<Suggestions> {
        return parse(&self.ask(format!("Decompiled function:\n\n```c\n{}```", code))?);
    }

    /// Asks the model to place functions in source files, the listing gives one function per line
    /// (name, current file, called functions)
    pub fn suggest_modules(&self, listing: &str) -> Result<ModuleSuggestions> {
        let text = self.ask(format!("Functions (name | current file | calls):\n\n{}", listing))?;
        let start = text.find('{').context("no JSON object in the answer")?;
        let end = text.rfind('}').context("no JSON object in the answer")?;

        return Ok(serde_json::from_str(&text[start..=end])?);
    }
}

const IMPROVE_SYSTEM: &str = "You are a reverse engineer improving the output of a decompiler. You are given the C code of \
one function, decompiled from a binary, and the prototypes of what it uses. Each line of the code ends with a marker such as \
/*@4011a0*/, the address of its machine code. Suggest a descriptive name for the function (snake_case, only when you understand \
it), names and C types for its parameters and local variables (char * for strings, size_t for sizes...) and a one sentence \
summary. Then rewrite the function as clear and documented C, the way a careful programmer would have written it: structured \
control flow instead of gotos where possible, for loops, early returns, no needless temporaries or casts, array indexing and \
field access instead of pointer arithmetic when the layout is clear, the names you suggested, and comments explaining what \
the code does and why where it is not obvious. The behavior must stay exactly the same: keep the function name of the \
signature, its parameters in the same order, every call (same functions, same arguments, same order of the side effects), \
every memory access and every constant. Do not invent functions or types that are not given. Keep the markers: end each line \
of your code that does the work of lines of the given code with the marker of the first of them, exactly as it was written, \
and put no marker on the lines you add (comments, braces, declarations). Answer with a JSON object only, the code being the \
whole function.";

fn improve_schema() -> serde_json::Value {
    let mut schema = schema();
    schema["properties"]["code"] = serde_json::json!({ "type": "string", "description": "The whole rewritten and documented function, its signature included, with the markers of the addresses" });
    schema["required"] = serde_json::json!(["function_name", "summary", "variables", "code"]);
    return schema;
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ImproveAnswer {
    function_name: Option<String>,
    summary: Option<String>,
    variables: Vec<VariableSuggestion>,
    code: String,
}

/// What the model proposes for a function: its suggestions, and its code rewritten with the addresses of its lines
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Improvement {
    pub suggestions: Suggestions,
    pub code: Option<(String, Vec<Option<u64>>)>,
}

/// The code of a function with the address of each line at its end (/*@4011a0*/), for the model
pub fn mark_lines(text: &str, lines: &[Option<u64>]) -> String {
    let mut marked = String::with_capacity(text.len() + lines.len() * 12);

    for (index, line) in text.lines().enumerate() {
        marked.push_str(line);

        if let Some(addr) = lines.get(index).copied().flatten().filter(|_| !line.trim().is_empty()) {
            marked.push_str(&format!(" /*@{:x}*/", addr));
        }

        marked.push('\n');
    }

    return marked;
}

/// The address of the first marker of each line
fn markers(text: &str) -> Vec<Option<u64>> {
    return text.lines().map(|line| line.split("/*@").skip(1).find_map(|rest| rest.split_once("*/").and_then(|(hex, _)| u64::from_str_radix(hex.trim(), 16).ok()))).collect();
}

/// The code without its markers, and the address of each of its lines: the first marker of the line among the known
/// addresses (a marker the model made up is no address)
pub fn unmark(code: &str, known: &HashSet<u64>) -> (String, Vec<Option<u64>>) {
    let addrs = markers(code).into_iter().map(|a| a.filter(|a| known.contains(a))).collect();
    let mut text = String::with_capacity(code.len());

    for line in code.lines() {
        let mut rest = line;
        let mut clean = String::new();

        while let Some(start) = rest.find("/*@") {
            match rest[start..].find("*/") {
                Some(end) if rest[start + 3..start + end].chars().all(|c| c.is_ascii_hexdigit() || c == ' ') => {
                    clean.push_str(&rest[..start]);
                    rest = &rest[start + end + 2..];
                }
                _ => break,
            }
        }

        clean.push_str(rest);
        text.push_str(clean.trim_end());
        text.push('\n');
    }

    return (text, addrs);
}

/// What a rewritten function may have lost: its name, the balance of its braces, the functions it called
pub fn check_rewrite(name: &str, calls: &[String], code: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let words: HashSet<&str> = code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).collect();

    if !words.contains(name) {
        warnings.push(format!("the function is not named {} anymore", name));
    }

    if code.matches('{').count() != code.matches('}').count() || code.matches('(').count() != code.matches(')').count() {
        warnings.push("unbalanced braces or parentheses".to_string());
    }

    let dropped: Vec<&str> = calls.iter().map(|c| c.as_str()).filter(|c| !words.contains(c)).collect();

    if !dropped.is_empty() {
        warnings.push(format!("no call to {} anymore", dropped.join(", ")));
    }

    return warnings;
}

const MODULES_SYSTEM: &str = "You are a reverse engineer organizing the functions of a decompiled binary into C source files. \
You get a list of functions with their current file and the functions they call. Group the functions that belong together \
(same feature, same data structures, functions calling each other) into source files with descriptive relative paths such as \
net/socket.c. Keep the files of the functions that are already well placed, and only use the function names you were given. \
Answer with a JSON object only.";

fn modules_schema() -> serde_json::Value {
    return serde_json::json!({
        "type": "object",
        "properties": {
            "files": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Relative path of the C source file" },
                        "functions": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["path", "functions"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["files"],
        "additionalProperties": false
    });
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct FileSuggestion {
    pub path: String,
    pub functions: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ModuleSuggestions {
    pub files: Vec<FileSuggestion>,
}

/// Suggestions from the answer of the model (the first JSON object of the text)
pub fn parse(text: &str) -> Result<Suggestions> {
    let start = text.find('{').context("no JSON object in the answer")?;
    let end = text.rfind('}').context("no JSON object in the answer")?;

    return Ok(serde_json::from_str(&text[start..=end])?);
}

const KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "bool", "NULL",
];

pub fn valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let first = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');

    return first && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64 && !KEYWORDS.contains(&name);
}

/// C type of a type name: builtins, known typedefs and structs, with const and pointers
pub fn parse_type(text: &str, typedb: &TypeDb) -> Option<CType> {
    let text = text.trim();
    let stars = text.chars().rev().take_while(|c| *c == '*' || c.is_whitespace()).filter(|c| *c == '*').count();
    let base = text.trim_end_matches(|c: char| c == '*' || c.is_whitespace()).trim();
    let (is_const, base) = match base.strip_prefix("const ") {
        Some(rest) => (true, rest.trim()),
        None => (false, base),
    };

    let mut ty = match base {
        "void" => CType::Void,
        "bool" | "_Bool" => CType::Bool,
        "char" => CType::Char,
        "signed char" | "int8_t" => CType::int(8),
        "unsigned char" | "uint8_t" => CType::uint(8),
        "short" | "int16_t" => CType::int(16),
        "unsigned short" | "uint16_t" => CType::uint(16),
        "int" | "int32_t" => CType::int(32),
        "unsigned int" | "unsigned" | "uint32_t" => CType::uint(32),
        "long long" | "int64_t" => CType::int(64),
        "unsigned long long" | "uint64_t" => CType::uint(64),
        "float" => CType::Float { bits: 32 },
        "double" => CType::Float { bits: 64 },
        _ => match base.strip_prefix("struct ") {
            Some(name) if typedb.aggregates.contains_key(name.trim()) => CType::Struct(name.trim().to_string()),
            _ if typedb.typedefs.contains_key(base) => CType::Typedef(base.to_string()),
            _ => return None,
        },
    };

    if is_const {
        ty = CType::Const(Box::new(ty));
    }

    for _ in 0..stars {
        ty = CType::ptr(ty);
    }

    // Values are not void
    if ty == CType::Void {
        return None;
    }

    return Some(ty);
}

/// Renames of functions (C name to the name chosen by the model), applied to every function
pub type Renames = HashMap<String, String>;

fn rename_expr(e: &mut Expr, renames: &Renames) {
    match e {
        Expr::Name(name) => {
            if let Some(new) = renames.get(name) {
                *name = new.clone();
            }
        }
        Expr::Unary(_, a) | Expr::Cast(_, a) | Expr::Member(a, ..) => rename_expr(a, renames),
        Expr::Binary(_, a, b) | Expr::Index(a, b) => {
            rename_expr(a, renames);
            rename_expr(b, renames);
        }
        Expr::Call(callee, args) => {
            rename_expr(callee, renames);
            args.iter_mut().for_each(|a| rename_expr(a, renames));
        }
        Expr::Ternary(a, b, c) => {
            rename_expr(a, renames);
            rename_expr(b, renames);
            rename_expr(c, renames);
        }
        _ => {}
    }
}

fn rename_stmts(stmts: &mut [Stmt], renames: &Renames) {
    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => rename_expr(e, renames),
            StmtKind::Assign(a, b) => {
                rename_expr(a, renames);
                rename_expr(b, renames);
            }
            StmtKind::If(c, a, b) => {
                rename_expr(c, renames);
                rename_stmts(a, renames);
                rename_stmts(b, renames);
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                rename_expr(c, renames);
                rename_stmts(body, renames);
            }
            StmtKind::For(init, c, step, body) => {
                rename_stmts(std::slice::from_mut(init), renames);
                rename_expr(c, renames);
                rename_stmts(std::slice::from_mut(step), renames);
                rename_stmts(body, renames);
            }
            StmtKind::Switch(c, cases, default) => {
                rename_expr(c, renames);
                cases.iter_mut().for_each(|case| rename_stmts(&mut case.body, renames));
                rename_stmts(default, renames);
            }
            _ => {}
        }
    }
}

/// Applies the function renames to a function and to the functions it calls
pub fn apply_renames(function: &mut CFunction, renames: &Renames) {
    if let Some(new) = renames.get(&function.name) {
        function.name = new.clone();
    }

    rename_stmts(&mut function.body, renames);
}

/// Applies the valid suggestions, returns the rename of the function when there is one
pub fn apply(function: &mut CFunction, suggestions: &Suggestions, typedb: &TypeDb, taken: &HashSet<String>) -> Option<(String, String)> {
    let mut names: HashSet<String> = taken.clone();
    names.extend(function.vars.iter().map(|v| v.name.clone()));

    for suggestion in suggestions.variables.iter() {
        let Some(id) = function.vars.iter().position(|v| v.name == suggestion.name) else {
            continue;
        };

        if let Some(new) = suggestion.new_name.as_deref().map(str::trim).filter(|n| !n.is_empty() && *n != suggestion.name) {
            if valid_identifier(new) && !names.contains(new) {
                names.remove(&function.vars[id].name);
                names.insert(new.to_string());
                function.vars[id].name = new.to_string();
            }
        }

        // Only the types of the same size: the code stays correct
        if let Some(ty) = suggestion.ty.as_deref().and_then(|t| parse_type(t, typedb)) {
            if typedb.size_of(&ty) == typedb.size_of(&function.vars[id].ty) {
                function.vars[id].ty = ty;
            }
        }
    }

    if let Some(summary) = suggestions.summary.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let summary: String = summary.chars().filter(|c| !c.is_control()).collect();
        function.body.insert(0, Stmt::new(StmtKind::Comment(summary), None));
    }

    let rename = suggestions.function_name.as_deref().map(str::trim).filter(|n| !n.is_empty() && *n != function.name && valid_identifier(n) && !taken.contains(*n));

    if let Some(new) = rename {
        let old = std::mem::replace(&mut function.name, new.to_string());
        return Some((old, new.to_string()));
    }

    return None;
}

#[cfg(test)]
mod tests {
    #[test]
    fn improvement() {
        use super::Assistant;

        // The markers the model kept are the addresses of the lines, a made up one is none; fenced code
        let code = "```c\n// Sign of a value\nint sign(int value)\n{\n    if (value < 0) { /*@1004*/\n        return -1; /*@1008*/\n    }\n    return 1; /*@99*/\n}\n```";
        let answer = serde_json::json!({ "function_name": "sign", "summary": "Sign of a value.", "variables": [], "code": code }).to_string();
        let body = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::json!({ "choices": [{ "delta": { "content": answer }, "finish_reason": "stop" }] }));
        let (url, request) = crate::chat::tests::serve("200 OK", body);

        let config = super::LlmConfig { backend: "openai-compatible".to_string(), model: "test".to_string(), base_url: Some(url), timeout: 10, ..Default::default() };
        let assistant = Assistant::improve(&config).unwrap();
        let marked = super::mark_lines("int f(int a1)\n{\n    if (a1 < 0) {\n        return -1;\n    }\n    return 1;\n}\n", &[Some(0x1000), None, Some(0x1004), Some(0x1008), None, Some(0x100c), None]);
        assert_eq!(marked.lines().nth(2), Some("    if (a1 < 0) { /*@1004*/"));

        let improvement = assistant.improve_code(&marked, &[]).unwrap();
        assert_eq!(improvement.suggestions.summary.as_deref(), Some("Sign of a value."));

        let (text, lines) = improvement.code.unwrap();
        assert_eq!(text, "// Sign of a value\nint sign(int value)\n{\n    if (value < 0) {\n        return -1;\n    }\n    return 1;\n}\n");
        assert_eq!(lines, [None, None, None, Some(0x1004), Some(0x1008), None, None, None]);
        assert!(request.recv().unwrap().contains("\"max_tokens\":8192"));
    }

    #[test]
    fn rewrite_checks() {
        use super::check_rewrite;

        let calls = vec!["lib_add".to_string(), "fatal".to_string()];
        let good = "int classify(int value)\n{\n    if (value < 0) {\n        fatal(1);\n    }\n    return lib_add(value, 1);\n}\n";
        assert!(check_rewrite("classify", &calls, good).is_empty());

        let bad = "int sort_values(int value)\n{\n    return value + 1;\n";
        let warnings = check_rewrite("classify", &calls, bad);
        assert_eq!(warnings.len(), 3, "{:?}", warnings);
        assert!(warnings[2].contains("lib_add, fatal"));
    }

    use super::*;

    use crate::c::ast::Var;
    use crate::typedb::Platform;
    use crate::types::DataModel;

    use execdump_core::disasm::Architecture;

    fn function() -> CFunction {
        return CFunction {
            name: "sub_1000".to_string(),
            ret: CType::int(32),
            params: vec![0],
            variadic: false,
            vars: vec![Var { name: "a1".to_string(), ty: CType::int(64) }, Var { name: "v1".to_string(), ty: CType::int(32) }],
            body: vec![
                Stmt::new(StmtKind::Assign(Expr::Var(1), Expr::Call(Box::new(Expr::Name("sub_2000".to_string())), vec![Expr::Var(0)])), Some(0x1000)),
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
    fn suggestions_are_validated() {
        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
        let answer = r#"Sure! {"function_name": "count_words", "summary": "Counts the words of a string.",
            "variables": [{"name": "a1", "new_name": "text", "type": "const char *"},
                          {"name": "v1", "new_name": "int", "type": "struct unknown"},
                          {"name": "missing", "new_name": "x", "type": ""}]}"#;

        let suggestions = parse(answer).unwrap();
        let mut f = function();
        let taken: HashSet<String> = ["sub_2000".to_string()].into_iter().collect();
        let rename = apply(&mut f, &suggestions, &typedb, &taken);

        assert_eq!(rename, Some(("sub_1000".to_string(), "count_words".to_string())));
        assert_eq!(f.vars[0].name, "text");
        assert_eq!(f.vars[0].ty, CType::ptr(CType::Const(Box::new(CType::Char))));
        // Keywords and unknown types are refused
        assert_eq!(f.vars[1].name, "v1");
        assert_eq!(f.vars[1].ty, CType::int(32));

        let printed = f.print().text;
        assert!(printed.starts_with("int count_words(const char *text)"), "{}", printed);
        assert!(printed.contains("// Counts the words of a string."), "{}", printed);

        let renames: Renames = [("sub_2000".to_string(), "next_word".to_string())].into_iter().collect();
        apply_renames(&mut f, &renames);
        assert!(f.print().text.contains("v1 = next_word(text);"));
    }

    #[test]
    fn types() {
        let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));

        assert_eq!(parse_type("size_t", &typedb), Some(CType::Typedef("size_t".to_string())));
        assert_eq!(parse_type("FILE *", &typedb), Some(CType::ptr(CType::Typedef("FILE".to_string()))));
        assert_eq!(parse_type("struct stat*", &typedb), Some(CType::ptr(CType::Struct("stat".to_string()))));
        assert_eq!(parse_type("unsigned int", &typedb), Some(CType::uint(32)));
        assert_eq!(parse_type("my_type", &typedb), None);
        assert_eq!(parse_type("void", &typedb), None);
    }
}
