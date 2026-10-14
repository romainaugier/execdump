/*
 * LLM assistance: an improvement pass over the decompiled C code
 *
 * The model gets the C code of a function and answers with structured suggestions (names of
 * the function and of its variables, types of the variables, a summary). Suggestions are edits
 * of the C syntax tree: names must be valid and unique C identifiers, types must be known C
 * types, anything else is dropped. The code itself is only replaced by a rewrite the user accepts.
 *
 * The APIs are called by the clients of the chat module.
 */

use crate::c::ast::{CFunction, Expr, Stmt, StmtKind};
use crate::typedb::TypeDb;
use crate::types::CType;

use crate::chat::Chat;

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
    pub fn new(config: &LlmConfig) -> Result<Self, String> {
        return Assistant::for_task(config, SYSTEM, "suggestions", schema());
    }

    /// Assistant rewriting the code of a function as clear C
    pub fn rewrite(config: &LlmConfig) -> Result<Self, String> {
        return Assistant::for_task(config, REWRITE_SYSTEM, "rewrite", rewrite_schema());
    }

    /// Asks the model to rewrite a function, with the prototypes of what it uses
    pub fn rewrite_code(&self, code: &str, declarations: &[String]) -> Result<String, String> {
        let prototypes = if declarations.is_empty() { String::new() } else { format!("Prototypes:\n\n```c\n{}\n```\n\n", declarations.join("\n")) };
        let text = self.ask(format!("{}Decompiled function:\n\n```c\n{}```", prototypes, code))?;
        let start = text.find('{').ok_or("no JSON object in the answer")?;
        let end = text.rfind('}').ok_or("no JSON object in the answer")?;
        let rewrite: Rewrite = serde_json::from_str(&text[start..=end]).map_err(|e| e.to_string())?;

        // Models wrap code in fences out of habit
        let code = rewrite.code.trim().trim_start_matches("```c").trim_start_matches("```").trim_end_matches("```").trim();

        if code.is_empty() {
            return Err("empty code in the answer".to_string());
        }

        return Ok(format!("{}\n", code));
    }

    /// Assistant organizing functions into source files
    pub fn modules(config: &LlmConfig) -> Result<Self, String> {
        return Assistant::for_task(config, MODULES_SYSTEM, "files", modules_schema());
    }

    fn for_task(config: &LlmConfig, system: &str, name: &str, schema: serde_json::Value) -> Result<Self, String> {
        if !config.is_enabled() {
            return Err("the [llm] section of the configuration needs a backend and a model".to_string());
        }

        // A rewrite is the whole function: more tokens than the suggestions
        let max_tokens = if name == "rewrite" { config.max_tokens.max(8192) } else { config.max_tokens };
        let chat = Chat::new(config, system, name, schema, max_tokens)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;

        return Ok(Assistant { chat, runtime });
    }

    fn ask(&self, prompt: String) -> Result<String, String> {
        return self.runtime.block_on(self.chat.ask(&prompt));
    }

    /// Asks the model for suggestions on a function (its printed C code)
    pub fn suggest(&self, code: &str) -> Result<Suggestions, String> {
        return parse(&self.ask(format!("Decompiled function:\n\n```c\n{}```", code))?);
    }

    /// Asks the model to place functions in source files, the listing gives one function per line
    /// (name, current file, called functions)
    pub fn suggest_modules(&self, listing: &str) -> Result<ModuleSuggestions, String> {
        let text = self.ask(format!("Functions (name | current file | calls):\n\n{}", listing))?;
        let start = text.find('{').ok_or("no JSON object in the answer")?;
        let end = text.rfind('}').ok_or("no JSON object in the answer")?;

        return serde_json::from_str(&text[start..=end]).map_err(|e| e.to_string());
    }
}

const REWRITE_SYSTEM: &str = "You are a reverse engineer cleaning up the output of a decompiler. You are given the C code of \
one function, decompiled from a binary, and the prototypes of what it uses. Rewrite it as clear and understandable C code, \
the way a careful programmer would have written it: structured control flow instead of gotos where possible, for loops, \
early returns, no needless temporaries or casts, array indexing and field access instead of pointer arithmetic when the \
code makes the layout clear, meaningful names for the parameters and local variables, and a short comment only where the \
code is not obvious. The behavior must stay exactly the same: keep the function name, its parameters in the same order, \
every call (same functions, same arguments, same order of the side effects), every memory access and every constant. Do \
not invent functions or types that are not given. Answer with a JSON object only, the code being the whole function.";

fn rewrite_schema() -> serde_json::Value {
    return serde_json::json!({
        "type": "object",
        "properties": {
            "code": { "type": "string", "description": "The whole rewritten function, its signature included" }
        },
        "required": ["code"],
        "additionalProperties": false
    });
}

#[derive(Deserialize)]
struct Rewrite {
    code: String,
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
pub fn parse(text: &str) -> Result<Suggestions, String> {
    let start = text.find('{').ok_or("no JSON object in the answer")?;
    let end = text.rfind('}').ok_or("no JSON object in the answer")?;

    return serde_json::from_str(&text[start..=end]).map_err(|e| e.to_string());
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
    fn rewrite() {
        use super::Assistant;

        // Fenced code in the JSON answer
        let answer = serde_json::json!({ "code": "```c\nint f(void)\n{\n    return 1;\n}\n```" }).to_string();
        let body = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::json!({ "choices": [{ "delta": { "content": answer }, "finish_reason": "stop" }] }));
        let (url, request) = crate::chat::tests::serve("200 OK", body);

        let config = super::LlmConfig { backend: "openai-compatible".to_string(), model: "test".to_string(), base_url: Some(url), timeout: 10, ..Default::default() };
        let assistant = Assistant::rewrite(&config).unwrap();
        assert_eq!(assistant.rewrite_code("int f(void) { return 1; }", &[]).unwrap(), "int f(void)\n{\n    return 1;\n}\n");
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
