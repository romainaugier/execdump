/*
 * LLM assistance: an improvement pass over the decompiled C code
 *
 * The model gets the C code of a function and answers with structured suggestions (names of
 * the function and of its variables, types of the variables, a summary). Suggestions are edits
 * of the C syntax tree: names must be valid and unique C identifiers, types must be known C
 * types, anything else is dropped. The code itself is never replaced by the model's text.
 */

use crate::c::ast::{CFunction, Expr, Stmt, StmtKind};
use crate::typedb::TypeDb;
use crate::types::CType;

use llm::builder::{LLMBackend, LLMBuilder};
use llm::chat::{ChatMessage, StructuredOutputFormat};
use llm::LLMProvider;

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
    /// openai, anthropic, ollama, google, deepseek, mistral, groq, xai, openrouter
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
    provider: Box<dyn LLMProvider>,
    runtime: tokio::runtime::Runtime,
}

impl Assistant {
    pub fn new(config: &LlmConfig) -> Result<Self, String> {
        if !config.is_enabled() {
            return Err("the [llm] section of the configuration needs a backend and a model".to_string());
        }

        let backend: LLMBackend = config.backend.parse().map_err(|e| format!("{}", e))?;
        let api_key = config.api_key.clone().or_else(|| config.api_key_env.as_ref().and_then(|v| std::env::var(v).ok()));

        let mut builder = LLMBuilder::new()
            .backend(backend)
            .model(&config.model)
            .max_tokens(config.max_tokens)
            .temperature(config.temperature)
            .timeout_seconds(config.timeout)
            .system(SYSTEM)
            .schema(StructuredOutputFormat { name: "suggestions".to_string(), description: None, schema: Some(schema()), strict: Some(true) });

        if let Some(key) = api_key {
            builder = builder.api_key(key);
        }

        if let Some(url) = &config.base_url {
            builder = builder.base_url(url);
        }

        let provider = builder.build().map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;

        return Ok(Assistant { provider, runtime });
    }

    /// Asks the model for suggestions on a function (its printed C code)
    pub fn suggest(&self, code: &str) -> Result<Suggestions, String> {
        let messages = vec![ChatMessage::user().content(format!("Decompiled function:\n\n```c\n{}```", code)).build()];
        let response = self.runtime.block_on(self.provider.chat(&messages)).map_err(|e| e.to_string())?;
        let text = response.text().ok_or("empty answer")?;

        return parse(&text);
    }
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

fn valid_identifier(name: &str) -> bool {
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
