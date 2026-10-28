// SPDX-License-Identifier: Apache-2.0
/*
 * Syntax highlighting of the code: a language is a table (its keywords, its types, its comments and its strings), one
 * highlighter reads them all. A line is cut into tokens, the theme colors them as VS Code does (Dark+ with the
 * semantic colors of C/C++): the control flow purple, the other keywords and the built-in types blue, the names of
 * the types (structs, unions, enums, classes, typedefs) teal, the functions yellow, the variables light blue.
 *
 * The names of the types come from the language (after struct, union, enum, class, type; the _t suffix of C; the
 * capitalized names of Rust) and from the types a view knows (the typedefs of the type database: FILE, pthread_t).
 */

use crate::theme::Theme;

use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Plain,
    Control,
    Keyword,
    Type,
    Function,
    Variable,
    Constant,
    Number,
    String,
    Comment,
    /// A marker of a conflict between edits (<<<<<<<, =======, >>>>>>>)
    Conflict,
}

#[derive(Debug)]
pub struct Syntax {
    pub name: &'static str,
    pub extensions: &'static [&'static str],
    control: &'static [&'static str],
    /// The other keywords, the built-in types the language colors as keywords
    keywords: &'static [&'static str],
    /// Keywords naming the type after them (struct x, class x, type x)
    declares_type: &'static [&'static str],
    /// Types by name: the built-in types the language colors as types, the common ones of its library
    types: &'static [&'static str],
    constants: &'static [&'static str],
    /// Suffix of the names of the types (size_t)
    type_suffix: Option<&'static str>,
    /// The names starting with an uppercase letter are types
    capitalized_types: bool,
    line_comment: &'static str,
    block_comment: Option<(&'static str, &'static str)>,
    /// Delimiter of the strings without escapes (the raw strings of Go)
    raw_string: Option<char>,
    /// 'a is a lifetime, not a character
    lifetimes: bool,
    /// name! is a macro, colored as a function
    macros: bool,
}

const C_CONTROL: &[&str] = &["if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return", "goto"];
const C_KEYWORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "bool", "_Bool", "struct", "union", "enum", "const", "volatile", "static", "extern",
    "inline", "register", "restrict", "typedef", "sizeof", "__int128", "undefined",
];

pub static C: Syntax = Syntax {
    name: "C",
    extensions: &["c", "h"],
    control: C_CONTROL,
    keywords: C_KEYWORDS,
    declares_type: &["struct", "union", "enum"],
    types: &["FILE", "DIR", "va_list", "jmp_buf"],
    constants: &["NULL", "true", "false"],
    type_suffix: Some("_t"),
    capitalized_types: false,
    line_comment: "//",
    block_comment: Some(("/*", "*/")),
    raw_string: None,
    lifetimes: false,
    macros: false,
};

pub static CPP: Syntax = Syntax {
    name: "C++",
    extensions: &["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
    control: &["if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return", "goto", "try", "catch", "throw", "co_return", "co_await", "co_yield"],
    keywords: &[
        "void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "bool", "wchar_t", "char8_t", "char16_t", "char32_t", "struct", "union", "enum", "class",
        "const", "constexpr", "consteval", "volatile", "static", "extern", "inline", "virtual", "override", "final", "public", "private", "protected", "friend", "namespace",
        "using", "template", "typename", "typedef", "sizeof", "new", "delete", "operator", "this", "auto", "explicit", "mutable", "noexcept", "static_cast", "dynamic_cast",
        "reinterpret_cast", "const_cast", "decltype", "__int128",
    ],
    declares_type: &["struct", "union", "enum", "class", "typename"],
    types: &["string", "vector", "map", "unordered_map", "set", "unique_ptr", "shared_ptr", "FILE"],
    constants: &["NULL", "nullptr", "true", "false"],
    type_suffix: Some("_t"),
    capitalized_types: false,
    line_comment: "//",
    block_comment: Some(("/*", "*/")),
    raw_string: None,
    lifetimes: false,
    macros: false,
};

pub static GO: Syntax = Syntax {
    name: "Go",
    extensions: &["go"],
    control: &["if", "else", "for", "range", "switch", "case", "default", "break", "continue", "return", "goto", "fallthrough", "select", "go", "defer"],
    keywords: &["package", "import", "func", "var", "const", "type", "struct", "interface", "map", "chan"],
    declares_type: &["type"],
    types: &[
        "bool", "byte", "rune", "string", "error", "any", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "float32", "float64",
        "complex64", "complex128",
    ],
    constants: &["nil", "true", "false", "iota"],
    type_suffix: None,
    capitalized_types: false,
    line_comment: "//",
    block_comment: Some(("/*", "*/")),
    raw_string: Some('`'),
    lifetimes: false,
    macros: false,
};

pub static RUST: Syntax = Syntax {
    name: "Rust",
    extensions: &["rs"],
    control: &["if", "else", "while", "loop", "for", "in", "match", "break", "continue", "return", "await", "yield"],
    keywords: &[
        "fn", "let", "mut", "const", "static", "struct", "enum", "union", "trait", "impl", "type", "where", "pub", "crate", "mod", "use", "as", "ref", "move", "unsafe", "async",
        "dyn", "extern", "self", "super", "Self",
    ],
    declares_type: &["struct", "enum", "union", "trait", "type"],
    types: &["bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64"],
    constants: &["true", "false", "None"],
    type_suffix: None,
    capitalized_types: true,
    line_comment: "//",
    block_comment: Some(("/*", "*/")),
    raw_string: None,
    lifetimes: true,
    macros: true,
};

pub static LANGUAGES: [&Syntax; 4] = [&C, &CPP, &GO, &RUST];

/// A language by its name or the extension of its files (c, c++, cpp, go, rs, rust)
pub fn find(name: &str) -> Option<&'static Syntax> {
    let name = name.trim_start_matches('.');
    return LANGUAGES.iter().find(|s| s.name.eq_ignore_ascii_case(name) || s.extensions.iter().any(|e| e.eq_ignore_ascii_case(name))).copied();
}

fn is_word(c: char) -> bool {
    return c.is_alphanumeric() || c == '_';
}

fn starts(chars: &[char], at: usize, text: &str) -> bool {
    return !text.is_empty() && text.chars().enumerate().all(|(i, c)| chars.get(at + i) == Some(&c));
}

impl Syntax {
    fn word(&self, word: &str, previous: Option<&str>, next: Option<char>, known: &dyn Fn(&str) -> bool) -> Token {
        if self.control.contains(&word) {
            return Token::Control;
        }

        if previous.is_some_and(|p| self.declares_type.contains(&p)) {
            return Token::Type;
        }

        if self.keywords.contains(&word) {
            return Token::Keyword;
        }

        if self.constants.contains(&word) {
            return Token::Constant;
        }

        let suffixed = self.type_suffix.is_some_and(|s| word.len() > s.len() && word.ends_with(s));
        let capitalized = self.capitalized_types && word.starts_with(|c: char| c.is_ascii_uppercase()) && word.chars().any(|c| c.is_ascii_lowercase());

        if self.types.contains(&word) || suffixed || capitalized || known(word) {
            return Token::Type;
        }

        if next == Some('(') || (self.macros && next == Some('!')) {
            return Token::Function;
        }

        return Token::Variable;
    }

    /// Tokens of a line as ranges of its characters; comment tells whether the line starts in a block comment and
    /// whether one is still open at its end
    pub fn tokens(&self, line: &str, comment: &mut bool, known: &dyn Fn(&str) -> bool) -> Vec<(Token, usize, usize)> {
        let chars: Vec<char> = line.chars().collect();

        if line.starts_with("<<<<<<<") || line.starts_with("=======") || line.starts_with(">>>>>>>") {
            return vec![(Token::Conflict, 0, chars.len())];
        }

        let mut tokens = Vec::new();
        let mut previous: Option<String> = None;
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];
            let start = i;

            let token = match self.block_comment {
                Some((open, close)) if *comment || starts(&chars, i, open) => {
                    let from = if *comment { i } else { i + open.chars().count() };
                    let end = (from..chars.len()).find(|&j| starts(&chars, j, close));
                    *comment = end.is_none();
                    i = end.map_or(chars.len(), |j| j + close.chars().count());
                    Token::Comment
                }
                _ if starts(&chars, i, self.line_comment) => {
                    i = chars.len();
                    Token::Comment
                }
                // A lifetime ('a, 'static) is not a character
                _ if self.lifetimes && c == '\'' && chars.get(i + 1).is_some_and(|&n| is_word(n)) && chars.get(i + 2) != Some(&'\'') => {
                    i += 1;

                    while i < chars.len() && is_word(chars[i]) {
                        i += 1;
                    }

                    Token::Keyword
                }
                _ if Some(c) == self.raw_string => {
                    i = (i + 1..chars.len()).find(|&j| chars[j] == c).map_or(chars.len(), |j| j + 1);
                    Token::String
                }
                _ if c == '"' || c == '\'' => {
                    i += 1;

                    while i < chars.len() && chars[i] != c {
                        i += if chars[i] == '\\' { 2 } else { 1 };
                    }

                    i = (i + 1).min(chars.len());
                    Token::String
                }
                _ if c.is_ascii_digit() => {
                    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }

                    Token::Number
                }
                _ if c.is_alphabetic() || c == '_' => {
                    while i < chars.len() && is_word(chars[i]) {
                        i += 1;
                    }

                    let word: String = chars[start..i].iter().collect();
                    let next = chars[i..].iter().copied().find(|c| *c != ' ');
                    let token = self.word(&word, previous.as_deref(), next, known);
                    previous = Some(word);
                    tokens.push((token, start, i));
                    continue;
                }
                _ => {
                    i += 1;

                    if !c.is_whitespace() {
                        previous = None;
                    }

                    Token::Plain
                }
            };

            tokens.push((token, start, i.min(chars.len())));
        }

        return tokens;
    }

    /// Spans of a line in the colors of the theme
    pub fn highlight(&self, theme: &Theme, line: &str, comment: &mut bool, known: &dyn Fn(&str) -> bool) -> Vec<Span<'static>> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans: Vec<Span<'static>> = Vec::new();

        for (token, start, end) in self.tokens(line, comment, known) {
            let style = theme.token_style(token);
            let text: String = chars[start..end].iter().collect();

            // The plain characters go together
            match spans.last_mut() {
                Some(last) if last.style == style && token == Token::Plain => last.content.to_mut().push_str(&text),
                _ => spans.push(Span::styled(text, style)),
            }
        }

        return spans;
    }

    /// Whether a block comment is still open after some lines
    pub fn comment_after<'a>(&self, lines: impl Iterator<Item = &'a str>) -> bool {
        let mut comment = false;

        for line in lines {
            self.tokens(line, &mut comment, &|_| false);
        }

        return comment;
    }
}

impl Theme {
    pub fn token_style(&self, token: Token) -> Style {
        let color = match token {
            Token::Plain => self.fg,
            Token::Control => self.asm_call,
            Token::Keyword | Token::Constant => self.asm_instruction,
            Token::Type => self.code_type,
            Token::Function => self.asm_label,
            Token::Variable => self.asm_register,
            Token::Number => self.asm_immediate,
            Token::String => self.hex_ascii,
            Token::Comment => self.comment,
            Token::Conflict => return Style::default().fg(self.warning).add_modifier(Modifier::BOLD),
        };

        return Style::default().fg(color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(syntax: &Syntax, line: &str, known: &dyn Fn(&str) -> bool) -> Vec<(String, Token)> {
        let chars: Vec<char> = line.chars().collect();
        return syntax.tokens(line, &mut false, known).into_iter().filter(|(t, ..)| *t != Token::Plain).map(|(t, s, e)| (chars[s..e].iter().collect(), t)).collect();
    }

    fn kind(syntax: &Syntax, line: &str, word: &str, known: &dyn Fn(&str) -> bool) -> Token {
        return kinds(syntax, line, known).into_iter().find(|(w, _)| w == word).unwrap_or_else(|| panic!("no {} in {}", word, line)).1;
    }

    #[test]
    fn c_types() {
        let none = |_: &str| false;
        let line = "    struct st_492e70_0 *v3 = (struct go_slice *)foo(v1, size_t_count, 0x10);";
        assert_eq!(kind(&C, line, "struct", &none), Token::Keyword);
        assert_eq!(kind(&C, line, "st_492e70_0", &none), Token::Type);
        assert_eq!(kind(&C, line, "go_slice", &none), Token::Type);
        assert_eq!(kind(&C, line, "foo", &none), Token::Function);
        assert_eq!(kind(&C, line, "v1", &none), Token::Variable);
        assert_eq!(kind(&C, line, "0x10", &none), Token::Number);

        assert_eq!(kind(&C, "size_t n = strlen(s);", "size_t", &none), Token::Type);
        assert_eq!(kind(&C, "if (p == NULL) return;", "if", &none), Token::Control);
        assert_eq!(kind(&C, "if (p == NULL) return;", "NULL", &none), Token::Constant);
        assert_eq!(kind(&C, "Elf64_Sym *sym;", "Elf64_Sym", &none), Token::Variable);
        assert_eq!(kind(&C, "Elf64_Sym *sym;", "Elf64_Sym", &|w| w == "Elf64_Sym"), Token::Type);

        // Comments over lines, not in strings
        let mut comment = false;
        let tokens = C.tokens("x = \"/*\"; /* summary", &mut comment, &none);
        assert!(comment && tokens.last().is_some_and(|(t, ..)| *t == Token::Comment));
        C.tokens("   of it */ y = 1;", &mut comment, &none);
        assert!(!comment);
        assert!(C.comment_after(["/* a", "b */", "/* c"].into_iter()));
    }

    #[test]
    fn other_languages() {
        let none = |_: &str| false;
        assert_eq!(find("go").map(|s| s.name), Some("Go"));
        assert_eq!(find("rs").map(|s| s.name), Some("Rust"));
        assert_eq!(find("C++").map(|s| s.name), Some("C++"));
        assert_eq!(find(".hpp").map(|s| s.name), Some("C++"));
        assert_eq!(find("c").map(|s| s.name), Some("C"));
        assert!(find("cobol").is_none());

        assert_eq!(kind(&GO, "type Point struct {", "Point", &none), Token::Type);
        assert_eq!(kind(&GO, "defer f.Close()", "defer", &none), Token::Control);
        assert_eq!(kind(&GO, "var s string = `raw \\n`", "`raw \\n`", &none), Token::String);
        assert_eq!(kind(&GO, "x := len(s) + int64(n)", "int64", &none), Token::Type);

        assert_eq!(kind(&RUST, "fn get<'a>(v: &'a Vec<u8>) -> Option<&'a u8> {", "'a", &none), Token::Keyword);
        assert_eq!(kind(&RUST, "fn get<'a>(v: &'a Vec<u8>) -> Option<&'a u8> {", "Vec", &none), Token::Type);
        assert_eq!(kind(&RUST, "let c = 'x';", "'x'", &none), Token::String);
        assert_eq!(kind(&RUST, "println!(\"{}\", x);", "println", &none), Token::Function);

        assert_eq!(kind(&CPP, "class Widget : public Base {", "Widget", &none), Token::Type);
        assert_eq!(kind(&CPP, "auto p = nullptr;", "nullptr", &none), Token::Constant);
    }
}
