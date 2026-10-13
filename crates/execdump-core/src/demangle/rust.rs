use super::symbol::{Name, NamePart, Symbol, SymbolKind};

/*
 * Rust legacy mangling (Itanium-like with a trailing hash), output follows rustc-demangle's alternate format
 * https://doc.rust-lang.org/rustc/symbol-mangling/index.html
 */

const HASH_LENGTH: usize = 16;

fn parse_components(symbol: &str) -> Option<Vec<&str>> {
    let inner = symbol.strip_prefix("_ZN").or_else(|| symbol.strip_prefix("__ZN"))?;
    let bytes = inner.as_bytes();

    let mut components = Vec::new();
    let mut pos = 0;

    while bytes.get(pos)? != &b'E' {
        let start = pos;

        while bytes.get(pos)?.is_ascii_digit() {
            pos += 1;
        }

        let length: usize = inner[start..pos].parse().ok()?;
        let component = inner.get(pos..pos + length)?;

        components.push(component);
        pos += length;
    }

    let suffix = &inner[pos + 1..];

    if !suffix.is_empty() && !suffix.starts_with('.') {
        return None;
    }

    return Some(components);
}

fn is_hash(component: &str) -> bool {
    return component.len() == HASH_LENGTH + 1
        && component.starts_with('h')
        && component[1..].bytes().all(|b| b.is_ascii_hexdigit());
}

pub fn is_rust_legacy(symbol: &str) -> bool {
    return parse_components(symbol).is_some_and(|c| c.len() > 1 && c.last().is_some_and(|h| is_hash(h)));
}

fn decode_escape(escape: &str) -> Option<char> {
    let c = match escape {
        "SP" => '@',
        "BP" => '*',
        "RF" => '&',
        "LT" => '<',
        "GT" => '>',
        "LP" => '(',
        "RP" => ')',
        "C" => ',',
        _ => {
            let hex = escape.strip_prefix('u')?;
            return char::from_u32(u32::from_str_radix(hex, 16).ok()?);
        }
    };

    return Some(c);
}

fn decode_component(component: &str) -> Option<String> {
    let mut rest = component;

    if rest.starts_with("_$") {
        rest = &rest[1..];
    }

    let mut out = String::new();

    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('$') {
            let end = after.find('$')?;
            out.push(decode_escape(&after[..end])?);
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix("..") {
            out.push_str("::");
            rest = after;
        } else {
            let next = rest.find(['$', '.']).unwrap_or(rest.len()).max(1);
            out.push_str(&rest[..next]);
            rest = &rest[next..];
        }
    }

    return Some(out);
}

pub fn demangle(symbol: &str) -> Option<String> {
    let components = parse_components(symbol)?;
    let (hash, path) = components.split_last()?;

    if !is_hash(hash) || path.is_empty() {
        return None;
    }

    let decoded: Option<Vec<String>> = path.iter().map(|c| decode_component(c)).collect();

    return Some(decoded?.join("::"));
}

/// Name only, the legacy mangling does not encode types
pub fn demangle_symbol(symbol: &str) -> Option<Symbol> {
    return Some(name_symbol(&demangle(symbol)?));
}

fn name_symbol(demangled: &str) -> Symbol {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    // Split on the top level "::", generic arguments can contain paths
    for (i, c) in demangled.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            // Generic arguments of a value path (f::<T>) stay with their name
            ':' if depth == 0 && demangled[i..].starts_with("::") && !demangled[i..].starts_with("::<") && i >= start => {
                parts.push(&demangled[start..i]);
                start = i + 2;
            }
            _ => {}
        }
    }

    parts.push(&demangled[start..]);

    let parts = parts.into_iter().map(|p| NamePart { ident: p.to_string(), template_args: Vec::new() }).collect();

    return Symbol { name: Name { parts }, kind: SymbolKind::Name };
}

/*
 * Rust v0 mangling (RFC 2603), output follows llvm-cxxfilt (rustc-demangle without the crate hashes)
 * https://doc.rust-lang.org/rustc/symbol-mangling/v0.html
 */

const MAX_DEPTH: usize = 300;

pub fn is_rust_v0(symbol: &str) -> bool {
    return v0_body(symbol).is_some_and(|b| b.starts_with(|c: char| c.is_ascii_uppercase()));
}

/// The symbol without its prefix (_R, __R on Mach-O) and its encoding version
fn v0_body(symbol: &str) -> Option<&str> {
    let body = symbol.strip_prefix("_R").or_else(|| symbol.strip_prefix("__R"))?;
    return Some(body.trim_start_matches(|c: char| c.is_ascii_digit()));
}

struct V0<'a> {
    sym: &'a [u8],
    pos: usize,
    depth: usize,
    out: String,
    /// Lifetimes bound by the enclosing binders (for<'a>), named from 'a
    bound: u64,
}

impl<'a> V0<'a> {
    fn peek(&self) -> Option<u8> {
        return self.sym.get(self.pos).copied();
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            return true;
        }

        return false;
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        return Some(c);
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        return (self.depth < MAX_DEPTH).then_some(());
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    /// {<0-9a-zA-Z>} "_": "_" is 0, the others are their value plus one
    fn base62(&mut self) -> Option<u64> {
        if self.eat(b'_') {
            return Some(0);
        }

        let mut value: u64 = 0;

        loop {
            let c = self.next()?;

            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 36,
                b'_' => return value.checked_add(1),
                _ => return None,
            };

            value = value.checked_mul(62)?.checked_add(digit as u64)?;
        }
    }

    /// "0" | [1-9] {0-9}
    fn decimal(&mut self) -> Option<usize> {
        if self.eat(b'0') {
            return Some(0);
        }

        let start = self.pos;

        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }

        return std::str::from_utf8(&self.sym[start..self.pos]).ok()?.parse().ok();
    }

    /// ["s" <base-62-number>]
    fn disambiguator(&mut self) -> Option<u64> {
        if self.eat(b's') {
            return self.base62().map(|v| v + 1);
        }

        return Some(0);
    }

    /// ["u"] <decimal-number> ["_"] <bytes>
    fn identifier(&mut self) -> Option<String> {
        let punycode = self.eat(b'u');
        let length = self.decimal()?;
        self.eat(b'_');

        let bytes = self.sym.get(self.pos..self.pos + length)?;
        self.pos += length;
        let text = std::str::from_utf8(bytes).ok()?;

        if !punycode {
            return Some(text.to_string());
        }

        return Some(decode_punycode(text).unwrap_or_else(|| format!("punycode{{{}}}", text)));
    }

    /// Prints a backreference by parsing the earlier position again
    fn backref(&mut self, print: fn(&mut Self) -> Option<()>) -> Option<()> {
        let start = self.pos - 1;
        let target = self.base62()? as usize;

        if target >= start {
            return None;
        }

        let saved = self.pos;
        self.pos = target;
        self.enter()?;
        print(self)?;
        self.leave();
        self.pos = saved;

        return Some(());
    }

    /// Paths in values print their generic arguments after "::"
    fn path(&mut self, in_value: bool) -> Option<()> {
        self.enter()?;

        match self.next()? {
            b'C' => {
                self.disambiguator()?;
                let name = self.identifier()?;
                self.out.push_str(&name);
            }
            b'N' => {
                let namespace = self.next()?;
                self.path(in_value)?;
                let disambiguator = self.disambiguator()?;
                let name = self.identifier()?;

                if namespace.is_ascii_lowercase() {
                    if !name.is_empty() {
                        self.out.push_str("::");
                        self.out.push_str(&name);
                    }
                } else {
                    let kind = match namespace {
                        b'C' => "closure".to_string(),
                        b'S' => "shim".to_string(),
                        other => (other as char).to_string(),
                    };

                    self.out.push_str("::{");
                    self.out.push_str(&kind);

                    if !name.is_empty() {
                        self.out.push(':');
                        self.out.push_str(&name);
                    }

                    self.out.push_str(&format!("#{}}}", disambiguator));
                }
            }
            b'M' => {
                self.disambiguator()?;
                self.impl_path()?;
                self.out.push('<');
                self.ty()?;
                self.out.push('>');
            }
            b'X' => {
                self.disambiguator()?;
                self.impl_path()?;
                self.out.push('<');
                self.ty()?;
                self.out.push_str(" as ");
                self.path(false)?;
                self.out.push('>');
            }
            b'Y' => {
                self.out.push('<');
                self.ty()?;
                self.out.push_str(" as ");
                self.path(false)?;
                self.out.push('>');
            }
            b'I' => {
                self.path(in_value)?;

                if in_value {
                    self.out.push_str("::");
                }

                self.out.push('<');
                let mut first = true;

                while !self.eat(b'E') {
                    if !first {
                        self.out.push_str(", ");
                    }

                    first = false;
                    self.generic_arg()?;
                }

                self.out.push('>');
            }
            b'B' => {
                if in_value {
                    self.backref(|p| p.path(true))?;
                } else {
                    self.backref(|p| p.path(false))?;
                }
            }
            _ => return None,
        }

        self.leave();
        return Some(());
    }

    /// The path of an impl is not printed (only its type and trait)
    fn impl_path(&mut self) -> Option<()> {
        let length = self.out.len();
        self.disambiguator()?;
        self.path(false)?;
        self.out.truncate(length);
        return Some(());
    }

    /// 0 is the erased lifetime, the others count the binders from the innermost one
    fn lifetime(&mut self, index: u64) -> Option<()> {
        self.out.push('\'');

        if index == 0 {
            self.out.push('_');
            return Some(());
        }

        let depth = self.bound.checked_sub(index)?;

        if depth < 26 {
            self.out.push((b'a' + depth as u8) as char);
        } else {
            self.out.push_str(&format!("_{}", depth));
        }

        return Some(());
    }

    /// ["G" <base-62-number>] before what the lifetimes are bound in: for<'a, 'b>
    fn binder(&mut self) -> Option<u64> {
        if !self.eat(b'G') {
            return Some(0);
        }

        let count = self.base62()?.checked_add(1)?;
        self.out.push_str("for<");

        for i in 0..count {
            if i > 0 {
                self.out.push_str(", ");
            }

            self.bound += 1;
            self.lifetime(1)?;
        }

        self.out.push_str("> ");
        return Some(count);
    }

    fn generic_arg(&mut self) -> Option<()> {
        if self.eat(b'L') {
            let index = self.base62()?;
            return self.lifetime(index);
        }

        if self.eat(b'K') {
            return self.constant();
        }

        return self.ty();
    }

    fn ty(&mut self) -> Option<()> {
        self.enter()?;
        let c = self.next()?;

        let basic = match c {
            b'a' => Some("i8"),
            b'b' => Some("bool"),
            b'c' => Some("char"),
            b'd' => Some("f64"),
            b'e' => Some("str"),
            b'f' => Some("f32"),
            b'h' => Some("u8"),
            b'i' => Some("isize"),
            b'j' => Some("usize"),
            b'l' => Some("i32"),
            b'm' => Some("u32"),
            b'n' => Some("i128"),
            b'o' => Some("u128"),
            b's' => Some("i16"),
            b't' => Some("u16"),
            b'u' => Some("()"),
            b'v' => Some("..."),
            b'x' => Some("i64"),
            b'y' => Some("u64"),
            b'z' => Some("!"),
            b'p' => Some("_"),
            _ => None,
        };

        if let Some(basic) = basic {
            self.out.push_str(basic);
            self.leave();
            return Some(());
        }

        match c {
            b'R' | b'Q' => {
                self.out.push('&');

                if self.eat(b'L') {
                    let index = self.base62()?;

                    if index != 0 {
                        self.lifetime(index)?;
                        self.out.push(' ');
                    }
                }

                if c == b'Q' {
                    self.out.push_str("mut ");
                }

                self.ty()?;
            }
            b'P' => {
                self.out.push_str("*const ");
                self.ty()?;
            }
            b'O' => {
                self.out.push_str("*mut ");
                self.ty()?;
            }
            b'A' => {
                self.out.push('[');
                self.ty()?;
                self.out.push_str("; ");
                self.constant()?;
                self.out.push(']');
            }
            b'S' => {
                self.out.push('[');
                self.ty()?;
                self.out.push(']');
            }
            b'T' => {
                self.out.push('(');
                let mut count = 0;

                while !self.eat(b'E') {
                    if count > 0 {
                        self.out.push_str(", ");
                    }

                    self.ty()?;
                    count += 1;
                }

                if count == 1 {
                    self.out.push(',');
                }

                self.out.push(')');
            }
            b'F' => self.fn_sig()?,
            b'D' => {
                self.out.push_str("dyn ");
                let bound = self.binder()?;
                let mut first = true;

                while !self.eat(b'E') {
                    if !first {
                        self.out.push_str(" + ");
                    }

                    first = false;
                    self.dyn_trait()?;
                }

                self.bound -= bound;

                // The lifetime of the object, printed when it is not erased
                if !self.eat(b'L') {
                    return None;
                }

                let index = self.base62()?;

                if index != 0 {
                    self.out.push_str(" + ");
                    self.lifetime(index)?;
                }
            }
            b'B' => self.backref(|p| p.ty())?,
            _ => {
                self.pos -= 1;
                self.path(false)?;
            }
        }

        self.leave();
        return Some(());
    }

    fn fn_sig(&mut self) -> Option<()> {
        let bound = self.binder()?;
        let result = self.fn_sig_bound();
        self.bound -= bound;
        return result;
    }

    fn fn_sig_bound(&mut self) -> Option<()> {
        if self.eat(b'U') {
            self.out.push_str("unsafe ");
        }

        if self.eat(b'K') {
            let abi = if self.eat(b'C') { "C".to_string() } else { self.identifier()?.replace('_', "-") };
            self.out.push_str(&format!("extern \"{}\" ", abi));
        }

        self.out.push_str("fn(");
        let mut first = true;

        while !self.eat(b'E') {
            if !first {
                self.out.push_str(", ");
            }

            first = false;
            self.ty()?;
        }

        self.out.push(')');

        // Unit results are not printed
        if self.eat(b'u') {
            return Some(());
        }

        self.out.push_str(" -> ");
        return self.ty();
    }

    /// <path> {"p" <undisambiguated-identifier> <type>}: Trait<Assoc = T>
    fn dyn_trait(&mut self) -> Option<()> {
        self.path(false)?;
        let mut open = self.out.ends_with('>');

        while self.eat(b'p') {
            let name = self.identifier()?;

            if open {
                self.out.pop();
                self.out.push_str(", ");
            } else {
                self.out.push('<');
                open = true;
            }

            self.out.push_str(&name);
            self.out.push_str(" = ");
            self.ty()?;
            self.out.push('>');
        }

        return Some(());
    }

    fn constant(&mut self) -> Option<()> {
        self.enter()?;

        if self.eat(b'p') {
            self.out.push('_');
            self.leave();
            return Some(());
        }

        if self.eat(b'B') {
            self.backref(|p| p.constant())?;
            self.leave();
            return Some(());
        }

        let ty = self.next()?;
        let negative = self.eat(b'n');
        let start = self.pos;

        while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            self.pos += 1;
        }

        let hex = std::str::from_utf8(&self.sym[start..self.pos]).ok()?;

        if !self.eat(b'_') {
            return None;
        }

        let value = if hex.is_empty() { 0 } else { u128::from_str_radix(hex, 16).ok()? };

        match ty {
            b'b' => self.out.push_str(match value {
                0 => "false",
                1 => "true",
                _ => return None,
            }),
            b'c' => {
                let c = char::from_u32(u32::try_from(value).ok()?)?;
                self.out.push_str(&format!("{:?}", c));
            }
            b'a' | b's' | b'l' | b'x' | b'n' | b'i' | b'h' | b't' | b'm' | b'y' | b'o' | b'j' => {
                if negative {
                    self.out.push('-');
                }

                self.out.push_str(&value.to_string());
            }
            _ => return None,
        }

        self.leave();
        return Some(());
    }
}

/// RFC 3492, with '_' instead of '-' between the basic and the encoded characters
fn decode_punycode(text: &str) -> Option<String> {
    let (basic, encoded) = match text.rfind('_') {
        Some(index) => (&text[..index], &text[index + 1..]),
        None => ("", text),
    };

    let mut output: Vec<char> = basic.chars().collect();
    let (mut n, mut bias, mut i): (u32, u32, u32) = (128, 72, 0);
    let mut digits = encoded.bytes().peekable();

    while digits.peek().is_some() {
        let old = i;
        let mut weight = 1u32;
        let mut k = 36;

        loop {
            let digit = match digits.next()? {
                c @ b'a'..=b'z' => (c - b'a') as u32,
                c @ b'0'..=b'9' => (c - b'0') as u32 + 26,
                _ => return None,
            };

            i = i.checked_add(digit.checked_mul(weight)?)?;
            let t = if k <= bias { 1 } else if k >= bias + 26 { 26 } else { k - bias };

            if digit < t {
                break;
            }

            weight = weight.checked_mul(36 - t)?;
            k += 36;
        }

        let length = output.len() as u32 + 1;
        let mut delta = if old == 0 { (i - old) / 700 } else { (i - old) / 2 };
        delta += delta / length;
        let mut k = 0;

        while delta > ((36 - 1) * 26) / 2 {
            delta /= 36 - 1;
            k += 36;
        }

        bias = k + (36 * delta) / (delta + 38);
        n = n.checked_add(i / length)?;
        i %= length;
        output.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }

    return Some(output.into_iter().collect());
}

#[cfg(test)]
pub fn decode_punycode_for_tests(text: &str) -> Option<String> {
    return decode_punycode(text);
}

pub fn demangle_v0(symbol: &str) -> Option<String> {
    let body = v0_body(symbol)?;
    let mut parser = V0 { sym: body.as_bytes(), pos: 0, depth: 0, out: String::new(), bound: 0 };

    parser.path(true)?;

    // The instantiating crate is not printed, the vendor suffix (.llvm.N) is
    if parser.peek().is_some_and(|c| c.is_ascii_uppercase()) {
        let length = parser.out.len();
        parser.path(false)?;
        parser.out.truncate(length);
    }

    let rest = &body[parser.pos..];

    if rest.is_empty() {
        return Some(parser.out);
    }

    if !rest.starts_with(['.', '$']) {
        return None;
    }

    return Some(format!("{} ({})", parser.out, rest));
}

/// Name only (the path split on its top level "::")
pub fn demangle_v0_symbol(symbol: &str) -> Option<Symbol> {
    return Some(name_symbol(&demangle_v0(symbol)?));
}
