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
