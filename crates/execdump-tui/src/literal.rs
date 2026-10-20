/*
 * The string literal under the cursor of the C code in the forms it is used in: its text, a C literal of
 * ASCII characters, its bytes, a shell argument and a Python bytes object. The C code shows the UTF-8 text,
 * the offsets of the bytes are in the other forms.
 */

use std::fmt::Write;

/// A string literal of a line: its columns (characters, end excluded) and its bytes
struct Literal {
    start: usize,
    end: usize,
    bytes: Vec<u8>,
}

/// Bytes of an escape sequence starting after the backslash at index i, and the index after it
fn unescape(chars: &[char], i: usize, bytes: &mut Vec<u8>) -> usize {
    let Some(&c) = chars.get(i) else {
        return i;
    };

    let digits = |from: usize, radix: u32, max: usize| chars[from..].iter().take(max).take_while(|c| c.is_digit(radix)).count();

    match c {
        'x' => {
            let count = digits(i + 1, 16, usize::MAX);
            let text: String = chars[i + 1..i + 1 + count].iter().collect();
            bytes.push(u32::from_str_radix(&text, 16).unwrap_or(0) as u8);
            return i + 1 + count;
        }
        '0'..='7' => {
            let count = digits(i, 8, 3);
            let text: String = chars[i..i + count].iter().collect();
            bytes.push(u32::from_str_radix(&text, 8).unwrap_or(0) as u8);
            return i + count;
        }
        _ => {}
    }

    let byte = match c {
        'n' => b'\n',
        'r' => b'\r',
        't' => b'\t',
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'v' => 11,
        'e' => 27,
        other => {
            bytes.extend_from_slice(other.encode_utf8(&mut [0; 4]).as_bytes());
            return i + 1;
        }
    };

    bytes.push(byte);
    return i + 1;
}

/// The string literals of a line, the ones separated by spaces only are one ("a" "b")
fn literals(line: &str) -> Vec<Literal> {
    let chars: Vec<char> = line.chars().collect();
    let mut found: Vec<Literal> = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            // A character literal can hold a quote: '"'
            '\'' => {
                i += 1;

                while i < chars.len() && chars[i] != '\'' {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }

                i += 1;
            }
            '/' if chars.get(i + 1) == Some(&'/') => break,
            '"' => {
                let start = i;
                let mut bytes = Vec::new();
                i += 1;

                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i = unescape(&chars, i + 1, &mut bytes);
                    } else {
                        bytes.extend_from_slice(chars[i].encode_utf8(&mut [0; 4]).as_bytes());
                        i += 1;
                    }
                }

                i += 1;

                let joined = found.last_mut().filter(|previous| chars[previous.end..start].iter().all(|c| c.is_whitespace()));

                match joined {
                    Some(previous) => {
                        previous.bytes.extend(bytes);
                        previous.end = i.min(chars.len());
                    }
                    None => found.push(Literal { start, end: i.min(chars.len()), bytes }),
                }
            }
            _ => i += 1,
        }
    }

    return found;
}

/// Bytes of the string literal at a column of a line, or of the first one after it
pub fn literal_at(line: &str, col: usize) -> Option<Vec<u8>> {
    let found = literals(line);
    let literal = found.iter().find(|l| col >= l.start && col < l.end).or_else(|| found.iter().find(|l| l.start >= col))?;
    return Some(literal.bytes.clone());
}

/// The bytes as text, the control characters and the bytes that are not UTF-8 escaped
pub fn text(bytes: &[u8]) -> String {
    let mut out = String::new();

    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                c if c.is_control() => out.extend(c.escape_default()),
                c => out.push(c),
            }
        }

        for b in chunk.invalid() {
            let _ = write!(out, "\\x{:02x}", b);
        }
    }

    return out;
}

/// The bytes as printable ASCII, the others escaped (\r, \xc3), the quote and the backslash too
pub fn escaped(bytes: &[u8], quote: char) -> String {
    let mut out = String::new();

    for &b in bytes {
        match b {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            b if b as char == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(b as char),
            b => {
                let _ = write!(out, "\\x{:02x}", b);
            }
        }
    }

    return out;
}

/// C literal: the hexadecimal escapes take every hexadecimal digit after them, the literal is split there
pub fn c_literal(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut hex = false;

    for &b in bytes {
        let form = escaped(&[b], '"');

        if hex && b.is_ascii_hexdigit() {
            out.push_str("\" \"");
        }

        hex = form.starts_with("\\x");
        out.push_str(&form);
    }

    out.push('"');
    return out;
}

/// The forms of a string: its label and its text
pub fn forms(bytes: &[u8]) -> Vec<(&'static str, String)> {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let characters = String::from_utf8_lossy(bytes).chars().count();

    return vec![
        ("text", text(bytes)),
        ("C", c_literal(bytes)),
        ("bytes", hex.join(" ")),
        ("shell", format!("$'{}'", escaped(bytes, '\''))),
        ("python", format!("b\"{}\"", escaped(bytes, '"'))),
        ("length", format!("{} bytes, {} characters", bytes.len(), characters)),
    ];
}

/// Base64 of bytes (OSC 52 sends the text to copy in it)
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));

        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }

    return out;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_under_the_cursor() {
        let line = r#"    memcpy(ptr, "_0cGj35m9V5T3Ç" "8CJ0\xc3\x80" "9H9", 31); c = '"'; puts("x\r\n\0012");"#;

        let col = |text: &str| line[..line.find(text).unwrap()].chars().count();

        // The literals next to each other are one, from any of their columns
        let bytes = literal_at(line, col("_0c")).unwrap();
        assert_eq!(bytes, "_0cGj35m9V5T3Ç8CJ0À9H9".as_bytes());
        assert_eq!(literal_at(line, col("8CJ0")).unwrap(), bytes);
        assert_eq!(literal_at(line, col("memcpy")).unwrap(), bytes);

        // The quote of a character literal starts nothing, the escapes are bytes
        assert_eq!(literal_at(line, col("c = ")).unwrap(), b"x\r\n\x012");
        assert_eq!(literal_at("no string", 0), None);
    }

    #[test]
    fn forms_of_a_string() {
        let forms = forms(b"_0c\xc3\x878\r\n\0'");
        let form = |label: &str| forms.iter().find(|(l, _)| *l == label).unwrap().1.clone();

        assert_eq!(form("text"), "_0cÇ8\\r\\n\\u{0}'");
        assert_eq!(form("C"), "\"_0c\\xc3\\x87\" \"8\\r\\n\\x00'\"");
        assert_eq!(form("bytes"), "5f 30 63 c3 87 38 0d 0a 00 27");
        assert_eq!(form("shell"), "$'_0c\\xc3\\x878\\r\\n\\x00\\''");
        assert_eq!(form("python"), "b\"_0c\\xc3\\x878\\r\\n\\x00'\"");
        assert_eq!(form("length"), "10 bytes, 9 characters");
    }

    #[test]
    fn base64_of_bytes() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }
}
