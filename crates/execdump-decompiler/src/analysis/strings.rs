// SPDX-License-Identifier: Apache-2.0
/*
 * String extraction from the non executable regions
 */

use execdump_core::program::Program;

use std::collections::BTreeMap;

const MIN_STRING_LENGTH: usize = 4;
const MAX_STRING_LENGTH: usize = 4096;

fn is_string_char(c: u8) -> bool {
    return c.is_ascii_graphic() || c == b' ' || c == b'\t' || c == b'\n' || c == b'\r';
}

/// Length in bytes and in characters of the string at the start of the data: ASCII text and UTF-8
/// characters (Vérification, réussie)
fn text_length(data: &[u8]) -> (usize, usize) {
    let (mut bytes, mut chars) = (0, 0);

    while bytes < data.len() && chars < MAX_STRING_LENGTH {
        if is_string_char(data[bytes]) {
            bytes += 1;
            chars += 1;
            continue;
        }

        let width = match data[bytes] {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => break,
        };

        let decoded = data.get(bytes..bytes + width).and_then(|b| std::str::from_utf8(b).ok()).and_then(|s| s.chars().next());

        if !decoded.is_some_and(|c| !c.is_control()) {
            break;
        }

        bytes += width;
        chars += 1;
    }

    return (bytes, chars);
}

/// Extracts the NUL terminated ASCII and UTF-8 (and UTF-16LE for PE) strings
pub fn extract_strings(program: &Program) -> BTreeMap<u64, String> {
    let mut strings = BTreeMap::new();
    let wide = program.name.starts_with("PE");

    for region in program.regions.iter().filter(|r| !r.perms.exec) {
        let data = &region.data;
        let mut start = 0usize;

        while start < data.len() {
            let (len, chars) = text_length(&data[start..]);

            if chars >= MIN_STRING_LENGTH && data.get(start + len) == Some(&0) {
                strings.insert(region.vaddr + start as u64, String::from_utf8_lossy(&data[start..start + len]).to_string());
            }

            start += len + 1;
        }

        if !wide {
            continue;
        }

        let mut start = 0usize;

        while start + 1 < data.len() {
            let mut chars = Vec::new();
            let mut pos = start;

            while pos + 1 < data.len() && chars.len() < MAX_STRING_LENGTH && data[pos + 1] == 0 && is_string_char(data[pos]) {
                chars.push(data[pos]);
                pos += 2;
            }

            let terminated = data.get(pos) == Some(&0) && data.get(pos + 1) == Some(&0);

            if chars.len() >= MIN_STRING_LENGTH && terminated {
                strings.entry(region.vaddr + start as u64).or_insert_with(|| String::from_utf8_lossy(&chars).to_string());
            }

            start = if chars.is_empty() { start + 2 } else { pos + 2 };
        }
    }

    return strings;
}

/// Escapes and truncates a string for display on a single line
pub fn escape(string: &str, max_len: usize) -> String {
    let mut res = String::new();

    for c in string.chars() {
        if res.len() >= max_len {
            res.push_str("...");
            break;
        }

        match c {
            '\n' => res.push_str("\\n"),
            '\r' => res.push_str("\\r"),
            '\t' => res.push_str("\\t"),
            '"' => res.push_str("\\\""),
            c => res.push(c),
        }
    }

    return res;
}

#[cfg(test)]
mod tests {
    use super::*;
    use execdump_core::program::{Perms, Region};

    #[test]
    fn ascii_and_wide() {
        let mut program = Program::default();
        program.name = "PE X86_64".to_string();

        let mut data = b"\0hello world\0abc\0\0".to_vec();
        data.extend_from_slice(&[b'w', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0]);

        program.regions.push(Region { name: ".rdata".to_string(), vaddr: 0x1000, size: data.len() as u64, data, perms: Perms { read: true, write: false, exec: false } });

        let strings = extract_strings(&program);

        assert_eq!(strings.get(&0x1001).map(|s| s.as_str()), Some("hello world"));
        assert!(!strings.values().any(|s| s == "abc"));
        assert_eq!(strings.get(&0x1012).map(|s| s.as_str()), Some("wide"));
        assert_eq!(escape("a\nb", 10), "a\\nb");
    }

    #[test]
    fn utf8() {
        let mut program = Program::default();
        let data = b"\0V\xc3\xa9rification...\0abcd\xc3\0xyz\xe9zzzz\0".to_vec();

        program.regions.push(Region { name: ".rodata".to_string(), vaddr: 0x1000, size: data.len() as u64, data, perms: Perms { read: true, write: false, exec: false } });

        let strings = extract_strings(&program);

        assert_eq!(strings.get(&0x1001).map(|s| s.as_str()), Some("Vérification..."));
        // Invalid UTF-8 ends a string
        assert_eq!(strings.len(), 2, "{:?}", strings);
        assert_eq!(strings.get(&0x101c).map(|s| s.as_str()), Some("zzzz"));
    }
}
