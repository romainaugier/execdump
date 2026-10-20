/*
 * A value of the debugger in the forms it is used in (:value): as it is shown, in hexadecimal, as the integers of each
 * size (signed and unsigned) and the floats its bytes make, as a pointer (what it points to: a function, a string),
 * and as bytes (a C array, a Python bytes object, base64). The integers and the floats are read in the byte order of
 * the program from the first bytes of the value.
 */

use crate::literal;

/// The forms :value <expression> <form> copies
pub(crate) const FORMS: &[&str] = &[
    "value", "hex", "pointer", "string", "text", "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64", "char", "bytes", "c", "python", "base64",
];

/// Values up to this size are numbers too (the larger ones are blocks of memory)
const NUMBER_MAX: usize = 16;

/// What a value points to: the name of the place, the bytes there (a string up to its NUL)
#[derive(Clone, Debug, Default)]
pub(crate) struct Pointee {
    pub name: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

/// The unsigned integer of the first bytes of a value
pub(crate) fn unsigned(bytes: &[u8], big_endian: bool) -> u128 {
    let bytes = &bytes[..bytes.len().min(NUMBER_MAX)];

    return match big_endian {
        true => bytes.iter().fold(0u128, |v, &b| v << 8 | b as u128),
        false => bytes.iter().rev().fold(0u128, |v, &b| v << 8 | b as u128),
    };
}

fn signed(value: u128, width: usize) -> i128 {
    let bits = width as u32 * 8;

    if bits >= 128 || value >> (bits - 1) & 1 == 0 {
        return value as i128;
    }

    return value as i128 - (1i128 << bits);
}

/// A C character literal of a byte
fn character(byte: u8) -> String {
    return format!("'{}'", literal::escaped(&[byte], '\''));
}

/// The text a pointer points to: its bytes up to the NUL, when they look like text
fn text_of(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().position(|&b| b == 0)?;
    let text = &bytes[..end];
    let printable = text.iter().filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b >= 0x80).count();

    return (!text.is_empty() && printable * 10 >= text.len() * 9).then_some(text);
}

/// The forms of a value: its label and its text, the first one is the value as the debug view shows it
pub(crate) fn forms(bytes: &[u8], big_endian: bool, pointer_size: usize, shown: Option<String>, pointee: Option<Pointee>) -> Vec<(&'static str, String)> {
    let mut forms = Vec::new();
    let n = bytes.len();

    if let Some(shown) = shown {
        forms.push(("value", shown));
    }

    if n > 0 && n <= NUMBER_MAX {
        forms.push(("hex", format!("{:#0width$x}", unsigned(bytes, big_endian), width = 2 + 2 * n)));
    }

    // What it points to, else the text of its bytes (a buffer of characters, up to its NUL)
    let pointee = pointee.filter(|_| n >= pointer_size && n <= NUMBER_MAX).unwrap_or_default();

    if let Some(name) = pointee.name.as_ref() {
        forms.push(("pointer", format!("{:#x} <{}>", unsigned(&bytes[..pointer_size], big_endian), name)));
    }

    let text = match pointee.bytes.as_deref() {
        Some(pointed) => text_of(pointed),
        None => text_of(bytes).or_else(|| (n > NUMBER_MAX && !bytes.contains(&0)).then_some(bytes)),
    };

    if let Some(text) = text {
        forms.push(("string", literal::c_literal(text)));
        forms.push(("text", literal::text(text)));
    }

    if n > 0 && n <= NUMBER_MAX {
        let value = unsigned(bytes, big_endian);

        for (width, unsigned_label, signed_label) in [(1, "u8", "i8"), (2, "u16", "i16"), (4, "u32", "i32"), (8, "u64", "i64")] {
            if width > n {
                break;
            }

            let first = match big_endian {
                true => unsigned(&bytes[..width], true),
                false => value & ((1u128 << (width * 8)) - 1),
            };

            forms.push((unsigned_label, first.to_string()));
            forms.push((signed_label, signed(first, width).to_string()));
        }

        if n >= 4 {
            forms.push(("f32", format!("{:?}", f32::from_bits(unsigned(&bytes[..4], big_endian) as u32))));
        }

        if n >= 8 {
            forms.push(("f64", format!("{:?}", f64::from_bits(unsigned(&bytes[..8], big_endian) as u64))));
        }

        forms.push(("char", character(if big_endian { bytes[n - 1] } else { bytes[0] })));
    }

    let hex: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    forms.push(("bytes", bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")));
    forms.push(("c", format!("{{ {} }}", hex.join(", "))));
    forms.push(("python", format!("b\"{}\"", literal::escaped(bytes, '"'))));
    forms.push(("base64", literal::base64(bytes)));

    return forms;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form<'a>(forms: &'a [(&'static str, String)], label: &str) -> Option<&'a str> {
        return forms.iter().find(|(l, _)| *l == label).map(|(_, t)| t.as_str());
    }

    #[test]
    fn integers_and_floats() {
        let forms = forms(&(-2i32).to_le_bytes(), false, 8, Some("-2".to_string()), None);

        assert_eq!(form(&forms, "value"), Some("-2"));
        assert_eq!(form(&forms, "hex"), Some("0xfffffffe"));
        assert_eq!(form(&forms, "u32"), Some("4294967294"));
        assert_eq!(form(&forms, "i32"), Some("-2"));
        assert_eq!(form(&forms, "u16"), Some("65534"));
        assert_eq!(form(&forms, "i8"), Some("-2"));
        assert_eq!(form(&forms, "u64"), None);
        assert_eq!(form(&forms, "bytes"), Some("fe ff ff ff"));
        assert_eq!(form(&forms, "c"), Some("{ 0xfe, 0xff, 0xff, 0xff }"));
        assert_eq!(form(&forms, "python"), Some("b\"\\xfe\\xff\\xff\\xff\""));

        let forms = super::forms(&1.5f64.to_le_bytes(), false, 8, None, None);
        assert_eq!(form(&forms, "f64"), Some("1.5"));
        assert_eq!(form(&forms, "hex"), Some("0x3ff8000000000000"));

        // Big endian: the first bytes are the high ones
        let forms = super::forms(&[0x12, 0x34, 0x56, 0x78], true, 4, None, None);
        assert_eq!(form(&forms, "hex"), Some("0x12345678"));
        assert_eq!(form(&forms, "u16"), Some(&*0x1234.to_string()));
        assert_eq!(form(&forms, "char"), Some("'x'"));
    }

    #[test]
    fn pointers_and_text() {
        let pointee = Pointee { name: Some("main+0x10".to_string()), bytes: Some(b"hi \"you\"\n\0junk".to_vec()) };
        let forms = forms(&0x401020u64.to_le_bytes(), false, 8, None, Some(pointee));

        assert_eq!(form(&forms, "pointer"), Some("0x401020 <main+0x10>"));
        assert_eq!(form(&forms, "string"), Some("\"hi \\\"you\\\"\\n\""));
        assert_eq!(form(&forms, "text"), Some("hi \"you\"\\n"));

        // Bytes that are not text point to no string
        let pointee = Pointee { name: None, bytes: Some(vec![0x90, 0x01, 0x02, 0x00]) };
        assert_eq!(form(&super::forms(&8u64.to_le_bytes(), false, 8, None, Some(pointee)), "string"), None);

        // A buffer of characters in a value
        let forms = super::forms(b"hello\0\0\0\0\0\0\0\0\0\0\0", false, 8, None, None);
        assert_eq!(form(&forms, "text"), Some("hello"));

        // A block of memory: its bytes and its text, no numbers
        let block = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
        let forms = super::forms(block, false, 8, None, None);
        assert_eq!(form(&forms, "u8"), None);
        assert_eq!(form(&forms, "text"), Some("GET / HTTP/1.1\\r\\nHost: example\\r\\n\\r\\n"));
        assert_eq!(form(&forms, "base64"), Some(&*literal::base64(block)));
    }
}
