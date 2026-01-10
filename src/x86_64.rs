pub fn is_type_qualifier(s: &str) -> bool {
    return matches!(s, "byte" | "word" | "dword" | "qword");
}

pub fn starts_with_type_qualifier(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }

    if matches!(&s[..4], "byte" | "word") {
        return true;
    }

    if s.len() < 5 {
        return false;
    }

    if matches!(&s[..5], "dword" | "qword") {
        return true;
    }

    return false;
}

pub fn is_x86_64_register(s: &str) -> bool {
    if s.is_empty() || s.len() > 4 {
        return false;
    }

    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut buf = [0u8; 4];

    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }

    let lower = &buf[..len];

    match len {
        2 => {
            matches!(lower,
                b"ax" | b"bx" | b"cx" | b"dx" |
                b"si" | b"di" | b"bp" | b"sp" |
                b"al" | b"ah" | b"bl" | b"bh" |
                b"cl" | b"ch" | b"dl" | b"dh" |
                b"r8" | b"r9")
        }
        3 => {
            match lower[0] {
                b'e' => matches!(lower, b"eax" | b"ebx" | b"ecx" | b"edx" |
                                        b"esi" | b"edi" | b"ebp" | b"esp"),
                b'r' => matches!(lower, b"rax" | b"rbx" | b"rcx" | b"rdx" |
                                        b"rsi" | b"rdi" | b"rbp" | b"rsp" |
                                        b"rip" | b"r10" | b"r11" | b"r12" |
                                        b"r13" | b"r14" | b"r15") ||
                        (lower[1] == b'8' || lower[1] == b'9') &&
                        matches!(lower[2], b'd' | b'w' | b'b'),
                b's' => matches!(lower, b"spl" | b"sil"),
                b'b' | b'd' => lower[2] == b'l' && matches!(lower[1], b'p' | b'i'),
                b'x' | b'y' | b'z' => lower[1] == b'm' && lower[2] == b'm',
                _ => false,
            }
        }
        4 => {
            if lower[0] == b'r' && lower[1] >= b'1' && lower[1] <= b'9' {
                let num = if lower[2] >= b'0' && lower[2] <= b'9' {
                    (lower[1] - b'0') * 10 + (lower[2] - b'0')
                } else {
                    lower[1] - b'0'
                };

                if num >= 8 && num <= 9 {
                    lower[2] == b'd' || lower[2] == b'w' || lower[2] == b'b'
                } else if num >= 10 && num <= 15 {
                    lower[3] == 0 || matches!(lower[3], b'd' | b'w' | b'b')
                } else {
                    false
                }
            } else if matches!(lower[0], b'x' | b'y' | b'z') && lower[1] == b'm' && lower[2] == b'm' {
                lower[3] >= b'0' && lower[3] <= b'9'
            } else {
                lower[0] == b'r' && matches!(lower[1], b'8' | b'9') &&
                matches!(lower[2], b'd' | b'w' | b'b')
            }
        }
        5 => {
            if lower[0] == b'r' && lower[1] == b'1' &&
               lower[2] >= b'0' && lower[2] <= b'5' &&
               matches!(lower[3], b'd' | b'w' | b'b') {
               return true;
            } else if matches!(lower[0], b'x' | b'y' | b'z') &&
                      lower[1] == b'm' && lower[2] == b'm' &&
                      lower[3] >= b'1' && lower[3] <= b'3' &&
                      lower[4] >= b'0' && lower[4] <= b'9' {
                let num = (lower[3] - b'0') * 10 + (lower[4] - b'0');
                num >= 10 && num <= 31
            } else {
                return false;
            }
        }
        _ => false,
    }
}
