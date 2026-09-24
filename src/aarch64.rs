pub fn is_aarch64_register(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();

    if matches!(lower.as_str(), "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp" | "pc") {
        return true;
    }

    let register = lower.split('.').next().unwrap_or("");

    let Some(prefix) = register.chars().next() else {
        return false;
    };

    let digits = &register[1..];

    if !matches!(prefix, 'x' | 'w' | 'b' | 'h' | 's' | 'd' | 'q' | 'v') ||
       digits.is_empty() || digits.len() > 2 ||
       !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    let num: u8 = digits.parse().unwrap_or(u8::MAX);

    return num < 31 || (num == 31 && !matches!(prefix, 'x' | 'w'));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers() {
        for register in ["x0", "x30", "w12", "sp", "wsp", "xzr", "wzr", "lr", "d8", "q31", "v0.16b", "s1"] {
            assert!(is_aarch64_register(register), "{}", register);
        }

        for text in ["x31", "w32", "#0x10", "b", "x", "lsl", "x1a", "[sp", "xmm0", "rax"] {
            assert!(!is_aarch64_register(text), "{}", text);
        }
    }
}
