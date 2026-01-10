
pub fn is_digit(s: &str) -> bool {
    return s.as_bytes().first().map_or(false, |&b| matches!(b, b'0'..=b'9'));
}
