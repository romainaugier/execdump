/*
 * FNV-1a: stable across runs and Rust versions (the fingerprints are stored on disk)
 */

#[derive(Clone, Copy, Debug)]
pub struct Fnv(u64);

impl Fnv {
    pub fn new() -> Self {
        return Fnv(0xcbf29ce484222325);
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }

        return self;
    }

    /// Strings are length prefixed so that ("ab", "c") and ("a", "bc") differ
    pub fn str(&mut self, text: &str) -> &mut Self {
        self.u64(text.len() as u64);
        return self.bytes(text.as_bytes());
    }

    pub fn opt(&mut self, text: Option<&str>) -> &mut Self {
        return match text {
            Some(text) => self.u64(1).str(text),
            None => self.u64(0),
        };
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        return self.bytes(&value.to_le_bytes());
    }

    pub fn finish(&self) -> u64 {
        return self.0;
    }
}

/// Identifies the running build of execdump: its outputs are only reused by the same build
pub fn build_id() -> u64 {
    let mut hash = Fnv::new();
    hash.str(env!("CARGO_PKG_VERSION"));

    let metadata = std::env::current_exe().and_then(std::fs::metadata);

    if let Ok(metadata) = metadata {
        hash.u64(metadata.len());

        if let Ok(modified) = metadata.modified().map(|m| m.duration_since(std::time::UNIX_EPOCH).unwrap_or_default()) {
            hash.u64(modified.as_secs()).u64(modified.subsec_nanos() as u64);
        }
    }

    return hash.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable() {
        assert_eq!(Fnv::new().bytes(b"a").finish(), 0xaf63dc4c8601ec8c);
        assert_ne!(Fnv::new().str("ab").str("c").finish(), Fnv::new().str("a").str("bc").finish());
    }
}
