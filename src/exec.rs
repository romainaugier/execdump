use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::elf::{ELF_MAGIC_ARRAY, ELF};
use crate::macho::{is_macho, MachO};
use crate::pe::{DOS_MAGIC_ARRAY, PE};

pub enum ExecType {
    PE,
    ELF,
    MachO,
}

pub fn guess_exectype(path: &PathBuf) -> Result<ExecType, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0; 8];

    file.read_exact(&mut buffer)?;

    if buffer[0..4] == ELF_MAGIC_ARRAY {
        return Ok(ExecType::ELF);
    }

    if buffer[0..2] == DOS_MAGIC_ARRAY {
        return Ok(ExecType::PE);
    }

    if is_macho(&buffer) {
        return Ok(ExecType::MachO);
    }

    return Err("Cannot determine the executable type".into());
}

#[derive(Debug)]
pub enum Exec {
    PE(PE),
    ELF(ELF),
    MachO(MachO),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    }

    #[test]
    fn guess_fixtures_exectype() {
        assert!(matches!(guess_exectype(&fixture("elf_aarch64_static")).unwrap(), ExecType::ELF));
        assert!(matches!(guess_exectype(&fixture("pe_arm64.exe")).unwrap(), ExecType::PE));
        assert!(matches!(guess_exectype(&fixture("macho_x86_64")).unwrap(), ExecType::MachO));
        assert!(matches!(guess_exectype(&fixture("macho_fat.o")).unwrap(), ExecType::MachO));
    }
}
