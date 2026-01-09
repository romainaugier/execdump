use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::elf::{ELF_MAGIC_ARRAY, ELF};
use crate::pe::{DOS_MAGIC_ARRAY, PE};

pub enum ExecType {
    PE,
    ELF,
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

    return Err("Cannot determine the executable type".into());
}

#[derive(Debug)]
pub enum Exec {
    PE(PE),
    ELF(ELF),
}
