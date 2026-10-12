/*
 * aarch64 instruction semantics
 */

use super::regs::RegisterFile;
use super::{Lifter, MemAccess, Tracker};

use capstone::Capstone;

#[derive(Clone, Debug)]
pub struct Insn {
    pub addr: u64,
}

pub fn decode(_regs: &RegisterFile, _cs: &Capstone, _bytes: &[u8], _addr: u64) -> Option<Insn> {
    return None;
}

pub fn track(_insn: &Insn, _regs: &RegisterFile, _tracker: &mut Tracker) {}

pub fn memory(_insn: &Insn) -> Vec<MemAccess> {
    return Vec::new();
}

pub fn lift(_l: &mut Lifter, _insn: &Insn) -> Result<(), String> {
    return Err("aarch64 is not supported yet".to_string());
}
