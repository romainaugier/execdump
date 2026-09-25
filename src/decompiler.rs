/*
 * Decompiler (work in progress)
 *
 * The control flow recovery lives in crate::analysis, the IR below is built from the recovered functions
 */

#![allow(dead_code)]

use capstone::arch::x86::X86Reg;
use capstone::prelude::*;

use crate::analysis::function::Function;

/*
 * Ir
 */

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IrBlockId(usize);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IrValueId(usize);

#[derive(Debug)]
pub enum IrValue {
    /// RegisterId, used for the first mapping
    Register(RegId),
    /// Memory Address
    Memory(u64),
    /// Variable name (used in reconstruction passes)
    Variable(String),
}

impl Default for IrValue {
    fn default() -> Self {
        return Self::Register(RegId(X86Reg::X86_REG_RAX as u16));
    }
}

#[derive(Debug)]
pub enum IrOp {
    Unknown,
    Assign,
    Unary,
    Binary,
    Ternary,
    FunCall,
    Store,
    Load,
}

impl Default for IrOp {
    fn default() -> Self {
        return Self::Unknown;
    }
}

#[derive(Debug, Default)]
pub struct IrStatement {
    ret: IrValueId,
    op: IrOp,
    args: Vec<IrValueId>,
}

#[derive(Debug)]
pub enum IrTerminator {
    Ret,
    Jump(IrBlockId),
}

impl Default for IrTerminator {
    fn default() -> Self {
        return Self::Ret;
    }
}

#[derive(Debug, Default)]
pub struct IrBlock {
    stmts: Vec<IrStatement>,
    terminator: IrTerminator,
}

#[derive(Debug, Default)]
pub struct Ir {
    blocks: Vec<IrBlock>,
    values: Vec<IrValue>,
}

impl Ir {
    pub fn from_function(
        _function: &Function,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ir = Self::default();

        return Ok(ir);
    }
}
