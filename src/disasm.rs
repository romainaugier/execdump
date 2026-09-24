use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::x86;
use capstone::prelude::*;

use std::array;

#[derive(Clone, Debug, Default)]
pub struct X86Instruction {
    pub mnemonic: String,
    pub address: u64,
    pub num_operands: u8,
    pub operands: [x86::X86Operand; 4], // Let's use just 4 operands for now
}

fn format_x86_reg(cs: &Capstone, id: &RegId) -> String {
    return cs.reg_name(*id).unwrap_or("<invalid>".to_string());
}

fn format_x86_operand(cs: &Capstone, op: &x86::X86Operand) -> String {
    match &op.op_type {
        x86::X86OperandType::Reg(reg) => format_x86_reg(cs, reg),

        x86::X86OperandType::Imm(imm) => {
            format!("{:#x}", imm)
        }

        x86::X86OperandType::Mem(mem) => {
            let mut parts = Vec::new();

            if mem.base().0 != 0 {
                parts.push(format_x86_reg(cs, &mem.base()));
            }

            if mem.index().0 != 0 {
                let idx = format_x86_reg(cs, &mem.index());
                if mem.scale() != 1 {
                    parts.push(format!("{}*{}", idx, mem.scale()));
                } else {
                    parts.push(idx);
                }
            }

            let mut expr = parts.join(" + ");

            if mem.disp() != 0 || expr.is_empty() {
                if !expr.is_empty() {
                    if mem.disp() > 0 {
                        expr.push_str(&format!(" + {:#x}", mem.disp()));
                    } else {
                        expr.push_str(&format!(" - {:#x}", -mem.disp()));
                    }
                } else {
                    expr.push_str(&format!("{:#x}", mem.disp()));
                }
            }

            if mem.segment().0 != 0 {
                format!("{}:[{}]", format_x86_reg(cs, &mem.segment()), expr)
            } else {
                format!("[{}]", expr)
            }
        }

        _ => "<invalid>".to_string(),
    }
}

impl X86Instruction {
    pub fn from_cs(insn: &Insn, cs: &Capstone) -> Result<Self, Box<dyn std::error::Error>> {
        let detail = cs.insn_detail(insn)?;
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        return Ok(Self {
            mnemonic: insn
                .mnemonic()
                .map_or("???", |mnemonic| mnemonic)
                .to_string(),
            address: insn.address(),
            num_operands: ops.len() as u8,
            operands: array::from_fn(|i| {
                if let Some(ArchOperand::X86Operand(op)) = ops.get(i) {
                    op.clone()
                } else {
                    x86::X86Operand::default()
                }
            }),
        });
    }

    pub fn as_string(&self, cs: &Capstone) -> String {
        let mut operands = Vec::new();

        for (i, op) in self.operands.iter().enumerate() {
            if i >= self.num_operands as usize {
                break;
            }

            operands.push(format_x86_operand(cs, op));
        }

        return format!(
            "0x{:08x} {} {}",
            self.address,
            self.mnemonic,
            operands.join(", ")
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Aarch64,
    Unsupported,
}

pub fn is_padding_instruction(insn: &Insn) -> bool {
    match (insn.mnemonic(), insn.op_str()) {
        (Some("add"), Some("byte ptr [rax], al")) => true,
        (Some("nop"), _) => true,
        (Some("int3"), _) => true,
        (Some("ud2"), _) => true,
        (Some("hlt"), _) => true,
        (Some("mov"), Some("eax, eax")) => true,
        (Some("sub"), Some("rsp, 0")) => true,
        _ => false,
    }
}

pub fn is_aarch64_padding_instruction(insn: &Insn) -> bool {
    match (insn.mnemonic(), insn.op_str()) {
        (Some("nop"), _) => true,
        (Some("udf"), Some("#0")) => true,
        _ => false,
    }
}

fn disasm_and_format_x86_code(
    code: &[u8],
    addr: u64,
    mode: arch::x86::ArchMode,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;

    let insns = cs.disasm_all(code, addr)?;

    let mut res = Vec::new();

    for insn in insns.as_ref() {
        if is_padding_instruction(insn) {
            continue;
        }

        res.push(X86Instruction::from_cs(insn, &cs)?.as_string(&cs))
    }

    return Ok(res);
}

fn disasm_and_format_aarch64_code(
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(false)
        .build()?;

    let insns = cs.disasm_all(code, addr)?;

    let mut res = Vec::new();

    for insn in insns.as_ref() {
        if is_aarch64_padding_instruction(insn) {
            continue;
        }

        res.push(format!(
            "0x{:08x} {} {}",
            insn.address(),
            insn.mnemonic().unwrap_or("???"),
            insn.op_str().unwrap_or(""),
        ));
    }

    return Ok(res);
}

pub fn disasm_and_format_code(
    arch: Architecture,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match arch {
        Architecture::X86 => disasm_and_format_x86_code(code, addr, arch::x86::ArchMode::Mode32),
        Architecture::X86_64 => disasm_and_format_x86_code(code, addr, arch::x86::ArchMode::Mode64),
        Architecture::Aarch64 => disasm_and_format_aarch64_code(code, addr),
        Architecture::Unsupported => Err("Unsupported architecture for disassembly".into()),
    }
}
