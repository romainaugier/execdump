/*
 * Architecture-neutral instruction model built on top of Capstone
 */

use capstone::arch::arm64::{Arm64OperandType, ArchMode as Arm64Mode};
use capstone::arch::x86::{ArchMode as X86Mode, ArchSyntax, X86OperandType, X86Reg};
use capstone::arch::ArchOperand;
use capstone::prelude::*;

use crate::disasm::Architecture;

/// Control flow effect of an instruction
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Execution continues with the next instruction
    Seq,
    Jump(u64),
    CondJump(u64),
    IndirectJump,
    Call(u64),
    IndirectCall,
    Ret,
    /// Execution does not continue (hlt, ud2, brk...)
    Trap,
}

impl Flow {
    /// True if the instruction ends a basic block
    pub fn ends_block(&self) -> bool {
        return matches!(self, Flow::Jump(_) | Flow::CondJump(_) | Flow::IndirectJump | Flow::Ret | Flow::Trap);
    }

    pub fn target(&self) -> Option<u64> {
        match self {
            Flow::Jump(t) | Flow::CondJump(t) | Flow::Call(t) => Some(*t),
            _ => None,
        }
    }
}

/// Compact instruction kept in the analysis results, the text is decoded again on demand
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub addr: u64,
    pub size: u8,
    pub flow: Flow,
    /// Address of the memory read or written by the instruction, when it can be computed
    pub mem_ref: Option<u64>,
    /// Address computed or loaded as a constant by the instruction (lea, adr, adrp+add, mov imm)
    pub imm_ref: Option<u64>,
}

impl Instruction {
    pub fn end(&self) -> u64 {
        return self.addr + self.size as u64;
    }
}

/// Operand summary, used by the analysis passes that need to look at instruction operands
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operand {
    #[default]
    None,
    Reg(u16),
    Imm(i64),
    Mem { base: u16, index: u16, scale: i32, disp: i64 },
}

/// Fully decoded instruction, only used during the analysis
#[derive(Clone, Debug)]
pub struct Decoded {
    pub insn: Instruction,
    pub mnemonic: String,
    pub operands: [Operand; 4],
    pub num_operands: usize,
}

impl Decoded {
    pub fn operand(&self, index: usize) -> Operand {
        if index < self.num_operands {
            return self.operands[index];
        }

        return Operand::None;
    }

    /// Mnemonic without the x86 prefixes (bnd, notrack, rep, lock...)
    pub fn base_mnemonic(&self) -> &str {
        return self.mnemonic.rsplit(' ').next().unwrap_or("");
    }
}

/// Text form of an instruction
#[derive(Clone, Debug, Default)]
pub struct InsnText {
    pub addr: u64,
    pub size: usize,
    pub mnemonic: String,
    pub operands: String,
}

pub struct Decoder {
    arch: Architecture,
    detailed: Capstone,
    text: Capstone,
    address_mask: u64,
}

fn build_capstone(arch: Architecture, detail: bool) -> Result<Capstone, Box<dyn std::error::Error>> {
    let cs = match arch {
        Architecture::X86 => Capstone::new().x86().mode(X86Mode::Mode32).syntax(ArchSyntax::Intel).detail(detail).build()?,
        Architecture::X86_64 => Capstone::new().x86().mode(X86Mode::Mode64).syntax(ArchSyntax::Intel).detail(detail).build()?,
        Architecture::Aarch64 => Capstone::new().arm64().mode(Arm64Mode::Arm).detail(detail).build()?,
        Architecture::Unsupported => return Err("Unsupported architecture for disassembly".into()),
    };

    return Ok(cs);
}

fn classify_x86(mnemonic: &str, operand: Operand, addr_mask: u64) -> Flow {
    let direct = match operand {
        Operand::Imm(imm) => Some(imm as u64 & addr_mask),
        _ => None,
    };

    match mnemonic {
        "ret" | "retf" | "retn" | "iret" | "iretd" | "iretq" | "sysret" | "sysretq" | "sysexit" | "sysexitq" => Flow::Ret,
        "hlt" | "ud2" | "ud1" | "ud0" | "int3" => Flow::Trap,
        "jmp" | "ljmp" => direct.map_or(Flow::IndirectJump, Flow::Jump),
        "call" | "lcall" => direct.map_or(Flow::IndirectCall, Flow::Call),
        "loop" | "loope" | "loopne" | "jcxz" | "jecxz" | "jrcxz" => direct.map_or(Flow::IndirectJump, Flow::CondJump),
        m if m.starts_with('j') => direct.map_or(Flow::IndirectJump, Flow::CondJump),
        _ => Flow::Seq,
    }
}

fn classify_aarch64(mnemonic: &str, operands: &[Operand]) -> Flow {
    let last_imm = operands.iter().rev().find_map(|op| match op {
        Operand::Imm(imm) => Some(*imm as u64),
        _ => None,
    });

    match mnemonic {
        "b" => last_imm.map_or(Flow::IndirectJump, Flow::Jump),
        "bl" => last_imm.map_or(Flow::IndirectCall, Flow::Call),
        "cbz" | "cbnz" | "tbz" | "tbnz" => last_imm.map_or(Flow::IndirectJump, Flow::CondJump),
        "br" | "braa" | "brab" | "braaz" | "brabz" => Flow::IndirectJump,
        "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => Flow::IndirectCall,
        "ret" | "retaa" | "retab" | "eret" | "eretaa" | "eretab" => Flow::Ret,
        "brk" | "udf" | "hlt" => Flow::Trap,
        m if m.starts_with("b.") || m.starts_with("bc.") => last_imm.map_or(Flow::IndirectJump, Flow::CondJump),
        _ => Flow::Seq,
    }
}

impl Decoder {
    pub fn new(arch: Architecture) -> Result<Self, Box<dyn std::error::Error>> {
        return Ok(Self {
            arch,
            detailed: build_capstone(arch, true)?,
            text: build_capstone(arch, false)?,
            address_mask: if arch == Architecture::X86 { 0xffff_ffff } else { u64::MAX },
        });
    }

    pub fn arch(&self) -> Architecture {
        return self.arch;
    }

    /// Decodes a single instruction with its operands
    pub fn decode(&self, bytes: &[u8], addr: u64) -> Option<Decoded> {
        let bytes = &bytes[..bytes.len().min(16)];
        let insns = self.detailed.disasm_count(bytes, addr, 1).ok()?;
        let insn = insns.iter().next()?;
        let detail = self.detailed.insn_detail(&insn).ok()?;

        let mut operands = [Operand::None; 4];
        let mut num_operands = 0;

        for op in detail.arch_detail().operands().iter().take(4) {
            operands[num_operands] = match op {
                ArchOperand::X86Operand(op) => match &op.op_type {
                    X86OperandType::Reg(reg) => Operand::Reg(reg.0),
                    X86OperandType::Imm(imm) => Operand::Imm(*imm),
                    X86OperandType::Mem(mem) => Operand::Mem {
                        base: mem.base().0,
                        index: mem.index().0,
                        scale: mem.scale(),
                        disp: mem.disp(),
                    },
                    _ => Operand::None,
                },
                ArchOperand::Arm64Operand(op) => match &op.op_type {
                    Arm64OperandType::Reg(reg) => Operand::Reg(reg.0),
                    Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => Operand::Imm(*imm),
                    Arm64OperandType::Mem(mem) => Operand::Mem {
                        base: mem.base().0,
                        index: mem.index().0,
                        scale: 1,
                        disp: mem.disp() as i64,
                    },
                    _ => Operand::None,
                },
                _ => Operand::None,
            };

            num_operands += 1;
        }

        let mnemonic = insn.mnemonic().unwrap_or("").to_string();
        let base_mnemonic = mnemonic.rsplit(' ').next().unwrap_or("");
        let end = insn.address() + insn.len() as u64;

        let flow = match self.arch {
            Architecture::X86 | Architecture::X86_64 => classify_x86(base_mnemonic, operands[0], self.address_mask),
            _ => classify_aarch64(base_mnemonic, &operands[..num_operands]),
        };

        let mut mem_ref = None;
        let mut imm_ref = None;

        if matches!(self.arch, Architecture::X86 | Architecture::X86_64) {
            let is_lea = base_mnemonic == "lea";

            for op in operands[..num_operands].iter() {
                match *op {
                    Operand::Mem { base, index, disp, .. } => {
                        let addr = if base == X86Reg::X86_REG_RIP as u16 {
                            Some(end.wrapping_add(disp as u64))
                        } else if base == 0 && index == 0 {
                            Some(disp as u64 & self.address_mask)
                        } else {
                            None
                        };

                        if is_lea {
                            imm_ref = imm_ref.or(addr);
                        } else {
                            mem_ref = mem_ref.or(addr);
                        }
                    }
                    Operand::Imm(imm) if flow == Flow::Seq && imm > 0 => {
                        imm_ref = imm_ref.or(Some(imm as u64 & self.address_mask));
                    }
                    _ => {}
                }
            }
        } else if base_mnemonic == "adr" {
            imm_ref = operands[..num_operands].iter().find_map(|op| match op {
                Operand::Imm(imm) => Some(*imm as u64),
                _ => None,
            });
        }

        return Some(Decoded {
            insn: Instruction { addr: insn.address(), size: insn.len() as u8, flow, mem_ref, imm_ref },
            mnemonic,
            operands,
            num_operands,
        });
    }

    /// Decodes the text of a single instruction
    pub fn text(&self, bytes: &[u8], addr: u64) -> Option<InsnText> {
        let bytes = &bytes[..bytes.len().min(16)];
        let insns = self.text.disasm_count(bytes, addr, 1).ok()?;
        let insn = insns.iter().next()?;

        return Some(InsnText {
            addr: insn.address(),
            size: insn.len(),
            mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
        });
    }

    /// Decodes the text of all the instructions in a buffer, skipping undecodable bytes
    pub fn text_all(&self, bytes: &[u8], addr: u64) -> Vec<InsnText> {
        let mut res = Vec::new();
        let mut offset = 0usize;
        let step = if self.arch == Architecture::Aarch64 { 4 } else { 1 };

        while offset < bytes.len() {
            let Ok(insns) = self.text.disasm_all(&bytes[offset..], addr + offset as u64) else {
                break;
            };

            let mut decoded = 0usize;

            for insn in insns.iter() {
                decoded += insn.len();

                res.push(InsnText {
                    addr: insn.address(),
                    size: insn.len(),
                    mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
                    operands: insn.op_str().unwrap_or("").to_string(),
                });
            }

            offset += decoded;

            // Capstone stops at the first invalid instruction, emit it as data and continue
            if offset < bytes.len() {
                let len = step.min(bytes.len() - offset);

                res.push(InsnText {
                    addr: addr + offset as u64,
                    size: len,
                    mnemonic: if len == 4 { ".word".to_string() } else { ".byte".to_string() },
                    operands: bytes[offset..offset + len].iter().rev().map(|b| format!("{:02x}", b)).collect::<String>(),
                });

                offset += len;
            }
        }

        return res;
    }
}

/// Register value tracking used to resolve aarch64 adrp/add/ldr address computations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegValue {
    Const(u64),
    /// Value loaded from the given address
    Loaded(u64),
}

#[derive(Clone, Debug, Default)]
pub struct Aarch64Tracker {
    regs: Vec<(u16, RegValue)>,
}

impl Aarch64Tracker {
    fn get(&self, reg: u16) -> Option<RegValue> {
        return self.regs.iter().find(|(r, _)| *r == reg).map(|(_, v)| *v);
    }

    fn set(&mut self, reg: u16, value: Option<RegValue>) {
        self.regs.retain(|(r, _)| *r != reg);

        if let Some(value) = value {
            self.regs.push((reg, value));
        }
    }

    pub fn reset(&mut self) {
        self.regs.clear();
    }

    /// Updates the tracked registers with the instruction and fills its references
    pub fn step(&mut self, decoded: &mut Decoded) {
        let mnemonic = decoded.base_mnemonic().to_string();

        match (mnemonic.as_str(), decoded.operand(0), decoded.operand(1), decoded.operand(2)) {
            ("adrp" | "adr", Operand::Reg(rd), Operand::Imm(imm), _) => {
                self.set(rd, Some(RegValue::Const(imm as u64)));
            }
            ("add", Operand::Reg(rd), Operand::Reg(rn), Operand::Imm(imm)) => {
                let value = match self.get(rn) {
                    Some(RegValue::Const(v)) => Some(v.wrapping_add(imm as u64)),
                    _ => None,
                };

                decoded.insn.imm_ref = decoded.insn.imm_ref.or(value);
                self.set(rd, value.map(RegValue::Const));
            }
            (m, Operand::Reg(rt), Operand::Mem { base, index: 0, disp, .. }, Operand::None) if m.starts_with("ldr") || m.starts_with("ldur") => {
                let addr = match self.get(base) {
                    Some(RegValue::Const(v)) => Some(v.wrapping_add(disp as u64)),
                    _ => None,
                };

                decoded.insn.mem_ref = decoded.insn.mem_ref.or(addr);
                self.set(rt, addr.map(RegValue::Loaded));
            }
            (m, _, Operand::Mem { base, index: 0, disp, .. }, _) if m.starts_with("str") || m.starts_with("stur") || m.starts_with("ld") => {
                if let Some(RegValue::Const(v)) = self.get(base) {
                    decoded.insn.mem_ref = decoded.insn.mem_ref.or(Some(v.wrapping_add(disp as u64)));
                }

                if m.starts_with("ld") {
                    if let Operand::Reg(rt) = decoded.operand(0) {
                        self.set(rt, None);
                    }

                    if let Operand::Reg(rt2) = decoded.operand(1) {
                        self.set(rt2, None);
                    }
                }
            }
            (_, Operand::Reg(rn), _, _) if matches!(decoded.insn.flow, Flow::IndirectJump | Flow::IndirectCall) => {
                if let Some(RegValue::Loaded(slot)) = self.get(rn) {
                    decoded.insn.mem_ref = Some(slot);
                }
            }
            (m, Operand::Reg(rd), _, _) => {
                let writes_first_operand = !(m.starts_with("st") || m.starts_with("cmp") || m.starts_with("cmn") ||
                                            m.starts_with("tst") || m.starts_with("cb") || m.starts_with("tb") ||
                                            m.starts_with("b") || m.starts_with("prfm"));

                if writes_first_operand {
                    self.set(rd, None);
                }
            }
            _ => {}
        }

        // Calls clobber the caller-saved registers, only keep x19-x28
        if matches!(decoded.insn.flow, Flow::Call(_) | Flow::IndirectCall) {
            self.regs.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_flow() {
        let decoder = Decoder::new(Architecture::X86_64).unwrap();

        // jne +0x10
        let d = decoder.decode(&[0x75, 0x0e], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::CondJump(0x1010));

        // call rel32
        let d = decoder.decode(&[0xe8, 0x0b, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Call(0x1010));

        // jmp qword ptr [rip + 0x2fe2]
        let d = decoder.decode(&[0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::IndirectJump);
        assert_eq!(d.insn.mem_ref, Some(0x1006 + 0x2fe2));

        // bnd jmp qword ptr [rip + 0x2fe2]
        let d = decoder.decode(&[0xf2, 0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::IndirectJump);

        // lea rdi, [rip + 0x10]
        let d = decoder.decode(&[0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Seq);
        assert_eq!(d.insn.imm_ref, Some(0x1017));

        let d = decoder.decode(&[0xc3], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Ret);

        let d = decoder.decode(&[0x0f, 0x0b], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Trap);
    }

    #[test]
    fn aarch64_flow() {
        let decoder = Decoder::new(Architecture::Aarch64).unwrap();

        // b.ne #0x1010
        let d = decoder.decode(&[0x81, 0x00, 0x00, 0x54], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::CondJump(0x1010));

        // bl #0x1010
        let d = decoder.decode(&[0x04, 0x00, 0x00, 0x94], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Call(0x1010));

        // cbz x0, #0x1008
        let d = decoder.decode(&[0x40, 0x00, 0x00, 0xb4], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::CondJump(0x1008));

        // ret
        let d = decoder.decode(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::Ret);

        // br x17
        let d = decoder.decode(&[0x20, 0x02, 0x1f, 0xd6], 0x1000).unwrap();
        assert_eq!(d.insn.flow, Flow::IndirectJump);
    }

    #[test]
    fn aarch64_plt_tracking() {
        let decoder = Decoder::new(Architecture::Aarch64).unwrap();
        let mut tracker = Aarch64Tracker::default();

        // adrp x16, #0x11000 ; ldr x17, [x16, #0x18] ; add x16, x16, #0x18 ; br x17
        let code: [[u8; 4]; 4] = [[0x90, 0x00, 0x00, 0x90], [0x11, 0x0e, 0x40, 0xf9], [0x10, 0x62, 0x00, 0x91], [0x20, 0x02, 0x1f, 0xd6]];
        let mut last = None;

        for (i, bytes) in code.iter().enumerate() {
            let mut d = decoder.decode(bytes, 0x10000 + i as u64 * 4).unwrap();
            tracker.step(&mut d);
            last = Some(d);
        }

        assert_eq!(last.unwrap().insn.mem_ref, Some(0x20018));
    }
}
