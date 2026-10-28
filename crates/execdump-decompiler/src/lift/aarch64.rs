// SPDX-License-Identifier: Apache-2.0
/*
 * aarch64 instruction semantics (Capstone prints the aliases: mov, cmp, cset, lsl, ubfx...)
 */

use super::regs::{RegRef, RegisterFile};
use super::{llvm, Access, Cond, FlagOp, Known, Lifter, MemAccess, Tracker};

use crate::analysis::function::CallTarget;
use execdump_core::program::GUARD_CHECK;

use anyhow::{anyhow, bail, Context, Result};

use capstone::arch::arm64::{Arm64CC, Arm64Extender, Arm64OperandType, Arm64Shift};
use capstone::arch::ArchOperand;
use capstone::Capstone;

use inkwell::values::{FloatValue, IntValue, PointerValue};
use inkwell::{FloatPredicate, InlineAsmDialect, IntPredicate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ext {
    None,
    Zero(u32),
    Sign(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shift {
    None,
    Lsl(u32),
    Lsr(u32),
    Asr(u32),
    Ror(u32),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    Reg { r: RegRef, ext: Ext, shift: Shift },
    /// wzr and xzr
    Zero(u32),
    Imm(i64, Shift),
    Fp(f64),
    Mem { base: RegRef, index: Option<(RegRef, Ext, Shift)>, disp: i64 },
}

impl Op {
    fn reg(&self) -> Option<RegRef> {
        return match self {
            Op::Reg { r, .. } => Some(*r),
            _ => None,
        };
    }

    fn bits(&self) -> u32 {
        return match self {
            Op::Reg { r, .. } => r.bits,
            Op::Zero(bits) => *bits,
            _ => 64,
        };
    }
}

#[derive(Clone, Debug)]
pub struct Insn {
    pub addr: u64,
    pub mnemonic: String,
    pub ops: Vec<Op>,
    pub cc: Option<Cond>,
    pub writeback: bool,
    pub text: String,
}

fn condition(cc: Arm64CC) -> Option<Cond> {
    return Some(match cc {
        Arm64CC::ARM64_CC_EQ => Cond::Eq,
        Arm64CC::ARM64_CC_NE => Cond::Ne,
        Arm64CC::ARM64_CC_HS => Cond::Uge,
        Arm64CC::ARM64_CC_LO => Cond::Ult,
        Arm64CC::ARM64_CC_MI => Cond::Neg,
        Arm64CC::ARM64_CC_PL => Cond::NonNeg,
        Arm64CC::ARM64_CC_VS => Cond::Overflow,
        Arm64CC::ARM64_CC_VC => Cond::NoOverflow,
        Arm64CC::ARM64_CC_HI => Cond::Ugt,
        Arm64CC::ARM64_CC_LS => Cond::Ule,
        Arm64CC::ARM64_CC_GE => Cond::Sge,
        Arm64CC::ARM64_CC_LT => Cond::Slt,
        Arm64CC::ARM64_CC_GT => Cond::Sgt,
        Arm64CC::ARM64_CC_LE => Cond::Sle,
        Arm64CC::ARM64_CC_AL | Arm64CC::ARM64_CC_NV => Cond::Always,
        _ => return None,
    });
}

fn shift(shift: Arm64Shift) -> Shift {
    return match shift {
        Arm64Shift::Lsl(n) => Shift::Lsl(n),
        Arm64Shift::Lsr(n) => Shift::Lsr(n),
        Arm64Shift::Asr(n) => Shift::Asr(n),
        Arm64Shift::Ror(n) => Shift::Ror(n),
        _ => Shift::None,
    };
}

fn extender(ext: Arm64Extender) -> Ext {
    return match ext {
        Arm64Extender::ARM64_EXT_UXTB => Ext::Zero(8),
        Arm64Extender::ARM64_EXT_UXTH => Ext::Zero(16),
        Arm64Extender::ARM64_EXT_UXTW => Ext::Zero(32),
        Arm64Extender::ARM64_EXT_SXTB => Ext::Sign(8),
        Arm64Extender::ARM64_EXT_SXTH => Ext::Sign(16),
        Arm64Extender::ARM64_EXT_SXTW => Ext::Sign(32),
        _ => Ext::None,
    };
}

pub fn decode(regs: &RegisterFile, cs: &Capstone, bytes: &[u8], addr: u64) -> Option<Insn> {
    let insns = cs.disasm_count(bytes, addr, 1).ok()?;
    let insn = insns.iter().next()?;
    let detail = cs.insn_detail(insn).ok()?;
    let arch = detail.arch_detail();
    let arm = arch.arm64()?;

    let mnemonic = insn.mnemonic().unwrap_or("").to_string();
    let text = format!("{} {}", mnemonic, insn.op_str().unwrap_or("")).trim().to_string();

    let opaque = Insn { addr, mnemonic: String::new(), ops: Vec::new(), cc: None, writeback: false, text: text.clone() };
    let name = |id: capstone::RegId| cs.reg_name(id).unwrap_or_default();

    let mut ops = Vec::new();

    for op in arch.operands() {
        let ArchOperand::Arm64Operand(op) = op else {
            continue;
        };

        // Vector lanes and arrangements are not modeled
        if op.vector_index.is_some() || op.vas != capstone::arch::arm64::Arm64Vas::ARM64_VAS_INVALID {
            return Some(opaque);
        }

        ops.push(match &op.op_type {
            Arm64OperandType::Reg(id) => match name(*id).as_str() {
                "xzr" => Op::Zero(64),
                "wzr" => Op::Zero(32),
                reg => match regs.resolve(reg) {
                    Some(r) => Op::Reg { r, ext: extender(op.ext), shift: shift(op.shift) },
                    None => return Some(opaque),
                },
            },
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => Op::Imm(*imm, shift(op.shift)),
            Arm64OperandType::Fp(value) => Op::Fp(*value),
            Arm64OperandType::Mem(mem) => {
                let Some(base) = regs.resolve(&name(mem.base())) else {
                    return Some(opaque);
                };

                let index = match mem.index().0 {
                    0 => None,
                    _ => Some((regs.resolve(&name(mem.index()))?, extender(op.ext), shift(op.shift))),
                };

                Op::Mem { base, index, disp: mem.disp() as i64 }
            }
            _ => return Some(opaque),
        });
    }

    return Some(Insn { addr, mnemonic, ops, cc: condition(arm.cc()), writeback: arm.writeback(), text });
}

/// Width of a memory access from the mnemonic and the transferred register
fn access_bits(mnemonic: &str, reg: &Op) -> u32 {
    let base = mnemonic.trim_start_matches("ld").trim_start_matches("st").trim_start_matches("ur").trim_start_matches('r');

    return match base {
        _ if mnemonic.ends_with("sw") || mnemonic == "ldpsw" => 32,
        _ if mnemonic.ends_with('b') => 8,
        _ if mnemonic.ends_with('h') => 16,
        _ => reg.bits(),
    };
}

fn is_load(mnemonic: &str) -> bool {
    return mnemonic.starts_with("ld");
}

fn is_store(mnemonic: &str) -> bool {
    return mnemonic.starts_with("st");
}

/// The atomic operations that load what the memory held into their second operand (ldadd w1, w0, [x2]), the first
/// one is their operand
fn is_atomic_load(mnemonic: &str) -> bool {
    const OPS: [&str; 9] = ["ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp"];
    return OPS.iter().any(|op| mnemonic.starts_with(op));
}

fn is_pair(mnemonic: &str) -> bool {
    return mnemonic.starts_with("ldp") || mnemonic.starts_with("stp") || mnemonic.starts_with("ldnp") || mnemonic.starts_with("stnp");
}

/// Memory operand, and the post-index increment (ldr x0, [x1], #8)
fn memory_operand(insn: &Insn) -> Option<(RegRef, Option<(RegRef, Ext, Shift)>, i64, Option<i64>)> {
    let position = insn.ops.iter().position(|o| matches!(o, Op::Mem { .. }))?;
    let Op::Mem { base, index, disp } = insn.ops[position] else {
        return None;
    };

    let post = match insn.ops.get(position + 1) {
        Some(Op::Imm(imm, _)) if insn.writeback => Some(*imm),
        _ => None,
    };

    return Some((base, index, disp, post));
}

pub fn track(insn: &Insn, regs: &RegisterFile, tracker: &mut Tracker) {
    let mnemonic = insn.mnemonic.as_str();
    let ops = insn.ops.as_slice();

    // Base register updates of the pre and post indexed accesses
    if insn.writeback {
        if let Some((base, _, disp, post)) = memory_operand(insn) {
            tracker.set(base.reg, tracker.offset(base.reg, post.unwrap_or(disp)));
        }
    }

    match (mnemonic, ops) {
        ("adrp" | "adr", [Op::Reg { r, .. }, Op::Imm(imm, _)]) => tracker.set(r.reg, Some(Known::Const(*imm as u64))),
        ("mov" | "movz", [Op::Reg { r, .. }, Op::Imm(imm, Shift::None)]) if r.bits == 64 => tracker.set(r.reg, Some(Known::Const(*imm as u64))),
        ("mov", [Op::Reg { r, .. }, Op::Reg { r: src, .. }]) if r.bits == 64 && src.bits == 64 => tracker.set(r.reg, tracker.get(src.reg)),
        ("add", [Op::Reg { r, .. }, Op::Reg { r: src, .. }, Op::Imm(imm, sh)]) if r.bits == 64 => {
            let imm = if *sh == Shift::Lsl(12) { imm << 12 } else { *imm };
            tracker.set(r.reg, tracker.offset(src.reg, imm));
        }
        ("sub", [Op::Reg { r, .. }, Op::Reg { r: src, .. }, Op::Imm(imm, sh)]) if r.bits == 64 => {
            let imm = if *sh == Shift::Lsl(12) { imm << 12 } else { *imm };
            tracker.set(r.reg, tracker.offset(src.reg, -imm));
        }
        ("bl" | "blr", _) => {
            for i in (0..=18).chain([30]) {
                tracker.set(regs.reg(&format!("x{}", i)), None);
            }
        }
        _ => {
            let writes = !is_store(mnemonic) && !matches!(mnemonic, "cmp" | "cmn" | "tst" | "fcmp" | "fcmpe" | "ccmp" | "ccmn" | "b" | "br" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz") && !mnemonic.starts_with("b.");

            if writes {
                for op in ops.iter().take(if is_pair(mnemonic) { 2 } else { 1 }) {
                    if let Some(r) = op.reg() {
                        tracker.set(r.reg, None);
                    }
                }
            }

            // Store exclusives write their status register
            if mnemonic.starts_with("stxr") || mnemonic.starts_with("stlxr") {
                if let Some(r) = ops.first().and_then(|o| o.reg()) {
                    tracker.set(r.reg, None);
                }
            }
        }
    }
}

pub fn memory(insn: &Insn) -> Vec<MemAccess> {
    let Some((base, index, disp, post)) = memory_operand(insn) else {
        return Vec::new();
    };

    let Some(first) = insn.ops.first() else {
        return Vec::new();
    };

    let bits = access_bits(&insn.mnemonic, first) * if is_pair(&insn.mnemonic) { 2 } else { 1 };
    let disp = if post.is_some() { 0 } else { disp };

    let kind = if is_store(&insn.mnemonic) { Access::Write } else { Access::Read };
    return vec![MemAccess { base: Some(base.reg), has_index: index.is_some(), disp, bytes: bits / 8, kind }];
}

/*
 * Operands
 */

/// Value of a register or immediate operand, with its extension and shift
fn get<'ctx>(l: &Lifter<'ctx, '_>, op: &Op, bits: u32) -> Result<IntValue<'ctx>> {
    let b = &l.builder;

    let (mut value, ext, sh) = match op {
        Op::Reg { r, ext, shift } => (l.read(*r)?, *ext, *shift),
        Op::Zero(_) => return Ok(l.int(bits).const_zero()),
        Op::Imm(imm, shift) => (l.int(bits).const_int(*imm as u64, true), Ext::None, *shift),
        _ => bail!("not a value operand"),
    };

    value = match ext {
        Ext::Zero(from) => l.resize(l.resize(value, from, false)?, bits, false)?,
        Ext::Sign(from) => l.resize(l.resize(value, from, false)?, bits, true)?,
        Ext::None => l.resize(value, bits, false)?,
    };

    let amount = |n: u32| l.constant(bits, n as u64);

    value = match sh {
        Shift::None | Shift::Lsl(0) => value,
        Shift::Lsl(n) => llvm!(b.build_left_shift(value, amount(n), "")),
        Shift::Lsr(n) => llvm!(b.build_right_shift(value, amount(n), false, "")),
        Shift::Asr(n) => llvm!(b.build_right_shift(value, amount(n), true, "")),
        Shift::Ror(n) => {
            let name = format!("llvm.fshr.i{}", bits);
            l.call_intrinsic(&name, &[value.into(), value.into(), amount(n).into()], Some(l.int(bits).into()))?.unwrap().into_int_value()
        }
    };

    return Ok(value);
}

/// Writes a register, 32-bit writes clear the upper half (as do the scalar floating point writes)
fn set<'ctx>(l: &Lifter<'ctx, '_>, op: &Op, value: IntValue<'ctx>) -> Result<()> {
    return match op {
        Op::Reg { r, .. } if r.bits < l.env.regs.regs[r.reg].bits => l.write_zext(*r, value),
        Op::Reg { r, .. } => l.write(*r, value),
        Op::Zero(_) => Ok(()),
        _ => Err(anyhow!("not a register operand")),
    };
}

fn get_float<'ctx>(l: &Lifter<'ctx, '_>, op: &Op) -> Result<FloatValue<'ctx>> {
    return match op {
        Op::Reg { r, .. } => l.read_float(*r, r.bits),
        Op::Fp(value) => Ok(l.cx.f64_type().const_float(*value)),
        Op::Zero(bits) => l.int_to_float(l.int(*bits).const_zero()),
        _ => Err(anyhow!("not a floating point operand")),
    };
}

fn set_float<'ctx>(l: &Lifter<'ctx, '_>, op: &Op, value: FloatValue<'ctx>) -> Result<()> {
    let Op::Reg { r, .. } = op else {
        bail!("not a register operand");
    };

    return l.write_float(*r, value, true);
}

/// Address of the memory operand (before the base update of the post indexed forms)
fn address<'ctx>(l: &Lifter<'ctx, '_>, insn: &Insn) -> Result<PointerValue<'ctx>> {
    let (base, index, disp, post) = memory_operand(insn).context("no memory operand")?;
    let disp = if post.is_some() { 0 } else { disp };

    let Some((index, ext, sh)) = index else {
        return l.address(Some(base.reg), None, disp);
    };

    let offset = get(l, &Op::Reg { r: index, ext, shift: sh }, 64)?;
    let ptr = l.address(Some(base.reg), None, disp)?;

    return Ok(unsafe { llvm!(l.builder.build_gep(l.cx.i8_type(), ptr, &[offset], "")) });
}

fn writeback<'ctx>(l: &Lifter<'ctx, '_>, insn: &Insn) -> Result<()> {
    if !insn.writeback {
        return Ok(());
    }

    let (base, _, disp, post) = memory_operand(insn).context("no memory operand")?;
    let value = l.read(base)?;
    let value = llvm!(l.builder.build_int_add(value, l.constant(64, post.unwrap_or(disp) as u64), ""));

    return l.write(base, value);
}

fn unsupported(l: &Lifter, insn: &Insn) -> Result<()> {
    let asm_type = l.cx.void_type().fn_type(&[], false);
    let asm = l.cx.create_inline_asm(asm_type, insn.text.clone(), String::new(), true, false, Some(InlineAsmDialect::ATT), false);
    llvm!(l.builder.build_indirect_call(asm_type, asm, &[], ""));
    return Ok(());
}

fn bitfield_mask(width: u32) -> u64 {
    return if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
}

/*
 * Semantics
 */

pub fn lift<'ctx>(l: &mut Lifter<'ctx, '_>, insn: &Insn) -> Result<()> {
    let ops = insn.ops.as_slice();
    let mnemonic = insn.mnemonic.as_str();
    let b = &l.builder;

    match (mnemonic, ops) {
        ("nop" | "hint" | "bti" | "paciasp" | "autiasp" | "pacibsp" | "autibsp" | "xpaclri" | "dmb" | "dsb" | "isb" | "prfm" | "prfum" | "clrex" | "yield", _) => {}

        ("mov" | "movz", [dst, src]) => {
            let value = get(l, src, dst.bits())?;
            set(l, dst, value)?;
        }
        ("movn", [dst, src]) => {
            let value = get(l, src, dst.bits())?;
            set(l, dst, llvm!(b.build_not(value, "")))?;
        }
        ("movk", [dst, Op::Imm(imm, sh)]) => {
            let bits = dst.bits();
            let position = if let Shift::Lsl(n) = sh { *n } else { 0 };
            let mask = !(0xffffu64 << position) & bitfield_mask(bits);
            let kept = llvm!(b.build_and(get(l, dst, bits)?, l.constant(bits, mask), ""));
            let value = llvm!(b.build_or(kept, l.constant(bits, (*imm as u64) << position), ""));
            set(l, dst, value)?;
        }
        // adr gives the address of the global, adrp its page (the add that follows gives the global)
        ("adr", [dst, Op::Imm(addr, _)]) if l.env.program.region_at(*addr as u64).is_some() => {
            let value = llvm!(b.build_ptr_to_int(l.global_ptr(*addr as u64)?, l.int(64), ""));
            set(l, dst, value)?;
        }
        ("adrp" | "adr", [dst, Op::Imm(..)]) => {
            let value = get(l, &ops[1], 64)?;
            set(l, dst, value)?;
        }

        ("add" | "adds" | "sub" | "subs", [_, _, _]) | ("cmp" | "cmn", [_, _]) => arithmetic(l, insn)?,
        ("neg" | "negs", [dst, src]) => {
            let bits = dst.bits();
            let value = get(l, src, bits)?;
            let result = llvm!(b.build_int_neg(value, ""));
            set(l, dst, result)?;

            if mnemonic == "negs" {
                l.set_flags(FlagOp::Sub, l.int(bits).const_zero(), value, result)?;
            }
        }
        ("adc" | "sbc" | "adcs" | "sbcs", [dst, lhs, rhs]) => {
            let bits = dst.bits();
            let (x, y) = (get(l, lhs, bits)?, get(l, rhs, bits)?);
            let carry = l.resize(l.condition(Cond::Uge)?, bits, false)?;

            let result = if mnemonic.starts_with("adc") {
                llvm!(b.build_int_add(llvm!(b.build_int_add(x, y, "")), carry, ""))
            } else {
                // x - y - !carry = x + !y + carry
                llvm!(b.build_int_add(llvm!(b.build_int_add(x, llvm!(b.build_not(y, "")), "")), carry, ""))
            };

            set(l, dst, result)?;
            l.flags = None;
        }
        ("and" | "ands" | "orr" | "eor" | "bic" | "bics" | "orn" | "eon" | "tst", _) => {
            let (dst, lhs, rhs) = if mnemonic == "tst" { (None, &ops[0], &ops[1]) } else { (Some(&ops[0]), &ops[1], &ops[2]) };
            let bits = lhs.bits();
            let x = get(l, lhs, bits)?;
            let mut y = get(l, rhs, bits)?;

            if matches!(mnemonic, "bic" | "bics" | "orn" | "eon") {
                y = llvm!(b.build_not(y, ""));
            }

            let result = match mnemonic {
                "orr" | "orn" => llvm!(b.build_or(x, y, "")),
                "eor" | "eon" => llvm!(b.build_xor(x, y, "")),
                _ => llvm!(b.build_and(x, y, "")),
            };

            if let Some(dst) = dst {
                set(l, dst, result)?;
            }

            if matches!(mnemonic, "ands" | "bics" | "tst") {
                l.set_flags(FlagOp::Logic, x, y, result)?;
            }
        }
        ("mvn", [dst, src]) => {
            let value = get(l, src, dst.bits())?;
            set(l, dst, llvm!(b.build_not(value, "")))?;
        }
        ("lsl" | "lsr" | "asr" | "ror", [dst, src, count]) => {
            let bits = dst.bits();
            let value = get(l, src, bits)?;
            let count = llvm!(b.build_and(get(l, count, bits)?, l.constant(bits, bits as u64 - 1), ""));

            let result = match mnemonic {
                "lsl" => llvm!(b.build_left_shift(value, count, "")),
                "lsr" => llvm!(b.build_right_shift(value, count, false, "")),
                "asr" => llvm!(b.build_right_shift(value, count, true, "")),
                _ => l.call_intrinsic(&format!("llvm.fshr.i{}", bits), &[value.into(), value.into(), count.into()], Some(l.int(bits).into()))?.unwrap().into_int_value(),
            };

            set(l, dst, result)?;
        }

        ("mul" | "mneg", [dst, x, y]) => {
            let bits = dst.bits();
            let product = llvm!(b.build_int_mul(get(l, x, bits)?, get(l, y, bits)?, ""));
            let result = if mnemonic == "mneg" { llvm!(b.build_int_neg(product, "")) } else { product };
            set(l, dst, result)?;
        }
        ("madd" | "msub", [dst, x, y, acc]) => {
            let bits = dst.bits();
            let product = llvm!(b.build_int_mul(get(l, x, bits)?, get(l, y, bits)?, ""));
            let acc = get(l, acc, bits)?;
            let result = if mnemonic == "madd" { llvm!(b.build_int_add(acc, product, "")) } else { llvm!(b.build_int_sub(acc, product, "")) };
            set(l, dst, result)?;
        }
        ("smull" | "umull" | "smaddl" | "umaddl" | "smsubl" | "umsubl", [dst, x, y, rest @ ..]) => {
            let signed = mnemonic.starts_with('s');
            let x = l.resize(get(l, x, 32)?, 64, signed)?;
            let y = l.resize(get(l, y, 32)?, 64, signed)?;
            let mut result = llvm!(b.build_int_mul(x, y, ""));

            if let Some(acc) = rest.first() {
                let acc = get(l, acc, 64)?;
                result = if mnemonic.contains("add") { llvm!(b.build_int_add(acc, result, "")) } else { llvm!(b.build_int_sub(acc, result, "")) };
            }

            set(l, dst, result)?;
        }
        ("smulh" | "umulh", [dst, x, y]) => {
            let signed = mnemonic == "smulh";
            let x = l.resize(get(l, x, 64)?, 128, signed)?;
            let y = l.resize(get(l, y, 64)?, 128, signed)?;
            let product = llvm!(b.build_int_mul(x, y, ""));
            let high = llvm!(b.build_right_shift(product, l.constant(128, 64), false, ""));
            set(l, dst, l.resize(high, 64, false)?)?;
        }
        ("sdiv" | "udiv", [dst, x, y]) => {
            let bits = dst.bits();
            let (x, y) = (get(l, x, bits)?, get(l, y, bits)?);
            let result = if mnemonic == "sdiv" { llvm!(b.build_int_signed_div(x, y, "")) } else { llvm!(b.build_int_unsigned_div(x, y, "")) };
            set(l, dst, result)?;
        }

        ("sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" | "uxtw", [dst, src]) => {
            let from = match &mnemonic[3..] {
                "b" => 8,
                "h" => 16,
                _ => 32,
            };
            let value = get(l, src, from)?;
            set(l, dst, l.resize(value, dst.bits(), mnemonic.starts_with('s'))?)?;
        }
        ("ubfx" | "sbfx", [dst, src, Op::Imm(lsb, _), Op::Imm(width, _)]) => {
            let bits = dst.bits();
            let value = get(l, src, bits)?;
            let shifted = llvm!(b.build_right_shift(value, l.constant(bits, *lsb as u64), false, ""));
            let field = l.resize(shifted, *width as u32, false)?;
            set(l, dst, l.resize(field, bits, mnemonic == "sbfx")?)?;
        }
        ("ubfiz" | "sbfiz", [dst, src, Op::Imm(lsb, _), Op::Imm(width, _)]) => {
            let bits = dst.bits();
            let field = l.resize(get(l, src, bits)?, *width as u32, false)?;
            let field = l.resize(field, bits, mnemonic == "sbfiz")?;
            set(l, dst, llvm!(b.build_left_shift(field, l.constant(bits, *lsb as u64), "")))?;
        }
        ("bfi" | "bfxil", [dst, src, Op::Imm(lsb, _), Op::Imm(width, _)]) => {
            let bits = dst.bits();
            let (lsb, width) = (*lsb as u64, *width as u32);
            let field_mask = bitfield_mask(width);
            let source = get(l, src, bits)?;

            // bfi inserts the low bits of the source at lsb, bfxil extracts them from lsb into the low bits
            let (field, mask) = if mnemonic == "bfi" {
                let field = llvm!(b.build_and(source, l.constant(bits, field_mask), ""));
                (llvm!(b.build_left_shift(field, l.constant(bits, lsb), "")), field_mask << lsb)
            } else {
                let shifted = llvm!(b.build_right_shift(source, l.constant(bits, lsb), false, ""));
                (llvm!(b.build_and(shifted, l.constant(bits, field_mask), "")), field_mask)
            };

            let kept = llvm!(b.build_and(get(l, dst, bits)?, l.constant(bits, !mask & bitfield_mask(bits)), ""));
            set(l, dst, llvm!(b.build_or(kept, field, "")))?;
        }
        ("extr", [dst, high, low, Op::Imm(lsb, _)]) => {
            let bits = dst.bits();
            let name = format!("llvm.fshr.i{}", bits);
            let args = [get(l, high, bits)?.into(), get(l, low, bits)?.into(), l.constant(bits, *lsb as u64).into()];
            let value = l.call_intrinsic(&name, &args, Some(l.int(bits).into()))?.unwrap().into_int_value();
            set(l, dst, value)?;
        }
        ("clz" | "rbit" | "rev" | "cls", [dst, src]) => {
            let bits = dst.bits();
            let value = get(l, src, bits)?;
            let (name, extra) = match mnemonic {
                "clz" => (format!("llvm.ctlz.i{}", bits), true),
                "rbit" => (format!("llvm.bitreverse.i{}", bits), false),
                "rev" => (format!("llvm.bswap.i{}", bits), false),
                _ => return unsupported(l, insn),
            };

            let args = if extra { vec![value.into(), l.int(1).const_zero().into()] } else { vec![value.into()] };
            let result = l.call_intrinsic(&name, &args, Some(l.int(bits).into()))?.unwrap().into_int_value();
            set(l, dst, result)?;
        }

        ("csel" | "csinc" | "csinv" | "csneg", [dst, x, y]) => {
            let bits = dst.bits();
            let cond = l.condition(insn.cc.context("conditional select without a condition")?)?;
            let (x, y) = (get(l, x, bits)?, get(l, y, bits)?);

            let y = match mnemonic {
                "csinc" => llvm!(b.build_int_add(y, l.constant(bits, 1), "")),
                "csinv" => llvm!(b.build_not(y, "")),
                "csneg" => llvm!(b.build_int_neg(y, "")),
                _ => y,
            };

            set(l, dst, llvm!(b.build_select(cond, x, y, "")).into_int_value())?;
        }
        ("cset" | "csetm", [dst]) => {
            let bits = dst.bits();
            let cond = l.condition(insn.cc.context("cset without a condition")?)?;
            let value = l.resize(cond, bits, mnemonic == "csetm")?;
            set(l, dst, value)?;
        }
        ("cinc" | "cinv" | "cneg", [dst, src]) => {
            let bits = dst.bits();
            let cond = l.condition(insn.cc.context("conditional operation without a condition")?)?;
            let value = get(l, src, bits)?;
            let changed = match mnemonic {
                "cinc" => llvm!(b.build_int_add(value, l.constant(bits, 1), "")),
                "cinv" => llvm!(b.build_not(value, "")),
                _ => llvm!(b.build_int_neg(value, "")),
            };

            set(l, dst, llvm!(b.build_select(cond, changed, value, "")).into_int_value())?;
        }
        ("ccmp" | "ccmn", [x, y, Op::Imm(nzcv, _)]) => {
            // Compares when the condition holds, sets the flags to nzcv otherwise
            let bits = x.bits();
            let cond = l.condition(insn.cc.context("conditional compare without a condition")?)?;
            let (a, c) = (get(l, x, bits)?, get(l, y, bits)?);
            let (op, result) = if mnemonic == "ccmp" { (FlagOp::Sub, llvm!(b.build_int_sub(a, c, ""))) } else { (FlagOp::Add, llvm!(b.build_int_add(a, c, ""))) };

            l.set_flags(op, a, c, result)?;
            l.flags = None;

            for (bit, name) in [(8, "n"), (4, "z"), (2, "c"), (1, "v")] {
                let flag = l.env.regs.full(l.env.regs.reg(name));
                let computed = l.read(flag)?;
                let forced = l.int(1).const_int((*nzcv & bit != 0) as u64, false);
                l.write(flag, llvm!(l.builder.build_select(cond, computed, forced, "")).into_int_value())?;
            }
        }

        // Loads and stores
        (m, [first, ..]) if (is_load(m) || is_store(m)) && memory_operand(insn).is_some() => {
            let bits = access_bits(m, first);
            let ptr = address(l, insn)?;
            let pair = is_pair(m);
            let signed = m.contains("ldrs") || m == "ldpsw";
            let exclusive = m.starts_with("stxr") || m.starts_with("stlxr");

            // Store exclusives: the first operand is the status, always a success here
            let registers: Vec<&Op> = if exclusive { ops[1..2].iter().collect() } else { ops.iter().take(if pair { 2 } else { 1 }).collect() };

            for (i, reg) in registers.iter().enumerate() {
                let slot = if i == 0 { ptr } else { unsafe { llvm!(b.build_gep(l.cx.i8_type(), ptr, &[l.constant(64, bits as u64 / 8)], "")) } };

                if is_load(m) {
                    let value = l.load(slot, bits)?;
                    set(l, reg, l.resize(value, reg.bits(), signed)?)?;
                } else {
                    let value = get(l, reg, reg.bits().max(bits))?;
                    l.store(slot, l.resize(value, bits, false)?)?;
                }
            }

            if exclusive {
                set(l, &ops[0], l.int(32).const_zero())?;
            }

            writeback(l, insn)?;
        }
        // Literal loads (ldr x0, #0x1234)
        ("ldr" | "ldrsw", [dst, Op::Imm(addr, _)]) => {
            let bits = if mnemonic == "ldrsw" { 32 } else { dst.bits() };
            let value = l.load(l.global_ptr(*addr as u64)?, bits)?;
            set(l, dst, l.resize(value, dst.bits(), mnemonic == "ldrsw")?)?;
        }

        // Branches
        ("b", [Op::Imm(..)]) => {}
        (m, [Op::Imm(..)]) if m.starts_with("b.") || m.starts_with("bc.") => {
            l.branch = Some(l.condition(insn.cc.context("conditional branch without a condition")?)?);
        }
        ("cbz" | "cbnz", [reg, _]) => {
            let value = get(l, reg, reg.bits())?;
            let predicate = if mnemonic == "cbz" { IntPredicate::EQ } else { IntPredicate::NE };
            l.branch = Some(llvm!(b.build_int_compare(predicate, value, value.get_type().const_zero(), "")));
        }
        ("tbz" | "tbnz", [reg, Op::Imm(bit, _), _]) => {
            let value = get(l, reg, reg.bits())?;
            let masked = llvm!(b.build_and(value, l.constant(reg.bits(), 1u64 << bit), ""));
            let predicate = if mnemonic == "tbz" { IntPredicate::EQ } else { IntPredicate::NE };
            l.branch = Some(llvm!(b.build_int_compare(predicate, masked, value.get_type().const_zero(), "")));
        }
        ("br" | "braa" | "brab" | "braaz" | "brabz", [target, ..]) => {
            l.jump = Some(get(l, target, 64)?);
        }
        // The check of Control Flow Guard changes nothing
        ("blr", _) if l.guard_call(insn.addr) == Some(GUARD_CHECK) => {}
        ("bl", _) | ("blr" | "blraa" | "blrab" | "blraaz" | "blrabz", _) => {
            let site = l.function.calls.iter().find(|c| c.addr == insn.addr).map(|c| c.target.clone()).unwrap_or(CallTarget::Indirect);
            let value = match ops.first() {
                Some(op @ Op::Reg { .. }) => Some(get(l, op, 64)?),
                _ => None,
            };

            l.call(&site, value, false)?;
        }
        ("ret" | "retaa" | "retab", _) => {}
        ("svc", _) => {
            let (x8, x0) = (l.env.regs.reg("x8"), l.env.regs.reg("x0"));
            l.syscall(x8, &["x0", "x1", "x2", "x3", "x4", "x5"], x0)?;
        }

        // Scalar floating point
        ("fmov", [dst @ Op::Reg { r, .. }, src]) if l.env.regs.regs[r.reg].bits == 128 => {
            let value = match src {
                Op::Fp(_) | Op::Zero(_) => {
                    let value = get_float(l, src)?;
                    if r.bits == 32 { llvm!(b.build_float_trunc(value, l.cx.f32_type(), "")) } else { value }
                }
                _ => l.int_to_float(get(l, src, r.bits)?)?,
            };
            set_float(l, dst, value)?;
        }
        ("fmov", [dst, Op::Reg { r, .. }]) => {
            let value = l.read(*r)?;
            set(l, dst, value)?;
        }
        ("fadd" | "fsub" | "fmul" | "fdiv" | "fmax" | "fmin" | "fmaxnm" | "fminnm" | "fnmul", [dst, x, y]) => {
            let (x, y) = (get_float(l, x)?, get_float(l, y)?);

            let value = match mnemonic {
                "fadd" => llvm!(b.build_float_add(x, y, "")),
                "fsub" => llvm!(b.build_float_sub(x, y, "")),
                "fmul" => llvm!(b.build_float_mul(x, y, "")),
                "fnmul" => llvm!(b.build_float_neg(llvm!(b.build_float_mul(x, y, "")), "")),
                "fdiv" => llvm!(b.build_float_div(x, y, "")),
                op => {
                    let bits = x.get_type().get_bit_width();
                    let name = format!("llvm.{}num.f{}", if op.starts_with("fmin") { "min" } else { "max" }, bits);
                    l.call_intrinsic(&name, &[x.into(), y.into()], Some(x.get_type().into()))?.unwrap().into_float_value()
                }
            };

            set_float(l, dst, value)?;
        }
        ("fmadd" | "fmsub" | "fnmadd" | "fnmsub", [dst, x, y, acc]) => {
            let (x, y, acc) = (get_float(l, x)?, get_float(l, y)?, get_float(l, acc)?);
            let product = llvm!(b.build_float_mul(x, y, ""));

            let value = match mnemonic {
                "fmadd" => llvm!(b.build_float_add(acc, product, "")),
                "fmsub" => llvm!(b.build_float_sub(acc, product, "")),
                "fnmadd" => llvm!(b.build_float_neg(llvm!(b.build_float_add(acc, product, "")), "")),
                _ => llvm!(b.build_float_sub(product, acc, "")),
            };

            set_float(l, dst, value)?;
        }
        ("fneg" | "fabs" | "fsqrt", [dst, src]) => {
            let value = get_float(l, src)?;
            let bits = value.get_type().get_bit_width();

            let result = match mnemonic {
                "fneg" => llvm!(b.build_float_neg(value, "")),
                "fabs" => l.call_intrinsic(&format!("llvm.fabs.f{}", bits), &[value.into()], Some(value.get_type().into()))?.unwrap().into_float_value(),
                _ => l.call_intrinsic(&format!("llvm.sqrt.f{}", bits), &[value.into()], Some(value.get_type().into()))?.unwrap().into_float_value(),
            };

            set_float(l, dst, result)?;
        }
        ("fcvt", [dst @ Op::Reg { r, .. }, src]) => {
            let value = get_float(l, src)?;
            let to = if r.bits == 32 { l.cx.f32_type() } else { l.cx.f64_type() };
            let value = if value.get_type().get_bit_width() < to.get_bit_width() { llvm!(b.build_float_ext(value, to, "")) } else { llvm!(b.build_float_trunc(value, to, "")) };
            set_float(l, dst, value)?;
        }
        ("scvtf" | "ucvtf", [dst @ Op::Reg { r, .. }, src]) if src.bits() != 128 => {
            let to = if r.bits == 32 { l.cx.f32_type() } else { l.cx.f64_type() };
            let value = get(l, src, src.bits())?;
            let value = if mnemonic == "scvtf" { llvm!(b.build_signed_int_to_float(value, to, "")) } else { llvm!(b.build_unsigned_int_to_float(value, to, "")) };
            set_float(l, dst, value)?;
        }
        ("fcvtzs" | "fcvtzu", [dst, src]) if dst.bits() <= 64 => {
            let value = get_float(l, src)?;
            let ty = l.int(dst.bits());
            let value = if mnemonic == "fcvtzs" { llvm!(b.build_float_to_signed_int(value, ty, "")) } else { llvm!(b.build_float_to_unsigned_int(value, ty, "")) };
            set(l, dst, value)?;
        }
        ("fcmp" | "fcmpe", [x, y]) => {
            let x = get_float(l, x)?;
            let y = match y {
                Op::Fp(_) | Op::Zero(_) | Op::Imm(..) => {
                    let zero = x.get_type().const_float(0.0);
                    if let Op::Fp(v) = y { x.get_type().const_float(*v) } else { zero }
                }
                _ => get_float(l, y)?,
            };

            l.set_float_flags(x, y)?;
        }
        ("fcsel", [dst, x, y]) => {
            let cond = l.condition(insn.cc.context("fcsel without a condition")?)?;
            let (x, y) = (get_float(l, x)?, get_float(l, y)?);
            let value = llvm!(b.build_select(cond, x, y, "")).into_float_value();
            set_float(l, dst, value)?;
        }

        _ => unsupported(l, insn)?,
    }

    return Ok(());
}

/// add, sub and the compares, with their flags
fn arithmetic<'ctx>(l: &mut Lifter<'ctx, '_>, insn: &Insn) -> Result<()> {
    let ops = insn.ops.as_slice();
    let mnemonic = insn.mnemonic.as_str();
    let b = &l.builder;

    let compare = matches!(mnemonic, "cmp" | "cmn");
    let (lhs, rhs) = if compare { (&ops[0], &ops[1]) } else { (&ops[1], &ops[2]) };
    let bits = lhs.bits();
    let x = get(l, lhs, bits)?;
    let y = get(l, rhs, bits)?;

    // Address computations from adrp give the address of the global
    let known = match (lhs, rhs) {
        (Op::Reg { r, .. }, Op::Imm(imm, sh)) if mnemonic == "add" => {
            let imm = if *sh == Shift::Lsl(12) { imm << 12 } else { *imm };

            match l.tracker.offset(r.reg, imm) {
                Some(Known::Const(addr)) if l.env.program.region_at(addr).is_some() => Some(llvm!(b.build_ptr_to_int(l.global_ptr(addr)?, l.int(64), ""))),
                _ => None,
            }
        }
        _ => None,
    };

    let (op, result) = match mnemonic {
        "add" | "adds" | "cmn" => (FlagOp::Add, known.map_or_else(|| b.build_int_add(x, y, ""), Ok)?),
        _ => (FlagOp::Sub, llvm!(b.build_int_sub(x, y, ""))),
    };

    if !compare {
        set(l, &ops[0], result)?;
    }

    if mnemonic.ends_with('s') || compare {
        l.set_flags(op, x, y, result)?;
    }

    return Ok(());
}

/// Float comparison predicates of the arm conditions after fcmp (unordered sets C and V)
pub fn float_predicate(cond: Cond) -> Option<FloatPredicate> {
    return Some(match cond {
        Cond::Eq => FloatPredicate::OEQ,
        Cond::Ne => FloatPredicate::UNE,
        Cond::Neg | Cond::Ult => FloatPredicate::OLT,
        Cond::NonNeg | Cond::Uge => FloatPredicate::UGE,
        Cond::Ule => FloatPredicate::OLE,
        Cond::Ugt => FloatPredicate::UGT,
        Cond::Sge => FloatPredicate::OGE,
        Cond::Slt => FloatPredicate::ULT,
        Cond::Sgt => FloatPredicate::OGT,
        Cond::Sle => FloatPredicate::ULE,
        Cond::Overflow => FloatPredicate::UNO,
        Cond::NoOverflow => FloatPredicate::ORD,
        _ => return None,
    });
}

/// Whether the instruction reads (Some(true)) or overwrites (Some(false)) a register, None otherwise
pub fn register_access(insn: &Insn, reg: super::regs::Reg) -> Option<bool> {
    let mnemonic = insn.mnemonic.as_str();
    let uses = |op: &Op| match op {
        Op::Reg { r, .. } => r.reg == reg,
        Op::Mem { base, index, .. } => base.reg == reg || index.is_some_and(|(i, _, _)| i.reg == reg),
        _ => false,
    };

    // x0 is returned by ret and passed by the calls
    if reg == 0 && matches!(mnemonic, "ret" | "bl" | "blr" | "b") {
        return Some(true);
    }

    // The exclusive stores write their status, cas compares and receives the first one
    if is_atomic_load(mnemonic) || matches!(mnemonic, "stxr" | "stlxr" | "stxrb" | "stlxrb" | "stxrh" | "stlxrh" | "stxp" | "stlxp") {
        let write = if is_atomic_load(mnemonic) { 1 } else { 0 };

        if insn.ops.iter().enumerate().any(|(i, op)| i != write && uses(op)) {
            return Some(true);
        }

        let writes = insn.ops.get(write).is_some_and(|op| matches!(op, Op::Reg { r, .. } if r.reg == reg && r.bits >= 32));
        return if writes { Some(false) } else { None };
    }

    if mnemonic.starts_with("cas") {
        return if insn.ops.iter().any(uses) { Some(true) } else { None };
    }

    let reads_all = is_store(mnemonic) || matches!(mnemonic, "cmp" | "cmn" | "tst" | "cbz" | "cbnz" | "tbz" | "tbnz" | "br" | "ccmp" | "ccmn" | "fcmp" | "fcmpe") || mnemonic.starts_with("b.");

    if reads_all {
        return if insn.ops.iter().any(uses) { Some(true) } else { None };
    }

    let destinations = if is_pair(mnemonic) { 2 } else { 1 };

    if insn.ops.iter().skip(destinations).any(uses) {
        return Some(true);
    }

    let writes = insn.ops.iter().take(destinations).any(|op| matches!(op, Op::Reg { r, .. } if r.reg == reg && r.bits >= 32));
    let partial = matches!(mnemonic, "movk" | "bfi" | "bfxil");

    return if writes && !partial { Some(false) } else if writes { Some(true) } else { None };
}

/// Full registers an instruction may write, besides the flags (a call writes what its callee writes)
pub fn written(insn: &Insn) -> u128 {
    let mnemonic = insn.mnemonic.as_str();
    let reg = |op: Option<&Op>| -> u128 { op.and_then(|op| op.reg()).map_or(0, |r| 1u128 << r.reg) };
    let base = match insn.ops.iter().find(|op| matches!(op, Op::Mem { .. })) {
        Some(Op::Mem { base, .. }) if insn.writeback => 1u128 << base.reg,
        _ => 0,
    };

    let stores = mnemonic.starts_with("st") && !mnemonic.starts_with("stx") && !mnemonic.starts_with("stlx");

    let written = match mnemonic {
        _ if stores => 0,
        _ if is_atomic_load(mnemonic) => reg(insn.ops.get(1)),
        "cmp" | "cmn" | "tst" | "fcmp" | "fcmpe" | "ccmp" | "ccmn" | "fccmp" | "fccmpe" => 0,
        "b" | "bl" | "blr" | "br" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz" | "nop" | "prfm" | "dmb" | "dsb" | "isb" | "hint" | "bti" | "brk" | "svc" => 0,
        _ if mnemonic.starts_with("b.") => 0,
        "ldp" | "ldnp" | "ldpsw" | "ldxp" | "ldaxp" => reg(insn.ops.first()) | reg(insn.ops.get(1)),
        _ => reg(insn.ops.first()),
    };

    return written | base;
}
