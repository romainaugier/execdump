/*
 * x86 and x86-64 instruction semantics
 */

use super::regs::{RegRef, RegisterFile};
use super::{llvm, Cond, FlagOp, Known, Lifter, MemAccess, Tracker};

use crate::analysis::function::CallTarget;

use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::Capstone;

use execdump_core::disasm::Architecture;

use inkwell::values::{IntValue, PointerValue};
use inkwell::IntPredicate;
use inkwell::InlineAsmDialect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    Fs,
    Gs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mem {
    pub base: Option<RegRef>,
    pub index: Option<RegRef>,
    pub scale: i64,
    /// Absolute address when there is neither base nor index (rip relative operands are resolved)
    pub disp: i64,
    pub bits: u32,
    pub segment: Option<Segment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Reg(RegRef),
    Imm(i64, u32),
    Mem(Mem),
}

impl Op {
    pub fn bits(&self) -> u32 {
        return match self {
            Op::Reg(r) => r.bits,
            Op::Imm(_, bits) => *bits,
            Op::Mem(m) => m.bits,
        };
    }
}

#[derive(Clone, Debug)]
pub struct Insn {
    pub addr: u64,
    pub size: u8,
    pub mnemonic: String,
    pub rep: bool,
    pub ops: Vec<Op>,
    pub text: String,
    wide: bool,
}

pub fn decode(regs: &RegisterFile, cs: &Capstone, bytes: &[u8], addr: u64) -> Option<Insn> {
    let insns = cs.disasm_count(bytes, addr, 1).ok()?;
    let insn = insns.iter().next()?;
    let detail = cs.insn_detail(insn).ok()?;
    let next = addr + insn.len() as u64;

    let full_mnemonic = insn.mnemonic().unwrap_or("").to_string();
    let mnemonic = full_mnemonic.rsplit(' ').next().unwrap_or("").to_string();
    let rep = full_mnemonic.starts_with("rep");

    let reg = |id: capstone::RegId| -> Option<RegRef> { regs.resolve(&cs.reg_name(id)?) };
    let text = format!("{} {}", full_mnemonic, insn.op_str().unwrap_or("")).trim().to_string();
    let wide = regs.arch == Architecture::X86_64;

    // Operands that are not modeled (x87 stack, segment and control registers) make the instruction opaque
    let opaque = Insn { addr, size: insn.len() as u8, mnemonic: String::new(), rep, ops: Vec::new(), text: text.clone(), wide };

    let mut ops = Vec::new();

    for op in detail.arch_detail().operands() {
        let ArchOperand::X86Operand(op) = op else {
            continue;
        };

        let bits = op.size as u32 * 8;

        ops.push(match &op.op_type {
            X86OperandType::Reg(id) => match reg(*id) {
                Some(r) => Op::Reg(r),
                None => return Some(opaque),
            },
            X86OperandType::Imm(imm) => Op::Imm(*imm, bits),
            X86OperandType::Mem(mem) => {
                let base_name = cs.reg_name(mem.base()).unwrap_or_default();
                let segment = match cs.reg_name(mem.segment()).as_deref() {
                    Some("fs") => Some(Segment::Fs),
                    Some("gs") => Some(Segment::Gs),
                    _ => None,
                };

                if base_name == "rip" || base_name == "eip" {
                    Op::Mem(Mem { base: None, index: None, scale: 1, disp: next.wrapping_add(mem.disp() as u64) as i64, bits, segment })
                } else {
                    let (base, index) = (reg(mem.base()), reg(mem.index()));

                    if (mem.base().0 != 0 && base.is_none()) || (mem.index().0 != 0 && index.is_none()) {
                        return Some(opaque);
                    }

                    Op::Mem(Mem {
                        base,
                        index,
                        scale: mem.scale() as i64,
                        disp: mem.disp(),
                        bits,
                        segment,
                    })
                }
            }
            _ => return Some(opaque),
        });
    }

    return Some(Insn { addr, size: insn.len() as u8, mnemonic, rep, ops, text, wide });
}

fn stack_slot(insn: &Insn) -> i64 {
    return if insn.wide { 8 } else { 4 };
}

/// Instructions that do not write their first operand
fn writes_first_operand(mnemonic: &str) -> bool {
    return !matches!(mnemonic, "cmp" | "test" | "push" | "bt" | "jmp" | "call" | "ret" | "ucomiss" | "ucomisd" | "comiss" | "comisd" | "nop")
        && !mnemonic.starts_with('j');
}

pub fn track(insn: &Insn, regs: &RegisterFile, tracker: &mut Tracker) {
    let sp = regs.reg(if insn.wide { "rsp" } else { "esp" });
    let slot = stack_slot(insn);
    let full = |r: &RegRef| r.offset == 0 && r.bits >= 32;

    match (insn.mnemonic.as_str(), insn.ops.as_slice()) {
        ("push", _) => tracker.set(sp, tracker.offset(sp, -slot)),
        ("pop", [Op::Reg(r)]) => {
            tracker.set(r.reg, None);
            tracker.set(sp, tracker.offset(sp, slot));
        }
        ("pop", _) => tracker.set(sp, tracker.offset(sp, slot)),
        ("leave", _) => {
            let bp = regs.reg(if insn.wide { "rbp" } else { "ebp" });
            tracker.set(sp, tracker.offset(bp, slot));
            tracker.set(bp, None);
        }
        ("mov" | "movabs", [Op::Reg(dst), Op::Imm(imm, _)]) if full(dst) => tracker.set(dst.reg, Some(Known::Const(*imm as u64))),
        ("mov", [Op::Reg(dst), Op::Reg(src)]) if full(dst) && src.bits == dst.bits => tracker.set(dst.reg, tracker.get(src.reg)),
        ("lea", [Op::Reg(dst), Op::Mem(mem)]) if full(dst) && mem.index.is_none() => {
            let value = match mem.base {
                Some(base) => tracker.offset(base.reg, mem.disp),
                None => Some(Known::Const(mem.disp as u64)),
            };

            tracker.set(dst.reg, value);
        }
        ("add", [Op::Reg(dst), Op::Imm(imm, _)]) if full(dst) => tracker.set(dst.reg, tracker.offset(dst.reg, *imm)),
        ("sub", [Op::Reg(dst), Op::Imm(imm, _)]) if full(dst) => tracker.set(dst.reg, tracker.offset(dst.reg, -imm)),
        // Stack realignment keeps the offsets (the frame layout is still consistent)
        ("and", [Op::Reg(dst), Op::Imm(..)]) if dst.reg == sp => {}
        ("call", _) => {
            for name in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "eax", "ecx", "edx"] {
                if let Some(r) = regs.index(name) {
                    tracker.set(r, None);
                }
            }
        }
        (mnemonic, ops) => {
            if let Some(Op::Reg(dst)) = ops.first() {
                if writes_first_operand(mnemonic) {
                    tracker.set(dst.reg, None);
                }
            }

            if matches!(mnemonic, "xchg" | "xadd") {
                if let Some(Op::Reg(src)) = ops.get(1) {
                    tracker.set(src.reg, None);
                }
            }

            // Implicit destinations
            let implicit: &[&str] = match mnemonic {
                "mul" | "imul" | "div" | "idiv" if ops.len() == 1 => &["rax", "rdx", "eax", "edx"],
                "cdq" | "cqo" | "cwd" => &["rdx", "edx"],
                "cpuid" | "rdtsc" | "rdtscp" => &["rax", "rbx", "rcx", "rdx", "eax", "ebx", "ecx", "edx"],
                "stosb" | "stosw" | "stosd" | "stosq" | "movsb" | "movsw" | "movsd" | "movsq" | "scasb" | "cmpsb" => &["rcx", "rsi", "rdi", "ecx", "esi", "edi"],
                "cmpxchg" => &["rax", "eax"],
                _ => &[],
            };

            for name in implicit {
                if let Some(r) = regs.index(name) {
                    tracker.set(r, None);
                }
            }
        }
    }
}

pub fn memory(insn: &Insn) -> Vec<MemAccess> {
    let mut accesses: Vec<MemAccess> = insn
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Mem(mem) if insn.mnemonic != "lea" && mem.segment.is_none() => Some(MemAccess { base: mem.base.map(|b| b.reg), has_index: mem.index.is_some(), disp: mem.disp, bytes: mem.bits / 8 }),
            _ => None,
        })
        .collect();

    let slot = stack_slot(insn);

    // push and call write below the stack pointer, pop reads at it
    let sp_access = match insn.mnemonic.as_str() {
        "push" | "call" => Some(-slot),
        "pop" => Some(0),
        _ => None,
    };

    if let Some(disp) = sp_access {
        // The stack pointer is the register at index 4 of both register files (rsp, esp)
        accesses.push(MemAccess { base: Some(4), has_index: false, disp, bytes: slot as u32 });
    }

    return accesses;
}

fn condition_code(suffix: &str) -> Option<Cond> {
    return Some(match suffix {
        "e" | "z" => Cond::Eq,
        "ne" | "nz" => Cond::Ne,
        "l" | "nge" => Cond::Slt,
        "le" | "ng" => Cond::Sle,
        "g" | "nle" => Cond::Sgt,
        "ge" | "nl" => Cond::Sge,
        "b" | "c" | "nae" => Cond::Ult,
        "be" | "na" => Cond::Ule,
        "a" | "nbe" => Cond::Ugt,
        "ae" | "nb" | "nc" => Cond::Uge,
        "s" => Cond::Neg,
        "ns" => Cond::NonNeg,
        "o" => Cond::Overflow,
        "no" => Cond::NoOverflow,
        "p" | "pe" => Cond::Parity,
        "np" | "po" => Cond::NoParity,
        _ => return None,
    });
}

/*
 * Operands
 */

fn segment_access<'ctx>(l: &Lifter<'ctx, '_>, mem: &Mem, value: Option<IntValue<'ctx>>) -> Result<Option<IntValue<'ctx>>, String> {
    // TLS and TEB accesses become the MSVC intrinsics (__readfsqword(0x28))
    let segment = if mem.segment == Some(Segment::Fs) { "fs" } else { "gs" };
    let size = match mem.bits {
        8 => "byte",
        16 => "word",
        32 => "dword",
        _ => "qword",
    };
    let offset = l.constant(64, mem.disp as u64);

    return match value {
        None => {
            let name = format!("__read{}{}", segment, size);
            Ok(l.call_intrinsic(&name, &[offset.into()], Some(l.int(mem.bits).into()))?.map(|v| v.into_int_value()))
        }
        Some(value) => {
            let name = format!("__write{}{}", segment, size);
            l.call_intrinsic(&name, &[offset.into(), value.into()], None)?;
            Ok(None)
        }
    };
}

fn address<'ctx>(l: &Lifter<'ctx, '_>, mem: &Mem) -> Result<PointerValue<'ctx>, String> {
    return l.address(mem.base.map(|b| b.reg), mem.index.map(|i| (i, mem.scale)), mem.disp);
}

/// Value of an operand, immediates are sign extended to the requested width
fn get<'ctx>(l: &Lifter<'ctx, '_>, op: &Op, bits: u32) -> Result<IntValue<'ctx>, String> {
    let value = match op {
        Op::Reg(r) => l.read(*r)?,
        Op::Imm(imm, _) => return Ok(l.int(bits).const_int(*imm as u64, true)),
        Op::Mem(mem) if mem.segment.is_some() => segment_access(l, mem, None)?.ok_or("segment read")?,
        Op::Mem(mem) => l.load(address(l, mem)?, mem.bits)?,
    };

    return l.resize(value, bits, true);
}

fn set<'ctx>(l: &Lifter<'ctx, '_>, op: &Op, value: IntValue<'ctx>, wide: bool) -> Result<(), String> {
    match op {
        // 32-bit writes clear the upper half of the 64-bit registers
        Op::Reg(r) if wide && r.bits == 32 && r.offset == 0 && l.env.regs.regs[r.reg].bits == 64 => l.write_zext(*r, value),
        Op::Reg(r) => l.write(*r, value),
        Op::Mem(mem) if mem.segment.is_some() => segment_access(l, mem, Some(l.resize(value, mem.bits, false)?)).map(|_| ()),
        Op::Mem(mem) => l.store(address(l, mem)?, l.resize(value, mem.bits, false)?),
        Op::Imm(..) => Err("write to an immediate".to_string()),
    }
}

/// Integer value of the address computed by lea
fn effective_address<'ctx>(l: &Lifter<'ctx, '_>, mem: &Mem, bits: u32) -> Result<IntValue<'ctx>, String> {
    let ptr = address(l, mem)?;
    let value = llvm!(l.builder.build_ptr_to_int(ptr, l.int(64), ""));
    return l.resize(value, bits, false);
}

fn sp_reg(l: &Lifter) -> RegRef {
    return l.env.regs.full(l.env.abi.stack_pointer);
}

fn push<'ctx>(l: &Lifter<'ctx, '_>, value: IntValue<'ctx>, slot: i64) -> Result<(), String> {
    let value = l.resize(value, slot as u32 * 8, true)?;
    let ptr = l.sp_address(-slot)?;
    l.store(ptr, value)?;

    let sp = l.read(sp_reg(l))?;
    let sp = llvm!(l.builder.build_int_sub(sp, l.constant(slot as u32 * 8, slot as u64), ""));

    return l.write(sp_reg(l), sp);
}

fn pop<'ctx>(l: &Lifter<'ctx, '_>, slot: i64) -> Result<IntValue<'ctx>, String> {
    let ptr = l.sp_address(0)?;
    let value = l.load(ptr, slot as u32 * 8)?;

    let sp = l.read(sp_reg(l))?;
    let sp = llvm!(l.builder.build_int_add(sp, l.constant(slot as u32 * 8, slot as u64), ""));
    l.write(sp_reg(l), sp)?;

    return Ok(value);
}

/// Unsupported instructions are kept as inline assembly
fn unsupported(l: &Lifter, insn: &Insn) -> Result<(), String> {
    let asm_type = l.cx.void_type().fn_type(&[], false);
    let asm = l.cx.create_inline_asm(asm_type, insn.text.clone(), String::new(), true, false, Some(InlineAsmDialect::Intel), false);
    llvm!(l.builder.build_indirect_call(asm_type, asm, &[], ""));
    return Ok(());
}

/*
 * Semantics
 */

pub fn lift<'ctx>(l: &mut Lifter<'ctx, '_>, insn: &Insn) -> Result<(), String> {
    let ops = insn.ops.as_slice();
    let mnemonic = insn.mnemonic.as_str();
    let wide = insn.wide;
    let slot = stack_slot(insn);
    let b = &l.builder;

    match (mnemonic, ops) {
        ("nop" | "endbr64" | "endbr32" | "pause" | "lfence" | "mfence" | "sfence" | "hlt" | "ud2" | "int3" | "cld" | "fnop", _) => {}
        (m, _) if m.starts_with("prefetch") => {}

        ("mov" | "movabs", [dst, src]) => {
            let value = get(l, src, dst.bits())?;
            set(l, dst, value, wide)?;
        }
        ("movzx", [dst, src]) => {
            let value = get(l, src, src.bits())?;
            set(l, dst, l.resize(value, dst.bits(), false)?, wide)?;
        }
        ("movsx" | "movsxd", [dst, src]) => {
            let value = get(l, src, src.bits())?;
            set(l, dst, l.resize(value, dst.bits(), true)?, wide)?;
        }
        ("lea", [dst, Op::Mem(mem)]) => {
            let value = effective_address(l, mem, dst.bits())?;
            set(l, dst, value, wide)?;
        }
        ("xchg", [a, c]) if a != c => {
            let (x, y) = (get(l, a, a.bits())?, get(l, c, c.bits())?);
            set(l, a, y, wide)?;
            set(l, c, x, wide)?;
        }
        ("xchg", _) => {}

        ("push", [src]) => {
            let value = get(l, src, slot as u32 * 8)?;
            push(l, value, slot)?;
        }
        ("pop", [dst]) => {
            let value = pop(l, slot)?;
            set(l, dst, value, wide)?;
        }
        ("leave", _) => {
            let bp = l.env.regs.full(l.env.regs.reg(if wide { "rbp" } else { "ebp" }));
            let frame = l.address(Some(bp.reg), None, 0)?;
            let saved = l.load(frame, bp.bits)?;
            let bp_value = l.read(bp)?;
            let sp = llvm!(b.build_int_add(bp_value, l.constant(bp.bits, slot as u64), ""));

            l.write(sp_reg(l), sp)?;
            l.write(bp, saved)?;
        }

        // xor eax, eax and sub eax, eax clear the register without reading it
        ("xor" | "sub", [dst, src]) if dst == src && matches!(dst, Op::Reg(_)) => {
            let zero = l.int(dst.bits()).const_zero();
            set(l, dst, zero, wide)?;
            l.set_flags(if mnemonic == "xor" { FlagOp::Logic } else { FlagOp::Sub }, zero, zero, zero)?;
        }
        ("add" | "sub" | "adc" | "sbb" | "cmp", [dst, src]) => {
            let bits = dst.bits();
            let lhs = get(l, dst, bits)?;
            let mut rhs = get(l, src, bits)?;

            if matches!(mnemonic, "adc" | "sbb") {
                let carry = l.condition(Cond::Ult)?;
                let carry = l.resize(carry, bits, false)?;
                rhs = llvm!(b.build_int_add(rhs, carry, ""));
            }

            let (op, result) = match mnemonic {
                "add" | "adc" => (FlagOp::Add, llvm!(b.build_int_add(lhs, rhs, ""))),
                _ => (FlagOp::Sub, llvm!(b.build_int_sub(lhs, rhs, ""))),
            };

            if mnemonic != "cmp" {
                set(l, dst, result, wide)?;
            }

            l.set_flags(op, lhs, rhs, result)?;
        }
        ("inc" | "dec", [dst]) => {
            let bits = dst.bits();
            let lhs = get(l, dst, bits)?;
            let one = l.constant(bits, 1);
            let (op, result) = match mnemonic {
                "inc" => (FlagOp::Add, llvm!(b.build_int_add(lhs, one, ""))),
                _ => (FlagOp::Sub, llvm!(b.build_int_sub(lhs, one, ""))),
            };

            set(l, dst, result, wide)?;
            l.set_flags(op, lhs, one, result)?;
        }
        ("neg", [dst]) => {
            let bits = dst.bits();
            let value = get(l, dst, bits)?;
            let zero = l.int(bits).const_zero();
            let result = llvm!(b.build_int_neg(value, ""));

            set(l, dst, result, wide)?;
            l.set_flags(FlagOp::Sub, zero, value, result)?;
        }
        ("not", [dst]) => {
            let value = get(l, dst, dst.bits())?;
            set(l, dst, llvm!(b.build_not(value, "")), wide)?;
        }
        ("and" | "or" | "xor" | "test", [dst, src]) => {
            let bits = dst.bits();
            let lhs = get(l, dst, bits)?;
            let rhs = get(l, src, bits)?;

            let result = match mnemonic {
                "or" => llvm!(b.build_or(lhs, rhs, "")),
                "xor" => llvm!(b.build_xor(lhs, rhs, "")),
                _ => llvm!(b.build_and(lhs, rhs, "")),
            };

            if mnemonic != "test" {
                set(l, dst, result, wide)?;
            }

            l.set_flags(FlagOp::Logic, lhs, rhs, result)?;
        }

        ("shl" | "sal" | "shr" | "sar" | "rol" | "ror", [dst, count]) | ("shl" | "sal" | "shr" | "sar" | "rol" | "ror", [dst, count, ..]) => {
            let bits = dst.bits();
            let value = get(l, dst, bits)?;
            let count = get(l, count, bits)?;
            let count = llvm!(b.build_and(count, l.constant(bits, if bits == 64 { 63 } else { 31 }), ""));

            let result = match mnemonic {
                "shl" | "sal" => llvm!(b.build_left_shift(value, count, "")),
                "shr" => llvm!(b.build_right_shift(value, count, false, "")),
                "sar" => llvm!(b.build_right_shift(value, count, true, "")),
                _ => {
                    let name = format!("llvm.fsh{}.i{}", if mnemonic == "rol" { "l" } else { "r" }, bits);
                    l.call_intrinsic(&name, &[value.into(), value.into(), count.into()], Some(l.int(bits).into()))?.unwrap().into_int_value()
                }
            };

            set(l, dst, result, wide)?;
            l.set_flags(FlagOp::Logic, value, count, result)?;
        }
        ("shl" | "sal" | "shr" | "sar", [dst]) => {
            let bits = dst.bits();
            let value = get(l, dst, bits)?;
            let one = l.constant(bits, 1);
            let result = match mnemonic {
                "shr" => llvm!(b.build_right_shift(value, one, false, "")),
                "sar" => llvm!(b.build_right_shift(value, one, true, "")),
                _ => llvm!(b.build_left_shift(value, one, "")),
            };

            set(l, dst, result, wide)?;
            l.set_flags(FlagOp::Logic, value, one, result)?;
        }

        ("imul", [dst, src]) => {
            let bits = dst.bits();
            let result = llvm!(b.build_int_mul(get(l, dst, bits)?, get(l, src, bits)?, ""));
            set(l, dst, result, wide)?;
            l.flags = None;
        }
        ("imul", [dst, src, imm]) => {
            let bits = dst.bits();
            let result = llvm!(b.build_int_mul(get(l, src, bits)?, get(l, imm, bits)?, ""));
            set(l, dst, result, wide)?;
            l.flags = None;
        }
        ("mul" | "imul", [src]) => {
            // rdx:rax = rax * src
            let bits = src.bits();
            let signed = mnemonic == "imul";
            let (lo, hi) = accumulator(l, bits)?;
            let a = l.resize(l.read(lo)?, bits * 2, signed)?;
            let c = l.resize(get(l, src, bits)?, bits * 2, signed)?;
            let product = llvm!(b.build_int_mul(a, c, ""));

            write_pair(l, lo, hi, product, bits, wide)?;
            l.flags = None;
        }
        ("div" | "idiv", [src]) => {
            // rax = rdx:rax / src, rdx = rdx:rax % src
            let bits = src.bits();
            let signed = mnemonic == "idiv";
            let (lo, hi) = accumulator(l, bits)?;

            let low = l.resize(l.read(lo)?, bits * 2, false)?;
            let high = l.resize(l.read(hi)?, bits * 2, false)?;
            let high = llvm!(b.build_left_shift(high, l.constant(bits * 2, bits as u64), ""));
            let dividend = llvm!(b.build_or(high, low, ""));
            let divisor = l.resize(get(l, src, bits)?, bits * 2, signed)?;

            let (quotient, remainder) = if signed {
                (llvm!(b.build_int_signed_div(dividend, divisor, "")), llvm!(b.build_int_signed_rem(dividend, divisor, "")))
            } else {
                (llvm!(b.build_int_unsigned_div(dividend, divisor, "")), llvm!(b.build_int_unsigned_rem(dividend, divisor, "")))
            };

            set(l, &Op::Reg(lo), l.resize(quotient, bits, false)?, wide)?;
            set(l, &Op::Reg(hi), l.resize(remainder, bits, false)?, wide)?;
            l.flags = None;
        }

        ("cbw" | "cwde" | "cdqe", _) => {
            let bits = match mnemonic {
                "cbw" => 16,
                "cwde" => 32,
                _ => 64,
            };
            let rax = l.env.regs.full(l.env.regs.reg(if wide { "rax" } else { "eax" }));
            let value = l.read(RegRef { bits: bits / 2, ..rax })?;
            set(l, &Op::Reg(RegRef { bits, ..rax }), l.resize(value, bits, true)?, wide)?;
        }
        ("cwd" | "cdq" | "cqo", _) => {
            let bits = match mnemonic {
                "cwd" => 16,
                "cdq" => 32,
                _ => 64,
            };
            let (lo, hi) = accumulator(l, bits)?;
            let value = l.read(lo)?;
            let sign = llvm!(b.build_right_shift(value, l.constant(bits, bits as u64 - 1), true, ""));
            set(l, &Op::Reg(hi), sign, wide)?;
        }

        (m, [dst]) if m.starts_with("set") => {
            let cond = condition_code(&m[3..]).ok_or_else(|| format!("unknown condition {}", m))?;
            let value = l.condition(cond)?;
            set(l, dst, l.resize(value, 8, false)?, wide)?;
        }
        (m, [dst, src]) if m.starts_with("cmov") => {
            let cond = condition_code(&m[4..]).ok_or_else(|| format!("unknown condition {}", m))?;
            let bits = dst.bits();
            let condition = l.condition(cond)?;
            let value = llvm!(b.build_select(condition, get(l, src, bits)?, get(l, dst, bits)?, "")).into_int_value();
            set(l, dst, value, wide)?;
        }
        (m, [_]) if m.starts_with('j') && m != "jmp" => {
            let cond = match m {
                "jcxz" | "jecxz" | "jrcxz" => {
                    let rcx = l.env.regs.full(l.env.regs.reg(if wide { "rcx" } else { "ecx" }));
                    let value = l.read(rcx)?;
                    l.branch = Some(llvm!(b.build_int_compare(IntPredicate::EQ, value, value.get_type().const_zero(), "")));
                    return Ok(());
                }
                _ => condition_code(&m[1..]).ok_or_else(|| format!("unknown condition {}", m))?,
            };

            l.branch = Some(l.condition(cond)?);
        }
        ("jmp", [Op::Imm(..)]) => {}
        ("jmp", [target]) => {
            l.jump = Some(get(l, target, slot as u32 * 8)?);
        }
        ("call", [target]) => {
            let site = l.function.calls.iter().find(|c| c.addr == insn.addr).map(|c| c.target.clone()).unwrap_or(CallTarget::Indirect);
            let value = match target {
                Op::Imm(..) => None,
                _ => Some(get(l, target, slot as u32 * 8)?),
            };

            l.call(&site, value, false)?;
        }
        ("ret" | "retn", _) => {}

        ("syscall", _) => {
            let rax = l.env.regs.reg("rax");
            l.syscall(rax, &["rdi", "rsi", "rdx", "r10", "r8", "r9"], rax)?;
        }
        ("int", [Op::Imm(0x80, _)]) if !wide => {
            let eax = l.env.regs.reg("eax");
            l.syscall(eax, &["ebx", "ecx", "edx", "esi", "edi", "ebp"], eax)?;
        }
        ("bswap", [dst]) => {
            let bits = dst.bits();
            let name = format!("llvm.bswap.i{}", bits);
            let value = l.call_intrinsic(&name, &[get(l, dst, bits)?.into()], Some(l.int(bits).into()))?.unwrap().into_int_value();
            set(l, dst, value, wide)?;
        }
        ("bt", [base, bit]) => {
            let bits = base.bits();
            let value = get(l, base, bits)?;
            let bit = llvm!(b.build_and(get(l, bit, bits)?, l.constant(bits, bits as u64 - 1), ""));
            let shifted = llvm!(b.build_right_shift(value, bit, false, ""));
            let set_bit = llvm!(b.build_int_truncate(shifted, l.int(1), ""));
            l.flags = None;
            store_carry(l, set_bit)?;
        }
        ("xadd", [dst, src]) => {
            let bits = dst.bits();
            let (old, add) = (get(l, dst, bits)?, get(l, src, bits)?);
            let sum = llvm!(b.build_int_add(old, add, ""));
            set(l, src, old, wide)?;
            set(l, dst, sum, wide)?;
            l.set_flags(FlagOp::Add, old, add, sum)?;
        }
        ("cmpxchg", [dst, src]) => {
            let bits = dst.bits();
            let acc = l.env.regs.full(l.env.regs.reg(if wide { "rax" } else { "eax" }));
            let acc = RegRef { bits, ..acc };
            let (current, expected) = (get(l, dst, bits)?, l.read(acc)?);
            let equal = llvm!(b.build_int_compare(IntPredicate::EQ, current, expected, ""));
            let stored = llvm!(b.build_select(equal, get(l, src, bits)?, current, "")).into_int_value();

            set(l, dst, stored, wide)?;
            set(l, &Op::Reg(acc), current, wide)?;
            let difference = llvm!(b.build_int_sub(expected, current, ""));
            l.set_flags(FlagOp::Sub, expected, current, difference)?;
        }

        ("stosb" | "stosw" | "stosd" | "stosq" | "movsb" | "movsw" | "movsq", _) | ("movsd", [] | [Op::Mem(_), Op::Mem(_)]) => string_op(l, insn)?,
        ("bts" | "btr" | "btc", [base, bit]) => {
            let bits = base.bits();
            let value = get(l, base, bits)?;
            let bit = llvm!(b.build_and(get(l, bit, bits)?, l.constant(bits, bits as u64 - 1), ""));
            let mask = llvm!(b.build_left_shift(l.constant(bits, 1), bit, ""));
            let result = match mnemonic {
                "bts" => llvm!(b.build_or(value, mask, "")),
                "btr" => llvm!(b.build_and(value, llvm!(b.build_not(mask, "")), "")),
                _ => llvm!(b.build_xor(value, mask, "")),
            };
            let shifted = llvm!(b.build_right_shift(value, bit, false, ""));

            set(l, base, result, wide)?;
            l.flags = None;
            store_carry(l, llvm!(b.build_int_truncate(shifted, l.int(1), "")))?;
        }
        ("bsf" | "bsr" | "tzcnt" | "lzcnt" | "popcnt", [dst, src]) => {
            let bits = dst.bits();
            let value = get(l, src, bits)?;
            let name = match mnemonic {
                "bsf" | "tzcnt" => format!("llvm.cttz.i{}", bits),
                "bsr" | "lzcnt" => format!("llvm.ctlz.i{}", bits),
                _ => format!("llvm.ctpop.i{}", bits),
            };

            let args = if mnemonic == "popcnt" { vec![value.into()] } else { vec![value.into(), l.int(1).const_zero().into()] };
            let mut count = l.call_intrinsic(&name, &args, Some(l.int(bits).into()))?.unwrap().into_int_value();

            // bsr gives the index of the highest set bit
            if mnemonic == "bsr" {
                count = llvm!(b.build_int_sub(l.constant(bits, bits as u64 - 1), count, ""));
            }

            set(l, dst, count, wide)?;
            l.set_flags(FlagOp::Logic, value, value, value)?;
        }

        _ => {
            if !lift_sse(l, insn)? {
                unsupported(l, insn)?;
            }
        }
    }

    return Ok(());
}

/// rax/rdx pair (or eax/edx, ax/dx) for the widening multiplications and the divisions
fn accumulator(l: &Lifter, bits: u32) -> Result<(RegRef, RegRef), String> {
    let wide = l.env.regs.arch == Architecture::X86_64;
    let rax = l.env.regs.full(l.env.regs.reg(if wide { "rax" } else { "eax" }));
    let rdx = l.env.regs.full(l.env.regs.reg(if wide { "rdx" } else { "edx" }));

    // 8-bit: ah:al
    if bits == 8 {
        return Ok((RegRef { bits: 8, ..rax }, RegRef { bits: 8, offset: 8, ..rax }));
    }

    return Ok((RegRef { bits, ..rax }, RegRef { bits, ..rdx }));
}

fn write_pair<'ctx>(l: &Lifter<'ctx, '_>, lo: RegRef, hi: RegRef, value: IntValue<'ctx>, bits: u32, wide: bool) -> Result<(), String> {
    let low = l.resize(value, bits, false)?;
    let high = llvm!(l.builder.build_right_shift(value, l.constant(bits * 2, bits as u64), false, ""));
    let high = l.resize(high, bits, false)?;

    set(l, &Op::Reg(lo), low, wide)?;
    set(l, &Op::Reg(hi), high, wide)?;

    return Ok(());
}

fn store_carry<'ctx>(l: &Lifter<'ctx, '_>, value: IntValue<'ctx>) -> Result<(), String> {
    let cf = l.env.regs.full(l.env.regs.reg("cf"));
    return l.write(cf, value);
}

/// rep stos and rep movs: memset and memcpy for the bytes, the MSVC intrinsics otherwise (__stosq)
fn string_op(l: &Lifter, insn: &Insn) -> Result<(), String> {
    let wide = insn.wide;
    let regs = l.env.regs;
    let name = |n64: &str, n32: &str| regs.full(regs.reg(if wide { n64 } else { n32 }));
    let (rdi, rsi, rcx, rax) = (name("rdi", "edi"), name("rsi", "esi"), name("rcx", "ecx"), name("rax", "eax"));

    let size = match insn.mnemonic.chars().last() {
        Some('b') => 1,
        Some('w') => 2,
        Some('d') => 4,
        _ => 8,
    };

    let dst = l.address(Some(rdi.reg), None, 0)?;
    let count = if insn.rep { l.read(rcx)? } else { l.constant(rcx.bits, 1) };
    let count64 = l.resize(count, 64, false)?;
    let store = insn.mnemonic.starts_with("stos");

    if store {
        let value = l.read(RegRef { bits: size * 8, ..rax })?;

        if size == 1 {
            let bytes = count64;
            l.call_intrinsic("llvm.memset.p0.i64", &[dst.into(), value.into(), bytes.into(), l.int(1).const_zero().into()], None)?;
        } else {
            l.call_intrinsic(&format!("__stos{}", &insn.mnemonic[4..]), &[dst.into(), value.into(), count64.into()], None)?;
        }
    } else {
        let src = l.address(Some(rsi.reg), None, 0)?;

        if size == 1 {
            l.call_intrinsic("llvm.memcpy.p0.p0.i64", &[dst.into(), src.into(), count64.into(), l.int(1).const_zero().into()], None)?;
        } else {
            l.call_intrinsic(&format!("__movs{}", &insn.mnemonic[4..]), &[dst.into(), src.into(), count64.into()], None)?;
        }

        advance(l, rsi, count, size)?;
    }

    advance(l, rdi, count, size)?;

    if insn.rep {
        l.write(rcx, l.int(rcx.bits).const_zero())?;
    }

    return Ok(());
}

fn advance<'ctx>(l: &Lifter<'ctx, '_>, reg: RegRef, count: IntValue<'ctx>, size: u32) -> Result<(), String> {
    let count = l.resize(count, reg.bits, false)?;
    let bytes = llvm!(l.builder.build_int_mul(count, l.constant(reg.bits, size as u64), ""));
    let value = llvm!(l.builder.build_int_add(l.read(reg)?, bytes, ""));
    return l.write(reg, value);
}

/// Scalar SSE: moves, arithmetic, conversions and comparisons on the low lane
pub fn lift_sse<'ctx>(l: &mut Lifter<'ctx, '_>, insn: &Insn) -> Result<bool, String> {
    let ops = insn.ops.as_slice();
    let mnemonic = insn.mnemonic.as_str();
    let wide = insn.wide;
    let b = &l.builder;

    let scalar_bits = |m: &str| if m.ends_with("ss") || m.ends_with("ps") { 32 } else { 64 };

    match (mnemonic, ops) {
        ("movss" | "movsd", [Op::Reg(dst), Op::Reg(src)]) => {
            let bits = scalar_bits(mnemonic);
            let value = l.read(RegRef { bits, ..*src })?;
            l.write(RegRef { bits, ..*dst }, value)?;
        }
        ("movss" | "movsd", [Op::Reg(dst), Op::Mem(mem)]) => {
            let value = l.load(address(l, mem)?, mem.bits)?;
            l.write_zext(*dst, value)?;
        }
        ("movss" | "movsd" | "movq" | "movd", [Op::Mem(mem), Op::Reg(src)]) => {
            let value = l.read(RegRef { bits: mem.bits, ..*src })?;
            l.store(address(l, mem)?, value)?;
        }
        ("movq" | "movd", [Op::Reg(dst), src]) if l.env.regs.regs[dst.reg].bits == 128 => {
            let value = get(l, src, src.bits())?;
            l.write_zext(*dst, value)?;
        }
        ("movq" | "movd", [dst, Op::Reg(src)]) => {
            let value = l.read(RegRef { bits: dst.bits(), ..*src })?;
            set(l, dst, value, wide)?;
        }
        ("movaps" | "movups" | "movapd" | "movupd" | "movdqa" | "movdqu" | "lddqu" | "vmovaps" | "vmovups" | "vmovdqa" | "vmovdqu", [dst, src]) => {
            let value = get(l, src, 128)?;
            set(l, dst, value, wide)?;
        }
        ("xorps" | "xorpd" | "pxor", [Op::Reg(dst), Op::Reg(src)]) if dst == src => {
            l.write(*dst, l.int(128).const_zero())?;
        }
        ("xorps" | "xorpd" | "pxor" | "andps" | "andpd" | "pand" | "orps" | "orpd" | "por" | "andnps" | "andnpd" | "pandn", [dst, src]) => {
            let (x, y) = (get(l, dst, 128)?, get(l, src, 128)?);
            let value = match mnemonic {
                "xorps" | "xorpd" | "pxor" => llvm!(b.build_xor(x, y, "")),
                "orps" | "orpd" | "por" => llvm!(b.build_or(x, y, "")),
                "andnps" | "andnpd" | "pandn" => llvm!(b.build_and(llvm!(b.build_not(x, "")), y, "")),
                _ => llvm!(b.build_and(x, y, "")),
            };
            set(l, dst, value, wide)?;
        }
        ("addss" | "addsd" | "subss" | "subsd" | "mulss" | "mulsd" | "divss" | "divsd" | "minss" | "minsd" | "maxss" | "maxsd" | "sqrtss" | "sqrtsd", [Op::Reg(dst), src]) => {
            let bits = scalar_bits(mnemonic);
            let x = l.read_float(*dst, bits)?;
            let y = l.int_to_float(get(l, src, bits)?)?;

            let value = match &mnemonic[..3] {
                "add" => llvm!(b.build_float_add(x, y, "")),
                "sub" => llvm!(b.build_float_sub(x, y, "")),
                "mul" => llvm!(b.build_float_mul(x, y, "")),
                "div" => llvm!(b.build_float_div(x, y, "")),
                "sqr" => l.call_intrinsic(&format!("llvm.sqrt.f{}", bits), &[y.into()], Some(y.get_type().into()))?.unwrap().into_float_value(),
                op => {
                    let name = format!("llvm.{}num.f{}", if op == "min" { "min" } else { "max" }, bits);
                    l.call_intrinsic(&name, &[x.into(), y.into()], Some(x.get_type().into()))?.unwrap().into_float_value()
                }
            };

            l.write_float(*dst, value, false)?;
        }
        ("cvtsi2ss" | "cvtsi2sd", [Op::Reg(dst), src]) => {
            let ty = if mnemonic.ends_with("ss") { l.cx.f32_type() } else { l.cx.f64_type() };
            let value = llvm!(b.build_signed_int_to_float(get(l, src, src.bits())?, ty, ""));
            l.write_float(*dst, value, false)?;
        }
        ("cvttss2si" | "cvttsd2si" | "cvtss2si" | "cvtsd2si", [dst, src]) => {
            let bits = if mnemonic.contains("ss") { 32 } else { 64 };
            let value = l.int_to_float(get(l, src, bits)?)?;
            let value = llvm!(b.build_float_to_signed_int(value, l.int(dst.bits()), ""));
            set(l, dst, value, wide)?;
        }
        ("cvtss2sd" | "cvtsd2ss", [Op::Reg(dst), src]) => {
            let (from, to) = if mnemonic == "cvtss2sd" { (32, l.cx.f64_type()) } else { (64, l.cx.f32_type()) };
            let value = l.int_to_float(get(l, src, from)?)?;
            let value = if from == 32 { llvm!(b.build_float_ext(value, to, "")) } else { llvm!(b.build_float_trunc(value, to, "")) };
            l.write_float(*dst, value, false)?;
        }
        ("ucomiss" | "ucomisd" | "comiss" | "comisd", [lhs, rhs]) => {
            let bits = scalar_bits(mnemonic);
            let x = l.int_to_float(get(l, lhs, bits)?)?;
            let y = l.int_to_float(get(l, rhs, bits)?)?;
            l.set_float_flags(x, y)?;
        }
        _ => return Ok(false),
    }

    return Ok(true);
}

/// Whether the instruction reads (Some(true)) or overwrites (Some(false)) a register, None otherwise
pub fn register_access(insn: &Insn, reg: super::regs::Reg) -> Option<bool> {
    let mnemonic = insn.mnemonic.as_str();
    let uses = |op: &Op| match op {
        Op::Reg(r) => r.reg == reg,
        Op::Mem(m) => m.base.is_some_and(|b| b.reg == reg) || m.index.is_some_and(|i| i.reg == reg),
        Op::Imm(..) => false,
    };

    // Implicit uses of the accumulator (rax is the first register of both files)
    let accumulator = reg == 0;

    if accumulator && matches!(mnemonic, "ret" | "retn" | "cdq" | "cqo" | "cwde" | "cdqe" | "cbw" | "stosb" | "stosw" | "stosd" | "stosq" | "cmpxchg") {
        return Some(true);
    }

    if accumulator && matches!(mnemonic, "mul" | "div" | "idiv") || (mnemonic == "imul" && insn.ops.len() == 1 && accumulator) {
        return Some(true);
    }

    if insn.ops.iter().skip(1).any(uses) || insn.ops.iter().any(|op| matches!(op, Op::Mem(_)) && uses(op)) {
        return Some(true);
    }

    let Some(Op::Reg(dst)) = insn.ops.first() else {
        return if accumulator && mnemonic == "call" { Some(false) } else { None };
    };

    if dst.reg != reg {
        return if accumulator && mnemonic == "call" { Some(false) } else { None };
    }

    let write_only = matches!(mnemonic, "mov" | "movabs" | "lea" | "movzx" | "movsx" | "movsxd" | "pop") || mnemonic.starts_with("set") || mnemonic.starts_with("cvt");

    // xor eax, eax clears the register without reading it
    let zeroing = matches!(mnemonic, "xor" | "sub") && insn.ops.get(1) == insn.ops.first();

    return if write_only && dst.bits >= 32 || zeroing {
        Some(false)
    } else if writes_first_operand(mnemonic) || matches!(mnemonic, "cmp" | "test" | "push") {
        Some(true)
    } else {
        None
    };
}

/// Full registers an instruction may write, besides the flags (a call writes what its callee writes)
pub fn written(insn: &Insn, regs: &RegisterFile) -> u128 {
    let named = |names: &[&str]| -> u128 { names.iter().filter_map(|n| regs.index(n)).fold(0, |mask, r| mask | 1 << r) };
    let wide = regs.arch == execdump_core::disasm::Architecture::X86_64;
    let (ax, cx, dx, bx, sp, bp, si, di) = if wide { ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi") } else { ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi") };
    let operands = |ops: &[Op]| -> u128 { ops.iter().filter_map(|op| if let Op::Reg(r) = op { Some(1u128 << r.reg) } else { None }).fold(0, |a, b| a | b) };
    let first = insn.ops.first().map_or(0, |op| operands(std::slice::from_ref(op)));
    let mnemonic = insn.mnemonic.as_str();

    // String instructions: their operands are memory (movsd xmm0, xmm1 is not one)
    let string = matches!(mnemonic.trim_end_matches(['b', 'w', 'd', 'q']), "movs" | "stos" | "lods" | "scas" | "cmps") && insn.ops.iter().all(|op| matches!(op, Op::Mem(_)));

    if string {
        let counter = if insn.rep { named(&[cx]) } else { 0 };
        let accumulator = if mnemonic.starts_with("lods") { named(&[ax]) } else { 0 };
        let pointers = match &mnemonic[..4] {
            "movs" | "cmps" => named(&[si, di]),
            "lods" => named(&[si]),
            _ => named(&[di]),
        };

        return counter | accumulator | pointers;
    }

    return match mnemonic {
        "call" | "jmp" | "ret" | "retn" | "nop" | "endbr64" | "endbr32" | "hlt" | "ud2" | "int3" | "pause" | "lfence" | "sfence" | "mfence" | "jrcxz" | "jecxz" => 0,
        "cmp" | "test" | "bt" | "ucomisd" | "ucomiss" | "comisd" | "comiss" | "ptest" | "vptest" | "vucomisd" | "vucomiss" | "vcomisd" | "vcomiss" => 0,
        _ if mnemonic.starts_with('j') || mnemonic.starts_with("prefetch") => 0,
        "push" | "pushf" | "pushfq" => named(&[sp]),
        "pop" | "popf" | "popfq" => named(&[sp]) | first,
        "leave" => named(&[sp, bp]),
        "mul" | "div" | "idiv" => named(&[ax, dx]),
        "imul" if insn.ops.len() == 1 => named(&[ax, dx]),
        "cdq" | "cqo" | "cwd" => named(&[dx]),
        "cdqe" | "cwde" | "cbw" => named(&[ax]),
        "cpuid" => named(&[ax, bx, cx, dx]),
        "rdtsc" => named(&[ax, dx]),
        "rdtscp" => named(&[ax, cx, dx]),
        "syscall" => named(&[ax, cx, "r11"]),
        "int" | "sysenter" => named(&[ax, cx, dx]),
        "xchg" | "xadd" => operands(&insn.ops),
        "cmpxchg" => named(&[ax]) | first,
        "cmpxchg8b" | "cmpxchg16b" => named(&[ax, dx]),
        "loop" | "loope" | "loopne" => named(&[cx]),
        _ => first,
    };
}
