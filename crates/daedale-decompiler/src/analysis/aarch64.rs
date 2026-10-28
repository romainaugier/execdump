// SPDX-License-Identifier: Apache-2.0
/*
 * aarch64 jump tables. The compilers load an entry of a table at the index the bound check before allows, then add it
 * to a base (or jump to it):
 *
 *   clang   adrp x9, table ; add x9, x9, :lo12:table ; adr x10, base ; ldrb w11, [x9, x8] ; add x10, x10, x11, lsl #2
 *   gcc     adrp x1, table ; add x1, x1, :lo12:table ; ldrh w1, [x1, w0, uxtw #1] ; adr x2, base ; add x1, x2, w1, sxth #2
 *   msvc    ldr w8, [x9, w8, uxtw #2] ; adr x9, base ; add x8, x9, w8, sxtw #2
 *   go      ldr x1, [x1, x0, lsl #3]
 *
 * Instead of matching each pattern the instructions before the jump are run for every index: the registers holding
 * the compared value are the index at the compare, the tables are read from the program.
 */

use crate::analysis::insn::{Decoded, Modifier, Operand, Shift};

use capstone::arch::arm64::Arm64Reg;

/// Value of a register while the instructions run: unknown or known, and the definition it comes from (a move keeps
/// it, so the copies of the index are the index)
#[derive(Clone, Copy, Debug)]
struct Slot {
    reg: u16,
    value: Option<u64>,
    origin: u32,
}

/// The 64-bit register of a register and whether it is the 32-bit one (w8 is x8)
fn full_register(reg: u16) -> (u16, bool) {
    let w0 = Arm64Reg::ARM64_REG_W0 as u16;
    let w30 = Arm64Reg::ARM64_REG_W30 as u16;

    return match reg {
        r if (w0..=w30).contains(&r) => match r - w0 {
            29 => (Arm64Reg::ARM64_REG_X29 as u16, true),
            30 => (Arm64Reg::ARM64_REG_X30 as u16, true),
            n => (Arm64Reg::ARM64_REG_X0 as u16 + n, true),
        },
        r if r == Arm64Reg::ARM64_REG_WZR as u16 => (Arm64Reg::ARM64_REG_XZR as u16, true),
        r if r == Arm64Reg::ARM64_REG_WSP as u16 => (Arm64Reg::ARM64_REG_SP as u16, true),
        r => (r, false),
    };
}

fn modify(value: u64, modifier: Modifier) -> Option<u64> {
    let value = match modifier.extend {
        Some((bits, signed)) => {
            let shift = 64 - bits as u32;
            if signed { ((value << shift) as i64 >> shift) as u64 } else { value << shift >> shift }
        }
        None => value,
    };

    return match modifier.shift {
        Shift::None => Some(value),
        Shift::Lsl(amount) => Some(value << (amount as u32 & 63)),
        Shift::Other => None,
    };
}

/// Size and signedness of the value a load reads
fn load_size(mnemonic: &str, narrow: bool) -> Option<(usize, bool)> {
    return match mnemonic {
        "ldrb" => Some((1, false)),
        "ldrh" => Some((2, false)),
        "ldrsb" => Some((1, true)),
        "ldrsh" => Some((2, true)),
        "ldrsw" => Some((4, true)),
        "ldr" | "ldur" => Some((if narrow { 4 } else { 8 }, false)),
        _ => None,
    };
}

/// Instructions that do not write their first operand
fn writes_first_operand(mnemonic: &str) -> bool {
    return !["st", "cmp", "cmn", "tst", "cb", "tb", "b", "prfm", "nop"].iter().any(|p| mnemonic.starts_with(p));
}

struct Machine<'a> {
    slots: Vec<Slot>,
    next_origin: u32,
    read: &'a dyn Fn(u64, usize) -> Option<u64>,
}

impl Machine<'_> {
    fn slot(&self, reg: u16) -> Slot {
        let (reg, _) = full_register(reg);

        if reg == Arm64Reg::ARM64_REG_XZR as u16 {
            return Slot { reg, value: Some(0), origin: 0 };
        }

        // A register not written yet is its own definition
        return self.slots.iter().find(|s| s.reg == reg).copied().unwrap_or(Slot { reg, value: None, origin: 1 << 20 | reg as u32 });
    }

    fn value(&self, reg: u16) -> Option<u64> {
        let (_, narrow) = full_register(reg);
        let value = self.slot(reg).value?;
        return Some(if narrow { value & 0xffff_ffff } else { value });
    }

    fn set(&mut self, reg: u16, value: Option<u64>, origin: Option<u32>) {
        let (full, narrow) = full_register(reg);
        let value = value.map(|v| if narrow { v & 0xffff_ffff } else { v });

        let origin = origin.unwrap_or_else(|| {
            self.next_origin += 1;
            self.next_origin
        });

        self.slots.retain(|s| s.reg != full);
        self.slots.push(Slot { reg: full, value, origin });
    }

    /// Value of a second operand: a register or an immediate, extended and shifted
    fn operand(&self, decoded: &Decoded, index: usize) -> Option<u64> {
        let value = match decoded.operand(index) {
            Operand::Reg(reg) => self.value(reg)?,
            Operand::Imm(imm) => imm as u64,
            _ => return None,
        };

        return modify(value, decoded.modifiers[index]);
    }

    fn step(&mut self, decoded: &Decoded) {
        let mnemonic = decoded.base_mnemonic();

        if matches!(mnemonic, "bl" | "blr") {
            self.slots.clear();
            return;
        }

        let Operand::Reg(rd) = decoded.operand(0) else {
            return;
        };

        if !writes_first_operand(mnemonic) {
            return;
        }

        let value = match (mnemonic, decoded.operand(1)) {
            ("adr" | "adrp", Operand::Imm(imm)) => Some(imm as u64),
            ("mov", Operand::Reg(rn)) if decoded.modifiers[1] == Modifier::default() => {
                let origin = self.slot(rn).origin;
                return self.set(rd, self.value(rn), Some(origin));
            }
            ("mov" | "movz", Operand::Imm(_)) => self.operand(decoded, 1),
            ("add", Operand::Reg(rn)) => self.value(rn).zip(self.operand(decoded, 2)).map(|(a, b)| a.wrapping_add(b)),
            ("sub", Operand::Reg(rn)) => self.value(rn).zip(self.operand(decoded, 2)).map(|(a, b)| a.wrapping_sub(b)),
            ("and", Operand::Reg(rn)) => self.value(rn).zip(self.operand(decoded, 2)).map(|(a, b)| a & b),
            ("lsl", Operand::Reg(rn)) => self.value(rn).zip(self.operand(decoded, 2)).map(|(a, b)| a << (b & 63)),
            ("sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" | "uxtw", Operand::Reg(rn)) => {
                let bits = match &mnemonic[3..] {
                    "b" => 8,
                    "h" => 16,
                    _ => 32,
                };

                self.value(rn).and_then(|v| modify(v, Modifier { extend: Some((bits, mnemonic.starts_with('s'))), shift: Shift::None }))
            }
            (m, Operand::Mem { base, index, disp, .. }) if load_size(m, full_register(rd).1).is_some() => {
                let (size, signed) = load_size(m, full_register(rd).1).unwrap();
                let offset = if index == 0 { Some(0) } else { self.value(index).and_then(|v| modify(v, decoded.modifiers[1])) };
                let address = self.value(base).zip(offset).map(|(b, o)| b.wrapping_add(o).wrapping_add(disp as u64));

                address.and_then(|a| (self.read)(a, size)).map(|v| {
                    let shift = 64 - 8 * size as u32;
                    if signed { ((v << shift) as i64 >> shift) as u64 } else { v }
                })
            }
            _ => None,
        };

        self.set(rd, value, None);
    }
}

/// The bound check before the jump: the position of the compare, the definition of the value it compares and the
/// number of values the jump takes
fn bound(window: &[Decoded], read: &dyn Fn(u64, usize) -> Option<u64>) -> Option<(usize, u32, u64)> {
    let mut machine = Machine { slots: Vec::new(), next_origin: 0, read };
    let mut compare = None;
    let mut found = None;

    for (position, decoded) in window.iter().enumerate() {
        match (decoded.base_mnemonic(), decoded.operand(0), decoded.operand(1)) {
            ("cmp", Operand::Reg(reg), Operand::Imm(imm)) if imm >= 0 => compare = Some((position, machine.slot(reg).origin, imm as u64)),
            ("b.hi", ..) => found = compare.map(|(p, origin, imm)| (p, origin, imm + 1)),
            ("b.hs" | "b.cs", ..) => found = compare,
            _ => {}
        }

        machine.step(decoded);
    }

    return found;
}

/// The targets of a jump through a register for every index of its table (None for an index the instructions do not
/// give an address for): the window is the instructions before the jump, in their order
pub fn jump_table(window: &[Decoded], jump: &Decoded, read: &dyn Fn(u64, usize) -> Option<u64>, max: u64) -> Option<Vec<Option<u64>>> {
    let Operand::Reg(target) = jump.operand(0) else {
        return None;
    };

    let (compare, origin, count) = bound(window, read)?;
    let mut targets = Vec::new();

    for index in 0..count.min(max) {
        let mut machine = Machine { slots: Vec::new(), next_origin: 0, read };

        for (position, decoded) in window.iter().enumerate() {
            if position == compare {
                // The index is the compared value, and every copy of it
                for slot in machine.slots.iter_mut().filter(|s| s.origin == origin) {
                    slot.value = Some(index);
                }

                if let Operand::Reg(reg) = decoded.operand(0) {
                    machine.set(reg, Some(index), Some(origin));
                }
            }

            machine.step(decoded);
        }

        targets.push(machine.value(target));
    }

    return Some(targets);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analysis::insn::Decoder;
    use daedale_core::disasm::Architecture;

    fn decode(words: &[u32], at: u64) -> Vec<Decoded> {
        let decoder = Decoder::new(Architecture::Aarch64).unwrap();
        return words.iter().enumerate().map(|(i, w)| decoder.decode(&w.to_le_bytes(), at + 4 * i as u64).unwrap()).collect();
    }

    fn table(base: u64, entries: Vec<u8>) -> impl Fn(u64, usize) -> Option<u64> {
        return move |addr: u64, size: usize| {
            let start = addr.checked_sub(base)? as usize;
            let bytes = entries.get(start..start + size)?;
            return Some(bytes.iter().rev().fold(0u64, |v, &b| v << 8 | b as u64));
        };
    }

    #[test]
    fn clang_byte_table() {
        // mov w8, w0 ; cmp w0, #3 ; mov w0, #-1 ; b.hi ; mov w8, w8 ; adr x9, table (0x2000) ; adr x10, 0x1020 ;
        // ldrb w11, [x9, x8] ; add x10, x10, x11, lsl #2 ; br x10
        let code = decode(&[0x2a0003e8, 0x71000c1f, 0x12800000, 0x54000088, 0x2a0803e8, 0x10007f69, 0x1000004a, 0x3868692b, 0x8b0b094a, 0xd61f0140], 0x1000);
        let read = table(0x2000, vec![0, 2, 1, 5]);
        let (window, jump) = code.split_at(code.len() - 1);
        let targets = jump_table(window, &jump[0], &read, 1024).unwrap();

        assert_eq!(targets, vec![Some(0x1020), Some(0x1028), Some(0x1024), Some(0x1034)]);
    }

    #[test]
    fn gcc_halfword_table() {
        // cmp w0, #2 ; b.hi ; adrp x1, 0x2000 ; add x1, x1, #0x10 ; ldrh w1, [x1, w0, uxtw #1] ; adr x2, 0x1020 ;
        // add x1, x2, w1, sxth #2 ; br x1
        let code = decode(&[0x7100081f, 0x54000108, 0xb0000001, 0x91004021, 0x78605821, 0x10000062, 0x8b21a841, 0xd61f0020], 0x1000);
        let read = table(0x2010, vec![0, 0, 3, 0, 0xff, 0xff]);
        let (window, jump) = code.split_at(code.len() - 1);
        let targets = jump_table(window, &jump[0], &read, 1024).unwrap();

        assert_eq!(targets, vec![Some(0x1020), Some(0x102c), Some(0x101c)]);
    }

    #[test]
    fn biased_absolute_table() {
        // sub w8, w0, #100 ; cmp w8, #1 ; b.hs ; adrp x9, 0x2000 ; add x9, x9, #0 ; ldr x9, [x9, x8, lsl #3] ; br x9
        let code = decode(&[0x51019008, 0x7100051f, 0x540000a2, 0xb0000009, 0x91000129, 0xf8687929, 0xd61f0120], 0x1000);
        let read = table(0x2000, [0x1100u64.to_le_bytes(), 0x1200u64.to_le_bytes()].concat());
        let (window, jump) = code.split_at(code.len() - 1);
        let targets = jump_table(window, &jump[0], &read, 1024).unwrap();

        assert_eq!(targets, vec![Some(0x1100)]);
    }
}
