// SPDX-License-Identifier: Apache-2.0
/*
 * Globals that hold one function: every instruction of the program that writes one writes the address of the
 * same function, or none writes it and it holds a function from the start, and its address is never taken. A call through such a global calls that function, with its
 * parameters (static void (*check)(...) = verify; check(a, b) is verify(a, b)).
 */

use super::function::{CallTarget, Function};
use super::insn::{Decoded, Decoder, Flow, Instruction, Operand};
use super::Analysis;

use execdump_core::disasm::Architecture;
use execdump_core::program::Program;

use std::collections::BTreeMap;

/// Instructions looked at before a use of a register for the value written to it
const MAX_LOOKBACK: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Held {
    Nothing,
    Function(u64),
    Unknown,
}

/// Calls through a global holding one function become calls to it
pub fn resolve(program: &Program, decoder: &Decoder, analysis: &mut Analysis) {
    if !matches!(decoder.arch(), Architecture::X86 | Architecture::X86_64) {
        return;
    }

    let decode = |addr: u64| program.bytes_from(addr).and_then(|bytes| decoder.decode(bytes, addr));
    let mask = if program.pointer_size == 4 { u32::MAX as u64 } else { u64::MAX };
    let mut sites: Vec<(u64, usize, u64)> = Vec::new();

    for function in analysis.functions.values() {
        for (index, call) in function.calls.iter().enumerate().filter(|(_, c)| c.target == CallTarget::Indirect && !c.tail) {
            let Some(decoded) = decode(call.addr) else {
                continue;
            };

            let global = match decoded.operand(0) {
                Operand::Mem { .. } => decoded.insn.mem_ref,
                Operand::Reg(reg) => before(function, call.addr).and_then(|insns| loaded(insns, reg, &decode)),
                _ => None,
            };

            if let Some(global) = global {
                sites.push((function.addr, index, global));
            }
        }
    }

    if sites.is_empty() {
        return;
    }

    let mut held: BTreeMap<u64, Held> = sites.iter().map(|&(_, _, global)| (global, Held::Nothing)).collect();

    for function in analysis.functions.values() {
        for block in function.blocks.values() {
            for (position, insn) in block.insns.iter().enumerate() {
                let accessed = [insn.mem_ref, insn.imm_ref].into_iter().flatten().find(|g| held.contains_key(g));

                let Some(global) = accessed else {
                    continue;
                };

                let written = match (insn.imm_ref == Some(global), decode(insn.addr)) {
                    // The address taken: anything may write it
                    (true, _) | (_, None) => Held::Unknown,
                    (false, Some(decoded)) => match written_value(&decoded, &block.insns[..position], &decode) {
                        Some(Some(value)) if analysis.functions.contains_key(&(value & mask)) => Held::Function(value & mask),
                        Some(_) => Held::Unknown,
                        None => continue,
                    },
                };

                let current = held.get_mut(&global).expect("the global is looked for");

                *current = match (*current, written) {
                    (Held::Nothing, w) => w,
                    (Held::Function(a), Held::Function(b)) if a == b => Held::Function(a),
                    _ => Held::Unknown,
                };
            }
        }
    }

    for (function, index, global) in sites {
        // The initial value is the function or nothing
        let initial = program.read_pointer(global).unwrap_or(0) & mask;

        let target = match held.get(&global) {
            Some(&Held::Function(target)) if initial == 0 || initial == target => target,
            // Never written by the code: the value written by the loader (the GOT slot of a local function)
            Some(Held::Nothing) if analysis.functions.contains_key(&initial) => initial,
            _ => continue,
        };

        if let Some(function) = analysis.functions.get_mut(&function) {
            function.calls[index].target = CallTarget::Function(target);
        }
    }
}

/// The instructions of the block of an instruction before it
fn before(function: &Function, addr: u64) -> Option<&[Instruction]> {
    let block = function.block_containing(addr)?;
    let position = block.insns.iter().position(|i| i.addr == addr)?;
    return Some(&block.insns[..position]);
}

/// Instructions that read their first operand without writing it
fn reads_only(decoded: &Decoded) -> bool {
    return matches!(decoded.base_mnemonic(), "cmp" | "test" | "push" | "call" | "jmp" | "bt");
}

/// The global a register was loaded from (mov eax, [g]) before its use
fn loaded(insns: &[Instruction], reg: u16, decode: &impl Fn(u64) -> Option<Decoded>) -> Option<u64> {
    for insn in insns.iter().rev().take(MAX_LOOKBACK) {
        let decoded = decode(insn.addr)?;

        if insn.flow != Flow::Seq {
            return None;
        }

        if decoded.operand(0) == Operand::Reg(reg) && !reads_only(&decoded) {
            return match (decoded.base_mnemonic(), decoded.operand(1)) {
                ("mov", Operand::Mem { .. }) => insn.mem_ref,
                _ => None,
            };
        }
    }

    return None;
}

/// The constant written to a register before its use (mov eax, imm or lea eax, [f])
fn constant(insns: &[Instruction], reg: u16, decode: &impl Fn(u64) -> Option<Decoded>) -> Option<u64> {
    for insn in insns.iter().rev().take(MAX_LOOKBACK) {
        let decoded = decode(insn.addr)?;

        if insn.flow != Flow::Seq {
            return None;
        }

        if decoded.operand(0) == Operand::Reg(reg) && !reads_only(&decoded) {
            return match (decoded.base_mnemonic(), decoded.operand(1)) {
                ("mov", Operand::Imm(value)) => Some(value as u64),
                ("lea", Operand::Mem { .. }) => insn.imm_ref,
                _ => None,
            };
        }
    }

    return None;
}

/// What an instruction accessing a global writes to it: None when it only reads it, Some(None) when the value
/// is not a constant
fn written_value(decoded: &Decoded, before: &[Instruction], decode: &impl Fn(u64) -> Option<Decoded>) -> Option<Option<u64>> {
    let Operand::Mem { .. } = decoded.operand(0) else {
        return match decoded.base_mnemonic() {
            "xchg" | "xadd" | "cmpxchg" => Some(None),
            _ => None,
        };
    };

    if reads_only(decoded) {
        return None;
    }

    return Some(match (decoded.base_mnemonic(), decoded.operand(1)) {
        ("mov", Operand::Imm(value)) => Some(value as u64),
        ("mov", Operand::Reg(reg)) => constant(before, reg, decode),
        _ => None,
    });
}
