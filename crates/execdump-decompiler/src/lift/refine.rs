/*
 * Signature refinement: the parameters and return values of a discovery lifting that are used,
 * with the width they are used with (an int passed in rdi is only used through its low 32 bits)
 */

use super::regs::Abi;
use super::{LType, Loc, Signature, Value, RETURN_SINK_FLOAT, RETURN_SINK_INT};

use inkwell::module::Module;
use inkwell::values::{AnyValue, AnyValueEnum, AsValueRef, BasicValue, BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, IntValue, Operand};

use std::collections::{HashMap, HashSet};

/// Results of the width analyses by value (None while in progress, phi cycles stop there)
type Memo = HashMap<usize, Option<u32>>;

/// Demanded widths by value and whether it was computed from the parameter
type DemandMemo = HashMap<(usize, bool), Option<u32>>;

fn key(value: BasicValueEnum) -> usize {
    return value.as_value_ref() as usize;
}

/// Analyses stop at this depth (long chains of arithmetic keep their width anyway)
const MAX_DEPTH: usize = 8;

/// Final signature of a function from its optimized discovery lifting: the parameters that are
/// used (the ABI registers in order up to the last used one), narrowed to the bits they are
/// used with, and the return register defined when returning. Registers used as addresses, and
/// a result that is always an address, are pointers.
pub fn refine(module: &Module, function: FunctionValue, discovery: &Signature, abi: &Abi) -> Signature {
    let mut memo = DemandMemo::new();
    let returns = [abi.int_ret, abi.float_ret];

    // A return register received as a parameter reaches the return sink as it was when the function does not
    // write it, the other parameters reaching it are the result (mov rax, rdi)
    let used: Vec<Option<u32>> = function
        .get_param_iter()
        .zip(discovery.params.iter())
        .map(|(p, param)| demanded(p, 0, !matches!(param.loc, Loc::Reg(r) if returns.contains(&r)), &mut memo))
        .collect();
    let mut keep = vec![false; discovery.params.len()];

    // Registers are assigned in order, a used register means the previous ones are parameters too
    for group in [&abi.int_args, &abi.float_args] {
        let positions: Vec<usize> = discovery.params.iter().enumerate().filter(|(_, p)| matches!(p.loc, Loc::Reg(r) if group.contains(&r))).map(|(i, _)| i).collect();

        if let Some(last) = positions.iter().rposition(|&i| used[i].is_some()) {
            for &i in positions[..=last].iter() {
                keep[i] = true;
            }
        }
    }

    for (i, param) in discovery.params.iter().enumerate() {
        if matches!(param.loc, Loc::Stack(_)) && used[i].is_some() {
            keep[i] = true;
        }
    }

    let params = discovery
        .params
        .iter()
        .enumerate()
        .filter(|(i, _)| keep[*i])
        .map(|(i, p)| {
            let ty = match (p.ty, used[i]) {
                // Vector registers used as scalars are floats
                (LType::Int(128), Some(bits)) if bits <= 32 => LType::Float(32),
                (LType::Int(128), _) => LType::Float(64),
                (LType::Int(full), Some(bits)) if bits >= full && used_as_address(function.get_nth_param(i as u32).unwrap(), 0, &mut HashSet::new()) => LType::Ptr,
                (LType::Int(full), Some(bits)) => LType::Int(c_width(bits).min(full)),
                (ty, None) => ty,
                (ty, _) => ty,
            };

            Value { loc: p.loc, ty, name: p.name.clone() }
        })
        .collect();

    let kept: Vec<BasicValueEnum> = function
        .get_param_iter()
        .zip(discovery.params.iter())
        .filter(|(_, param)| matches!(param.loc, Loc::Reg(r) if returns.contains(&r)))
        .map(|(p, _)| p)
        .collect();

    let int_ret = returned(module, RETURN_SINK_INT, &kept).map(|bits| {
        let ty = if returns_address(module, RETURN_SINK_INT) { LType::Ptr } else { LType::Int(c_width(bits)) };
        Value { loc: Loc::Reg(abi.int_ret), ty, name: None }
    });
    let float_ret = returned(module, RETURN_SINK_FLOAT, &kept).map(|bits| Value { loc: Loc::Reg(abi.float_ret), ty: LType::Float(if bits <= 32 { 32 } else { 64 }), name: None });

    return Signature { params, ret: int_ret.or(float_ret), ..discovery.clone() };
}

/// Integer widths of C (char and short values are promoted to int)
fn c_width(bits: u32) -> u32 {
    return if bits <= 32 { 32 } else { 64 };
}

fn instruction(user: AnyValueEnum) -> Option<InstructionValue> {
    return match user {
        AnyValueEnum::InstructionValue(instruction) => Some(instruction),
        other => BasicValueEnum::try_from(other).ok()?.as_instruction_value(),
    };
}

fn operand<'ctx>(instruction: InstructionValue<'ctx>, index: u32) -> Option<BasicValueEnum<'ctx>> {
    return match instruction.get_operand(index)? {
        Operand::Value(value) => Some(value),
        Operand::Block(_) => None,
    };
}

fn int_operand<'ctx>(instruction: InstructionValue<'ctx>, index: u32) -> Option<IntValue<'ctx>> {
    return match operand(instruction, index)? {
        BasicValueEnum::IntValue(value) => Some(value),
        _ => None,
    };
}

fn int_width(value: BasicValueEnum) -> u32 {
    return match value {
        BasicValueEnum::IntValue(v) => v.get_type().get_bit_width(),
        BasicValueEnum::FloatValue(v) => v.get_type().get_bit_width(),
        _ => 64,
    };
}

/// Number of significant bits of a constant (as an unsigned value)
fn constant_bits(value: IntValue) -> Option<u32> {
    let constant = value.get_zero_extended_constant()?;
    return Some(64 - constant.leading_zeros());
}

fn is_return_sink(instruction: InstructionValue) -> bool {
    let Some(BasicValueEnum::PointerValue(pointer)) = operand(instruction, 1) else {
        return false;
    };

    let name = pointer.get_name().to_string_lossy().to_string();

    return name == RETURN_SINK_INT || name == RETURN_SINK_FLOAT;
}

/// Low bits of a value its users depend on, None when nothing uses it
/// Bits of a value its users need. A value stored to a return sink is the result once computed from the
/// parameter.
fn demanded(value: BasicValueEnum, depth: usize, computed: bool, memo: &mut DemandMemo) -> Option<u32> {
    if let Some(&known) = memo.get(&(key(value), computed)) {
        return known;
    }

    memo.insert((key(value), computed), None);
    let result = demanded_uncached(value, depth, computed, memo);
    memo.insert((key(value), computed), result);

    return result;
}

fn demanded_uncached(value: BasicValueEnum, depth: usize, computed: bool, memo: &mut DemandMemo) -> Option<u32> {
    let width = int_width(value);

    if depth > MAX_DEPTH {
        return Some(width);
    }

    let mut result: Option<u32> = None;
    let mut next = value.get_first_use();

    while let Some(current) = next {
        next = current.get_next_use();

        let Some(user) = instruction(current.get_user()) else {
            result = Some(width);
            continue;
        };

        let bits = match user.get_opcode() {
            InstructionOpcode::Store if is_return_sink(user) && !computed => continue,
            InstructionOpcode::Trunc => Some(int_width(user.as_any_value_enum().try_into().unwrap_or(value))),
            InstructionOpcode::And => {
                let mask = int_operand(user, 0).filter(|v| v.is_const()).or(int_operand(user, 1).filter(|v| v.is_const()));
                let mask_bits = mask.and_then(constant_bits).unwrap_or(width);
                let result_bits = user_demanded(user, depth, true, memo);
                result_bits.map(|r| r.min(mask_bits))
            }
            InstructionOpcode::Shl => {
                let shift = int_operand(user, 1).and_then(|v| v.get_zero_extended_constant()).unwrap_or(0) as u32;
                user_demanded(user, depth, true, memo).map(|r| r.saturating_sub(shift).max(1))
            }
            // The low bits of these results only depend on the low bits of their operands
            InstructionOpcode::Add | InstructionOpcode::Sub | InstructionOpcode::Mul | InstructionOpcode::Or | InstructionOpcode::Xor => user_demanded(user, depth, true, memo),
            // A value joined with others is used where the join is (a register left as it was on some paths
            // only reaching the return sinks is not a parameter)
            InstructionOpcode::Phi => user_demanded(user, depth, computed, memo),
            InstructionOpcode::Select if operand(user, 0) != Some(value) => user_demanded(user, depth, computed, memo),
            _ => Some(width),
        };

        if let Some(bits) = bits {
            result = Some(result.map_or(bits, |r| r.max(bits)));
        }
    }

    return result;
}

fn user_demanded(user: InstructionValue, depth: usize, computed: bool, memo: &mut DemandMemo) -> Option<u32> {
    let value: BasicValueEnum = user.as_any_value_enum().try_into().ok()?;
    return demanded(value, depth + 1, computed, memo);
}

/// Bits a value can have set (zero extended i32 values have 32)
fn known_width(value: BasicValueEnum, kept: &[BasicValueEnum], depth: usize, memo: &mut Memo) -> Option<u32> {
    if let Some(&known) = memo.get(&key(value)) {
        return known;
    }

    memo.insert(key(value), None);
    let result = known_width_uncached(value, kept, depth, memo);
    memo.insert(key(value), result);

    return result;
}

fn known_width_uncached(value: BasicValueEnum, kept: &[BasicValueEnum], depth: usize, memo: &mut Memo) -> Option<u32> {
    let BasicValueEnum::IntValue(int) = value else {
        return Some(int_width(value));
    };

    if int.is_undef() || int.is_poison() {
        return None;
    }

    if int.is_const() {
        return constant_bits(int).or(Some(int.get_type().get_bit_width()));
    }

    let width = int.get_type().get_bit_width();

    let Some(instruction) = int.as_instruction() else {
        // A return register received as a parameter and left as it is does not make a return value
        return if kept.contains(&value) { None } else { Some(width) };
    };

    if depth > MAX_DEPTH {
        return Some(width);
    }

    let mut operand_width = |index| operand(instruction, index).and_then(|v| known_width(v, kept, depth + 1, memo));

    return match instruction.get_opcode() {
        InstructionOpcode::ZExt => operand(instruction, 0).map(int_width),
        InstructionOpcode::And => {
            let mask = [0, 1].iter().filter_map(|&i| int_operand(instruction, i)).filter(|v| v.is_const()).find_map(constant_bits);
            Some(mask.unwrap_or(width).min(operand_width(0).unwrap_or(width)))
        }
        InstructionOpcode::Phi | InstructionOpcode::Select => {
            let first = if instruction.get_opcode() == InstructionOpcode::Select { 1 } else { 0 };
            let widths: Vec<u32> = (first..instruction.get_num_operands()).filter_map(&mut operand_width).collect();
            widths.into_iter().max()
        }
        _ => Some(width),
    };
}

/// Whether a value is used as an address: converted to a pointer, maybe after adding a constant to it, or
/// joined with others that are
fn used_as_address(value: BasicValueEnum, depth: usize, seen: &mut HashSet<usize>) -> bool {
    if depth > MAX_DEPTH || !seen.insert(key(value)) {
        return false;
    }

    let mut next = value.get_first_use();

    while let Some(current) = next {
        next = current.get_next_use();

        let Some(user) = instruction(current.get_user()) else {
            continue;
        };

        let follow = match user.get_opcode() {
            InstructionOpcode::IntToPtr => return true,
            InstructionOpcode::Add | InstructionOpcode::Sub => [0, 1].iter().any(|&i| int_operand(user, i).is_some_and(|v| v.is_const())),
            InstructionOpcode::Phi => true,
            InstructionOpcode::Select => operand(user, 0) != Some(value),
            _ => false,
        };

        if follow {
            if let Ok(result) = BasicValueEnum::try_from(user.as_any_value_enum()) {
                if used_as_address(result, depth + 1, seen) {
                    return true;
                }
            }
        }
    }

    return false;
}

/// Whether every value stored to a return sink is an address (a pointer converted to an integer, a
/// parameter used as an address, a constant offset from one of them, or a join of addresses and null),
/// one at least
fn returns_address(module: &Module, sink: &str) -> bool {
    /// Some(true) for an address, Some(false) for null (and a join already being looked at), None otherwise
    fn address(value: BasicValueEnum, depth: usize, memo: &mut HashMap<usize, Option<bool>>) -> Option<bool> {
        if let BasicValueEnum::IntValue(int) = value {
            if int.is_const() {
                return (int.get_zero_extended_constant() == Some(0)).then_some(false);
            }
        }

        if depth > MAX_DEPTH {
            return Some(false);
        }

        if let Some(&known) = memo.get(&key(value)) {
            return known;
        }

        memo.insert(key(value), Some(false));

        let result = match value.as_instruction_value() {
            None => {
                let parameter = matches!(value.as_any_value_enum(), AnyValueEnum::IntValue(int) if !int.is_const());
                (parameter && used_as_address(value, 0, &mut HashSet::new())).then_some(true)
            }
            Some(instruction) => match instruction.get_opcode() {
                InstructionOpcode::PtrToInt => Some(true),
                InstructionOpcode::Add | InstructionOpcode::Sub => match (int_operand(instruction, 0), int_operand(instruction, 1)) {
                    (Some(x), Some(c)) if c.is_const() && !x.is_const() => address(x.into(), depth + 1, memo),
                    (Some(c), Some(x)) if c.is_const() && !x.is_const() && instruction.get_opcode() == InstructionOpcode::Add => address(x.into(), depth + 1, memo),
                    _ => None,
                },
                InstructionOpcode::Phi | InstructionOpcode::Select => {
                    let first = if instruction.get_opcode() == InstructionOpcode::Select { 1 } else { 0 };
                    let mut any = Some(false);

                    for i in first..instruction.get_num_operands() {
                        any = match (any, operand(instruction, i).and_then(|o| address(o, depth + 1, memo))) {
                            (Some(a), Some(b)) => Some(a || b),
                            _ => None,
                        };
                    }

                    any
                }
                _ => None,
            },
        };

        memo.insert(key(value), result);
        return result;
    }

    let Some(global) = module.get_global(sink) else {
        return false;
    };

    let mut any = false;
    let mut next = global.as_pointer_value().get_first_use();
    let mut memo = HashMap::new();

    while let Some(current) = next {
        next = current.get_next_use();

        let Some(value) = instruction(current.get_user()).and_then(|store| operand(store, 0)) else {
            continue;
        };

        match address(value, 0, &mut memo) {
            Some(found) => any |= found,
            None => return false,
        }
    }

    return any;
}

/// Width of the values stored to a return sink, None when nothing defined reaches it
fn returned(module: &Module, sink: &str, kept: &[BasicValueEnum]) -> Option<u32> {
    let global = module.get_global(sink)?;
    let mut widest: Option<u32> = None;
    let mut memo = Memo::new();
    let mut next = global.as_pointer_value().get_first_use();

    while let Some(current) = next {
        next = current.get_next_use();

        let Some(value) = instruction(current.get_user()).and_then(|store| operand(store, 0)) else {
            continue;
        };

        // Vector registers: the scalar is in the low bits
        let bits = match value {
            BasicValueEnum::IntValue(v) if v.get_type().get_bit_width() == 128 => known_width(value, kept, 0, &mut memo).map(|b| b.min(64)),
            _ => known_width(value, kept, 0, &mut memo),
        };

        if let Some(bits) = bits {
            widest = Some(widest.map_or(bits, |w| w.max(bits)));
        }
    }

    return widest;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::discovery_signature;
    use crate::lift::regs::RegisterFile;

    use execdump_core::disasm::Architecture;
    use inkwell::context::Context;
    use inkwell::memory_buffer::MemoryBuffer;

    use std::collections::BTreeSet;

    const ARGS: &str = "i64 %0, i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i128 %6, i128 %7, i128 %8, i128 %9, i128 %10, i128 %11, i128 %12, i128 %13";

    /// Signature refined from the optimized discovery body of a function
    fn refined(body: &str) -> Signature {
        let ir = format!("@__return_int = external global i64\n@__return_float = external global i128\ndefine void @f({}) {{\n{}\n  ret void\n}}\n", ARGS, body);
        let cx = Context::create();
        let module = cx.create_module_from_ir(MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "f")).unwrap();
        let regs = RegisterFile::new(Architecture::X86_64);
        let abi = Abi::new(&regs, false);
        let discovery = discovery_signature("f", &abi, &regs, &BTreeSet::new());

        return refine(&module, module.get_function("f").unwrap(), &discovery, &abi);
    }

    #[test]
    fn parameters_making_the_result() {
        let regs = RegisterFile::new(Architecture::X86_64);
        let reg = |sig: &Signature, i: usize| match sig.params[i].loc {
            Loc::Reg(r) => regs.regs[r].name,
            Loc::Stack(_) => "stack",
        };

        // return p + 1: the parameter only reaches the result
        let sig = refined("  %15 = add i64 %0, 1\n  store i64 %15, ptr @__return_int\n  store i128 %6, ptr @__return_float");
        assert_eq!((sig.params.len(), reg(&sig, 0)), (1, "rdi"));
        assert!(matches!(sig.ret, Some(Value { loc: Loc::Reg(r), .. }) if r == abi_int_ret(&regs)));

        // mov rax, rsi: returned as it is, after an unused first parameter
        let sig = refined("  store i64 %1, ptr @__return_int\n  store i128 %6, ptr @__return_float");
        assert_eq!(sig.params.len(), 2);
        assert!(sig.ret.is_some());

        // xmm0 left as it was is neither a parameter nor a result
        let sig = refined("  store i128 %6, ptr @__return_float");
        assert!(sig.params.is_empty() && sig.ret.is_none());
    }

    fn abi_int_ret(regs: &RegisterFile) -> usize {
        return Abi::new(regs, false).int_ret;
    }
}
