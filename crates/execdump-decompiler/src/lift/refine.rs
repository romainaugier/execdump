/*
 * Signature refinement: the parameters and return values of a discovery lifting that are used,
 * with the width they are used with (an int passed in rdi is only used through its low 32 bits)
 */

use super::regs::Abi;
use super::{LType, Loc, Signature, Value, RETURN_SINK_FLOAT, RETURN_SINK_INT};

use inkwell::module::Module;
use inkwell::values::{AnyValue, AnyValueEnum, AsValueRef, BasicValue, BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, IntValue, Operand};

use std::collections::HashMap;

/// Results of the width analyses by value (None while in progress, phi cycles stop there)
type Memo = HashMap<usize, Option<u32>>;

fn key(value: BasicValueEnum) -> usize {
    return value.as_value_ref() as usize;
}

/// Analyses stop at this depth (long chains of arithmetic keep their width anyway)
const MAX_DEPTH: usize = 8;

/// Final signature of a function from its optimized discovery lifting: the parameters that are
/// used (the ABI registers in order up to the last used one), narrowed to the bits they are
/// used with, and the return register defined when returning
pub fn refine(module: &Module, function: FunctionValue, discovery: &Signature, abi: &Abi) -> Signature {
    let mut memo = Memo::new();
    let used: Vec<Option<u32>> = function.get_param_iter().map(|p| demanded(p, 0, &mut memo)).collect();
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
                (LType::Int(full), Some(bits)) => LType::Int(c_width(bits).min(full)),
                (ty, None) => ty,
                (ty, _) => ty,
            };

            Value { loc: p.loc, ty, name: p.name.clone() }
        })
        .collect();

    let int_ret = returned(module, RETURN_SINK_INT, function).map(|bits| Value { loc: Loc::Reg(abi.int_ret), ty: LType::Int(c_width(bits)), name: None });
    let float_ret = returned(module, RETURN_SINK_FLOAT, function).map(|bits| Value { loc: Loc::Reg(abi.float_ret), ty: LType::Float(if bits <= 32 { 32 } else { 64 }), name: None });

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
fn demanded(value: BasicValueEnum, depth: usize, memo: &mut Memo) -> Option<u32> {
    if let Some(&known) = memo.get(&key(value)) {
        return known;
    }

    memo.insert(key(value), None);
    let result = demanded_uncached(value, depth, memo);
    memo.insert(key(value), result);

    return result;
}

fn demanded_uncached(value: BasicValueEnum, depth: usize, memo: &mut Memo) -> Option<u32> {
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
            InstructionOpcode::Store if is_return_sink(user) => continue,
            InstructionOpcode::Trunc => Some(int_width(user.as_any_value_enum().try_into().unwrap_or(value))),
            InstructionOpcode::And => {
                let mask = int_operand(user, 0).filter(|v| v.is_const()).or(int_operand(user, 1).filter(|v| v.is_const()));
                let mask_bits = mask.and_then(constant_bits).unwrap_or(width);
                let result_bits = user_demanded(user, depth, memo);
                result_bits.map(|r| r.min(mask_bits))
            }
            InstructionOpcode::Shl => {
                let shift = int_operand(user, 1).and_then(|v| v.get_zero_extended_constant()).unwrap_or(0) as u32;
                user_demanded(user, depth, memo).map(|r| r.saturating_sub(shift).max(1))
            }
            // The low bits of these results only depend on the low bits of their operands
            InstructionOpcode::Add | InstructionOpcode::Sub | InstructionOpcode::Mul | InstructionOpcode::Or | InstructionOpcode::Xor => user_demanded(user, depth, memo),
            _ => Some(width),
        };

        if let Some(bits) = bits {
            result = Some(result.map_or(bits, |r| r.max(bits)));
        }
    }

    return result;
}

fn user_demanded(user: InstructionValue, depth: usize, memo: &mut Memo) -> Option<u32> {
    let value: BasicValueEnum = user.as_any_value_enum().try_into().ok()?;
    return demanded(value, depth + 1, memo);
}

/// Bits a value can have set (zero extended i32 values have 32)
fn known_width(value: BasicValueEnum, function: FunctionValue, depth: usize, memo: &mut Memo) -> Option<u32> {
    if let Some(&known) = memo.get(&key(value)) {
        return known;
    }

    memo.insert(key(value), None);
    let result = known_width_uncached(value, function, depth, memo);
    memo.insert(key(value), result);

    return result;
}

fn known_width_uncached(value: BasicValueEnum, function: FunctionValue, depth: usize, memo: &mut Memo) -> Option<u32> {
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
        // A parameter returned as it is does not make a return value
        return if function.get_param_iter().any(|p| p == value) { None } else { Some(width) };
    };

    if depth > MAX_DEPTH {
        return Some(width);
    }

    let mut operand_width = |index| operand(instruction, index).and_then(|v| known_width(v, function, depth + 1, memo));

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

/// Width of the values stored to a return sink, None when nothing defined reaches it
fn returned(module: &Module, sink: &str, function: FunctionValue) -> Option<u32> {
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
            BasicValueEnum::IntValue(v) if v.get_type().get_bit_width() == 128 => known_width(value, function, 0, &mut memo).map(|b| b.min(64)),
            _ => known_width(value, function, 0, &mut memo),
        };

        if let Some(bits) = bits {
            widest = Some(widest.map_or(bits, |w| w.max(bits)));
        }
    }

    return widest;
}
