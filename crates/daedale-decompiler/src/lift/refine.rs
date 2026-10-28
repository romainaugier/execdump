// SPDX-License-Identifier: Apache-2.0
/*
 * Signature refinement: the parameters and return values of a discovery lifting that are used,
 * with the width they are used with (an int passed in rdi is only used through its low 32 bits)
 */

use super::regs::Abi;
use super::{LType, Loc, Signature, Value, RETURN_SINK_EXTRA, RETURN_SINK_LOW, RETURN_SINK_FLOAT, RETURN_SINK_HIGH, RETURN_SINK_INT, RETURN_SINK_REGS, RETURN_SINK_STACK};

use inkwell::module::Module;
use inkwell::values::{AnyValue, AnyValueEnum, AsValueRef, BasicValue, BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, IntValue, Operand};

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

/// Results of the width analyses by value (None while in progress, phi cycles stop there)
type Memo = HashMap<usize, Option<u32>>;

/// Demanded widths by value and the return sink of the parameter it is (while it is not computed with)
type DemandMemo = HashMap<(usize, Option<&'static str>), Option<u32>>;

fn key(value: BasicValueEnum) -> usize {
    return value.as_value_ref() as usize;
}

/// Analyses stop at this depth (long chains of arithmetic keep their width anyway)
const MAX_DEPTH: usize = 8;

/// Final signature of a function from its optimized discovery lifting: the parameters that are
/// used (the ABI registers in order up to the last used one, the other registers that are used),
/// narrowed to the bits they are used with, and the return register defined when returning (the
/// other registers changed when returning are candidate results in outs). Registers used as
/// addresses, and a result that is always an address, are pointers.
pub fn refine(module: &Module, function: FunctionValue, discovery: &Signature, abi: &Abi, high_read: &dyn Fn() -> bool) -> Signature {
    let lows = match function.count_params() as usize > discovery.params.len() {
        true => super::low_params(discovery),
        false => Vec::new(),
    };

    let mut memo = DemandMemo::default();
    let sinks = [(RETURN_SINK_INT, Some(abi.int_ret)), (RETURN_SINK_FLOAT, Some(abi.float_ret)), (RETURN_SINK_HIGH, abi.int_ret_high)];
    let own = |loc: Loc| -> Option<&'static str> {
        let Loc::Reg(reg) = loc else {
            return None;
        };

        if let Some((sink, _)) = sinks.iter().find(|(_, r)| *r == Some(reg)) {
            return Some(*sink);
        }

        if let Some(position) = abi.extra_results.iter().position(|&r| r == reg) {
            return RETURN_SINK_EXTRA.get(position).copied();
        }

        let position = abi.int_args.iter().position(|&r| r == reg).filter(|&p| abi.register_results && p > 0)?;
        return RETURN_SINK_REGS.get(position).copied();
    };

    // A return register received as a parameter reaches its return sink as it was when the function does not
    // write it, the other parameters reaching a sink are the result (mov rax, rdi)
    let mut used: Vec<Option<u32>> = function.get_param_iter().zip(discovery.params.iter()).map(|(p, param)| demanded(p, 0, own(param.loc), &mut memo)).collect();

    // The low halves received apart (see low_params) are used as their register
    for (position, &index) in lows.iter().enumerate() {
        if let Some(bits) = function.get_nth_param((discovery.params.len() + position) as u32).and_then(|low| demanded(low, 0, None, &mut memo)) {
            used[index] = Some(used[index].map_or(bits, |b| b.max(bits)));
        }
    }

    let mut keep = vec![false; discovery.params.len()];

    // Registers are assigned in order, a used register means the previous ones are parameters too
    for group in [&abi.int_args, &abi.float_args].into_iter().filter(|_| abi.ordered_args) {
        let positions: Vec<usize> = discovery.params.iter().enumerate().filter(|(_, p)| matches!(p.loc, Loc::Reg(r) if group.contains(&r))).map(|(i, _)| i).collect();

        if let Some(last) = positions.iter().rposition(|&i| used[i].is_some()) {
            for &i in positions[..=last].iter() {
                keep[i] = true;
            }
        }
    }

    // The other registers are in no order
    let extra = |loc: Loc| matches!(loc, Loc::Reg(r) if abi.extra_params.contains(&r) && !abi.int_args.contains(&r));

    for (i, param) in discovery.params.iter().enumerate() {
        if (matches!(param.loc, Loc::Stack(_)) || !abi.ordered_args || extra(param.loc)) && used[i].is_some() {
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
                (LType::Int(full), Some(bits)) if bits >= full && used_as_address(function.get_nth_param(i as u32).unwrap(), 0, &mut HashSet::default()) => LType::Ptr,
                (LType::Int(full), Some(bits)) => LType::Int(c_width(bits).min(full)),
                (ty, None) => ty,
                (ty, _) => ty,
            };

            Value { loc: p.loc, ty, name: p.name.clone() }
        })
        .collect();

    let kept = |sink: &str| -> Vec<BasicValueEnum> {
        return function.get_param_iter().zip(discovery.params.iter()).filter(|(_, param)| own(param.loc) == Some(sink)).map(|(p, _)| p).collect();
    };

    let int_ret = returned(module, RETURN_SINK_INT, &kept(RETURN_SINK_INT)).map(|bits| {
        let ty = if returns_address(module, RETURN_SINK_INT) { LType::Ptr } else { LType::Int(c_width(bits)) };
        Value { loc: Loc::Reg(abi.int_ret), ty, name: None }
    });
    let float_ret = returned(module, RETURN_SINK_FLOAT, &kept(RETURN_SINK_FLOAT)).map(|bits| Value { loc: Loc::Reg(abi.float_ret), ty: LType::Float(if bits <= 32 { 32 } else { 64 }), name: None });

    // Results twice as wide as a register (rdx:rax), when a caller reads the high half
    let high = abi.int_ret_high.is_some() && returned(module, RETURN_SINK_HIGH, &kept(RETURN_SINK_HIGH)).is_some();
    let register_bits = module.get_global(RETURN_SINK_INT).map(|g| g.get_value_type().into_int_type().get_bit_width());

    let int_ret = match (int_ret, register_bits) {
        (Some(low), Some(bits)) if high && high_read() => Some(Value { ty: LType::Int(2 * bits), ..low }),
        (low, _) => low,
    };

    // The results after the first one in the next argument registers, as long as they are set, up to the last one
    // computed (a parameter returned as it is in its register is a result before another one: growslice returns its
    // length argument then the new capacity)
    if abi.register_results && int_ret.is_some() {
        let mut outs = Vec::new();
        let mut computed = 0;

        for (position, &reg) in abi.int_args.iter().enumerate().skip(1).take(RETURN_SINK_REGS.len() - 1) {
            let sink = RETURN_SINK_REGS[position];

            let Some(bits) = returned(module, sink, &[]) else {
                break;
            };

            let ty = match returned(module, sink, &kept(sink)) {
                Some(_) if returns_address(module, sink) => LType::Ptr,
                Some(_) => LType::Int(c_width(bits)),
                None => LType::Int(regs_bits(&discovery.params, reg).unwrap_or(64)),
            };

            outs.push(Value { loc: Loc::Reg(reg), ty, name: None });

            if returned(module, sink, &kept(sink)).is_some() {
                computed = outs.len();
            }
        }

        outs.truncate(computed);
        return Signature { params, ret: int_ret, outs, ..discovery.clone() };
    }

    if abi.stack_results {
        let mut results = stack_results(module, discovery, abi.slot_size as u32 * 8).into_iter();
        return Signature { params, ret: results.next(), outs: results.collect(), ..discovery.clone() };
    }

    let extra_results = abi
        .extra_results
        .iter()
        .zip(RETURN_SINK_EXTRA)
        .filter_map(|(&reg, sink)| {
            let bits = returned(module, sink, &kept(sink))?;
            let ty = if returns_address(module, sink) { LType::Ptr } else { LType::Int(c_width(bits)) };
            Some(Value { loc: Loc::Reg(reg), ty, name: None })
        })
        .collect();

    return Signature { params, ret: int_ret.or(float_ret), outs: extra_results, ..discovery.clone() };
}

/// The results in stack slots a value reaches on return, the lowest one first: the ones always holding an address
/// of the width of a pointer are pointers, the others keep the width they are written with (two results may share
/// a slot: (bool, bool))
fn stack_results(module: &Module, discovery: &Signature, pointer_bits: u32) -> Vec<Value> {
    return discovery
        .outs
        .iter()
        .filter_map(|out| {
            let Loc::Stack(offset) = out.loc else {
                return None;
            };

            let sink = format!("{}{}", RETURN_SINK_STACK, offset);
            returned(module, &sink, &[])?;

            let ty = match out.ty {
                LType::Int(bits) if bits == pointer_bits && returns_address(module, &sink) => LType::Ptr,
                ty => ty,
            };

            Some(Value { loc: out.loc, ty, name: None })
        })
        .collect();
}

/// Width of the parameter of a register
fn regs_bits(params: &[Value], reg: usize) -> Option<u32> {
    return params.iter().find(|p| p.loc == Loc::Reg(reg)).and_then(|p| match p.ty {
        LType::Int(bits) => Some(bits),
        _ => None,
    });
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

/// The return sink an instruction stores to
fn return_sink(instruction: InstructionValue) -> Option<&'static str> {
    if instruction.get_opcode() != InstructionOpcode::Store {
        return None;
    }

    let Some(BasicValueEnum::PointerValue(pointer)) = operand(instruction, 1) else {
        return None;
    };

    let name = pointer.get_name().to_string_lossy();

    return [RETURN_SINK_INT, RETURN_SINK_FLOAT, RETURN_SINK_HIGH].into_iter().chain(RETURN_SINK_REGS).chain(RETURN_SINK_EXTRA).find(|sink| *sink == name);
}

/// A store to a low sink
fn low_sink(instruction: InstructionValue) -> bool {
    if instruction.get_opcode() != InstructionOpcode::Store {
        return false;
    }

    let Some(BasicValueEnum::PointerValue(pointer)) = operand(instruction, 1) else {
        return false;
    };

    return pointer.get_name().to_string_lossy().ends_with(RETURN_SINK_LOW);
}

/// A value only stored to low sinks (through the phis merging the returns)
fn is_low_sink_only(value: InstructionValue) -> bool {
    return low_sinks_only(value, &mut HashSet::default());
}

fn low_sinks_only(value: InstructionValue, visited: &mut HashSet<usize>) -> bool {
    if !visited.insert(value.as_value_ref() as usize) {
        return true;
    }

    let mut next = value.get_first_use();
    let mut any = false;

    while let Some(current) = next {
        next = current.get_next_use();

        let only = match instruction(current.get_user()) {
            Some(user) if user.get_opcode() == InstructionOpcode::Phi => low_sinks_only(user, visited),
            Some(user) => low_sink(user),
            None => false,
        };

        if !only {
            return false;
        }

        any = true;
    }

    return any;
}

/// Bits of a value its users need, None when nothing uses it. A value stored to a return sink is a result,
/// except the parameter of its register left as it is (own is its sink until it is computed with).
fn demanded(value: BasicValueEnum, depth: usize, own: Option<&'static str>, memo: &mut DemandMemo) -> Option<u32> {
    if let Some(&known) = memo.get(&(key(value), own)) {
        return known;
    }

    memo.insert((key(value), own), None);
    let result = demanded_uncached(value, depth, own, memo);
    memo.insert((key(value), own), result);

    return result;
}

fn demanded_uncached(value: BasicValueEnum, depth: usize, own: Option<&'static str>, memo: &mut DemandMemo) -> Option<u32> {
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
            InstructionOpcode::Store if own.is_some() && return_sink(user) == own => continue,
            // The low sinks are for the final function (see RETURN_SINK_LOW)
            InstructionOpcode::Store if low_sink(user) => continue,
            InstructionOpcode::Trunc if is_low_sink_only(user) => continue,
            InstructionOpcode::Trunc => Some(int_width(user.as_any_value_enum().try_into().unwrap_or(value))),
            // The bits of a register kept when its low bits are written (mov al, 1: eax & ~0xff | 1) are not used
            InstructionOpcode::And => {
                let mask = int_operand(user, 0).filter(|v| v.is_const()).or(int_operand(user, 1).filter(|v| v.is_const()));

                match (user_demanded(user, depth, mask.and(own), memo), mask.and_then(|m| m.get_zero_extended_constant())) {
                    // The low bits of the result that are used, of the ones the mask keeps (none: setne bl only uses bl)
                    (Some(result), Some(mask)) => {
                        let kept = mask & if result >= 64 { u64::MAX } else { (1u64 << result) - 1 };
                        (kept != 0).then(|| 64 - kept.leading_zeros())
                    }
                    (result, _) => result,
                }
            }
            InstructionOpcode::Or => user_demanded(user, depth, own, memo),
            InstructionOpcode::Shl => {
                let shift = int_operand(user, 1).and_then(|v| v.get_zero_extended_constant()).unwrap_or(0) as u32;
                user_demanded(user, depth, None, memo).map(|r| r.saturating_sub(shift).max(1))
            }
            // The low bits of these results only depend on the low bits of their operands
            InstructionOpcode::Add | InstructionOpcode::Sub | InstructionOpcode::Mul | InstructionOpcode::Xor => user_demanded(user, depth, None, memo),
            // A value joined with others is used where the join is (a register left as it was on some paths
            // only reaching the return sinks is not a parameter)
            InstructionOpcode::Phi => user_demanded(user, depth, own, memo),
            InstructionOpcode::Select if operand(user, 0) != Some(value) => user_demanded(user, depth, own, memo),
            _ => Some(width),
        };

        if let Some(bits) = bits {
            result = Some(result.map_or(bits, |r| r.max(bits)));
        }
    }

    return result;
}

fn user_demanded(user: InstructionValue, depth: usize, own: Option<&'static str>, memo: &mut DemandMemo) -> Option<u32> {
    let value: BasicValueEnum = user.as_any_value_enum().try_into().ok()?;
    return demanded(value, depth + 1, own, memo);
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
            // The address of a global (ptrtoint of it, folded to a constant)
            let global = unsafe {
                use inkwell::llvm_sys::core::{LLVMGetConstOpcode, LLVMIsAConstantExpr};
                !LLVMIsAConstantExpr(int.as_value_ref()).is_null() && LLVMGetConstOpcode(int.as_value_ref()) == inkwell::llvm_sys::LLVMOpcode::LLVMPtrToInt
            };

            if global {
                return Some(true);
            }

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
                (parameter && used_as_address(value, 0, &mut HashSet::default())).then_some(true)
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
    let mut memo = HashMap::default();

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
    let mut memo = Memo::default();
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

    use daedale_core::disasm::Architecture;
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
        let discovery = discovery_signature("f", &abi, &regs, &BTreeSet::new(), &std::collections::BTreeMap::new());

        return refine(&module, module.get_function("f").unwrap(), &discovery, &abi, &|| true);
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

    #[test]
    fn several_register_results() {
        // Go: return p + 1, 7 in rax and rbx, rcx left as it was is not a third result
        let regs = RegisterFile::new(Architecture::X86_64);
        let abi = crate::lang::go::abi::register_abi(&regs).unwrap();
        let discovery = discovery_signature("f", &abi, &regs, &BTreeSet::new(), &std::collections::BTreeMap::new());
        let args: Vec<String> = discovery.params.iter().enumerate().map(|(i, p)| format!("{} %{}", if p.ty == LType::Int(128) { "i128" } else { "i64" }, i)).collect();
        let body = "  %sum = add i64 %0, 1\n  store i64 %sum, ptr @__return_int\n  store i64 7, ptr @__return_reg_1\n  store i64 %2, ptr @__return_reg_2";
        let ir = format!(
            "@__return_int = external global i64\n@__return_reg_1 = external global i64\n@__return_reg_2 = external global i64\ndefine void @f({}) {{\n{}\n  ret void\n}}\n",
            args.join(", "),
            body
        );

        let cx = Context::create();
        let module = cx.create_module_from_ir(MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "f")).unwrap();
        let sig = refine(&module, module.get_function("f").unwrap(), &discovery, &abi, &|| false);

        assert!(matches!(sig.ret, Some(Value { loc: Loc::Reg(r), .. }) if r == regs.reg("rax")));
        assert_eq!(sig.outs.iter().map(|o| o.loc).collect::<Vec<_>>(), [Loc::Reg(regs.reg("rbx"))]);
        assert_eq!(sig.params.len(), 1);
    }

    fn abi_int_ret(regs: &RegisterFile) -> usize {
        return Abi::new(regs, false).int_ret;
    }
}
