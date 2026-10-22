/*
 * The final function from the discovery of its signature: the function lifted with every register a value can be
 * passed in as a parameter and its return registers stored to sinks, once optimized, becomes the function with the
 * signature found instead of being lifted again. Its parameters are the ones of the signature converted to the
 * registers and the stack slots as the lift converts them (the registers that are not parameters are undefined, as
 * the lift leaves them), the values that reach the sinks are its results. The passes that run again on it have
 * little left to do.
 */

use super::{function_type, high_half, int_type, Env, LType, Loc, Signature, Value, RETURN_SINK, RETURN_SINK_EXTRA, RETURN_SINK_FLOAT, RETURN_SINK_HIGH, RETURN_SINK_INT, RETURN_SINK_LOW, RETURN_SINK_LOW_BITS, RETURN_SINK_REGS, RETURN_SINK_STACK};

use anyhow::{Context as _, Result};

use inkwell::basic_block::BasicBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::llvm_sys::core::{LLVMAppendExistingBasicBlock, LLVMRemoveBasicBlockFromParent};
use inkwell::llvm_sys::debuginfo::{LLVMInstructionGetDebugLoc, LLVMInstructionSetDebugLoc, LLVMSetSubprogram};
use inkwell::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMValueRef};
use inkwell::module::Module;
use inkwell::types::BasicTypeEnum;
use inkwell::values::{AsValueRef, BasicValue, BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, IntValue, PointerValue};

use rustc_hash::FxHashMap as HashMap;

/// The function of the signature made of its optimized discovery, None when the discovery cannot be (the function
/// uses itself, a result it returns was not stored to a sink)
pub fn final_function<'ctx>(cx: &'ctx Context, module: &Module<'ctx>, env: &Env, discovery: FunctionValue<'ctx>, discovered: &Signature, sig: &Signature) -> Result<Option<FunctionValue<'ctx>>> {
    if discovery.as_global_value().as_pointer_value().get_first_use().is_some() {
        return Ok(None);
    }

    let pointer_bits = env.program.pointer_size as u32 * 8;
    let returns: Vec<InstructionValue> = discovery.get_basic_blocks().iter().filter_map(|b| b.get_terminator()).filter(|t| t.get_opcode() == InstructionOpcode::Return).collect();

    let results: Vec<&Value> = sig.ret.iter().chain(sig.outs.iter()).collect();

    // Every result has a sink of its width at least (the lift reads the narrower ones from its low bits)
    let stored = |name: &str| module.get_global(name).map(|g| g.get_value_type());
    let fits = |result: &Value| match (result_sink(env, result), high_half(env.abi, env.regs, result)) {
        (_, Some(high)) => [sink(env, env.abi.int_ret), sink(env, high)].iter().all(|s| s.as_deref().and_then(stored).is_some()),
        (Some(name), None) => stored(&name).is_some_and(|ty| ty.is_int_type() && ty.into_int_type().get_bit_width() >= width(result.ty, pointer_bits)),
        (None, None) => false,
    };

    if !returns.is_empty() && !results.iter().all(|r| fits(r)) {
        return Ok(None);
    }

    let name = sig.name.clone();
    discovery.as_global_value().set_name(&format!("{}.discovery", name));

    let function = module.add_function(&name, function_type(cx, sig, false, 0), None);
    let builder = cx.create_builder();

    unsafe {
        if let Some(subprogram) = discovery.get_subprogram() {
            LLVMSetSubprogram(discovery.as_value_ref(), std::ptr::null_mut());
            function.set_subprogram(subprogram);
        }

        for block in discovery.get_basic_blocks() {
            LLVMRemoveBasicBlockFromParent(block.as_mut_ptr());
            LLVMAppendExistingBasicBlock(function.as_value_ref(), block.as_mut_ptr());
        }
    }

    let entry = function.get_first_basic_block().context("the discovery has no block")?;
    let first = entry.get_first_instruction().context("the discovery has an empty block")?;
    builder.position_before(&first);
    locate(&builder, first);

    // The sinks become variables of the function, read where it returns
    let mut variables: HashMap<String, (PointerValue<'ctx>, BasicTypeEnum<'ctx>)> = HashMap::default();

    for global in module.get_globals().filter(|g| g.get_name().to_str().is_ok_and(|n| n.starts_with(RETURN_SINK))).collect::<Vec<_>>() {
        let ty = global.get_value_type();
        let Ok(ty) = BasicTypeEnum::try_from(ty) else {
            continue;
        };

        let variable = builder.build_alloca(ty, "")?;
        global.as_pointer_value().replace_all_uses_with(variable);
        variables.insert(global.get_name().to_string_lossy().to_string(), (variable, ty));
        unsafe { global.delete() };
    }

    for (index, param) in sig.params.iter().enumerate() {
        if let (Some(name), Some(value)) = (&param.name, function.get_nth_param(index as u32)) {
            value.set_name(name);
        }
    }

    // The low halves of the registers received apart (see low_params) are the low halves of the parameters
    let lows = super::low_params(discovered);
    let params: Vec<BasicValueEnum> = discovery.get_param_iter().collect();

    for (position, &index) in lows.iter().enumerate() {
        let Some(&old) = params.get(discovered.params.len() + position) else {
            break;
        };

        let replacement = match sig.params.iter().position(|p| p.loc == discovered.params[index].loc) {
            Some(index) => {
                let new = function.get_nth_param(index as u32).context("missing parameter")?;
                let int = to_int(cx, &builder, new, pointer_bits)?;
                resize(cx, &builder, int, 32)?
            }
            None => cx.i32_type().get_undef(),
        };

        old.into_int_value().replace_all_uses_with(replacement);
    }

    for (old, value) in discovery.get_param_iter().zip(discovered.params.iter()) {
        let ty = old.get_type();
        let bits = ty.into_int_type().get_bit_width();

        let received = match value.loc {
            Loc::Reg(_) => sig.params.iter().position(|p| p.loc == value.loc).map(|index| (index, 0)),
            // A parameter wider than a slot fills the next ones (a double of x86)
            Loc::Stack(offset) => sig.params.iter().enumerate().find_map(|(index, p)| match p.loc {
                Loc::Stack(start) if start <= offset && offset < start + (width(p.ty, pointer_bits) as i64 + 7) / 8 => Some((index, offset - start)),
                _ => None,
            }),
        };

        let replacement = match received {
            Some((index, skipped)) => {
                let new = function.get_nth_param(index as u32).context("missing parameter")?;
                let mut int = to_int(cx, &builder, new, pointer_bits)?;

                if skipped > 0 {
                    int = builder.build_right_shift(int, int.get_type().const_int(skipped as u64 * 8, false), false, "")?;
                }

                resize(cx, &builder, int, bits)?
            }
            None => ty.into_int_type().get_undef(),
        };

        old.into_int_value().replace_all_uses_with(replacement);
    }

    let read = |name: &str| -> Result<IntValue<'ctx>> {
        let (variable, ty) = variables.get(name).copied().with_context(|| format!("no sink {}", name))?;
        return Ok(builder.build_load(ty, variable, "")?.into_int_value());
    };

    let result = |value: &Value| -> Result<BasicValueEnum<'ctx>> {
        if let Some(high) = high_half(env.abi, env.regs, value) {
            let low = read(&sink(env, env.abi.int_ret).context("no sink of the return register")?)?;
            let high = read(&sink(env, high).context("no sink of the high half")?)?;
            let bits = low.get_type().get_bit_width();
            let wide = int_type(cx, 2 * bits);
            let low = builder.build_int_z_extend(low, wide, "")?;
            let high = builder.build_int_z_extend(high, wide, "")?;
            let high = builder.build_left_shift(high, wide.const_int(bits as u64, false), "")?;
            return Ok(builder.build_or(high, low, "")?.into());
        }

        let name = result_sink(env, value).context("a result without a sink")?;
        let low = format!("{}{}", name, RETURN_SINK_LOW);

        if matches!(value.ty, LType::Int(bits) if bits <= RETURN_SINK_LOW_BITS) && variables.contains_key(&low) {
            return from_int(cx, &builder, read(&low)?, value.ty, pointer_bits);
        }

        return from_int(cx, &builder, read(&name)?, value.ty, pointer_bits);
    };

    // The results written and returned in place of an instruction (the return of the discovery, or a jump to it)
    let build_return = |at: InstructionValue<'ctx>, location: InstructionValue<'ctx>| -> Result<()> {
        builder.position_before(&at);
        locate(&builder, location);

        for (index, out) in sig.outs.iter().enumerate() {
            let value = result(out)?;
            let pointer = function.get_nth_param((sig.params.len() + index) as u32).context("missing result pointer")?;
            builder.build_store(pointer.into_pointer_value(), value)?;
        }

        match sig.ret.as_ref() {
            Some(ret) => builder.build_return(Some(&result(ret)?))?,
            None => builder.build_return(None)?,
        };

        at.erase_from_basic_block();
        return Ok(());
    };

    // The passes merged the returns of the discovery into a block that only returns: the blocks jumping to it return
    // themselves, so that the results are written where they are computed (the passes merge the returns again,
    // the stores stay where they are)
    for ret in returns {
        let block = ret.get_parent().context("a return without a block")?;
        let jumps: Vec<InstructionValue> = match block.get_first_instruction() == Some(ret) {
            true => predecessors(function, block).into_iter().filter_map(|b| b.get_terminator()).filter(|t| t.get_opcode() == InstructionOpcode::Br && t.get_num_operands() == 1).collect(),
            false => Vec::new(),
        };

        for jump in jumps {
            build_return(jump, ret)?;
        }

        match predecessors(function, block).is_empty() && function.get_first_basic_block() != Some(block) {
            true => unsafe { block.delete().ok().context("cannot remove the return block")? },
            false => build_return(ret, ret)?,
        }
    }

    unsafe { discovery.delete() };
    return Ok(Some(function));
}

/// The blocks jumping to a block (once each)
fn predecessors<'ctx>(function: FunctionValue<'ctx>, block: BasicBlock<'ctx>) -> Vec<BasicBlock<'ctx>> {
    let mut found = Vec::new();

    for other in function.get_basic_blocks() {
        let Some(terminator) = other.get_terminator() else {
            continue;
        };

        let jumps = (0..terminator.get_num_operands()).any(|i| terminator.get_operand(i).and_then(|o| o.block()) == Some(block));

        if jumps {
            found.push(other);
        }
    }

    return found;
}

/// The instructions built take the address of an instruction of the function
fn locate(builder: &Builder, instruction: InstructionValue) {
    unsafe {
        let location = LLVMInstructionGetDebugLoc(instruction.as_value_ref());

        if !location.is_null() {
            inkwell::llvm_sys::core::LLVMSetCurrentDebugLocation2(builder.as_mut_ptr(), location);
        }
    }
}

/// The sink a discovery stores a register to when it returns
fn sink(env: &Env, reg: usize) -> Option<String> {
    let abi = env.abi;

    if !abi.stack_results {
        if reg == abi.int_ret {
            return Some(RETURN_SINK_INT.to_string());
        }

        if reg == abi.float_ret {
            return Some(RETURN_SINK_FLOAT.to_string());
        }

        if abi.int_ret_high == Some(reg) {
            return Some(RETURN_SINK_HIGH.to_string());
        }
    }

    if let Some(position) = abi.int_args.iter().position(|&r| r == reg).filter(|&p| abi.register_results && p > 0 && p < RETURN_SINK_REGS.len()) {
        return Some(RETURN_SINK_REGS[position].to_string());
    }

    return abi.extra_results.iter().zip(RETURN_SINK_EXTRA).find(|(r, _)| **r == reg).map(|(_, sink)| sink.to_string());
}

/// The sink of a result
fn result_sink(env: &Env, value: &Value) -> Option<String> {
    return match value.loc {
        Loc::Reg(reg) => sink(env, reg),
        Loc::Stack(offset) => Some(format!("{}{}", RETURN_SINK_STACK, offset)),
    };
}

fn width(ty: LType, pointer_bits: u32) -> u32 {
    return match ty {
        LType::Int(bits) | LType::Float(bits) => bits,
        LType::Ptr => pointer_bits,
    };
}

fn resize<'ctx>(cx: &'ctx Context, builder: &Builder<'ctx>, value: IntValue<'ctx>, bits: u32) -> Result<IntValue<'ctx>> {
    let ty = int_type(cx, bits);

    return Ok(match value.get_type().get_bit_width().cmp(&bits) {
        std::cmp::Ordering::Equal => value,
        std::cmp::Ordering::Greater => builder.build_int_truncate(value, ty, "")?,
        std::cmp::Ordering::Less => builder.build_int_z_extend(value, ty, "")?,
    });
}

/// A parameter as an integer, as the lift puts it in its register
fn to_int<'ctx>(cx: &'ctx Context, builder: &Builder<'ctx>, value: BasicValueEnum<'ctx>, pointer_bits: u32) -> Result<IntValue<'ctx>> {
    return Ok(match value {
        BasicValueEnum::IntValue(v) => v,
        BasicValueEnum::PointerValue(v) => builder.build_ptr_to_int(v, int_type(cx, pointer_bits), "")?,
        BasicValueEnum::FloatValue(v) => {
            let bits = v.get_type().get_bit_width();
            builder.build_bit_cast(v, int_type(cx, bits), "")?.into_int_value()
        }
        _ => anyhow::bail!("unsupported parameter type"),
    });
}

/// A register (or a slot) as a result, as the lift reads it
fn from_int<'ctx>(cx: &'ctx Context, builder: &Builder<'ctx>, value: IntValue<'ctx>, ty: LType, pointer_bits: u32) -> Result<BasicValueEnum<'ctx>> {
    return Ok(match ty {
        LType::Int(bits) => resize(cx, builder, value, bits)?.into(),
        LType::Ptr => builder.build_int_to_ptr(resize(cx, builder, value, pointer_bits)?, cx.ptr_type(Default::default()), "")?.into(),
        LType::Float(bits) => {
            let (float, float_bits) = if bits == 32 { (cx.f32_type(), 32) } else { (cx.f64_type(), 64) };
            let value = resize(cx, builder, resize(cx, builder, value, bits)?, float_bits)?;
            builder.build_bit_cast(value, float, "")?.as_basic_value_enum()
        }
    });
}

/// Returns of a conversion of a phi of their block return the conversions of its operands instead (a phi made of the
/// 64-bit sink is truncated where the final lift returns a phi of 32-bit values): the C backend returns them where
/// they come from
pub fn return_phis(function: FunctionValue) {
    unsafe {
        use inkwell::llvm_sys::core::*;
        use inkwell::llvm_sys::LLVMOpcode;

        let context = LLVMGetTypeContext(LLVMTypeOf(function.as_value_ref()));
        let builder = LLVMCreateBuilderInContext(context);
        let single_use = |value| !LLVMGetFirstUse(value).is_null() && LLVMGetNextUse(LLVMGetFirstUse(value)).is_null();

        for block in function.get_basic_blocks() {
            let ret = LLVMGetBasicBlockTerminator(block.as_mut_ptr());

            if ret.is_null() || LLVMGetInstructionOpcode(ret) != LLVMOpcode::LLVMRet || LLVMGetNumOperands(ret) != 1 {
                continue;
            }

            // The conversions from the phi to the returned value
            let mut casts = Vec::new();
            let mut value = LLVMGetOperand(ret, 0);

            while !LLVMIsACastInst(value).is_null() && LLVMGetInstructionParent(value) == block.as_mut_ptr() && single_use(value) {
                casts.push(value);
                value = LLVMGetOperand(value, 0);
            }

            if casts.is_empty() || LLVMIsAPHINode(value).is_null() || LLVMGetInstructionParent(value) != block.as_mut_ptr() || !single_use(value) {
                continue;
            }

            let phi = value;
            LLVMPositionBuilderBefore(builder, phi);
            let ty = LLVMTypeOf(casts[0]);
            let new = LLVMBuildPhi(builder, ty, c"".as_ptr());
            LLVMInstructionSetDebugLoc(new, LLVMInstructionGetDebugLoc(phi));
            let mut converted: HashMap<LLVMBasicBlockRef, LLVMValueRef> = HashMap::default();

            for i in 0..LLVMCountIncoming(phi) {
                let mut pred = LLVMGetIncomingBlock(phi, i);
                let mut operand = match converted.get(&pred) {
                    Some(&known) => known,
                    None => {
                        LLVMPositionBuilderBefore(builder, LLVMGetBasicBlockTerminator(pred));
                        let mut operand = LLVMGetIncomingValue(phi, i);

                        for &cast in casts.iter().rev() {
                            operand = LLVMBuildCast(builder, LLVMGetInstructionOpcode(cast), operand, LLVMTypeOf(cast), c"".as_ptr());

                            if !LLVMIsAInstruction(operand).is_null() {
                                LLVMInstructionSetDebugLoc(operand, LLVMInstructionGetDebugLoc(cast));
                            }
                        }

                        converted.insert(pred, operand);
                        operand
                    }
                };

                LLVMAddIncoming(new, &mut operand, &mut pred, 1);
            }

            LLVMSetOperand(ret, 0, new);

            for &cast in casts.iter() {
                LLVMInstructionEraseFromParent(cast);
            }

            LLVMInstructionEraseFromParent(phi);
        }

        LLVMDisposeBuilder(builder);
    }
}
