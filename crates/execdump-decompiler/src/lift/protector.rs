/*
 * Stack protector removal, once the optimizations ran
 *
 * The canary is a value of the thread (fs:0x28 on x86_64, gs:0x14 on x86) or a global
 * (__stack_chk_guard, __security_cookie) stored in the frame at the entry and compared with it
 * again before the returns: a mismatch calls __stack_chk_fail. It is recognised by its value, not
 * by where it is stored. For the C code the comparisons always pass: the branches go to the other
 * side, the stores of the canary and the calls to __security_check_cookie are removed. The slots
 * the canary was stored in bound the buffers of the frame below them.
 */

use super::frame::{byte_array, callee_name, constant, gep_offset};

use inkwell::llvm_sys::core::*;
use inkwell::llvm_sys::debuginfo::{LLVMInstructionGetDebugLoc, LLVMInstructionSetDebugLoc};
use inkwell::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMValueRef};
use inkwell::llvm_sys::LLVMOpcode;
use inkwell::values::{AsValueRef, FunctionValue};

use std::collections::HashSet;

/// What the removal changed
#[derive(Default)]
pub struct Protector {
    pub changed: bool,
    /// Frames (byte array allocas) and the offsets the canary was stored at
    pub slots: Vec<(LLVMValueRef, u64)>,
}

/// Name without the leading underscores of the C and Mach-O symbols
fn bare(name: &str) -> &str {
    return name.trim_start_matches('_');
}

fn is_guard(name: &str) -> bool {
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    return matches!(bare(name), "stack_chk_guard" | "security_cookie");
}

fn is_failure(name: &str) -> bool {
    return matches!(bare(name), "stack_chk_fail" | "stack_chk_fail_local");
}

fn global_name(value: LLVMValueRef) -> Option<String> {
    unsafe {
        if LLVMIsAGlobalVariable(value).is_null() {
            return None;
        }

        let mut length = 0;
        let pointer = LLVMGetValueName2(value, &mut length);
        return Some(String::from_utf8_lossy(std::slice::from_raw_parts(pointer as *const u8, length)).to_string());
    }
}

fn opcode(value: LLVMValueRef) -> Option<LLVMOpcode> {
    unsafe {
        if !LLVMIsAInstruction(value).is_null() {
            return Some(LLVMGetInstructionOpcode(value));
        }

        if !LLVMIsAConstantExpr(value).is_null() {
            return Some(LLVMGetConstOpcode(value));
        }

        return None;
    }
}

/// The value without its casts
fn uncast(mut value: LLVMValueRef) -> LLVMValueRef {
    while matches!(opcode(value), Some(LLVMOpcode::LLVMIntToPtr | LLVMOpcode::LLVMPtrToInt | LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMZExt | LLVMOpcode::LLVMTrunc)) {
        value = unsafe { LLVMGetOperand(value, 0) };
    }

    return value;
}

/// Read of the canary of the thread: __readfsqword(0x28), __readgsdword(0x14)
fn is_thread_canary(value: LLVMValueRef) -> bool {
    if opcode(value) != Some(LLVMOpcode::LLVMCall) {
        return false;
    }

    let name = unsafe { callee_name(value) };
    let offset = unsafe { constant(LLVMGetOperand(value, 0)) };

    return matches!((name.as_str(), offset), ("__readfsqword", Some(0x28)) | ("__readgsdword", Some(0x14)));
}

/// Address of the guard: the global, or the pointer read from its import slot
fn is_guard_address(value: LLVMValueRef) -> bool {
    let value = uncast(value);

    if global_name(value).is_some_and(|n| is_guard(&n) && !n.starts_with("__imp_")) {
        return true;
    }

    return opcode(value) == Some(LLVMOpcode::LLVMLoad) && global_name(uncast(unsafe { LLVMGetOperand(value, 0) })).is_some_and(|n| n.starts_with("__imp_") && is_guard(&n));
}

/// The canary, or a value made from it (MSVC stores the cookie xor the stack pointer)
fn is_canary(value: LLVMValueRef, depth: usize) -> bool {
    let value = uncast(value);

    if is_thread_canary(value) {
        return true;
    }

    return match opcode(value) {
        Some(LLVMOpcode::LLVMLoad) => is_guard_address(unsafe { LLVMGetOperand(value, 0) }),
        Some(LLVMOpcode::LLVMXor | LLVMOpcode::LLVMSub | LLVMOpcode::LLVMAdd) if depth > 0 => unsafe { is_canary(LLVMGetOperand(value, 0), depth - 1) || is_canary(LLVMGetOperand(value, 1), depth - 1) },
        _ => false,
    };
}

/// A comparison of the canary with what the frame kept of it
fn is_check(condition: LLVMValueRef) -> bool {
    if opcode(condition) != Some(LLVMOpcode::LLVMICmp) {
        return false;
    }

    return unsafe { is_canary(LLVMGetOperand(condition, 0), 3) || is_canary(LLVMGetOperand(condition, 1), 3) };
}

/// A block that only calls __stack_chk_fail (the instructions before the call have no effect)
fn is_failure_block(block: LLVMBasicBlockRef) -> bool {
    unsafe {
        let mut instruction = LLVMGetFirstInstruction(block);

        while !instruction.is_null() {
            match LLVMGetInstructionOpcode(instruction) {
                LLVMOpcode::LLVMPHI => return false,
                LLVMOpcode::LLVMCall => return is_failure(&callee_name(instruction)),
                LLVMOpcode::LLVMStore | LLVMOpcode::LLVMInvoke | LLVMOpcode::LLVMRet => return false,
                _ => {}
            }

            instruction = LLVMGetNextInstruction(instruction);
        }

        return false;
    }
}

/// Frame and offset of a pointer into a byte array alloca
fn frame_slot(pointer: LLVMValueRef) -> Option<(LLVMValueRef, u64)> {
    let pointer = uncast(pointer);

    unsafe {
        if opcode(pointer) == Some(LLVMOpcode::LLVMAlloca) {
            return Some((pointer, 0));
        }

        if opcode(pointer) == Some(LLVMOpcode::LLVMGetElementPtr) {
            let frame = LLVMGetOperand(pointer, 0);

            if opcode(frame) == Some(LLVMOpcode::LLVMAlloca) && byte_array(LLVMGetAllocatedType(frame)).is_some() {
                return Some((frame, gep_offset(pointer, frame)?));
            }
        }
    }

    return None;
}

/// Erases the instructions without effect that nothing uses anymore, and the ones they were the last
/// use of (erased holds what was erased, never touched again)
fn erase_dead(mut worklist: Vec<LLVMValueRef>, erased: &mut HashSet<LLVMValueRef>) {
    unsafe {
        while let Some(value) = worklist.pop() {
            if erased.contains(&value) || LLVMIsAInstruction(value).is_null() || !LLVMGetFirstUse(value).is_null() {
                continue;
            }

            let pure = match LLVMGetInstructionOpcode(value) {
                LLVMOpcode::LLVMLoad => LLVMGetVolatile(value) == 0,
                LLVMOpcode::LLVMCall => is_thread_canary(value),
                LLVMOpcode::LLVMICmp | LLVMOpcode::LLVMXor | LLVMOpcode::LLVMSub | LLVMOpcode::LLVMAdd | LLVMOpcode::LLVMGetElementPtr => true,
                LLVMOpcode::LLVMPHI | LLVMOpcode::LLVMSelect => true,
                LLVMOpcode::LLVMIntToPtr | LLVMOpcode::LLVMPtrToInt | LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMZExt | LLVMOpcode::LLVMTrunc => true,
                _ => false,
            };

            if !pure {
                continue;
            }

            let operands: Vec<LLVMValueRef> = (0..LLVMGetNumOperands(value) as u32).map(|i| LLVMGetOperand(value, i)).collect();
            LLVMInstructionEraseFromParent(value);
            erased.insert(value);
            worklist.extend(operands);
        }
    }
}

pub fn remove_stack_protector(function: FunctionValue) -> Protector {
    let mut protector = Protector::default();
    let mut checks: Vec<(LLVMValueRef, LLVMBasicBlockRef)> = Vec::new();
    let mut cookies: Vec<LLVMValueRef> = Vec::new();
    let mut stores: Vec<LLVMValueRef> = Vec::new();
    let mut reads: Vec<LLVMValueRef> = Vec::new();

    unsafe {
        for block in function.get_basic_blocks() {
            let mut instruction = LLVMGetFirstInstruction(block.as_mut_ptr());

            while !instruction.is_null() {
                match LLVMGetInstructionOpcode(instruction) {
                    // br i1 check, ok, fail -> br ok
                    LLVMOpcode::LLVMBr if LLVMIsConditional(instruction) != 0 && is_check(LLVMGetCondition(instruction)) => {
                        let (on_true, on_false) = (LLVMGetSuccessor(instruction, 0), LLVMGetSuccessor(instruction, 1));

                        match (is_failure_block(on_true), is_failure_block(on_false)) {
                            (false, true) => checks.push((instruction, on_true)),
                            (true, false) => checks.push((instruction, on_false)),
                            _ => {}
                        }
                    }
                    // MSVC: __security_check_cookie(cookie ^ rsp)
                    LLVMOpcode::LLVMCall if bare(&callee_name(instruction)) == "security_check_cookie" && LLVMGetNumArgOperands(instruction) == 1 => {
                        cookies.push(instruction);
                    }
                    LLVMOpcode::LLVMStore if is_canary(LLVMGetOperand(instruction, 0), 3) && frame_slot(LLVMGetOperand(instruction, 1)).is_some() => {
                        stores.push(instruction);
                    }
                    LLVMOpcode::LLVMCall if is_thread_canary(instruction) => reads.push(instruction),
                    _ => {}
                }

                instruction = LLVMGetNextInstruction(instruction);
            }
        }

        // The canary is also stored for (and checked by) a part of the function the compiler moved away,
        // its reads are left without use
        let mut dead = reads;

        if checks.is_empty() && cookies.is_empty() && stores.is_empty() {
            erase_dead(dead, &mut HashSet::new());
            return protector;
        }

        protector.changed = true;
        let builder = LLVMCreateBuilderInContext(LLVMGetTypeContext(LLVMTypeOf(function.as_value_ref())));

        for (branch, target) in checks {
            LLVMPositionBuilderBefore(builder, branch);
            let jump = LLVMBuildBr(builder, target);
            LLVMInstructionSetDebugLoc(jump, LLVMInstructionGetDebugLoc(branch));

            dead.push(LLVMGetCondition(branch));
            LLVMInstructionEraseFromParent(branch);
        }

        LLVMDisposeBuilder(builder);

        for call in cookies {
            dead.push(LLVMGetOperand(call, 0));
            LLVMInstructionEraseFromParent(call);
        }

        for store in stores {
            let (value, pointer) = (LLVMGetOperand(store, 0), LLVMGetOperand(store, 1));

            if let Some((frame, offset)) = frame_slot(pointer).filter(|(frame, _)| byte_array(LLVMGetAllocatedType(*frame)).is_some()) {
                protector.slots.push((frame, offset));
            }

            LLVMInstructionEraseFromParent(store);
            dead.push(value);
            dead.push(pointer);
        }

        erase_dead(dead, &mut HashSet::new());
    }

    return protector;
}
