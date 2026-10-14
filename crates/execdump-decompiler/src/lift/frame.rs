/*
 * Splitting of the stack frame into local variables, once the optimizations ran
 *
 * The frame is a byte array. When the address of a part of it is taken (a buffer passed to a call,
 * a pointer kept in a local variable, typical of 32-bit and unoptimized code), SROA keeps it whole
 * and every local is an offset in it. Here each byte array left is cut into slots by how it is
 * accessed, the optimizations then turn the slots that do not escape into values:
 *
 * - an address that escapes (taken, passed, indexed by a variable) is the start of an object that
 *   extends to the next escaping address, or to the end of the frame: what it points to may be
 *   reached from it, the slot keeps it whole. The slot of the stack protector canary (removed
 *   before, see protector.rs) ends the objects below it too: the buffers it protects end there
 * - below the first escaping address, the loads and stores make the slots (overlapping accesses
 *   share one)
 *
 * Strings written by consecutive stores of constants (mov dword [ebp-0x25], 0x4763305f...) are one
 * slot, written by one memcpy of the string.
 */

use super::text_bytes;

use inkwell::llvm_sys::core::*;
use inkwell::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMBuilderRef, LLVMContextRef, LLVMModuleRef, LLVMTypeRef, LLVMValueRef};
use inkwell::llvm_sys::target::{LLVMGetModuleDataLayout, LLVMStoreSizeOfType, LLVMTargetDataRef};
use inkwell::llvm_sys::{LLVMLinkage, LLVMOpcode, LLVMTypeKind, LLVMUnnamedAddr};
use inkwell::module::Module;
use inkwell::llvm_sys::debuginfo::{LLVMInstructionGetDebugLoc, LLVMInstructionSetDebugLoc};
use inkwell::values::FunctionValue;

use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Load,
    Store(Option<Vec<u8>>),
    /// Read or written with an unknown extent (the address escapes)
    Escape,
}

#[derive(Clone, Debug)]
struct Access {
    offset: u64,
    size: u64,
    kind: Kind,
    /// Type of the loaded or stored value
    ty: Option<LLVMTypeRef>,
}

#[derive(Clone, Debug)]
struct Slot {
    start: u64,
    end: u64,
    /// Indices of its accesses
    accesses: Vec<usize>,
}

/// Splits the byte arrays of the stack frame of a function, true when one was split. The bounds are
/// offsets in frames where the objects end (the slots of the stack protector canary).
pub fn split_frame(module: &Module, function: FunctionValue, bounds: &[(LLVMValueRef, u64)]) -> bool {
    let mut split = false;

    unsafe {
        let module = module.as_mut_ptr();

        for frame in frames(function) {
            let ends: BTreeSet<u64> = bounds.iter().filter(|(f, _)| *f == frame).map(|(_, offset)| *offset).collect();
            split |= split_one(module, frame, &ends);
        }
    }

    return split;
}

/// Byte array allocas of the entry block
unsafe fn frames(function: FunctionValue) -> Vec<LLVMValueRef> {
    let mut frames = Vec::new();

    unsafe {
        let Some(entry) = function.get_first_basic_block() else {
            return frames;
        };

        let mut instruction = LLVMGetFirstInstruction(entry.as_mut_ptr());

        while !instruction.is_null() {
            if LLVMGetInstructionOpcode(instruction) == LLVMOpcode::LLVMAlloca && byte_array(LLVMGetAllocatedType(instruction)).is_some() {
                frames.push(instruction);
            }

            instruction = LLVMGetNextInstruction(instruction);
        }
    }

    return frames;
}

/// Addresses of the stack frames computed on integers become addresses in the frames (before the other
/// passes that look at how the frames are accessed)
pub fn fold_frame_addresses(function: FunctionValue) {
    unsafe {
        for frame in frames(function) {
            fold_integer_addresses(frame, byte_array(LLVMGetAllocatedType(frame)).unwrap_or(0));
        }
    }
}

/// Length of an array of bytes
pub(super) unsafe fn byte_array(ty: LLVMTypeRef) -> Option<u64> {
    unsafe {
        if LLVMGetTypeKind(ty) != LLVMTypeKind::LLVMArrayTypeKind {
            return None;
        }

        let element = LLVMGetElementType(ty);
        let byte = LLVMGetTypeKind(element) == LLVMTypeKind::LLVMIntegerTypeKind && LLVMGetIntTypeWidth(element) == 8;

        return byte.then(|| LLVMGetArrayLength2(ty));
    }
}

pub(super) unsafe fn users(value: LLVMValueRef) -> Vec<LLVMValueRef> {
    let mut users = Vec::new();

    unsafe {
        let mut used = LLVMGetFirstUse(value);

        while !used.is_null() {
            users.push(LLVMGetUser(used));
            used = LLVMGetNextUse(used);
        }
    }

    return users;
}

pub(super) unsafe fn constant(value: LLVMValueRef) -> Option<i64> {
    unsafe {
        return (!LLVMIsAConstantInt(value).is_null() && LLVMGetIntTypeWidth(LLVMTypeOf(value)) <= 64).then(|| LLVMConstIntGetSExtValue(value));
    }
}

pub(super) unsafe fn callee_name(call: LLVMValueRef) -> String {
    unsafe {
        let callee = LLVMGetCalledValue(call);

        if callee.is_null() || LLVMIsAFunction(callee).is_null() {
            return String::new();
        }

        let mut length = 0;
        let pointer = LLVMGetValueName2(callee, &mut length);
        return String::from_utf8_lossy(std::slice::from_raw_parts(pointer as *const u8, length)).to_string();
    }
}

/// Constant offset of a GEP of the frame (i8 with one index, or the array with 0 and an index)
pub(super) unsafe fn gep_offset(gep: LLVMValueRef, frame: LLVMValueRef) -> Option<u64> {
    unsafe {
        if LLVMGetInstructionOpcode(gep) != LLVMOpcode::LLVMGetElementPtr || LLVMGetOperand(gep, 0) != frame {
            return None;
        }

        let indices: Vec<i64> = (1..LLVMGetNumOperands(gep) as u32).map(|i| constant(LLVMGetOperand(gep, i))).collect::<Option<_>>()?;
        let source = LLVMGetGEPSourceElementType(gep);

        let offset = match indices.as_slice() {
            [index] if byte_array(source).is_none() && LLVMGetTypeKind(source) == LLVMTypeKind::LLVMIntegerTypeKind && LLVMGetIntTypeWidth(source) == 8 => *index,
            [0, index] if byte_array(source).is_some() => *index,
            _ => return None,
        };

        return u64::try_from(offset).ok();
    }
}

/// Bytes of a constant integer (little endian)
unsafe fn constant_bytes(value: LLVMValueRef) -> Option<Vec<u8>> {
    unsafe {
        if LLVMIsAConstantInt(value).is_null() {
            return None;
        }

        let bits = LLVMGetIntTypeWidth(LLVMTypeOf(value));

        if bits % 8 != 0 || bits > 64 {
            return None;
        }

        return Some(LLVMConstIntGetZExtValue(value).to_le_bytes()[..bits as usize / 8].to_vec());
    }
}

/// How an instruction accesses the frame through a pointer at an offset
unsafe fn access(user: LLVMValueRef, pointer: LLVMValueRef, offset: u64, layout: LLVMTargetDataRef) -> Access {
    let escape = Access { offset, size: 1, kind: Kind::Escape, ty: None };

    unsafe {
        match LLVMGetInstructionOpcode(user) {
            LLVMOpcode::LLVMLoad if LLVMGetVolatile(user) == 0 => {
                let ty = LLVMTypeOf(user);
                return Access { offset, size: LLVMStoreSizeOfType(layout, ty).max(1), kind: Kind::Load, ty: Some(ty) };
            }
            LLVMOpcode::LLVMStore if LLVMGetVolatile(user) == 0 && LLVMGetOperand(user, 1) == pointer && LLVMGetOperand(user, 0) != pointer => {
                let value = LLVMGetOperand(user, 0);
                let ty = LLVMTypeOf(value);
                return Access { offset, size: LLVMStoreSizeOfType(layout, ty).max(1), kind: Kind::Store(constant_bytes(value)), ty: Some(ty) };
            }
            LLVMOpcode::LLVMCall => {
                let name = callee_name(user);
                let memory = name.starts_with("llvm.memset") || name.starts_with("llvm.memcpy") || name.starts_with("llvm.memmove");

                // The length of a memory intrinsic is its third operand
                if let Some(length) = memory.then(|| constant(LLVMGetOperand(user, 2))).flatten() {
                    let source = LLVMGetOperand(user, 1) == pointer && !name.starts_with("llvm.memset");
                    let kind = if source { Kind::Load } else { Kind::Store(None) };
                    return Access { offset, size: (length.max(1)) as u64, kind, ty: None };
                }

                return escape;
            }
            _ => return escape,
        }
    }
}

/// Text written in a slot: at least 4 characters, the NULs at its end only
fn is_text(bytes: &[u8]) -> bool {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let text = &bytes[..end];

    return text.len() >= 4 && !text.contains(&0) && text_bytes(text);
}

/// Slots of a frame of a size from its accesses, the objects also end at the bounds
fn layout(accesses: &[Access], size: u64, bounds: &BTreeSet<u64>) -> Vec<Slot> {
    let bases: BTreeSet<u64> = accesses.iter().filter(|a| a.kind == Kind::Escape).map(|a| a.offset).collect();
    let end = |b: u64| bases.range(b + 1..).chain(bounds.range(b + 1..)).min().copied().unwrap_or(size);

    // Objects from each escaping address to the next, then the accesses
    let mut intervals: Vec<(u64, u64, Vec<usize>)> = bases.iter().map(|&b| (b, end(b), Vec::new())).collect();

    for (index, access) in accesses.iter().enumerate() {
        intervals.push((access.offset, (access.offset + access.size).min(size).max(access.offset + 1), vec![index]));
    }

    intervals.sort_by_key(|(start, end, _)| (*start, std::cmp::Reverse(*end)));

    let mut slots: Vec<Slot> = Vec::new();

    for (start, end, indices) in intervals {
        match slots.last_mut() {
            Some(last) if start < last.end => {
                last.end = last.end.max(end);
                last.accesses.extend(indices);
            }
            _ => slots.push(Slot { start, end, accesses: indices }),
        }
    }

    // Strings written piece by piece: adjacent slots that are only one store of a constant each
    let written = |slot: &Slot| -> Option<Vec<u8>> {
        match slot.accesses.as_slice() {
            [index] => match &accesses[*index].kind {
                Kind::Store(Some(bytes)) if accesses[*index].offset == slot.start && bytes.len() as u64 == slot.end - slot.start => Some(bytes.clone()),
                _ => None,
            },
            _ => None,
        }
    };

    let mut merged: Vec<Slot> = Vec::new();
    let mut index = 0;

    while index < slots.len() {
        let mut run = vec![];

        while let Some(bytes) = slots.get(index + run.len()).filter(|s| run.is_empty() || s.start == slots[index + run.len() - 1].end).and_then(|s| written(s)) {
            run.push(bytes);
        }

        // The longest string at the start of the run
        let length = (2..=run.len()).rev().find(|&n| is_text(&run[..n].concat())).unwrap_or(1);
        let accesses = slots[index..index + length].iter().flat_map(|s| s.accesses.iter().copied()).collect();

        merged.push(Slot { start: slots[index].start, end: slots[index + length - 1].end, accesses });
        index += length;
    }

    return merged;
}

/// Addresses of the frame computed on integers (the stack pointer copied to a register, then offset:
/// inttoptr(ptrtoint(frame + a) + c)) become addresses in the frame (frame + a + c)
unsafe fn fold_integer_addresses(frame: LLVMValueRef, size: u64) {
    unsafe {
        let context = LLVMGetTypeContext(LLVMTypeOf(frame));
        let (i8, i64) = (LLVMInt8TypeInContext(context), LLVMInt64TypeInContext(context));
        let builder = LLVMCreateBuilderInContext(context);

        let mut bases: Vec<(LLVMValueRef, u64)> = vec![(frame, 0)];
        bases.extend(users(frame).into_iter().filter_map(|u| Some((u, gep_offset(u, frame)?))));

        for (base, offset) in bases {
            for integer in users(base).into_iter().filter(|&u| LLVMGetInstructionOpcode(u) == LLVMOpcode::LLVMPtrToInt) {
                for sum in users(integer) {
                    let delta = match LLVMGetInstructionOpcode(sum) {
                        LLVMOpcode::LLVMAdd if LLVMGetOperand(sum, 0) == integer => constant(LLVMGetOperand(sum, 1)),
                        LLVMOpcode::LLVMAdd => constant(LLVMGetOperand(sum, 0)),
                        LLVMOpcode::LLVMSub if LLVMGetOperand(sum, 0) == integer => constant(LLVMGetOperand(sum, 1)).map(|c| -c),
                        _ => None,
                    };

                    let Some(target) = delta.and_then(|d| offset.checked_add_signed(d)).filter(|&t| t < size) else {
                        continue;
                    };

                    LLVMPositionBuilderBefore(builder, sum);
                    let mut index = [LLVMConstInt(i64, target, 0)];
                    let address = LLVMBuildInBoundsGEP2(builder, i8, frame, index.as_mut_ptr(), 1, c"".as_ptr());

                    for pointer in users(sum).into_iter().filter(|&u| LLVMGetInstructionOpcode(u) == LLVMOpcode::LLVMIntToPtr && LLVMTypeOf(u) == LLVMTypeOf(address)) {
                        LLVMReplaceAllUsesWith(pointer, address);
                        LLVMInstructionEraseFromParent(pointer);
                    }

                    // The other uses keep the integer
                    if !LLVMGetFirstUse(sum).is_null() {
                        let value = LLVMBuildPtrToInt(builder, address, LLVMTypeOf(sum), c"".as_ptr());
                        LLVMReplaceAllUsesWith(sum, value);
                    }

                    LLVMInstructionEraseFromParent(sum);
                }

                if LLVMGetFirstUse(integer).is_null() {
                    LLVMInstructionEraseFromParent(integer);
                }
            }

            // The address of the top of the frame (the stack pointer at the entry) is out of it
            if base != frame && LLVMGetFirstUse(base).is_null() {
                LLVMInstructionEraseFromParent(base);
            }
        }

        LLVMDisposeBuilder(builder);
    }
}

unsafe fn split_one(module: LLVMModuleRef, frame: LLVMValueRef, bounds: &BTreeSet<u64>) -> bool {
    unsafe {
        let Some(size) = byte_array(LLVMGetAllocatedType(frame)) else {
            return false;
        };


        let layout_data = LLVMGetModuleDataLayout(module);
        let mut accesses = Vec::new();
        // Pointer (the frame or a GEP of it), its offset, the access of each user
        let mut pointers: Vec<(LLVMValueRef, u64, Vec<usize>)> = Vec::new();

        for user in users(frame) {
            if let Some(offset) = gep_offset(user, frame) {
                if pointers.iter().any(|(p, ..)| *p == user) {
                    continue;
                }

                if offset >= size {
                    return false;
                }

                if LLVMGetFirstUse(user).is_null() {
                    LLVMInstructionEraseFromParent(user);
                    continue;
                }

                let mut indices = Vec::new();

                for inner in users(user) {
                    accesses.push(access(inner, user, offset, layout_data));
                    indices.push(accesses.len() - 1);
                }

                pointers.push((user, offset, indices));
            } else {
                accesses.push(access(user, frame, 0, layout_data));
            }
        }

        let slots = layout(&accesses, size, bounds);

        if slots.len() <= 1 && slots.first().is_none_or(|s| s.start == 0 && s.end == size) {
            return false;
        }

        let context = LLVMGetTypeContext(LLVMTypeOf(frame));
        let builder = LLVMCreateBuilderInContext(context);
        LLVMPositionBuilderBefore(builder, frame);

        let i8 = LLVMInt8TypeInContext(context);
        let i64 = LLVMInt64TypeInContext(context);

        // A slot accessed with a single type of its size is of that type, the others are byte arrays
        let allocas: Vec<LLVMValueRef> = slots
            .iter()
            .map(|slot| {
                let types: BTreeSet<usize> = slot.accesses.iter().filter_map(|&i| accesses[i].ty).map(|t| t as usize).collect();
                let whole = slot.accesses.iter().all(|&i| accesses[i].offset == slot.start && accesses[i].size == slot.end - slot.start && accesses[i].ty.is_some());

                let ty = match (types.len(), whole) {
                    (1, true) => *types.iter().next().unwrap() as LLVMTypeRef,
                    _ => LLVMArrayType2(i8, slot.end - slot.start),
                };

                let alloca = LLVMBuildAlloca(builder, ty, c"".as_ptr());
                LLVMSetAlignment(alloca, LLVMGetAlignment(frame).max(1));
                alloca
            })
            .collect();

        let slot_of = |offset: u64| slots.iter().position(|s| s.start <= offset && offset < s.end);

        for (pointer, offset, _) in pointers.iter() {
            let Some(slot) = slot_of(*offset) else {
                continue;
            };

            let replacement = if *offset == slots[slot].start {
                allocas[slot]
            } else {
                LLVMPositionBuilderBefore(builder, *pointer);
                let mut index = [LLVMConstInt(i64, offset - slots[slot].start, 0)];
                LLVMBuildInBoundsGEP2(builder, i8, allocas[slot], index.as_mut_ptr(), 1, c"".as_ptr())
            };

            LLVMReplaceAllUsesWith(*pointer, replacement);
            LLVMInstructionEraseFromParent(*pointer);
        }

        // The frame itself is the slot at its start
        if let Some(slot) = slot_of(0).filter(|&s| slots[s].start == 0) {
            LLVMReplaceAllUsesWith(frame, allocas[slot]);
        }

        if LLVMGetFirstUse(frame).is_null() {
            LLVMInstructionEraseFromParent(frame);
        }

        for (slot, &alloca) in slots.iter().zip(allocas.iter()) {
            write_strings(module, context, builder, alloca, slot.end - slot.start);
        }

        LLVMDisposeBuilder(builder);
    }

    return true;
}

/// Store of a constant in a slot: the store, its offset and its bytes
unsafe fn constant_store(instruction: LLVMValueRef, alloca: LLVMValueRef) -> Option<(u64, Vec<u8>)> {
    unsafe {
        if LLVMGetInstructionOpcode(instruction) != LLVMOpcode::LLVMStore || LLVMGetVolatile(instruction) != 0 {
            return None;
        }

        let pointer = LLVMGetOperand(instruction, 1);
        let bytes = constant_bytes(LLVMGetOperand(instruction, 0))?;

        if pointer == alloca {
            return Some((0, bytes));
        }

        if LLVMIsAInstruction(pointer).is_null() || LLVMGetInstructionOpcode(pointer) != LLVMOpcode::LLVMGetElementPtr || LLVMGetOperand(pointer, 0) != alloca || LLVMGetNumOperands(pointer) != 2 {
            return None;
        }

        return Some((u64::try_from(constant(LLVMGetOperand(pointer, 1))?).ok()?, bytes));
    }
}

/// Runs of stores of constants that write a string in a slot become one memcpy of the string (volatile:
/// the string stays in the code when nothing reads it)
unsafe fn write_strings(module: LLVMModuleRef, context: LLVMContextRef, builder: LLVMBuilderRef, alloca: LLVMValueRef, size: u64) {
    unsafe {
        if byte_array(LLVMGetAllocatedType(alloca)).is_none() || size < 4 {
            return;
        }

        let mut blocks = BTreeSet::new();

        for user in users(alloca) {
            blocks.insert(LLVMGetInstructionParent(user) as usize);

            for inner in users(user) {
                if !LLVMIsAInstruction(inner).is_null() {
                    blocks.insert(LLVMGetInstructionParent(inner) as usize);
                }
            }
        }

        for block in blocks {
            let mut run: Vec<(LLVMValueRef, u64, Vec<u8>)> = Vec::new();
            let mut instruction = LLVMGetFirstInstruction(block as LLVMBasicBlockRef);

            while !instruction.is_null() {
                let next = LLVMGetNextInstruction(instruction);
                let store = constant_store(instruction, alloca);
                let contiguous = match (&store, run.last()) {
                    (Some((offset, _)), Some((_, last, bytes))) => *offset == last + bytes.len() as u64,
                    _ => true,
                };

                match store {
                    Some((offset, bytes)) if contiguous => run.push((instruction, offset, bytes)),
                    Some((offset, bytes)) => {
                        replace_run(module, context, builder, alloca, &run);
                        run = vec![(instruction, offset, bytes)];
                    }
                    // Address computations do not end a run, anything that touches memory does
                    None if matches!(LLVMGetInstructionOpcode(instruction), LLVMOpcode::LLVMGetElementPtr | LLVMOpcode::LLVMPtrToInt) => {}
                    None => {
                        replace_run(module, context, builder, alloca, &run);
                        run.clear();
                    }
                }

                instruction = next;
            }

            replace_run(module, context, builder, alloca, &run);
        }
    }
}

unsafe fn replace_run(module: LLVMModuleRef, context: LLVMContextRef, builder: LLVMBuilderRef, alloca: LLVMValueRef, run: &[(LLVMValueRef, u64, Vec<u8>)]) {
    let bytes: Vec<u8> = run.iter().flat_map(|(_, _, b)| b.iter().copied()).collect();

    if run.len() < 2 || !is_text(&bytes) {
        return;
    }

    unsafe {
        let data = LLVMConstStringInContext(context, bytes.as_ptr() as *const _, bytes.len() as u32, 1);
        let global = LLVMAddGlobal(module, LLVMTypeOf(data), c"stack_string".as_ptr());
        LLVMSetInitializer(global, data);
        LLVMSetGlobalConstant(global, 1);
        LLVMSetLinkage(global, LLVMLinkage::LLVMPrivateLinkage);
        LLVMSetUnnamedAddress(global, LLVMUnnamedAddr::LLVMGlobalUnnamedAddr);

        let (last, ..) = run.last().unwrap();
        LLVMPositionBuilderBefore(builder, *last);

        let i8 = LLVMInt8TypeInContext(context);
        let i64 = LLVMInt64TypeInContext(context);
        let mut index = [LLVMConstInt(i64, run[0].1, 0)];
        let destination = if run[0].1 == 0 { alloca } else { LLVMBuildInBoundsGEP2(builder, i8, alloca, index.as_mut_ptr(), 1, c"".as_ptr()) };

        let call = LLVMBuildMemCpy(builder, destination, 1, global, 1, LLVMConstInt(i64, bytes.len() as u64, 0));
        LLVMSetOperand(call, 3, LLVMConstInt(LLVMInt1TypeInContext(context), 1, 0));
        LLVMInstructionSetDebugLoc(call, LLVMInstructionGetDebugLoc(*last));

        for (store, ..) in run.iter() {
            let pointer = LLVMGetOperand(*store, 1);
            LLVMInstructionEraseFromParent(*store);

            if pointer != alloca && LLVMGetFirstUse(pointer).is_null() {
                LLVMInstructionEraseFromParent(pointer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(offset: u64, bytes: &[u8]) -> Access {
        return Access { offset, size: bytes.len() as u64, kind: Kind::Store(Some(bytes.to_vec())), ty: None };
    }

    fn load(offset: u64, size: u64) -> Access {
        return Access { offset, size, kind: Kind::Load, ty: None };
    }

    fn escape(offset: u64) -> Access {
        return Access { offset, size: 1, kind: Kind::Escape, ty: None };
    }

    fn spans(slots: &[Slot]) -> Vec<(u64, u64)> {
        return slots.iter().map(|s| (s.start, s.end)).collect();
    }

    #[test]
    fn slots() {
        // Scalars below the first escaping address, objects from each escaping address to the next
        let accesses = vec![load(4, 4), store(4, &[1, 0, 0, 0]), store(8, &[0; 4]), load(10, 2), escape(16), store(20, &[0; 4]), escape(32), load(40, 4)];
        assert_eq!(spans(&layout(&accesses, 48, &BTreeSet::new())), vec![(4, 8), (8, 12), (16, 32), (32, 48)]);

        // The canary slot ends the buffer below it
        let accesses = vec![load(4, 4), escape(8)];
        assert_eq!(spans(&layout(&accesses, 64, &BTreeSet::from([40]))), vec![(4, 8), (8, 40)]);

        // A string written 4 bytes at a time is one slot, not numbers
        let accesses = vec![store(0, b"libe"), store(4, b"rt\xc3\xa9"), store(8, b"!\0\0\0"), store(12, &[1, 0, 0, 0]), store(16, &[2, 0, 0, 0])];
        assert_eq!(spans(&layout(&accesses, 20, &BTreeSet::new())), vec![(0, 12), (12, 16), (16, 20)]);
    }
}
