/*
 * The registers as SSA values, built while lifting (Braun et al., Simple and Efficient Construction of Static Single
 * Assignment Form): the last value written to each register in each block is noted, a block that reads a register
 * before writing it gets a phi. The predecessors of the blocks are known once every block is lifted: the phis get
 * their operands then, the ones whose operands are all the same value are that value. LLVM has no register to
 * promote (SROA and mem2reg only see the stack frame), the IR is smaller.
 *
 * With the storage notes, the phis of the registers noted are noted at the start of their block (what mem2reg did
 * for the registers declared as debug variables), and so are the values the entry block writes to them.
 */

use super::regs::Reg;

use inkwell::llvm_sys::core::*;
use inkwell::llvm_sys::debuginfo::{LLVMDIBuilderInsertDbgValueAtEnd, LLVMDIBuilderInsertDbgValueBefore};
use inkwell::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMBuilderRef, LLVMDIBuilderRef, LLVMMetadataRef, LLVMTypeRef, LLVMValueRef};

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

/// A debug note of the value of a register at the start of a block: the builder, its variable, the location without
/// an address and the empty expression
#[derive(Clone, Copy)]
pub struct PhiNotes {
    pub builder: LLVMDIBuilderRef,
    pub location: LLVMMetadataRef,
    pub expression: LLVMMetadataRef,
}

pub struct Ssa {
    builder: LLVMBuilderRef,
    entry: LLVMBasicBlockRef,
    /// Type of each register
    types: Vec<LLVMTypeRef>,
    /// Debug variable of the registers whose values are noted
    vars: Vec<Option<LLVMMetadataRef>>,
    notes: Option<PhiNotes>,
    defs: HashMap<(LLVMBasicBlockRef, Reg), LLVMValueRef>,
    /// Phis waiting for the predecessors of their block
    incomplete: Vec<(LLVMBasicBlockRef, Reg, LLVMValueRef)>,
    /// Predecessors of each block (one per edge), known once every block is lifted
    preds: Option<HashMap<LLVMBasicBlockRef, Vec<LLVMBasicBlockRef>>>,
    /// Phis removed and the value they were
    replaced: HashMap<LLVMValueRef, LLVMValueRef>,
    /// The note of each phi, removed with it
    phi_notes: HashMap<LLVMValueRef, LLVMValueRef>,
    /// Phis getting their operands: not trivial before they have all of them
    completing: HashSet<LLVMValueRef>,
    /// The block and the register of each phi
    phi_regs: HashMap<LLVMValueRef, (LLVMBasicBlockRef, Reg)>,
}

impl Drop for Ssa {
    fn drop(&mut self) {
        unsafe { LLVMDisposeBuilder(self.builder) };
    }
}

impl Ssa {
    /// The values of the registers of a function whose entry block is the one given (it has no predecessor)
    pub fn new(entry: LLVMBasicBlockRef, types: Vec<LLVMTypeRef>, vars: Vec<Option<LLVMMetadataRef>>, notes: Option<PhiNotes>) -> Self {
        let builder = unsafe { LLVMCreateBuilderInContext(LLVMGetTypeContext(types[0])) };
        return Ssa { builder, entry, types, vars, notes, defs: HashMap::default(), incomplete: Vec::new(), preds: None, replaced: HashMap::default(), phi_notes: HashMap::default(), completing: HashSet::default(), phi_regs: HashMap::default() };
    }

    pub fn write(&mut self, block: LLVMBasicBlockRef, reg: Reg, value: LLVMValueRef) {
        self.defs.insert((block, reg), value);

        // The values written before the start of the function are where its registers are when it starts
        if let (Some(notes), Some(var), true) = (self.notes, self.vars[reg], block == self.entry) {
            unsafe { LLVMDIBuilderInsertDbgValueAtEnd(notes.builder, value, var, notes.expression, notes.location, block) };
        }
    }

    pub fn read(&mut self, block: LLVMBasicBlockRef, reg: Reg) -> LLVMValueRef {
        if let Some(&value) = self.defs.get(&(block, reg)) {
            return self.resolve(value);
        }

        let value = match self.preds.as_ref().map(|p| p.get(&block).map_or(&[][..], |p| p.as_slice())) {
            _ if block == self.entry => unsafe { LLVMGetUndef(self.types[reg]) },
            None => {
                let phi = self.phi(block, reg);
                self.incomplete.push((block, reg, phi));
                phi
            }
            Some([]) => unsafe { LLVMGetUndef(self.types[reg]) },
            Some(&[pred]) => self.read(pred, reg),
            Some(_) => {
                // Written before its operands are read: a loop reading the register finds the phi
                let phi = self.phi(block, reg);
                self.defs.insert((block, reg), phi);
                self.complete(block, reg, phi)
            }
        };

        self.defs.insert((block, reg), value);
        return value;
    }

    /// Gives their operands to the phis once every block of the function has its terminator. The predecessors of a
    /// block are in the order a depth first walk from the entry reaches it from them (the first successor followed
    /// first), as mem2reg gives them: the passes that follow see the IR they saw from it.
    pub fn finish(&mut self, function: LLVMValueRef) {
        let mut preds: HashMap<LLVMBasicBlockRef, Vec<LLVMBasicBlockRef>> = HashMap::default();
        let succs = |block: LLVMBasicBlockRef| -> Vec<LLVMBasicBlockRef> {
            unsafe {
                let terminator = LLVMGetBasicBlockTerminator(block);
                (0..if terminator.is_null() { 0 } else { LLVMGetNumSuccessors(terminator) }).map(|i| LLVMGetSuccessor(terminator, i)).collect()
            }
        };

        let mut visited: HashSet<LLVMBasicBlockRef> = HashSet::default();
        let mut work: Vec<(LLVMBasicBlockRef, LLVMBasicBlockRef)> = vec![(self.entry, std::ptr::null_mut())];

        while let Some((mut block, mut pred)) = work.pop() {
            loop {
                if !pred.is_null() {
                    let edges = succs(pred).into_iter().filter(|&s| s == block).count();
                    preds.entry(block).or_default().extend(std::iter::repeat_n(pred, edges));
                }

                if !visited.insert(block) {
                    break;
                }

                let mut next: Vec<LLVMBasicBlockRef> = Vec::new();

                for succ in succs(block) {
                    if !next.contains(&succ) {
                        next.push(succ);
                    }
                }

                let Some((&first, rest)) = next.split_first() else {
                    break;
                };

                work.extend(rest.iter().map(|&succ| (succ, block)));
                pred = block;
                block = first;
            }
        }

        // The edges from the blocks no path reaches
        unsafe {
            let mut block = LLVMGetFirstBasicBlock(function);

            while !block.is_null() {
                if !visited.contains(&block) {
                    for succ in succs(block) {
                        preds.entry(succ).or_default().push(block);
                    }
                }

                block = LLVMGetNextBasicBlock(block);
            }
        }

        self.preds = Some(preds);

        for (block, reg, phi) in std::mem::take(&mut self.incomplete) {
            self.complete(block, reg, phi);
        }

        for &phi in self.replaced.keys() {
            unsafe {
                if let Some(note) = self.phi_notes.remove(&phi) {
                    LLVMInstructionEraseFromParent(note);
                }

                LLVMInstructionEraseFromParent(phi);
            }

            self.phi_regs.remove(&phi);
        }

        self.replaced.clear();
        self.order_phis();
    }

    /// The phis of each block in the order of their registers
    fn order_phis(&mut self) {
        let mut phis: HashMap<LLVMBasicBlockRef, Vec<(Reg, LLVMValueRef)>> = HashMap::default();

        for (&phi, &(block, reg)) in self.phi_regs.iter() {
            phis.entry(block).or_default().push((reg, phi));
        }

        for (block, mut list) in phis {
            if list.len() < 2 {
                continue;
            }

            list.sort_by_key(|&(reg, _)| reg);

            unsafe {
                for &(_, phi) in list.iter().rev() {
                    LLVMInstructionRemoveFromParent(phi);
                    LLVMPositionBuilderBefore(self.builder, LLVMGetFirstInstruction(block));
                    LLVMInsertIntoBuilder(self.builder, phi);
                }
            }
        }
    }

    fn resolve(&self, mut value: LLVMValueRef) -> LLVMValueRef {
        while let Some(&next) = self.replaced.get(&value) {
            value = next;
        }

        return value;
    }

    /// A phi at the start of a block, noted when its register is
    fn phi(&mut self, block: LLVMBasicBlockRef, reg: Reg) -> LLVMValueRef {
        unsafe {
            let first = LLVMGetFirstInstruction(block);

            if first.is_null() {
                LLVMPositionBuilderAtEnd(self.builder, block);
            } else {
                LLVMPositionBuilderBefore(self.builder, first);
            }

            let phi = LLVMBuildPhi(self.builder, self.types[reg], c"".as_ptr());
            self.phi_regs.insert(phi, (block, reg));

            if let (Some(notes), Some(var)) = (self.notes, self.vars[reg]) {
                let mut after = LLVMGetNextInstruction(phi);

                while !after.is_null() && !LLVMIsAPHINode(after).is_null() {
                    after = LLVMGetNextInstruction(after);
                }

                let note = match after.is_null() {
                    true => LLVMDIBuilderInsertDbgValueAtEnd(notes.builder, phi, var, notes.expression, notes.location, block),
                    false => LLVMDIBuilderInsertDbgValueBefore(notes.builder, phi, var, notes.expression, notes.location, after),
                };

                self.phi_notes.insert(phi, note);
            }

            return phi;
        }
    }

    /// The operands of a phi, the value of the register at the end of each predecessor
    fn complete(&mut self, block: LLVMBasicBlockRef, reg: Reg, phi: LLVMValueRef) -> LLVMValueRef {
        let preds = self.preds.as_ref().and_then(|p| p.get(&block)).cloned().unwrap_or_default();
        self.completing.insert(phi);

        for pred in preds {
            let mut value = self.read(pred, reg);
            let mut from = pred;
            unsafe { LLVMAddIncoming(phi, &mut value, &mut from, 1) };
        }

        self.completing.remove(&phi);
        return self.remove_trivial(phi);
    }

    /// A phi whose operands are one value (or itself) is that value, the phis using it may become trivial too
    fn remove_trivial(&mut self, phi: LLVMValueRef) -> LLVMValueRef {
        if self.replaced.contains_key(&phi) {
            return self.resolve(phi);
        }

        if self.completing.contains(&phi) {
            return phi;
        }

        let mut same: Option<LLVMValueRef> = None;

        unsafe {
            for i in 0..LLVMCountIncoming(phi) {
                let operand = LLVMGetIncomingValue(phi, i);

                if Some(operand) == same || operand == phi {
                    continue;
                }

                if same.is_some() {
                    return phi;
                }

                same = Some(operand);
            }

            let same = same.unwrap_or_else(|| LLVMGetUndef(LLVMTypeOf(phi)));
            let mut users = Vec::new();
            let mut used = LLVMGetFirstUse(phi);

            while !used.is_null() {
                let user = LLVMGetUser(used);

                if user != phi && !LLVMIsAPHINode(user).is_null() {
                    users.push(user);
                }

                used = LLVMGetNextUse(used);
            }

            // Erased once every phi is complete: the memory of an erased one would be the next one's
            LLVMReplaceAllUsesWith(phi, same);
            self.replaced.insert(phi, same);

            for user in users {
                self.remove_trivial(user);
            }

            return self.resolve(same);
        }
    }
}
