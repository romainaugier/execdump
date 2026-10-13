/*
 * Read-only view of an optimized LLVM function, in plain data for the C backend
 * (values in an arena, constant expressions like ptrtoint (ptr @g to i64) are values too)
 */

use crate::lift::decode_location;

use inkwell::llvm_sys::core::*;
use inkwell::llvm_sys::prelude::{LLVMBasicBlockRef, LLVMModuleRef, LLVMTypeRef, LLVMValueRef};
use inkwell::llvm_sys::target::{LLVMABISizeOfType, LLVMGetModuleDataLayout, LLVMOffsetOfElement};
use inkwell::llvm_sys::{LLVMIntPredicate, LLVMOpcode, LLVMRealPredicate, LLVMTypeKind};
use inkwell::module::Module;
use inkwell::values::{AsValueRef, FunctionValue};

use std::collections::HashMap;

pub type ValueId = usize;
pub type BlockId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Int(u32),
    Float(u32),
    Ptr,
    Void,
    Other,
}

impl Ty {
    pub fn bits(&self) -> u32 {
        return match self {
            Ty::Int(bits) | Ty::Float(bits) => *bits,
            Ty::Ptr => 64,
            _ => 0,
        };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pred {
    Eq,
    Ne,
    Ugt,
    Uge,
    Ult,
    Ule,
    Sgt,
    Sge,
    Slt,
    Sle,
    /// Floating point predicates: ordered (false on NaN) or unordered (true on NaN)
    Float { op: FloatCmp, ordered: bool },
    True,
    False,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatCmp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Ord,
    Uno,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    Shl,
    LShr,
    AShr,
    And,
    Or,
    Xor,
    FAdd,
    FSub,
    FMul,
    FDiv,
    FRem,
    FNeg,
    Trunc,
    ZExt,
    SExt,
    FPTrunc,
    FPExt,
    FPToSI,
    FPToUI,
    SIToFP,
    UIToFP,
    PtrToInt,
    IntToPtr,
    BitCast,
    ICmp,
    FCmp,
    Select,
    Phi,
    Load,
    Store,
    Gep,
    Call,
    Ret,
    Br,
    Switch,
    Unreachable,
    ExtractValue,
    Freeze,
    Alloca,
    Other,
}

#[derive(Clone, Debug)]
pub enum ValueKind {
    Param(usize),
    Int(i128),
    Float(f64),
    Undef,
    Global(String),
    Function(String),
    /// Instruction, or constant expression (block None)
    Inst {
        op: Op,
        operands: Vec<ValueId>,
        /// Successors (br, switch) or incoming blocks (phi)
        blocks: Vec<BlockId>,
        pred: Option<Pred>,
        /// Call: name of the callee when it is direct, inline assembly is "asm"
        callee: Option<String>,
        /// Byte scale of each GEP index, extractvalue indices
        scales: Vec<i64>,
        block: Option<BlockId>,
        addr: Option<u64>,
        nsw: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Value {
    pub kind: ValueKind,
    pub ty: Ty,
    pub name: String,
    pub uses: Vec<ValueId>,
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub insts: Vec<ValueId>,
    pub succs: Vec<BlockId>,
    pub preds: Vec<BlockId>,
}

/// What an alloca holds: a scalar, or bytes (a buffer of the stack frame)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocated {
    Scalar(Ty),
    Bytes(u64),
}

#[derive(Clone, Debug)]
pub struct Func {
    pub name: String,
    pub params: Vec<ValueId>,
    pub ret: Ty,
    pub variadic: bool,
    pub values: Vec<Value>,
    pub blocks: Vec<Block>,
    pub allocated: HashMap<ValueId, Allocated>,
    /// Bytes of the constant globals made by the optimizations (strings written on the stack)
    pub data: HashMap<String, Vec<u8>>,
}

impl Func {
    pub fn inst(&self, id: ValueId) -> Option<(Op, &[ValueId])> {
        return match &self.values[id].kind {
            ValueKind::Inst { op, operands, .. } => Some((*op, operands.as_slice())),
            _ => None,
        };
    }

    pub fn op(&self, id: ValueId) -> Option<Op> {
        return self.inst(id).map(|(op, _)| op);
    }

    pub fn int(&self, id: ValueId) -> Option<i128> {
        return match self.values[id].kind {
            ValueKind::Int(value) => Some(value),
            _ => None,
        };
    }

    pub fn addr(&self, id: ValueId) -> Option<u64> {
        return match self.values[id].kind {
            ValueKind::Inst { addr, .. } => addr,
            _ => None,
        };
    }

    pub fn block_of(&self, id: ValueId) -> Option<BlockId> {
        return match self.values[id].kind {
            ValueKind::Inst { block, .. } => block,
            _ => None,
        };
    }

    pub fn is_constant(&self, id: ValueId) -> bool {
        return match &self.values[id].kind {
            ValueKind::Int(_) | ValueKind::Float(_) | ValueKind::Undef | ValueKind::Global(_) | ValueKind::Function(_) => true,
            ValueKind::Inst { block: None, .. } => true,
            _ => false,
        };
    }
}

fn opcode(op: LLVMOpcode) -> Op {
    use LLVMOpcode::*;

    return match op {
        LLVMAdd => Op::Add,
        LLVMSub => Op::Sub,
        LLVMMul => Op::Mul,
        LLVMUDiv => Op::UDiv,
        LLVMSDiv => Op::SDiv,
        LLVMURem => Op::URem,
        LLVMSRem => Op::SRem,
        LLVMShl => Op::Shl,
        LLVMLShr => Op::LShr,
        LLVMAShr => Op::AShr,
        LLVMAnd => Op::And,
        LLVMOr => Op::Or,
        LLVMXor => Op::Xor,
        LLVMFAdd => Op::FAdd,
        LLVMFSub => Op::FSub,
        LLVMFMul => Op::FMul,
        LLVMFDiv => Op::FDiv,
        LLVMFRem => Op::FRem,
        LLVMFNeg => Op::FNeg,
        LLVMTrunc => Op::Trunc,
        LLVMZExt => Op::ZExt,
        LLVMSExt => Op::SExt,
        LLVMFPTrunc => Op::FPTrunc,
        LLVMFPExt => Op::FPExt,
        LLVMFPToSI => Op::FPToSI,
        LLVMFPToUI => Op::FPToUI,
        LLVMSIToFP => Op::SIToFP,
        LLVMUIToFP => Op::UIToFP,
        LLVMPtrToInt => Op::PtrToInt,
        LLVMIntToPtr => Op::IntToPtr,
        LLVMBitCast => Op::BitCast,
        LLVMICmp => Op::ICmp,
        LLVMFCmp => Op::FCmp,
        LLVMSelect => Op::Select,
        LLVMPHI => Op::Phi,
        LLVMLoad => Op::Load,
        LLVMStore => Op::Store,
        LLVMGetElementPtr => Op::Gep,
        LLVMCall => Op::Call,
        LLVMRet => Op::Ret,
        LLVMBr => Op::Br,
        LLVMSwitch => Op::Switch,
        LLVMUnreachable => Op::Unreachable,
        LLVMExtractValue => Op::ExtractValue,
        LLVMFreeze => Op::Freeze,
        LLVMAlloca => Op::Alloca,
        _ => Op::Other,
    };
}

fn int_predicate(p: LLVMIntPredicate) -> Pred {
    use LLVMIntPredicate::*;

    return match p {
        LLVMIntEQ => Pred::Eq,
        LLVMIntNE => Pred::Ne,
        LLVMIntUGT => Pred::Ugt,
        LLVMIntUGE => Pred::Uge,
        LLVMIntULT => Pred::Ult,
        LLVMIntULE => Pred::Ule,
        LLVMIntSGT => Pred::Sgt,
        LLVMIntSGE => Pred::Sge,
        LLVMIntSLT => Pred::Slt,
        LLVMIntSLE => Pred::Sle,
    };
}

fn float_predicate(p: LLVMRealPredicate) -> Pred {
    use LLVMRealPredicate::*;

    let (op, ordered) = match p {
        LLVMRealPredicateFalse => return Pred::False,
        LLVMRealPredicateTrue => return Pred::True,
        LLVMRealOEQ => (FloatCmp::Eq, true),
        LLVMRealOGT => (FloatCmp::Gt, true),
        LLVMRealOGE => (FloatCmp::Ge, true),
        LLVMRealOLT => (FloatCmp::Lt, true),
        LLVMRealOLE => (FloatCmp::Le, true),
        LLVMRealONE => (FloatCmp::Ne, true),
        LLVMRealORD => (FloatCmp::Ord, true),
        LLVMRealUNO => (FloatCmp::Uno, false),
        LLVMRealUEQ => (FloatCmp::Eq, false),
        LLVMRealUGT => (FloatCmp::Gt, false),
        LLVMRealUGE => (FloatCmp::Ge, false),
        LLVMRealULT => (FloatCmp::Lt, false),
        LLVMRealULE => (FloatCmp::Le, false),
        LLVMRealUNE => (FloatCmp::Ne, false),
    };

    return Pred::Float { op, ordered };
}

struct Reader {
    module: LLVMModuleRef,
    values: Vec<Value>,
    ids: HashMap<LLVMValueRef, ValueId>,
    blocks: HashMap<LLVMBasicBlockRef, BlockId>,
    params: Vec<LLVMValueRef>,
    data: HashMap<String, Vec<u8>>,
}

unsafe fn name(value: LLVMValueRef) -> String {
    let mut length = 0;
    let pointer = unsafe { LLVMGetValueName2(value, &mut length) };

    if pointer.is_null() {
        return String::new();
    }

    let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, length) };

    return String::from_utf8_lossy(bytes).to_string();
}

unsafe fn type_ty(ty: LLVMTypeRef) -> Ty {
    return match unsafe { LLVMGetTypeKind(ty) } {
        LLVMTypeKind::LLVMIntegerTypeKind => Ty::Int(unsafe { LLVMGetIntTypeWidth(ty) }),
        LLVMTypeKind::LLVMFloatTypeKind => Ty::Float(32),
        LLVMTypeKind::LLVMDoubleTypeKind => Ty::Float(64),
        LLVMTypeKind::LLVMHalfTypeKind => Ty::Float(16),
        LLVMTypeKind::LLVMX86_FP80TypeKind => Ty::Float(80),
        LLVMTypeKind::LLVMPointerTypeKind => Ty::Ptr,
        LLVMTypeKind::LLVMVoidTypeKind => Ty::Void,
        _ => Ty::Other,
    };
}

impl Reader {
    unsafe fn ty(&self, value: LLVMValueRef) -> Ty {
        return unsafe { type_ty(LLVMTypeOf(value)) };
    }

    fn add(&mut self, raw: LLVMValueRef, value: Value) -> ValueId {
        let id = self.values.len();
        self.values.push(value);
        self.ids.insert(raw, id);
        return id;
    }

    /// Value id of an operand, constants are read the first time they are seen
    unsafe fn value(&mut self, raw: LLVMValueRef) -> ValueId {
        if let Some(&id) = self.ids.get(&raw) {
            return id;
        }

        let ty = unsafe { self.ty(raw) };
        let name = unsafe { name(raw) };

        let kind = unsafe {
            if let Some(index) = self.params.iter().position(|&p| p == raw) {
                ValueKind::Param(index)
            } else if !LLVMIsAConstantInt(raw).is_null() {
                let bits = LLVMGetIntTypeWidth(LLVMTypeOf(raw));
                let value = if bits <= 64 { LLVMConstIntGetSExtValue(raw) as i128 } else { LLVMConstIntGetZExtValue(raw) as i128 };
                ValueKind::Int(value)
            } else if !LLVMIsAConstantFP(raw).is_null() {
                let mut lost = 0;
                ValueKind::Float(LLVMConstRealGetDouble(raw, &mut lost))
            } else if LLVMIsUndef(raw) != 0 || LLVMIsPoison(raw) != 0 {
                ValueKind::Undef
            } else if !LLVMIsAConstantPointerNull(raw).is_null() {
                ValueKind::Int(0)
            } else if !LLVMIsAFunction(raw).is_null() {
                ValueKind::Function(name.clone())
            } else if !LLVMIsAGlobalVariable(raw).is_null() {
                let init = LLVMGetInitializer(raw);

                if LLVMIsGlobalConstant(raw) != 0 && !init.is_null() && !LLVMIsAConstantDataSequential(init).is_null() && LLVMIsConstantString(init) != 0 {
                    let mut length = 0;
                    let bytes = LLVMGetAsString(init, &mut length);
                    self.data.insert(name.clone(), std::slice::from_raw_parts(bytes as *const u8, length).to_vec());
                }

                ValueKind::Global(name.clone())
            } else if !LLVMIsAConstantExpr(raw).is_null() {
                // Operands are read after the value is registered (constant expressions are trees)
                let id = self.add(raw, Value { kind: ValueKind::Undef, ty, name: String::new(), uses: Vec::new() });
                let operands: Vec<ValueId> = (0..LLVMGetNumOperands(raw) as u32).map(|i| self.value(LLVMGetOperand(raw, i))).collect();
                let op = opcode(LLVMGetConstOpcode(raw));
                let scales = if op == Op::Gep { self.gep_scales(raw) } else { Vec::new() };

                self.values[id].kind = ValueKind::Inst { op, operands, blocks: Vec::new(), pred: None, callee: None, scales, block: None, addr: None, nsw: false };
                return id;
            } else if !LLVMIsAInlineAsm(raw).is_null() {
                ValueKind::Function("asm".to_string())
            } else {
                ValueKind::Undef
            }
        };

        return self.add(raw, Value { kind, ty, name, uses: Vec::new() });
    }

    /// Byte scale of each index of a GEP (its source element type, then the nested arrays)
    unsafe fn gep_scales(&self, raw: LLVMValueRef) -> Vec<i64> {
        unsafe {
            let layout = LLVMGetModuleDataLayout(self.module);
            let mut ty = LLVMGetGEPSourceElementType(raw);
            let mut scales = vec![LLVMABISizeOfType(layout, ty) as i64];

            for i in 2..LLVMGetNumOperands(raw) as u32 {
                match LLVMGetTypeKind(ty) {
                    LLVMTypeKind::LLVMArrayTypeKind => {
                        ty = LLVMGetElementType(ty);
                        scales.push(LLVMABISizeOfType(layout, ty) as i64);
                    }
                    LLVMTypeKind::LLVMStructTypeKind => {
                        // Struct indices are constants: the scale gives the field offset once multiplied by the index
                        let index = LLVMConstIntGetZExtValue(LLVMGetOperand(raw, i)) as u32;
                        let offset = LLVMOffsetOfElement(layout, ty, index) as i64;
                        scales.push(if index == 0 { 0 } else { offset / index as i64 });
                        ty = LLVMStructGetTypeAtIndex(ty, index);
                    }
                    _ => scales.push(1),
                }
            }

            return scales;
        }
    }

    /// Address of the machine instruction an instruction comes from (its debug location)
    unsafe fn address(&self, raw: LLVMValueRef) -> Option<u64> {
        unsafe {
            let location = inkwell::llvm_sys::debuginfo::LLVMInstructionGetDebugLoc(raw);

            if location.is_null() {
                return None;
            }

            return decode_location(inkwell::llvm_sys::debuginfo::LLVMDILocationGetLine(location), inkwell::llvm_sys::debuginfo::LLVMDILocationGetColumn(location));
        }
    }
}

/// Reads an LLVM function (instructions in block order, operands resolved)
pub fn read(module: &Module, function: FunctionValue) -> Func {
    unsafe {
        let raw = function.as_value_ref();

        let params: Vec<LLVMValueRef> = (0..LLVMCountParams(raw)).map(|i| LLVMGetParam(raw, i)).collect();
        let mut reader = Reader { module: module.as_mut_ptr(), values: Vec::new(), ids: HashMap::new(), blocks: HashMap::new(), params: params.clone(), data: HashMap::new() };
        let mut allocated = HashMap::new();

        let param_ids: Vec<ValueId> = params.iter().map(|&p| reader.value(p)).collect();

        let mut raw_blocks = Vec::new();
        let mut block = LLVMGetFirstBasicBlock(raw);

        while !block.is_null() {
            reader.blocks.insert(block, raw_blocks.len());
            raw_blocks.push(block);
            block = LLVMGetNextBasicBlock(block);
        }

        let mut blocks: Vec<Block> = vec![Block::default(); raw_blocks.len()];

        // Instructions first (operands can refer to instructions defined later, like phis)
        for (index, &block) in raw_blocks.iter().enumerate() {
            let mut inst = LLVMGetFirstInstruction(block);

            while !inst.is_null() {
                let ty = reader.ty(inst);
                let id = reader.add(inst, Value { kind: ValueKind::Undef, ty, name: name(inst), uses: Vec::new() });
                blocks[index].insts.push(id);
                inst = LLVMGetNextInstruction(inst);
            }
        }

        for (index, &block) in raw_blocks.iter().enumerate() {
            let mut inst = LLVMGetFirstInstruction(block);

            while !inst.is_null() {
                let id = reader.ids[&inst];
                let op = opcode(LLVMGetInstructionOpcode(inst));
                let mut operands = Vec::new();
                let mut targets = Vec::new();
                let mut callee = None;
                let mut scales = Vec::new();

                match op {
                    Op::Phi => {
                        for i in 0..LLVMCountIncoming(inst) {
                            operands.push(reader.value(LLVMGetIncomingValue(inst, i)));
                            targets.push(reader.blocks[&LLVMGetIncomingBlock(inst, i)]);
                        }
                    }
                    Op::Br | Op::Switch => {
                        for i in 0..LLVMGetNumOperands(inst) as u32 {
                            let operand = LLVMGetOperand(inst, i);

                            if LLVMValueIsBasicBlock(operand) == 0 {
                                operands.push(reader.value(operand));
                            }
                        }

                        for i in 0..LLVMGetNumSuccessors(inst) {
                            targets.push(reader.blocks[&LLVMGetSuccessor(inst, i)]);
                        }
                    }
                    Op::Call => {
                        let called = LLVMGetCalledValue(inst);
                        let count = LLVMGetNumArgOperands(inst);
                        operands = (0..count).map(|i| reader.value(LLVMGetOperand(inst, i))).collect();

                        callee = Some(if !LLVMIsAInlineAsm(called).is_null() {
                            "asm".to_string()
                        } else if !LLVMIsAFunction(called).is_null() {
                            name(called)
                        } else {
                            // Indirect call: the target is the last operand
                            operands.push(reader.value(called));
                            String::new()
                        });
                    }
                    _ => {
                        operands = (0..LLVMGetNumOperands(inst) as u32).map(|i| reader.value(LLVMGetOperand(inst, i))).collect();

                        if op == Op::Gep {
                            scales = reader.gep_scales(inst);
                        } else if op == Op::ExtractValue {
                            let count = LLVMGetNumIndices(inst);
                            let indices = std::slice::from_raw_parts(LLVMGetIndices(inst), count as usize);
                            scales = indices.iter().map(|&i| i as i64).collect();
                        }
                    }
                }

                let pred = match op {
                    Op::ICmp => Some(int_predicate(LLVMGetICmpPredicate(inst))),
                    Op::FCmp => Some(float_predicate(LLVMGetFCmpPredicate(inst))),
                    _ => None,
                };

                if op == Op::Alloca {
                    let ty = LLVMGetAllocatedType(inst);

                    let kind = match type_ty(ty) {
                        Ty::Other => Allocated::Bytes(LLVMABISizeOfType(LLVMGetModuleDataLayout(reader.module), ty)),
                        scalar => Allocated::Scalar(scalar),
                    };

                    allocated.insert(id, kind);
                }

                let nsw = matches!(op, Op::Add | Op::Sub | Op::Mul | Op::Shl) && LLVMGetNSW(inst) != 0;
                let addr = reader.address(inst);

                if matches!(op, Op::Br | Op::Switch) {
                    blocks[index].succs = targets.clone();
                }

                reader.values[id].kind = ValueKind::Inst { op, operands, blocks: targets, pred, callee, scales, block: Some(index), addr, nsw };
                inst = LLVMGetNextInstruction(inst);
            }
        }

        for index in 0..blocks.len() {
            for succ in blocks[index].succs.clone() {
                if !blocks[succ].preds.contains(&index) {
                    blocks[succ].preds.push(index);
                }
            }
        }

        let mut values = reader.values;

        for id in 0..values.len() {
            if let ValueKind::Inst { operands, .. } = &values[id].kind {
                for &operand in operands.clone().iter() {
                    values[operand].uses.push(id);
                }
            }
        }

        let fn_type = LLVMGlobalGetValueType(raw);
        let ret_kind = LLVMGetTypeKind(LLVMGetReturnType(fn_type));
        let ret = match ret_kind {
            LLVMTypeKind::LLVMVoidTypeKind => Ty::Void,
            LLVMTypeKind::LLVMIntegerTypeKind => Ty::Int(LLVMGetIntTypeWidth(LLVMGetReturnType(fn_type))),
            LLVMTypeKind::LLVMFloatTypeKind => Ty::Float(32),
            LLVMTypeKind::LLVMDoubleTypeKind => Ty::Float(64),
            LLVMTypeKind::LLVMPointerTypeKind => Ty::Ptr,
            _ => Ty::Other,
        };

        return Func { name: name(raw), params: param_ids, ret, variadic: LLVMIsFunctionVarArg(fn_type) != 0, values, blocks, allocated, data: reader.data };
    }
}
