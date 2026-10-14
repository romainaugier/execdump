/*
 * Lifting of a recovered function to LLVM IR
 *
 * Every register and flag lives in an alloca and the stack frame is a single byte array, LLVM's
 * mem2reg and SROA then turn them into SSA values and local variables. The stack pointer is
 * tracked as an offset from its value at the entry, so stack accesses address the frame directly
 * (keeping the pointer provenance), the other memory accesses go through inttoptr.
 *
 * Flags are lazy: the last flag producing operation of a block is kept and the conditions that
 * follow are built from its operands (cmp eax, 5; jle -> icmp sle i32 %eax, 5), the flag bits are
 * still computed for the conditions that cross blocks and are removed by LLVM when unused.
 */

pub mod regs;
mod frame;
mod protector;
mod refine;
mod x86;
mod aarch64;

pub use frame::{fold_frame_addresses, split_frame};
pub use protector::{remove_stack_protector, Protector};
pub use refine::refine;

use crate::analysis::function::{CallTarget, EdgeKind, Function};
use crate::analysis::insn::Flow;
use crate::analysis::Analysis;

use regs::{Abi, Reg, RegRef, RegisterFile};

use execdump_core::disasm::Architecture;
use execdump_core::program::Program;

use inkwell::basic_block::BasicBlock as LlvmBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::debug_info::{AsDIScope, DIFlags, DIFlagsConstants, DIScope, DWARFEmissionKind, DWARFSourceLanguage, DebugInfoBuilder};
use inkwell::module::{FlagBehavior, Linkage, Module};
use inkwell::types::{BasicMetadataTypeEnum, BasicType, BasicTypeEnum, FunctionType};
use inkwell::types::IntType;
use inkwell::values::{AsValueRef, BasicMetadataValueEnum, BasicValue, BasicValueEnum, FloatValue, FunctionValue, GlobalValue, InstructionOpcode, InstructionValue, IntValue, PointerValue};
use inkwell::{AddressSpace, FloatPredicate, IntPredicate};

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU32;

/// Name of the globals the discovery functions store their return registers to
pub(crate) const RETURN_SINK_INT: &str = "__return_int";
pub(crate) const RETURN_SINK_FLOAT: &str = "__return_float";

/// Metadata kind of the address of the machine instruction an LLVM instruction comes from
/// Address of a machine instruction as a debug location (line, column), see Lifter::locate
pub fn encode_location(addr: u64) -> (u32, u32) {
    return (addr as u32, ((addr >> 32) & 0xffff) as u32 + 1);
}

/// Address of a debug location, None for the locations the passes made unknown (column 0)
pub fn decode_location(line: u32, column: u32) -> Option<u64> {
    return (column != 0).then(|| ((column as u64 - 1) << 32) | line as u64);
}

/*
 * Signatures
 */

/// Machine level type of a parameter or of a return value
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LType {
    Int(u32),
    Float(u32),
    Ptr,
}

/// Where a parameter or a return value is
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Loc {
    Reg(Reg),
    /// Offset from the stack pointer at the function entry
    Stack(i64),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Value {
    pub loc: Loc,
    pub ty: LType,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    /// C identifier of the function
    pub name: String,
    pub params: Vec<Value>,
    pub ret: Option<Value>,
    pub variadic: bool,
    pub noreturn: bool,
    /// Unknown parameters: a call passes the argument registers written before it
    pub guessed: bool,
    /// Registers the function may write (one bit per full register of the register file): after a call,
    /// the ones the callee does not preserve hold nothing known (compilers keep values in the others
    /// across calls to the functions they know)
    pub clobbers: u128,
}

/// The callee may write any register
pub const CLOBBERS_ALL: u128 = u128::MAX;

/// Full registers a machine instruction may write besides the flags, None when it cannot be decoded (a
/// call writes what its callee writes, the caller adds it)
pub fn written_registers(regs: &RegisterFile, cs: &capstone::Capstone, bytes: &[u8], addr: u64) -> Option<u128> {
    return match Insn::decode(regs.arch, regs, cs, bytes, addr)? {
        Insn::X86(insn) => Some(x86::written(&insn, regs)),
        Insn::Aarch64(insn) => Some(aarch64::written(&insn)),
    };
}

/// What the lifter needs to know about the program
pub struct Env<'a> {
    pub program: &'a Program,
    pub analysis: &'a Analysis,
    pub regs: &'a RegisterFile,
    pub abi: &'a Abi,
    /// Signature of a callee, computed (and cached) by the decompiler
    pub signature: &'a dyn Fn(&CallTarget) -> Signature,
    /// Name of a global variable at an address
    pub global_name: &'a dyn Fn(u64) -> String,
}

/// Signature of a function before its parameters are known: every argument register and the
/// stack slots it reads, the return registers are stored to sinks to see which ones are set
pub fn discovery_signature(name: &str, abi: &Abi, regs: &RegisterFile, stack_params: &BTreeSet<i64>) -> Signature {
    let int_bits = regs.regs[abi.int_ret].bits;
    let mut params: Vec<Value> = Vec::new();

    let int = abi.int_args.iter().map(|&r| Value { loc: Loc::Reg(r), ty: LType::Int(int_bits), name: None });
    let float = abi.float_args.iter().map(|&r| Value { loc: Loc::Reg(r), ty: LType::Int(128), name: None });

    params.extend(int);
    params.extend(float);
    params.extend(stack_params.iter().map(|&offset| Value { loc: Loc::Stack(offset), ty: LType::Int(abi.slot_size as u32 * 8), name: None }));

    return Signature { name: name.to_string(), params, ret: None, variadic: false, noreturn: false, guessed: false, clobbers: CLOBBERS_ALL };
}

/// Signature of a function nothing is known about: int f(...), with the arguments of each call guessed
pub fn guessed_signature(name: &str, abi: &Abi) -> Signature {
    let ret = Value { loc: Loc::Reg(abi.int_ret), ty: LType::Int(32), name: None };
    return Signature { name: name.to_string(), params: Vec::new(), ret: Some(ret), variadic: true, noreturn: false, guessed: true, clobbers: CLOBBERS_ALL };
}

/// Printable text: ASCII, UTF-8 characters or a few other bytes
pub fn text_bytes(bytes: &[u8]) -> bool {
    let printable = |b: &u8| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\r' | b'\t');

    if bytes.is_empty() || !bytes.iter().all(|b| printable(b) || *b >= 0x80) {
        return false;
    }

    let ascii = bytes.iter().filter(|b| printable(b)).count();
    return ascii == bytes.len() || std::str::from_utf8(bytes).is_ok() || ascii * 4 >= bytes.len() * 3;
}

/// Bytes of a printable C string at an address
pub fn text_bytes_at(program: &Program, addr: u64) -> Option<&[u8]> {
    return program.c_string_bytes(addr, 4096).filter(|bytes| text_bytes(bytes));
}

/// A printable C string at an address, as the text of a C literal (see literal)
pub fn text_at(program: &Program, addr: u64) -> Option<String> {
    return text_bytes_at(program, addr).map(literal);
}

/// Text of a C literal: one character per byte, the bytes above 0x7f are the characters U+0080 to
/// U+00FF (printed as escapes, the offsets in the string stay visible)
pub fn literal(bytes: &[u8]) -> String {
    return bytes.iter().map(|&b| b as char).collect();
}

/*
 * Decoded instructions
 */

/// Value known statically for a register
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// Address in the stack frame, as an offset from the stack pointer at the entry
    Stack(i64),
    Const(u64),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tracker {
    values: BTreeMap<Reg, Known>,
}

impl Tracker {
    pub fn get(&self, reg: Reg) -> Option<Known> {
        return self.values.get(&reg).copied();
    }

    pub fn set(&mut self, reg: Reg, value: Option<Known>) {
        match value {
            Some(value) => self.values.insert(reg, value),
            None => self.values.remove(&reg),
        };
    }

    /// Value of a register plus a displacement
    pub fn offset(&self, reg: Reg, disp: i64) -> Option<Known> {
        return match self.get(reg)? {
            Known::Stack(offset) => Some(Known::Stack(offset + disp)),
            Known::Const(value) => Some(Known::Const(value.wrapping_add(disp as u64))),
        };
    }
}

#[derive(Clone, Debug)]
pub enum Insn {
    X86(x86::Insn),
    Aarch64(aarch64::Insn),
}

/// Memory operand summary, for the stack frame analysis
#[derive(Clone, Copy, Debug)]
pub struct MemAccess {
    pub base: Option<Reg>,
    pub has_index: bool,
    pub disp: i64,
    pub bytes: u32,
}

impl Insn {
    fn decode(arch: Architecture, regs: &RegisterFile, cs: &capstone::Capstone, bytes: &[u8], addr: u64) -> Option<Insn> {
        return match arch {
            Architecture::X86 | Architecture::X86_64 => x86::decode(regs, cs, bytes, addr).map(Insn::X86),
            Architecture::Aarch64 => aarch64::decode(regs, cs, bytes, addr).map(Insn::Aarch64),
            Architecture::Unsupported => None,
        };
    }

    /// Updates the statically known register values after the instruction
    fn track(&self, regs: &RegisterFile, tracker: &mut Tracker) {
        match self {
            Insn::X86(insn) => x86::track(insn, regs, tracker),
            Insn::Aarch64(insn) => aarch64::track(insn, regs, tracker),
        }
    }

    /// Whether the instruction reads (Some(true)) or overwrites (Some(false)) a register
    pub fn register_access(&self, reg: Reg) -> Option<bool> {
        return match self {
            Insn::X86(insn) => x86::register_access(insn, reg),
            Insn::Aarch64(insn) => aarch64::register_access(insn, reg),
        };
    }

    fn memory(&self) -> Vec<MemAccess> {
        return match self {
            Insn::X86(insn) => x86::memory(insn),
            Insn::Aarch64(insn) => aarch64::memory(insn),
        };
    }
}

/// Decoded instructions and stack frame of a function
pub struct Frame {
    pub blocks: BTreeMap<u64, Vec<Insn>>,
    entry_trackers: HashMap<u64, Tracker>,
    /// Lowest and highest stack offsets used (relative to the stack pointer at the entry)
    pub low: i64,
    pub high: i64,
    /// Stack offsets read at or above the first stack argument (the stack arguments of a tail call are
    /// the ones the function received)
    pub stack_params: BTreeSet<i64>,
}

pub fn capstone(arch: Architecture) -> Result<capstone::Capstone, String> {
    use capstone::prelude::*;

    let cs = match arch {
        Architecture::X86 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        Architecture::X86_64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).detail(true).build(),
        Architecture::Aarch64 => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build(),
        Architecture::Unsupported => return Err("unsupported architecture".to_string()),
    };

    return cs.map_err(|e| e.to_string());
}

/// Decodes the function and follows the stack pointer through its blocks (in reverse post order)
pub fn analyze_frame(env: &Env, cs: &capstone::Capstone, function: &Function) -> Result<Frame, String> {
    let arch = env.program.architecture();
    let sp = env.abi.stack_pointer;

    let mut frame = Frame { blocks: BTreeMap::new(), entry_trackers: HashMap::new(), low: 0, high: 0, stack_params: BTreeSet::new() };

    for block in function.blocks.values() {
        let mut insns = Vec::new();

        for insn in block.insns.iter() {
            let bytes = env.program.read(insn.addr, insn.size as usize).ok_or_else(|| format!("cannot read {:#x}", insn.addr))?;
            insns.push(Insn::decode(arch, env.regs, cs, bytes, insn.addr).ok_or_else(|| format!("cannot decode {:#x}", insn.addr))?);
        }

        frame.blocks.insert(block.start, insns);
    }

    let mut entry = Tracker::default();
    entry.set(sp, Some(Known::Stack(0)));
    frame.entry_trackers.insert(function.addr, entry);

    for addr in reverse_post_order(function) {
        let Some(mut tracker) = frame.entry_trackers.get(&addr).cloned() else {
            continue;
        };

        for (insn, info) in frame.blocks[&addr].iter().zip(function.blocks[&addr].insns.iter()) {
            if let (Some(site), Some(Known::Stack(at))) = (function.calls.iter().find(|c| c.tail && c.addr == info.addr), tracker.get(sp)) {
                for param in (env.signature)(&site.target).params.iter() {
                    if let Loc::Stack(offset) = param.loc {
                        frame.stack_params.insert(offset + at);
                    }
                }
            }

            for access in insn.memory() {
                let Some(Known::Stack(offset)) = access.base.and_then(|b| tracker.offset(b, access.disp)) else {
                    continue;
                };

                frame.low = frame.low.min(offset);
                frame.high = frame.high.max(offset + access.bytes as i64);

                if offset >= env.abi.stack_args && !access.has_index {
                    frame.stack_params.insert(offset);
                }
            }

            insn.track(env.regs, &mut tracker);

            if let Some(Known::Stack(offset)) = tracker.get(sp) {
                frame.low = frame.low.min(offset);
            }
        }

        for edge in function.blocks[&addr].succs.iter() {
            frame.entry_trackers.entry(edge.to).or_insert_with(|| tracker.clone());
        }
    }

    return Ok(frame);
}

/// Whether a caller reads the result register after a call (or returns it), following
/// the single successors of the block for a few blocks
pub fn result_used(env: &Env, cs: &capstone::Capstone, caller: &Function, call: u64, reg: Reg) -> bool {
    let Some(mut block) = caller.block_containing(call) else {
        return true;
    };

    let mut start = call;

    for _ in 0..4 {
        for insn in block.insns.iter().filter(|i| i.addr > start) {
            let Some(bytes) = env.program.read(insn.addr, insn.size as usize) else {
                return true;
            };

            let Some(decoded) = Insn::decode(env.program.architecture(), env.regs, cs, bytes, insn.addr) else {
                return true;
            };

            match decoded.register_access(reg) {
                Some(read) => return read,
                None => {}
            }

            if matches!(insn.flow, Flow::Ret | Flow::IndirectJump) {
                return true;
            }
        }

        // Calls to functions that do not return, or blocks that end the function
        if block.succs.is_empty() {
            return !matches!(block.last().flow, Flow::Call(_));
        }

        match block.succs.as_slice() {
            [edge] => match caller.blocks.get(&edge.to) {
                Some(next) => {
                    block = next;
                    start = 0;
                }
                None => return true,
            },
            _ => return true,
        }
    }

    return true;
}

/// Address a register holds at a call, when the instruction that last writes it before the call computes
/// or loads it as a constant (lea, adrp+add, mov): in the block of the call or the ones only reaching it,
/// without a call between
pub fn argument_address(env: &Env, cs: &capstone::Capstone, caller: &Function, call: u64, reg: Reg) -> Option<u64> {
    let mut block = caller.block_containing(call)?;
    let mut end = call;

    for _ in 0..4 {
        for insn in block.insns.iter().rev().filter(|i| i.addr < end) {
            if matches!(insn.flow, Flow::Call(_) | Flow::IndirectCall) {
                return None;
            }

            let bytes = env.program.read(insn.addr, insn.size as usize)?;
            let decoded = Insn::decode(env.program.architecture(), env.regs, cs, bytes, insn.addr)?;
            let written = match &decoded {
                Insn::X86(insn) => x86::written(insn, env.regs),
                Insn::Aarch64(insn) => aarch64::written(insn),
            };

            if written >> reg & 1 == 1 || decoded.register_access(reg) == Some(false) {
                return insn.imm_ref;
            }
        }

        let [pred] = block.preds.as_slice() else {
            return None;
        };

        block = caller.blocks.get(pred)?;
        end = block.end;
    }

    return None;
}

pub fn reverse_post_order(function: &Function) -> Vec<u64> {
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    let mut stack = vec![(function.addr, 0usize)];

    visited.insert(function.addr);

    while let Some((addr, next)) = stack.pop() {
        let succs = function.blocks.get(&addr).map_or(&[][..], |b| &b.succs[..]);

        if next < succs.len() {
            stack.push((addr, next + 1));

            let to = succs[next].to;

            if function.blocks.contains_key(&to) && visited.insert(to) {
                stack.push((to, 0));
            }
        } else {
            order.push(addr);
        }
    }

    order.reverse();

    return order;
}

/*
 * Flags
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagOp {
    /// cmp, sub, subs: the operands are compared
    Sub,
    Add,
    /// and, or, xor, test: carry and overflow are cleared
    Logic,
    /// ucomisd, fcmp
    Float,
}

#[derive(Clone, Copy, Debug)]
pub struct FlagProducer<'ctx> {
    pub op: FlagOp,
    pub lhs: BasicValueEnum<'ctx>,
    pub rhs: BasicValueEnum<'ctx>,
    pub result: Option<IntValue<'ctx>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    Always,
    Eq,
    Ne,
    Slt,
    Sle,
    Sgt,
    Sge,
    Ult,
    Ule,
    Ugt,
    Uge,
    Neg,
    NonNeg,
    Overflow,
    NoOverflow,
    Parity,
    NoParity,
}

impl Cond {
    pub fn invert(self) -> Cond {
        match self {
            Cond::Always => Cond::Always,
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Slt => Cond::Sge,
            Cond::Sge => Cond::Slt,
            Cond::Sle => Cond::Sgt,
            Cond::Sgt => Cond::Sle,
            Cond::Ult => Cond::Uge,
            Cond::Uge => Cond::Ult,
            Cond::Ule => Cond::Ugt,
            Cond::Ugt => Cond::Ule,
            Cond::Neg => Cond::NonNeg,
            Cond::NonNeg => Cond::Neg,
            Cond::Overflow => Cond::NoOverflow,
            Cond::NoOverflow => Cond::Overflow,
            Cond::Parity => Cond::NoParity,
            Cond::NoParity => Cond::Parity,
        }
    }
}

/// Flag registers of an architecture
#[derive(Clone, Copy, Debug)]
struct FlagRegs {
    zero: Reg,
    sign: Reg,
    carry: Reg,
    overflow: Reg,
    parity: Option<Reg>,
    /// x86 sets the carry on a borrow, arm clears it
    carry_is_borrow: bool,
}

impl FlagRegs {
    fn new(regs: &RegisterFile) -> Self {
        return match regs.arch {
            Architecture::Aarch64 => FlagRegs {
                zero: regs.reg("z"),
                sign: regs.reg("n"),
                carry: regs.reg("c"),
                overflow: regs.reg("v"),
                parity: None,
                carry_is_borrow: false,
            },
            _ => FlagRegs {
                zero: regs.reg("zf"),
                sign: regs.reg("sf"),
                carry: regs.reg("cf"),
                overflow: regs.reg("of"),
                parity: Some(regs.reg("pf")),
                carry_is_borrow: true,
            },
        };
    }
}

/*
 * Lifter
 */

pub struct Lifter<'ctx, 'a> {
    pub cx: &'ctx Context,
    pub module: &'a Module<'ctx>,
    pub builder: Builder<'ctx>,
    pub env: &'a Env<'a>,
    pub function: &'a Function,
    pub llvm: FunctionValue<'ctx>,
    pub sig: Signature,
    regs: Vec<PointerValue<'ctx>>,
    flag_regs: FlagRegs,
    frame: PointerValue<'ctx>,
    /// Frame index of the stack pointer at the entry
    frame_base: i64,
    pub tracker: Tracker,
    pub flags: Option<FlagProducer<'ctx>>,
    /// Condition of the conditional branch ending the block
    pub branch: Option<IntValue<'ctx>>,
    /// Target of the indirect jump ending the block
    pub jump: Option<IntValue<'ctx>>,
    pub addr: u64,
    discovery: bool,
    /// Debug information builder and scope of the function (the addresses of its instructions)
    debug: Option<(DebugInfoBuilder<'ctx>, DIScope<'ctx>)>,
    /// Registers written and not read since the last call, with the width written
    written: RefCell<BTreeMap<Reg, u32>>,
    /// Written registers at the end of the lifted blocks, merged at the start of their successors
    written_out: HashMap<u64, BTreeMap<Reg, u32>>,
    /// Instructions of the last flag producer whose flags have not been read yet: dead when the
    /// next producer of the same block overwrites them (keeps the IR to optimize small)
    unread_flags: RefCell<Vec<InstructionValue<'ctx>>>,
    /// Flag computations found dead, erased at the end of the block
    dead_flags: RefCell<Vec<InstructionValue<'ctx>>>,
    /// Whether the current block produced flags, and read the stored ones before
    produced_flags: Cell<bool>,
    reads_flags: Cell<bool>,
    /// Flags of the lifted blocks, to remove the unread computations of their last producer
    block_flags: HashMap<u64, BlockFlags<'ctx>>,
}

struct BlockFlags<'ctx> {
    produces: bool,
    /// The stored flags are read before the block produces its own
    reads_on_entry: bool,
    /// Instructions of the last producer, unread in the block
    tail: Vec<InstructionValue<'ctx>>,
}

/// Lifts a function into a module, with its signature or the discovery one
pub fn lift<'ctx>(cx: &'ctx Context, module: &Module<'ctx>, env: &Env, function: &Function, frame: &Frame, sig: Signature, discovery: bool) -> Result<FunctionValue<'ctx>, String> {
    let fn_type = function_type(cx, &sig, discovery);
    let llvm = module.get_function(&sig.name).unwrap_or_else(|| module.add_function(&sig.name, fn_type, None));

    let builder = cx.create_builder();
    let entry = cx.append_basic_block(llvm, "entry");

    // The discovery of a signature does not need the addresses
    let debug = (!discovery).then(|| debug_info(cx, module, llvm, &sig.name));
    builder.position_at_end(entry);

    // The stack frame belongs to the first instruction
    if let Some((debug, scope)) = debug.as_ref() {
        let (line, column) = encode_location(function.addr);
        builder.set_current_debug_location(debug.create_debug_location(cx, line, column, *scope, None));
    }

    let regs: Vec<PointerValue> = env.regs.regs.iter().map(|r| builder.build_alloca(int_type(cx, r.bits), r.name).unwrap()).collect();

    let frame_size = (frame.high - frame.low).max(1) as u32;
    let frame_ptr = builder.build_alloca(cx.i8_type().array_type(frame_size), "frame").map_err(|e| e.to_string())?;

    let mut lifter = Lifter {
        cx,
        module,
        builder,
        env,
        function,
        llvm,
        sig: sig.clone(),
        regs,
        flag_regs: FlagRegs::new(env.regs),
        frame: frame_ptr,
        frame_base: -frame.low,
        tracker: Tracker::default(),
        flags: None,
        branch: None,
        jump: None,
        addr: function.addr,
        discovery,
        debug,
        written: RefCell::new(BTreeMap::new()),
        written_out: HashMap::new(),
        unread_flags: RefCell::new(Vec::new()),
        dead_flags: RefCell::new(Vec::new()),
        produced_flags: Cell::new(false),
        reads_flags: Cell::new(false),
        block_flags: HashMap::new(),
    };

    lifter.lift_entry()?;

    let blocks: HashMap<u64, LlvmBlock> = function.blocks.keys().map(|&a| (a, cx.append_basic_block(llvm, &format!("bb_{:x}", a)))).collect();

    lifter.builder.build_unconditional_branch(blocks[&function.addr]).map_err(|e| e.to_string())?;

    for addr in reverse_post_order(function) {
        let Some(tracker) = frame.entry_trackers.get(&addr) else {
            continue;
        };

        lifter.builder.position_at_end(blocks[&addr]);
        lifter.tracker = tracker.clone();
        lifter.lift_block(addr, &frame.blocks[&addr], &blocks)?;

        let tail = std::mem::take(&mut *lifter.unread_flags.borrow_mut());
        lifter.block_flags.insert(addr, BlockFlags { produces: lifter.produced_flags.get(), reads_on_entry: lifter.reads_flags.get(), tail });
    }

    lifter.drop_unread_tail_flags();

    if let Some((builder, _)) = lifter.debug.as_ref() {
        builder.finalize();
    }

    // Blocks the reverse post order did not reach (only reachable through unresolved jumps)
    for block in blocks.values() {
        if block.get_terminator().is_none() {
            lifter.builder.position_at_end(*block);
            lifter.builder.build_unreachable().map_err(|e| e.to_string())?;
        }
    }

    return Ok(llvm);
}

/// Debug information of a lifted function: a compile unit and a subprogram, the scope of the locations
fn debug_info<'ctx>(cx: &'ctx Context, module: &Module<'ctx>, function: FunctionValue<'ctx>, name: &str) -> (DebugInfoBuilder<'ctx>, DIScope<'ctx>) {
    if module.get_flag("Debug Info Version").is_none() {
        module.add_basic_value_flag("Debug Info Version", FlagBehavior::Warning, cx.i32_type().const_int(3, false));
    }

    let (builder, unit) = module.create_debug_info_builder(
        true,
        DWARFSourceLanguage::C,
        "binary",
        ".",
        "execdump",
        true,
        "",
        0,
        "",
        DWARFEmissionKind::LineTablesOnly,
        0,
        false,
        false,
        "",
        "",
    );

    let file = unit.get_file();
    let ty = builder.create_subroutine_type(file, None, &[], DIFlags::ZERO);
    let subprogram = builder.create_function(unit.as_debug_info_scope(), name, None, file, 0, ty, false, true, 0, DIFlags::ZERO, true);
    function.set_subprogram(subprogram);

    return (builder, subprogram.as_debug_info_scope());
}

fn function_type<'ctx>(cx: &'ctx Context, sig: &Signature, discovery: bool) -> FunctionType<'ctx> {
    let params: Vec<BasicMetadataTypeEnum> = sig.params.iter().map(|p| llvm_type(cx, p.ty).into()).collect();

    return match (&sig.ret, discovery) {
        (Some(ret), false) => llvm_type(cx, ret.ty).fn_type(&params, sig.variadic),
        _ => cx.void_type().fn_type(&params, sig.variadic),
    };
}

pub fn int_type(cx: &Context, bits: u32) -> IntType<'_> {
    return cx.custom_width_int_type(NonZeroU32::new(bits).expect("integers have a width")).expect("valid integer width");
}

pub fn llvm_type(cx: &Context, ty: LType) -> BasicTypeEnum<'_> {
    return match ty {
        LType::Int(bits) => int_type(cx, bits).into(),
        LType::Float(32) => cx.f32_type().into(),
        LType::Float(_) => cx.f64_type().into(),
        LType::Ptr => cx.ptr_type(AddressSpace::default()).into(),
    };
}

macro_rules! llvm {
    ($e:expr) => {
        $e.map_err(|e| e.to_string())?
    };
}

pub(crate) use llvm;

impl<'ctx> Lifter<'ctx, '_> {
    pub fn int(&self, bits: u32) -> IntType<'ctx> {
        return int_type(self.cx, bits);
    }

    pub fn constant(&self, bits: u32, value: u64) -> IntValue<'ctx> {
        return self.int(bits).const_int(value, false);
    }

    pub fn ptr_type(&self) -> inkwell::types::PointerType<'ctx> {
        return self.cx.ptr_type(AddressSpace::default());
    }

    fn pointer_bits(&self) -> u32 {
        return self.env.program.pointer_size as u32 * 8;
    }

    /// Parameters to their locations, the stack pointer to the frame
    fn lift_entry(&mut self) -> Result<(), String> {
        let sp = self.env.abi.stack_pointer;
        let sp_value = self.stack_value(0)?;
        llvm!(self.builder.build_store(self.regs[sp], sp_value));

        for (index, param) in self.sig.params.clone().iter().enumerate() {
            let value = self.llvm.get_nth_param(index as u32).ok_or("missing parameter")?;

            if let Some(name) = &param.name {
                value.set_name(name);
            }

            match param.loc {
                Loc::Reg(reg) => {
                    let bits = self.env.regs.regs[reg].bits;
                    let value = self.to_int(value, bits)?;
                    llvm!(self.builder.build_store(self.regs[reg], value));
                }
                Loc::Stack(offset) => {
                    let ptr = self.frame_ptr(offset)?;
                    llvm!(self.builder.build_store(ptr, value));
                }
            }
        }

        return Ok(());
    }

    fn lift_block(&mut self, addr: u64, insns: &[Insn], blocks: &HashMap<u64, LlvmBlock<'ctx>>) -> Result<(), String> {
        let block = &self.function.blocks[&addr];

        self.flags = None;
        self.branch = None;
        self.jump = None;
        self.produced_flags.set(false);
        self.reads_flags.set(false);

        // The registers written on every path to the block are call argument candidates (on some paths
        // only, a register can be the value the function received)
        let mut written: Option<BTreeMap<Reg, u32>> = None;

        for pred in block.preds.iter().filter_map(|p| self.written_out.get(p)) {
            written = Some(match written {
                None => pred.clone(),
                Some(known) => known.into_iter().filter_map(|(r, b)| pred.get(&r).map(|&other| (r, b.max(other)))).collect(),
            });
        }

        *self.written.borrow_mut() = written.unwrap_or_default();

        for insn in insns.iter() {
            self.addr = match insn {
                Insn::X86(i) => i.addr,
                Insn::Aarch64(i) => i.addr,
            };

            self.locate(self.addr);

            match insn {
                Insn::X86(i) => x86::lift(self, i)?,
                Insn::Aarch64(i) => aarch64::lift(self, i)?,
            }

            insn.track(self.env.regs, &mut self.tracker);
        }

        for instruction in std::mem::take(&mut *self.dead_flags.borrow_mut()).into_iter().rev() {
            if instruction.get_first_use().is_none() {
                instruction.erase_from_basic_block();
            }
        }

        self.written_out.insert(addr, self.written.borrow().clone());

        let last = block.last();
        let tail = self.function.calls.iter().find(|c| c.addr == last.addr && c.tail).cloned();

        match last.flow {
            Flow::Ret => self.build_return()?,
            Flow::Trap => {
                llvm!(self.builder.build_unreachable());
            }
            // Conditional tail calls are branches (below)
            _ if tail.is_some() && !matches!(last.flow, Flow::CondJump(_)) => {
                let site = tail.unwrap();
                self.call(&site.target, self.jump, true)?;
                self.build_tail_return(&site.target)?;
            }
            Flow::CondJump(destination) => {
                let target = |kind| block.succs.iter().find(|e| e.kind == kind).and_then(|e| blocks.get(&e.to)).copied();
                let condition = self.branch.unwrap_or_else(|| self.int(1).const_zero());
                let current = self.builder.get_insert_block().ok_or("no current block")?;

                // Conditional tail calls jump to another function, the missing fall through does not return
                let on_true = match target(EdgeKind::True) {
                    Some(block) => block,
                    None => {
                        let tail = self.cx.append_basic_block(self.llvm, &format!("bb_{:x}_tail", addr));
                        self.builder.position_at_end(tail);
                        self.call(&CallTarget::Function(destination), None, true)?;
                        self.build_tail_return(&CallTarget::Function(destination))?;
                        tail
                    }
                };

                let on_false = match target(EdgeKind::False) {
                    Some(block) => block,
                    None => {
                        let missing = self.cx.append_basic_block(self.llvm, &format!("bb_{:x}_unreachable", addr));
                        self.builder.position_at_end(missing);
                        llvm!(self.builder.build_unreachable());
                        missing
                    }
                };

                self.builder.position_at_end(current);
                llvm!(self.builder.build_conditional_branch(condition, on_true, on_false));
            }
            Flow::IndirectJump if block.succs.iter().any(|e| e.kind == EdgeKind::Switch) => {
                // Jump tables: switch on the target address, the C backend turns it back into the table index
                let target = self.jump.ok_or("indirect jump without a target")?;
                let default = self.cx.append_basic_block(self.llvm, &format!("bb_{:x}_default", addr));
                let cases: Vec<(IntValue, LlvmBlock)> = block
                    .succs
                    .iter()
                    .filter_map(|e| Some((target.get_type().const_int(e.to, false), *blocks.get(&e.to)?)))
                    .collect();

                llvm!(self.builder.build_switch(target, default, &cases));

                self.builder.position_at_end(default);
                llvm!(self.builder.build_unreachable());
            }
            Flow::IndirectJump => {
                let target = self.jump.ok_or("indirect jump without a target")?;
                self.call_intrinsic("__indirect_jump", &[target.into()], None)?;
                llvm!(self.builder.build_unreachable());
            }
            _ => match block.succs.first() {
                Some(edge) if blocks.contains_key(&edge.to) => {
                    llvm!(self.builder.build_unconditional_branch(blocks[&edge.to]));
                }
                // Call to a function that does not return
                _ => {
                    llvm!(self.builder.build_unreachable());
                }
            },
        }

        return Ok(());
    }

    /// The instructions built from now on come from the machine instruction at this address. The address is
    /// their debug location (line: low 32 bits, column: the next 16 bits plus one), which the LLVM passes
    /// keep on the instructions they create from others, unlike other metadata.
    fn locate(&self, addr: u64) {
        if let Some((builder, scope)) = self.debug.as_ref() {
            let (line, column) = encode_location(addr);
            let location = builder.create_debug_location(self.cx, line, column, *scope, None);
            self.builder.set_current_debug_location(location);
        }
    }

    /// End of a tail call: the return of the callee, nothing when it does not return
    fn build_tail_return(&mut self, target: &CallTarget) -> Result<(), String> {
        if (self.env.signature)(target).noreturn {
            llvm!(self.builder.build_unreachable());
            return Ok(());
        }

        return self.build_return();
    }

    fn build_return(&mut self) -> Result<(), String> {
        if self.discovery {
            // The return registers go to sinks, the decompiler looks at what reaches them
            for (sink, reg) in [(RETURN_SINK_INT, self.env.abi.int_ret), (RETURN_SINK_FLOAT, self.env.abi.float_ret)] {
                let value = self.read(self.env.regs.full(reg))?;
                let global = self.module.get_global(sink).unwrap_or_else(|| self.module.add_global(value.get_type(), None, sink));
                llvm!(self.builder.build_store(global.as_pointer_value(), value));
            }

            llvm!(self.builder.build_return(None));
            return Ok(());
        }

        match self.sig.ret.clone() {
            Some(ret) => {
                let value = self.read_value(&ret, 0)?;
                llvm!(self.builder.build_return(Some(&value)));
            }
            None => {
                llvm!(self.builder.build_return(None));
            }
        }

        return Ok(());
    }

    /*
     * Registers
     */

    /// Reads a register view (al is the low 8 bits of rax), a value read is no longer a call argument candidate
    pub fn read(&self, r: RegRef) -> Result<IntValue<'ctx>, String> {
        self.written.borrow_mut().remove(&r.reg);
        return self.load_reg(r);
    }

    fn load_reg(&self, r: RegRef) -> Result<IntValue<'ctx>, String> {
        let full_bits = self.env.regs.regs[r.reg].bits;
        let mut value = llvm!(self.builder.build_load(self.int(full_bits), self.regs[r.reg], "")).into_int_value();

        if r.offset > 0 {
            value = llvm!(self.builder.build_right_shift(value, self.constant(full_bits, r.offset as u64), false, ""));
        }

        if r.bits < full_bits {
            value = llvm!(self.builder.build_int_truncate(value, self.int(r.bits), ""));
        }

        return Ok(value);
    }

    /// Writes a register view, the other bits of the full register are kept
    pub fn write(&self, r: RegRef, value: IntValue<'ctx>) -> Result<(), String> {
        let full_bits = self.env.regs.regs[r.reg].bits;
        let value = self.resize(value, r.bits, false)?;

        self.written.borrow_mut().insert(r.reg, r.bits);

        if r.bits == full_bits {
            llvm!(self.builder.build_store(self.regs[r.reg], value));
            return Ok(());
        }

        let old = self.load_reg(self.env.regs.full(r.reg))?;
        let mask = !(((1u128 << r.bits) - 1) << r.offset);
        let mask = self.int(full_bits).const_int_arbitrary_precision(&[mask as u64, (mask >> 64) as u64]);

        let kept = llvm!(self.builder.build_and(old, mask, ""));
        let mut wide = llvm!(self.builder.build_int_z_extend(value, self.int(full_bits), ""));

        if r.offset > 0 {
            wide = llvm!(self.builder.build_left_shift(wide, self.constant(full_bits, r.offset as u64), ""));
        }

        let merged = llvm!(self.builder.build_or(kept, wide, ""));
        llvm!(self.builder.build_store(self.regs[r.reg], merged));

        return Ok(());
    }

    /// Writes a register view zero extended to the full register (x86 32-bit writes)
    pub fn write_zext(&self, r: RegRef, value: IntValue<'ctx>) -> Result<(), String> {
        let full_bits = self.env.regs.regs[r.reg].bits;
        self.written.borrow_mut().insert(r.reg, value.get_type().get_bit_width());

        let value = self.resize(value, full_bits, false)?;
        llvm!(self.builder.build_store(self.regs[r.reg], value));
        return Ok(());
    }

    pub fn read_reg(&self, reg: Reg) -> Result<IntValue<'ctx>, String> {
        return self.read(self.env.regs.full(reg));
    }

    pub fn write_reg(&self, reg: Reg, value: IntValue<'ctx>) -> Result<(), String> {
        return self.write(self.env.regs.full(reg), value);
    }

    pub fn read_float(&self, r: RegRef, bits: u32) -> Result<FloatValue<'ctx>, String> {
        let value = self.read(RegRef { bits, ..r })?;
        return self.int_to_float(value);
    }

    /// Writes the low bits of a vector register, the upper bits are kept or cleared
    pub fn write_float(&self, r: RegRef, value: FloatValue<'ctx>, clear_upper: bool) -> Result<(), String> {
        let bits = value.get_type().get_bit_width();
        let value = llvm!(self.builder.build_bit_cast(value, self.int(bits), "")).into_int_value();

        return if clear_upper { self.write_zext(r, value) } else { self.write(RegRef { bits, ..r }, value) };
    }

    pub fn int_to_float(&self, value: IntValue<'ctx>) -> Result<FloatValue<'ctx>, String> {
        let ty = match value.get_type().get_bit_width() {
            32 => self.cx.f32_type(),
            _ => self.cx.f64_type(),
        };
        let value = self.resize(value, ty.get_bit_width(), false)?;

        return Ok(llvm!(self.builder.build_bit_cast(value, ty, "")).into_float_value());
    }

    /// Truncates or extends an integer
    pub fn resize(&self, value: IntValue<'ctx>, bits: u32, signed: bool) -> Result<IntValue<'ctx>, String> {
        let from = value.get_type().get_bit_width();

        return Ok(match from.cmp(&bits) {
            std::cmp::Ordering::Equal => value,
            std::cmp::Ordering::Greater => llvm!(self.builder.build_int_truncate(value, self.int(bits), "")),
            std::cmp::Ordering::Less if signed => llvm!(self.builder.build_int_s_extend(value, self.int(bits), "")),
            std::cmp::Ordering::Less => llvm!(self.builder.build_int_z_extend(value, self.int(bits), "")),
        });
    }

    /// Any value to an integer of the given width (pointers, floats, narrower integers)
    fn to_int(&self, value: BasicValueEnum<'ctx>, bits: u32) -> Result<IntValue<'ctx>, String> {
        let value = match value {
            BasicValueEnum::IntValue(v) => v,
            BasicValueEnum::PointerValue(v) => llvm!(self.builder.build_ptr_to_int(v, self.int(self.pointer_bits()), "")),
            BasicValueEnum::FloatValue(v) => {
                let width = v.get_type().get_bit_width();
                llvm!(self.builder.build_bit_cast(v, self.int(width), "")).into_int_value()
            }
            _ => return Err("unsupported value type".to_string()),
        };

        return self.resize(value, bits, false);
    }

    /// Integer (a full register) to a parameter or return type
    fn from_int(&self, value: IntValue<'ctx>, ty: LType) -> Result<BasicValueEnum<'ctx>, String> {
        return Ok(match ty {
            LType::Int(bits) => self.resize(value, bits, false)?.into(),
            LType::Ptr => {
                let value = self.resize(value, self.pointer_bits(), false)?;
                llvm!(self.builder.build_int_to_ptr(value, self.ptr_type(), "")).into()
            }
            LType::Float(bits) => {
                let value = self.resize(value, bits, false)?;
                self.int_to_float(value)?.into()
            }
        });
    }

    /// Reads a parameter or return value at its location (stack offsets relative to sp_offset)
    fn read_value(&self, value: &Value, sp_offset: i64) -> Result<BasicValueEnum<'ctx>, String> {
        let raw = match value.loc {
            Loc::Reg(reg) => self.read_reg(reg)?,
            Loc::Stack(offset) => {
                let bits = match value.ty {
                    LType::Int(bits) | LType::Float(bits) => bits,
                    LType::Ptr => self.pointer_bits(),
                };
                let ptr = self.sp_address(offset + sp_offset)?;
                self.load(ptr, bits)?
            }
        };

        return self.from_int(raw, value.ty);
    }

    /// Constant last stored at [sp + delta] in the current block (an argument written before a call)
    fn stored_constant(&self, delta: i64) -> Option<u64> {
        let Some(Known::Stack(offset)) = self.tracker.offset(self.env.abi.stack_pointer, delta) else {
            return None;
        };

        let index = (self.frame_base + offset) as u64;
        let mut instruction = self.builder.get_insert_block()?.get_last_instruction();

        while let Some(current) = instruction {
            instruction = current.get_previous_instruction();

            if current.get_opcode() != InstructionOpcode::Store {
                continue;
            }

            let Some(gep) = current.get_operand(1).and_then(|o| o.value()).and_then(|v| v.as_instruction_value()) else {
                continue;
            };

            let frame = gep.get_operand(0).and_then(|o| o.value()).is_some_and(|base| base.as_value_ref() == self.frame.as_value_ref());
            let at = gep.get_operand(1).and_then(|o| o.value()).and_then(|v| v.into_int_value().get_zero_extended_constant());

            if gep.get_opcode() != InstructionOpcode::GetElementPtr || !frame || at != Some(index) {
                continue;
            }

            return match current.get_operand(0).and_then(|o| o.value()) {
                Some(BasicValueEnum::IntValue(value)) => value.get_zero_extended_constant(),
                _ => None,
            };
        }

        return None;
    }

    /*
     * Memory
     */

    /// Pointer into the stack frame
    pub fn frame_ptr(&self, offset: i64) -> Result<PointerValue<'ctx>, String> {
        let index = self.int(64).const_int((self.frame_base + offset) as u64, true);
        return Ok(unsafe { llvm!(self.builder.build_gep(self.cx.i8_type(), self.frame, &[index], "")) });
    }

    /// Integer value of an address in the stack frame
    pub fn stack_value(&self, offset: i64) -> Result<IntValue<'ctx>, String> {
        let ptr = self.frame_ptr(offset)?;
        return Ok(llvm!(self.builder.build_ptr_to_int(ptr, self.int(self.pointer_bits()), "")));
    }

    /// Address of [sp + delta]
    pub fn sp_address(&self, delta: i64) -> Result<PointerValue<'ctx>, String> {
        return self.address(Some(self.env.abi.stack_pointer), None, delta);
    }

    /// Address of [base + index * scale + disp], in the frame when the base is a known stack address
    pub fn address(&self, base: Option<Reg>, index: Option<(RegRef, i64)>, disp: i64) -> Result<PointerValue<'ctx>, String> {
        let known = match base {
            Some(base) => self.tracker.offset(base, disp),
            None => Some(Known::Const(disp as u64)),
        };

        let scaled = match index {
            Some((reg, scale)) => {
                let value = self.read(reg)?;
                let value = self.resize(value, 64, true)?;
                Some(llvm!(self.builder.build_int_mul(value, self.constant(64, scale as u64), "")))
            }
            None => None,
        };

        match (known, scaled) {
            (Some(Known::Stack(offset)), None) => return self.frame_ptr(offset),
            (Some(Known::Stack(offset)), Some(scaled)) => {
                let ptr = self.frame_ptr(offset)?;
                return Ok(unsafe { llvm!(self.builder.build_gep(self.cx.i8_type(), ptr, &[scaled], "")) });
            }
            (Some(Known::Const(addr)), None) => return self.global_ptr(addr & self.address_mask()),
            (Some(Known::Const(addr)), Some(scaled)) => {
                let ptr = self.global_ptr(addr & self.address_mask())?;
                return Ok(unsafe { llvm!(self.builder.build_gep(self.cx.i8_type(), ptr, &[scaled], "")) });
            }
            (None, _) => {}
        }

        let mut value = self.resize(self.read_reg(base.unwrap())?, 64, false)?;

        if let Some(scaled) = scaled {
            value = llvm!(self.builder.build_int_add(value, scaled, ""));
        }

        if disp != 0 {
            value = llvm!(self.builder.build_int_add(value, self.constant(64, disp as u64), ""));
        }

        return Ok(llvm!(self.builder.build_int_to_ptr(value, self.ptr_type(), "")));
    }

    fn address_mask(&self) -> u64 {
        return if self.pointer_bits() == 32 { 0xffff_ffff } else { u64::MAX };
    }

    pub fn load(&self, ptr: PointerValue<'ctx>, bits: u32) -> Result<IntValue<'ctx>, String> {
        return Ok(llvm!(self.builder.build_load(self.int(bits), ptr, "")).into_int_value());
    }

    pub fn store(&self, ptr: PointerValue<'ctx>, value: IntValue<'ctx>) -> Result<(), String> {
        llvm!(self.builder.build_store(ptr, value));
        return Ok(());
    }

    /// Pointer to a global (data, string, function or import slot) at an address
    pub fn global_ptr(&self, addr: u64) -> Result<PointerValue<'ctx>, String> {
        let program = self.env.program;

        if self.env.analysis.functions.contains_key(&addr) {
            let sig = (self.env.signature)(&CallTarget::Function(addr));
            return Ok(self.declare(&sig).as_global_value().as_pointer_value());
        }

        let Some(region) = program.region_at(addr) else {
            let value = self.constant(self.pointer_bits(), addr);
            return Ok(llvm!(self.builder.build_int_to_ptr(value, self.ptr_type(), "")));
        };

        // Accesses inside a sized symbol go through the symbol
        let (start, offset) = match program.symbol_near(addr) {
            Some((symbol, offset)) if symbol.size > 0 && offset > 0 => (symbol.addr, offset),
            _ => (addr, 0),
        };

        let global = self.global(start, !region.perms.write)?;
        let ptr = global.as_pointer_value();

        if offset == 0 {
            return Ok(ptr);
        }

        let index = self.constant(64, offset);
        return Ok(unsafe { llvm!(self.builder.build_gep(self.cx.i8_type(), ptr, &[index], "")) });
    }

    /// Global variable of the module for an address, constant data keeps its initializer
    fn global(&self, addr: u64, read_only: bool) -> Result<GlobalValue<'ctx>, String> {
        let program = self.env.program;
        let name = (self.env.global_name)(addr);

        if let Some(global) = self.module.get_global(&name) {
            return Ok(global);
        }

        if let Some(slot) = program.import_slots.get(&addr) {
            let slot_name = format!("__imp_{}", slot.split('@').next().unwrap_or(slot));

            if let Some(global) = self.module.get_global(&slot_name) {
                return Ok(global);
            }

            let global = self.module.add_global(self.ptr_type(), None, &slot_name);
            global.set_linkage(Linkage::External);
            return Ok(global);
        }

        // Strings keep their content, other data stays opaque (its size is unknown)
        if let Some(bytes) = text_bytes_at(program, addr).filter(|_| read_only) {
            let init = self.cx.const_string(bytes, true);
            let global = self.module.add_global(init.get_type(), None, &name);
            global.set_initializer(&init);
            global.set_constant(true);
            global.set_linkage(Linkage::Private);
            return Ok(global);
        }

        let global = self.module.add_global(self.cx.i8_type(), None, &name);
        global.set_linkage(Linkage::External);
        global.set_constant(read_only);

        return Ok(global);
    }

    /*
     * Calls
     */

    /// Declares a function of the module with a signature
    pub fn declare(&self, sig: &Signature) -> FunctionValue<'ctx> {
        return self.module.get_function(&sig.name).unwrap_or_else(|| {
            let function = self.module.add_function(&sig.name, function_type(self.cx, sig, false), Some(Linkage::External));

            for (param, value) in sig.params.iter().zip(function.get_param_iter()) {
                if let Some(name) = &param.name {
                    value.set_name(name);
                }
            }

            function
        });
    }

    /// Calls a helper (intrinsic like) function, declared with the types of its arguments
    pub fn call_intrinsic(&self, name: &str, args: &[BasicValueEnum<'ctx>], ret: Option<BasicTypeEnum<'ctx>>) -> Result<Option<BasicValueEnum<'ctx>>, String> {
        let params: Vec<BasicMetadataTypeEnum> = args.iter().map(|a| a.get_type().into()).collect();
        let fn_type = match ret {
            Some(ret) => ret.fn_type(&params, false),
            None => self.cx.void_type().fn_type(&params, false),
        };

        let function = self.module.get_function(name).unwrap_or_else(|| self.module.add_function(name, fn_type, Some(Linkage::External)));
        let args: Vec<BasicMetadataValueEnum> = args.iter().map(|&a| a.into()).collect();

        // A helper used with other widths keeps the type it was declared with first
        let call = if function.get_type() == fn_type {
            llvm!(self.builder.build_call(function, &args, ""))
        } else {
            llvm!(self.builder.build_indirect_call(fn_type, function.as_global_value().as_pointer_value(), &args, ""))
        };

        return Ok(call.try_as_basic_value().basic());
    }

    /// Calls a function: the arguments are read where its signature puts them, the result is written back.
    /// A tail call (a jump) passes the arguments above the return address of the function.
    pub fn call(&mut self, target: &CallTarget, indirect: Option<IntValue<'ctx>>, tail: bool) -> Result<(), String> {
        let sig = (self.env.signature)(target);

        // Stack arguments are above the return address the call pushes
        let sp_offset = if tail { 0 } else { -self.env.abi.return_address };

        let mut args: Vec<BasicMetadataValueEnum> = Vec::new();

        for param in sig.params.iter() {
            args.push(self.read_value(param, sp_offset)?.into());
        }

        if sig.guessed {
            let written = self.written.borrow().clone();
            let int_args = &self.env.abi.int_args;
            let count = int_args.iter().rposition(|r| written.contains_key(r)).map_or(0, |i| i + 1);

            for &reg in int_args[..count].iter() {
                let full = self.env.regs.full(reg);
                let bits = written.get(&reg).copied().unwrap_or(full.bits);
                args.push(self.load_reg(RegRef { bits, ..full })?.into());
            }
        }

        if sig.variadic {
            for extra in self.variadic_args(&sig, &args)? {
                args.push(extra.into());
            }
        }

        let call = match (target, indirect) {
            (CallTarget::Indirect, Some(pointer)) => {
                let pointer = self.resize(pointer, self.pointer_bits(), false)?;
                let pointer = llvm!(self.builder.build_int_to_ptr(pointer, self.ptr_type(), ""));
                llvm!(self.builder.build_indirect_call(function_type(self.cx, &sig, false), pointer, &args, ""))
            }
            _ => {
                let function = self.declare(&sig);
                let fn_type = function_type(self.cx, &sig, false);

                // Overloads (C++) share their C name, the first one declared it with its own type
                if function.get_type() == fn_type {
                    llvm!(self.builder.build_call(function, &args, ""))
                } else {
                    llvm!(self.builder.build_indirect_call(fn_type, function.as_global_value().as_pointer_value(), &args, ""))
                }
            }
        };

        // The registers the callee does not have to preserve hold nothing known after the call: a value
        // the function received in one is not passed through the call
        let result = match (&sig.ret, call.try_as_basic_value().basic()) {
            (Some(Value { loc: Loc::Reg(reg), .. }), Some(_)) => Some(*reg),
            _ => None,
        };

        for (reg, info) in self.env.regs.regs.iter().enumerate() {
            if sig.clobbers >> reg & 1 == 1 && reg != self.env.abi.stack_pointer && Some(reg) != result && !self.env.abi.callee_saved.contains(&reg) {
                llvm!(self.builder.build_store(self.regs[reg], self.int(info.bits).get_undef()));
            }
        }

        if let (Some(ret), Some(value)) = (&sig.ret, call.try_as_basic_value().basic()) {
            if let Loc::Reg(reg) = ret.loc {
                let bits = self.env.regs.regs[reg].bits;
                let value = self.to_int(value, bits)?;
                self.write_reg(reg, value)?;
            }
        }

        // The flags and the argument registers do not survive a call
        self.flags = None;
        self.written.borrow_mut().clear();

        return Ok(());
    }

    /// System call: __syscall(number, args...), the arguments are the registers written before it
    pub fn syscall(&mut self, number: Reg, args: &[&str], ret: Reg) -> Result<(), String> {
        let written = self.written.borrow().clone();
        let regs: Vec<Reg> = args.iter().map(|name| self.env.regs.reg(name)).collect();
        let count = regs.iter().rposition(|r| written.contains_key(r)).map_or(0, |i| i + 1);
        let bits = self.env.regs.regs[ret].bits;

        let mut values: Vec<BasicValueEnum> = vec![self.load_reg(self.env.regs.full(number))?.into()];

        for &reg in regs[..count].iter() {
            values.push(self.load_reg(self.env.regs.full(reg))?.into());
        }

        // One declaration per argument count
        let name = format!("__syscall{}", count);
        let result = self.call_intrinsic(&name, &values, Some(self.int(bits).into()))?.ok_or("syscall without a result")?;
        self.write_reg(ret, result.into_int_value())?;
        self.flags = None;
        self.written.borrow_mut().clear();

        return Ok(());
    }

    /// Extra arguments of a variadic call, from its format string when it is a constant
    /// (printf("%d %s", ...)) or the next argument registers otherwise
    fn variadic_args(&self, sig: &Signature, fixed: &[BasicMetadataValueEnum<'ctx>]) -> Result<Vec<BasicValueEnum<'ctx>>, String> {
        let format = sig.params.iter().zip(fixed.iter()).rev().find_map(|(param, _)| match param.loc {
            Loc::Reg(reg) if param.ty == LType::Ptr => match self.tracker.get(reg) {
                Some(Known::Const(addr)) => self.env.program.read_c_string(addr, 4096),
                _ => None,
            },
            Loc::Stack(offset) if param.ty == LType::Ptr => self.stored_constant(offset - self.env.abi.return_address).and_then(|addr| self.env.program.read_c_string(addr, 4096)),
            _ => None,
        });

        let Some(format) = format else {
            return Ok(Vec::new());
        };

        let abi = self.env.abi;
        let used_int = sig.params.iter().filter(|p| matches!(p.loc, Loc::Reg(r) if abi.int_args.contains(&r))).count();
        let used_float = sig.params.iter().filter(|p| matches!(p.loc, Loc::Reg(r) if abi.float_args.contains(&r))).count();
        let (mut next_int, mut next_float) = if abi.positional { (sig.params.len(), sig.params.len()) } else { (used_int, used_float) };
        let pointer_bits = self.pointer_bits() as u16;
        let bytes = |ty| crate::decompiler::stack_bytes(ty, abi.slot_size, pointer_bits);

        // After the fixed stack arguments
        let mut next_stack = sig.params.iter().filter_map(|p| match p.loc {
            Loc::Stack(offset) => Some(offset - abi.stack_args + bytes(p.ty)),
            _ => None,
        }).max().unwrap_or(0);

        let mut extra = Vec::new();

        for float in format_conversions(&format) {
            let regs = if float { &abi.float_args } else { &abi.int_args };
            let next = if float { &mut next_float } else { &mut next_int };

            let ty = if float { LType::Float(64) } else { LType::Int(abi.slot_size as u32 * 8) };

            let value = match regs.get(*next) {
                // Variadic floats are passed in the integer registers on Win64
                Some(&reg) if !(abi.positional && float) => Value { loc: Loc::Reg(reg), ty, name: None },
                Some(_) => Value { loc: Loc::Reg(abi.int_args[*next]), ty: LType::Float(64), name: None },
                None => {
                    next_stack += bytes(ty);
                    Value { loc: Loc::Stack(abi.stack_args + next_stack - bytes(ty)), ty, name: None }
                }
            };

            if abi.positional {
                next_int += 1;
                next_float += 1;
            } else {
                *next += 1;
            }

            extra.push(self.read_value(&value, -abi.return_address)?);
        }

        return Ok(extra);
    }

    /*
     * Flags and conditions
     */

    /// Records a flag producing operation and computes the flag bits
    pub fn set_flags(&mut self, op: FlagOp, lhs: IntValue<'ctx>, rhs: IntValue<'ctx>, result: IntValue<'ctx>) -> Result<(), String> {
        let start = self.drop_unread_flags()?;
        let flags = self.flag_regs;
        let bits = result.get_type().get_bit_width();
        let zero = result.get_type().const_zero();

        let zf = llvm!(self.builder.build_int_compare(IntPredicate::EQ, result, zero, "zf"));
        let sf = llvm!(self.builder.build_int_compare(IntPredicate::SLT, result, zero, "sf"));

        let (cf, of) = match op {
            FlagOp::Sub => {
                let borrow = llvm!(self.builder.build_int_compare(IntPredicate::ULT, lhs, rhs, "cf"));
                let cf = if flags.carry_is_borrow { borrow } else { llvm!(self.builder.build_not(borrow, "cf")) };
                // Overflow when the operands have different signs and the result has the sign of rhs
                let a = llvm!(self.builder.build_xor(lhs, rhs, ""));
                let b = llvm!(self.builder.build_xor(lhs, result, ""));
                let both = llvm!(self.builder.build_and(a, b, ""));
                (cf, llvm!(self.builder.build_int_compare(IntPredicate::SLT, both, zero, "of")))
            }
            FlagOp::Add => {
                let cf = llvm!(self.builder.build_int_compare(IntPredicate::ULT, result, lhs, "cf"));
                let a = llvm!(self.builder.build_xor(result, lhs, ""));
                let b = llvm!(self.builder.build_xor(result, rhs, ""));
                let both = llvm!(self.builder.build_and(a, b, ""));
                (cf, llvm!(self.builder.build_int_compare(IntPredicate::SLT, both, zero, "of")))
            }
            FlagOp::Logic | FlagOp::Float => (self.int(1).const_zero(), self.int(1).const_zero()),
        };

        llvm!(self.builder.build_store(self.regs[flags.zero], zf));
        llvm!(self.builder.build_store(self.regs[flags.sign], sf));
        llvm!(self.builder.build_store(self.regs[flags.carry], cf));
        llvm!(self.builder.build_store(self.regs[flags.overflow], of));

        if let Some(pf) = flags.parity {
            let low = self.resize(result, 8.min(bits), false)?;
            let low = self.resize(low, 8, false)?;
            let count = self.call_intrinsic("llvm.ctpop.i8", &[low.into()], Some(self.int(8).into()))?.unwrap().into_int_value();
            let odd = llvm!(self.builder.build_and(count, self.constant(8, 1), ""));
            let parity = llvm!(self.builder.build_int_compare(IntPredicate::EQ, odd, self.constant(8, 0), "pf"));
            llvm!(self.builder.build_store(self.regs[pf], parity));
        }

        self.flags = Some(FlagProducer { op, lhs: lhs.into(), rhs: rhs.into(), result: Some(result) });
        self.keep_unread_flags(start)?;

        return Ok(());
    }

    /// The computation of the flags of the previous producer is dead when nothing read them since
    /// and the new producer is in the same block: it overwrites them all. Returns the last
    /// instruction before the new producer's ones.
    fn drop_unread_flags(&self) -> Result<Option<InstructionValue<'ctx>>, String> {
        let block = self.builder.get_insert_block().ok_or("no current block")?;
        let unread = std::mem::take(&mut *self.unread_flags.borrow_mut());

        if unread.iter().all(|i| i.get_parent() == Some(block)) {
            self.dead_flags.borrow_mut().extend(unread);
        }

        self.produced_flags.set(true);

        return Ok(block.get_last_instruction());
    }

    /// The flags of the last producer of a block are dead when no path from it reaches a block
    /// reading the stored flags before producing its own
    fn drop_unread_tail_flags(&mut self) {
        let succs = |addr: u64| self.function.blocks[&addr].succs.iter().map(|e| e.to).filter(|to| self.block_flags.contains_key(to));
        let mut live: HashMap<u64, bool> = self.block_flags.iter().map(|(&a, f)| (a, f.reads_on_entry)).collect();
        let mut changed = true;

        while changed {
            changed = false;

            for (&addr, flags) in self.block_flags.iter() {
                if !live[&addr] && !flags.produces && succs(addr).any(|s| live[&s]) {
                    live.insert(addr, true);
                    changed = true;
                }
            }
        }

        for (&addr, flags) in self.block_flags.iter() {
            if succs(addr).any(|s| live[&s]) {
                continue;
            }

            for instruction in flags.tail.iter().rev() {
                if instruction.get_first_use().is_none() {
                    instruction.erase_from_basic_block();
                }
            }
        }
    }

    /// The instructions a producer added after start, until its flags are read
    fn keep_unread_flags(&self, start: Option<InstructionValue<'ctx>>) -> Result<(), String> {
        let block = self.builder.get_insert_block().ok_or("no current block")?;
        let mut next = match start {
            Some(instruction) => instruction.get_next_instruction(),
            None => block.get_first_instruction(),
        };

        let mut unread = self.unread_flags.borrow_mut();

        while let Some(instruction) = next {
            unread.push(instruction);
            next = instruction.get_next_instruction();
        }

        return Ok(());
    }

    /// Records a floating point comparison (x86 ucomis, arm fcmp)
    pub fn set_float_flags(&mut self, lhs: FloatValue<'ctx>, rhs: FloatValue<'ctx>) -> Result<(), String> {
        let start = self.drop_unread_flags()?;
        let flags = self.flag_regs;
        let compare = |p, name| self.builder.build_float_compare(p, lhs, rhs, name).map_err(|e| e.to_string());

        // x86: unordered sets ZF, PF and CF; arm: unordered sets C and V
        let (zf, cf, of) = if flags.carry_is_borrow {
            (compare(FloatPredicate::UEQ, "zf")?, compare(FloatPredicate::ULT, "cf")?, self.int(1).const_zero())
        } else {
            (compare(FloatPredicate::OEQ, "z")?, compare(FloatPredicate::UGE, "c")?, compare(FloatPredicate::UNO, "v")?)
        };

        let sf = if flags.carry_is_borrow { self.int(1).const_zero() } else { compare(FloatPredicate::OLT, "n")? };

        llvm!(self.builder.build_store(self.regs[flags.zero], zf));
        llvm!(self.builder.build_store(self.regs[flags.sign], sf));
        llvm!(self.builder.build_store(self.regs[flags.carry], cf));
        llvm!(self.builder.build_store(self.regs[flags.overflow], of));

        if let Some(pf) = flags.parity {
            llvm!(self.builder.build_store(self.regs[pf], compare(FloatPredicate::UNO, "pf")?));
        }

        self.flags = Some(FlagProducer { op: FlagOp::Float, lhs: lhs.into(), rhs: rhs.into(), result: None });
        self.keep_unread_flags(start)?;

        return Ok(());
    }

    /// A condition as an i1, from the operands of the last flag producer when it is in the block
    pub fn condition(&self, cond: Cond) -> Result<IntValue<'ctx>, String> {
        if cond == Cond::Always {
            return Ok(self.int(1).const_all_ones());
        }

        if let Some(producer) = self.flags {
            if let Some(value) = self.lazy_condition(&producer, cond)? {
                return Ok(value);
            }
        }

        // The stored flags are read: the last producer's are needed (or the predecessors' ones)
        self.unread_flags.borrow_mut().clear();

        if !self.produced_flags.get() {
            self.reads_flags.set(true);
        }

        let flags = self.flag_regs;
        let read = |reg| self.builder.build_load(self.int(1), self.regs[reg], "").map(|v| v.into_int_value()).map_err(|e| e.to_string());
        let not = |v| self.builder.build_not(v, "").map_err(|e| e.to_string());
        let or = |a, b| self.builder.build_or(a, b, "").map_err(|e| e.to_string());
        let and = |a, b| self.builder.build_and(a, b, "").map_err(|e| e.to_string());
        let ne = |a, b| self.builder.build_xor(a, b, "").map_err(|e| e.to_string());

        let zf = read(flags.zero)?;
        let sf = read(flags.sign)?;
        let of = read(flags.overflow)?;
        let carry = read(flags.carry)?;
        let borrow = if flags.carry_is_borrow { carry } else { not(carry)? };

        return match cond {
            Cond::Always => unreachable!(),
            Cond::Eq => Ok(zf),
            Cond::Ne => not(zf),
            Cond::Slt => ne(sf, of),
            Cond::Sge => not(ne(sf, of)?),
            Cond::Sle => or(zf, ne(sf, of)?),
            Cond::Sgt => and(not(zf)?, not(ne(sf, of)?)?),
            Cond::Ult => Ok(borrow),
            Cond::Uge => not(borrow),
            Cond::Ule => or(borrow, zf),
            Cond::Ugt => and(not(borrow)?, not(zf)?),
            Cond::Neg => Ok(sf),
            Cond::NonNeg => not(sf),
            Cond::Overflow => Ok(of),
            Cond::NoOverflow => not(of),
            Cond::Parity => read(flags.parity.ok_or("no parity flag")?),
            Cond::NoParity => not(read(flags.parity.ok_or("no parity flag")?)?),
        };
    }

    fn lazy_condition(&self, producer: &FlagProducer<'ctx>, cond: Cond) -> Result<Option<IntValue<'ctx>>, String> {
        let b = &self.builder;

        if producer.op == FlagOp::Float {
            let (lhs, rhs) = (producer.lhs.into_float_value(), producer.rhs.into_float_value());

            // x86 maps the comparison to the unsigned conditions (unordered sets ZF, PF and CF)
            let predicate = if self.flag_regs.carry_is_borrow {
                match cond {
                    Cond::Eq => FloatPredicate::UEQ,
                    Cond::Ne => FloatPredicate::ONE,
                    Cond::Ugt => FloatPredicate::OGT,
                    Cond::Uge => FloatPredicate::OGE,
                    Cond::Ult => FloatPredicate::ULT,
                    Cond::Ule => FloatPredicate::ULE,
                    Cond::Parity => FloatPredicate::UNO,
                    Cond::NoParity => FloatPredicate::ORD,
                    _ => return Ok(None),
                }
            } else {
                match aarch64::float_predicate(cond) {
                    Some(predicate) => predicate,
                    None => return Ok(None),
                }
            };

            return Ok(Some(llvm!(b.build_float_compare(predicate, lhs, rhs, ""))));
        }

        let (lhs, rhs) = (producer.lhs.into_int_value(), producer.rhs.into_int_value());
        let result = producer.result.ok_or("integer flags without a result")?;
        let zero = result.get_type().const_zero();

        let compare = |p, a, c| b.build_int_compare(p, a, c, "").map(Some).map_err(|e| e.to_string());

        return match (producer.op, cond) {
            (_, Cond::Eq) => compare(IntPredicate::EQ, result, zero),
            (_, Cond::Ne) => compare(IntPredicate::NE, result, zero),
            (_, Cond::Neg) => compare(IntPredicate::SLT, result, zero),
            (_, Cond::NonNeg) => compare(IntPredicate::SGE, result, zero),
            (FlagOp::Sub, Cond::Slt) => compare(IntPredicate::SLT, lhs, rhs),
            (FlagOp::Sub, Cond::Sle) => compare(IntPredicate::SLE, lhs, rhs),
            (FlagOp::Sub, Cond::Sgt) => compare(IntPredicate::SGT, lhs, rhs),
            (FlagOp::Sub, Cond::Sge) => compare(IntPredicate::SGE, lhs, rhs),
            (FlagOp::Sub, Cond::Ult) => compare(IntPredicate::ULT, lhs, rhs),
            (FlagOp::Sub, Cond::Ule) => compare(IntPredicate::ULE, lhs, rhs),
            (FlagOp::Sub, Cond::Ugt) => compare(IntPredicate::UGT, lhs, rhs),
            (FlagOp::Sub, Cond::Uge) => compare(IntPredicate::UGE, lhs, rhs),
            // Carry and overflow are cleared by the logic operations
            (FlagOp::Logic, Cond::Slt) => compare(IntPredicate::SLT, result, zero),
            (FlagOp::Logic, Cond::Sge) => compare(IntPredicate::SGE, result, zero),
            (FlagOp::Logic, Cond::Sle) => compare(IntPredicate::SLE, result, zero),
            (FlagOp::Logic, Cond::Sgt) => compare(IntPredicate::SGT, result, zero),
            (FlagOp::Logic, Cond::Ugt) => compare(IntPredicate::NE, result, zero),
            (FlagOp::Logic, Cond::Ule) => compare(IntPredicate::EQ, result, zero),
            (FlagOp::Logic, Cond::Ult) => Ok(Some(self.int(1).const_zero())),
            (FlagOp::Logic, Cond::Uge) => Ok(Some(self.int(1).const_all_ones())),
            (FlagOp::Add, Cond::Ult) => compare(IntPredicate::ULT, result, lhs),
            (FlagOp::Add, Cond::Uge) => compare(IntPredicate::UGE, result, lhs),
            _ => Ok(None),
        };
    }
}

/// Conversions of a printf format string, true for the floating point ones
fn format_conversions(format: &str) -> Vec<bool> {
    let mut conversions = Vec::new();
    let mut chars = format.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }

        // Flags, width, precision and length modifiers, a * consumes an int argument
        while let Some(&next) = chars.peek() {
            if next == '*' {
                conversions.push(false);
            }

            if "-+ #0123456789.*hlLqjzt'".contains(next) {
                chars.next();
            } else {
                break;
            }
        }

        match chars.next() {
            Some('%') | None => {}
            Some('f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A') => conversions.push(true),
            Some(_) => conversions.push(false),
        }
    }

    return conversions;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_conversions() {
        assert_eq!(format_conversions("%d %s %5.2f%%\n"), [false, false, true]);
        assert_eq!(format_conversions("%*d %lu %c"), [false, false, false, false]);
        assert!(format_conversions("no conversion").is_empty());
    }
}
