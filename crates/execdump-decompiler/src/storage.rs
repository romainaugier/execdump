/*
 * Runtime storage of the variables: where each one is (a register, a stack slot) over ranges of the
 * addresses of its function, to read their values while the program runs.
 *
 * A location is one u32: 2 bits of kind, then a register (8 bits of id, 2 of width, 2 of byte offset),
 * a stack slot (28-bit signed offset from the stack pointer at the entry, 1 bit for the slot of the
 * stack canary) or a constant (30-bit signed). A range is 12 bytes: the start and the end of the
 * addresses, as offsets from the start of the function, and the location. The ranges of a variable are
 * sorted and do not overlap, the location at an address is a binary search.
 *
 * The offset of the stack pointer from its value at the entry is kept the same way (ranges of stack
 * locations), with the shape of each variable (its size, an integer, a float, a pointer to text): a debugger
 * finds and shows the values of the variables of a running function from them.
 */

use crate::lift::regs::RegisterFile;
use crate::lift::SlotWrite;
use crate::typedb::TypeDb;
use crate::types::CType;

use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Loc(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    None,
    /// A register (its index in the register file), the bits of the value and their byte offset in it
    Register { reg: usize, bits: u32, offset: u32 },
    /// A stack slot, at an offset from the stack pointer at the entry of the function
    Stack { offset: i64, canary: bool },
    Constant(i64),
}

const KIND_BITS: u32 = 2;
const KIND_MASK: u32 = 0b11;
const REGISTER: u32 = 1;
const STACK: u32 = 2;
const CONSTANT: u32 = 3;
const STACK_OFFSET_BITS: u32 = 28;
const CANARY: u32 = 1 << (KIND_BITS + STACK_OFFSET_BITS);
const WIDTHS: [u32; 4] = [8, 16, 32, 64];

/// Signed value of the low bits of a field
fn signed(raw: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    return ((raw << shift) as i32 >> shift) as i64;
}

impl Loc {
    pub const NONE: Loc = Loc(0);

    /// A register holding a value of 8, 16, 32 or 64 bits (wider values are noted as 64) at a byte offset
    /// of at most 3
    pub fn register(reg: usize, bits: u32, offset: u32) -> Option<Loc> {
        if reg > 0xff || offset > 3 {
            return None;
        }

        let width = WIDTHS.iter().position(|&w| bits <= w).unwrap_or(3) as u32;
        return Some(Loc(REGISTER | (reg as u32) << 2 | width << 10 | offset << 12));
    }

    pub fn stack(offset: i64) -> Option<Loc> {
        let limit = 1i64 << (STACK_OFFSET_BITS - 1);

        if offset < -limit || offset >= limit {
            return None;
        }

        return Some(Loc(STACK | ((offset as u32) & ((1 << STACK_OFFSET_BITS) - 1)) << KIND_BITS));
    }

    pub fn constant(value: i64) -> Option<Loc> {
        let limit = 1i64 << 29;

        if value < -limit || value >= limit {
            return None;
        }

        return Some(Loc(CONSTANT | (value as u32) << KIND_BITS));
    }

    /// The slot of the stack canary (the debugger hides it)
    pub fn canary(self) -> Loc {
        return if self.0 & KIND_MASK == STACK { Loc(self.0 | CANARY) } else { self };
    }

    pub fn place(self) -> Place {
        let payload = self.0 >> KIND_BITS;

        return match self.0 & KIND_MASK {
            REGISTER => Place::Register { reg: (payload & 0xff) as usize, bits: WIDTHS[(payload >> 8 & 3) as usize], offset: payload >> 10 & 3 },
            STACK => Place::Stack { offset: signed(payload & ((1 << STACK_OFFSET_BITS) - 1), STACK_OFFSET_BITS), canary: self.0 & CANARY != 0 },
            CONSTANT => Place::Constant(signed(payload, 32 - KIND_BITS)),
            _ => Place::None,
        };
    }

    /// The same register at its full width, or the same slot (what is written over)
    pub fn whole(self) -> Loc {
        return match self.place() {
            Place::Register { reg, .. } => Loc::register(reg, 64, 0).unwrap_or(self),
            Place::Stack { offset, .. } => Loc::stack(offset).unwrap_or(self),
            _ => self,
        };
    }

    /// rax, eax (the views of the x86 registers by their width), xmm0, [sp-0x18]
    pub fn describe(self, regs: &RegisterFile) -> String {
        return match self.place() {
            Place::None => "none".to_string(),
            Place::Register { reg, bits, offset } => {
                let Some(info) = regs.regs.get(reg) else {
                    return format!("r{}", reg);
                };

                let view = (offset == 0 && info.bits <= 64 && bits < info.bits).then(|| regs.view_name(reg, bits)).flatten();

                match view {
                    Some(name) => name,
                    None if bits < info.bits || offset > 0 => format!("{}[{}:{}]", info.name, offset * 8 + bits - 1, offset * 8),
                    None => info.name.to_string(),
                }
            }
            Place::Stack { offset, canary } => {
                let slot = if offset < 0 { format!("[sp-{:#x}]", -offset) } else { format!("[sp+{:#x}]", offset) };
                if canary { format!("{} canary", slot) } else { slot }
            }
            Place::Constant(value) => value.to_string(),
        };
    }
}

/// A variable (of the C function) is in a location from an address on: at the start of a block (entry), or
/// after the instruction ending there. Its value has these bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarNote {
    pub var: usize,
    pub loc: Loc,
    pub start: u64,
    pub entry: bool,
    pub bits: u32,
}

/// Storage of the variables of a function: the notes the C backend reads, then the ranges of each variable
/// made from them, the slots of the stack canary, and where the stack pointer is
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Storage {
    pub notes: Vec<VarNote>,
    /// Variables of the stack frame (buffers): their slot holds them while the function runs
    pub frame_vars: Vec<(usize, Loc)>,
    pub vars: Vec<(usize, Vec<Range>)>,
    pub canaries: Vec<Loc>,
    /// Offset of the stack pointer from its value at the entry over the addresses of the function (stack
    /// locations): the stack slots of the variables are found from the stack pointer of a running function
    pub frame: Vec<Range>,
}

/// How the debugger reads the value of a variable and shows it
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Shape {
    Int { bytes: u8, signed: bool },
    Float { bytes: u8 },
    Bool,
    /// A pointer, to text (char *) or to anything
    Pointer { text: bool },
    /// An array of chars (a buffer of text), its size
    Text(u32),
    /// Aggregates, arrays and the unknown types: their bytes
    Bytes(u32),
    #[default]
    Unknown,
}

impl Shape {
    pub fn of(ty: &CType, typedb: &TypeDb) -> Shape {
        let ty = typedb.resolve(ty).unqualified();
        let size = typedb.size_of(ty);

        return match ty {
            CType::Bool => Shape::Bool,
            CType::Char => Shape::Int { bytes: 1, signed: true },
            CType::Int { bits, signed } => Shape::Int { bytes: (*bits / 8).max(1) as u8, signed: *signed },
            CType::Enum(_) => Shape::Int { bytes: size.unwrap_or(4) as u8, signed: true },
            CType::Float { bits } => Shape::Float { bytes: (*bits / 8) as u8 },
            CType::Pointer(to) => Shape::Pointer { text: matches!(typedb.resolve(to).unqualified(), CType::Char) },
            CType::Array(element, Some(n)) if matches!(typedb.resolve(element).unqualified(), CType::Char) => Shape::Text((*n).min(u32::MAX as u64) as u32),
            CType::Unknown(bits) if *bits > 0 && *bits <= 64 => Shape::Int { bytes: (*bits / 8) as u8, signed: false },
            _ => size.filter(|&s| s > 0).map_or(Shape::Unknown, |s| Shape::Bytes(s.min(u32::MAX as u64) as u32)),
        };
    }

    /// i4, u8, f8, b, p, s, t64, x16, ?
    pub fn encode(self) -> String {
        return match self {
            Shape::Int { bytes, signed } => format!("{}{}", if signed { 'i' } else { 'u' }, bytes),
            Shape::Float { bytes } => format!("f{}", bytes),
            Shape::Bool => "b".to_string(),
            Shape::Pointer { text } => if text { "s" } else { "p" }.to_string(),
            Shape::Text(n) => format!("t{}", n),
            Shape::Bytes(n) => format!("x{}", n),
            Shape::Unknown => "?".to_string(),
        };
    }

    pub fn decode(text: &str) -> Shape {
        let number = |t: &str| t.get(1..).and_then(|n| n.parse().ok());

        return match text.chars().next() {
            Some('i') => number(text).map_or(Shape::Unknown, |bytes| Shape::Int { bytes, signed: true }),
            Some('u') => number(text).map_or(Shape::Unknown, |bytes| Shape::Int { bytes, signed: false }),
            Some('f') => number(text).map_or(Shape::Unknown, |bytes| Shape::Float { bytes }),
            Some('b') => Shape::Bool,
            Some('p') => Shape::Pointer { text: false },
            Some('s') => Shape::Pointer { text: true },
            Some('t') => text.get(1..).and_then(|n| n.parse().ok()).map_or(Shape::Unknown, Shape::Text),
            Some('x') => text.get(1..).and_then(|n| n.parse().ok()).map_or(Shape::Unknown, Shape::Bytes),
            _ => Shape::Unknown,
        };
    }

    /// Bytes of the value (pointers have the size of a pointer of the program)
    pub fn size(self, pointer_size: u8) -> usize {
        return match self {
            Shape::Int { bytes, .. } | Shape::Float { bytes } => bytes as usize,
            Shape::Bool => 1,
            Shape::Pointer { .. } => pointer_size as usize,
            Shape::Text(n) | Shape::Bytes(n) => n as usize,
            Shape::Unknown => pointer_size as usize,
        };
    }
}

/// Offset of the stack pointer from its value at the entry, at an offset of its function
pub fn stack_offset_at(frame: &[Range], offset: u32) -> Option<i64> {
    return match location_at(frame, offset)?.place() {
        Place::Stack { offset, .. } => Some(offset),
        _ => None,
    };
}

/// Addresses of a function (offsets from its start) where a variable is in a location
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: u32,
    pub end: u32,
    pub loc: Loc,
}

/// A machine instruction for the ranges: where it ends, the registers it writes
#[derive(Clone, Copy, Debug)]
pub struct Step {
    pub end: u64,
    pub kills: u128,
}

/// A machine block for the ranges: its addresses, the blocks before it (indices), its instructions
#[derive(Clone, Debug)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub preds: Vec<usize>,
    pub steps: Vec<Step>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Held {
    var: usize,
    loc: Loc,
    bytes: u32,
}

type State = BTreeMap<Loc, Held>;

/// Rounds of the propagation of the locations between the blocks (the loops need a few)
const MAX_ROUNDS: usize = 16;

/// Ranges of the variables from the notes: a location holds a variable from a note on, until an
/// instruction writes it (a register it writes, a call clobbers, a stack slot it stores to). A block starts
/// with what all the blocks before it agree on, and the notes of its start. The ranges of a variable do not
/// overlap: when two locations hold it, the one holding it first is kept.
pub fn ranges(function: u64, blocks: &[Block], notes: &[VarNote], slot_writes: &[SlotWrite]) -> Vec<(usize, Vec<Range>)> {
    let mut entry: HashMap<u64, Vec<&VarNote>> = HashMap::new();
    let mut written: HashMap<u64, Vec<&VarNote>> = HashMap::new();
    let mut slots: HashMap<u64, Vec<&SlotWrite>> = HashMap::new();

    for note in notes.iter() {
        if note.entry { entry.entry(note.start).or_default().push(note) } else { written.entry(note.start).or_default().push(note) }
    }

    for write in slot_writes.iter() {
        slots.entry(write.at).or_default().push(write);
    }

    let hold = |state: &mut State, note: &VarNote| {
        state.insert(note.loc.whole(), Held { var: note.var, loc: note.loc, bytes: note.bits.div_ceil(8).max(1) });
    };

    let step = |state: &mut State, step: &Step| {
        let stored = slots.get(&step.end).map_or(&[][..], |s| s.as_slice());

        state.retain(|key, held| match key.place() {
            Place::Register { reg, .. } => reg >= 128 || step.kills >> reg & 1 == 0,
            Place::Stack { offset, .. } => !stored.iter().any(|w| w.offset < offset + held.bytes as i64 && offset < w.offset + w.bytes as i64),
            _ => true,
        });

        written.get(&step.end).into_iter().flatten().for_each(|note| hold(state, note));
    };

    let start = |b: usize, outs: &[Option<State>]| -> State {
        let mut known = blocks[b].preds.iter().filter_map(|&p| outs[p].as_ref());
        let mut state = known.next().cloned().unwrap_or_default();

        for other in known {
            state.retain(|key, held| other.get(key) == Some(held));
        }

        entry.get(&blocks[b].start).into_iter().flatten().for_each(|note| hold(&mut state, note));
        state
    };

    let mut outs: Vec<Option<State>> = vec![None; blocks.len()];

    for _ in 0..MAX_ROUNDS {
        let mut changed = false;

        for b in 0..blocks.len() {
            let mut state = start(b, &outs);
            blocks[b].steps.iter().for_each(|s| step(&mut state, s));

            if outs[b].as_ref() != Some(&state) {
                outs[b] = Some(state);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    // Intervals of each variable: a location keeps it from where it gets it to where it loses it
    let mut intervals: HashMap<usize, Vec<Range>> = HashMap::new();
    let offset = |addr: u64| addr.wrapping_sub(function) as u32;

    for (b, block) in blocks.iter().enumerate() {
        let mut state = start(b, &outs);
        let mut open: BTreeMap<Loc, (Held, u64)> = state.iter().map(|(&k, &h)| (k, (h, block.start))).collect();

        let mut close = |held: Held, from: u64, to: u64| {
            if from < to {
                intervals.entry(held.var).or_default().push(Range { start: offset(from), end: offset(to), loc: held.loc });
            }
        };

        for s in block.steps.iter() {
            step(&mut state, s);

            let gone: Vec<Loc> = open.iter().filter(|(k, (h, _))| state.get(k) != Some(h)).map(|(&k, _)| k).collect();

            for key in gone {
                let (held, from) = open.remove(&key).unwrap();
                close(held, from, s.end);
            }

            for (&key, &held) in state.iter() {
                open.entry(key).or_insert((held, s.end));
            }
        }

        for (held, from) in open.into_values() {
            close(held, from, block.end);
        }
    }

    let mut vars: Vec<(usize, Vec<Range>)> = intervals.into_iter().map(|(var, ranges)| (var, without_overlaps(ranges))).collect();
    vars.sort_by_key(|(var, _)| *var);

    return vars;
}

/// Sorted ranges that do not overlap: where several locations hold the variable, the one it was in before
/// stays, else the one holding it first; the contiguous ranges of the same location are merged
fn without_overlaps(ranges: Vec<Range>) -> Vec<Range> {
    let mut bounds: Vec<u32> = ranges.iter().flat_map(|r| [r.start, r.end]).collect();
    bounds.sort_unstable();
    bounds.dedup();

    let mut out: Vec<Range> = Vec::new();

    for pair in bounds.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        let covering = ranges.iter().filter(|r| r.start <= start && end <= r.end);
        let previous = out.last().filter(|last| last.end == start).map(|last| last.loc);

        let chosen = match previous {
            Some(loc) if ranges.iter().any(|r| r.loc == loc && r.start <= start && end <= r.end) => Some(loc),
            _ => covering.min_by_key(|r| (r.start, r.loc)).map(|r| r.loc),
        };

        let Some(loc) = chosen else {
            continue;
        };

        match out.last_mut() {
            Some(last) if last.end == start && last.loc == loc => last.end = end,
            _ => out.push(Range { start, end, loc }),
        }
    }

    return out;
}

/// Location of a variable at an offset of its function
pub fn location_at(ranges: &[Range], offset: u32) -> Option<Loc> {
    let index = ranges.partition_point(|r| r.start <= offset).checked_sub(1)?;
    let range = ranges[index];
    return (offset < range.end).then_some(range.loc);
}

/// Text form of ranges, for the caches: start-end:loc separated by spaces, in hexadecimal
pub fn encode(ranges: &[Range]) -> String {
    return ranges.iter().map(|r| format!("{:x}-{:x}:{:x}", r.start, r.end, r.loc.0)).collect::<Vec<_>>().join(" ");
}

pub fn decode(text: &str) -> Vec<Range> {
    return text
        .split_whitespace()
        .filter_map(|item| {
            let (span, loc) = item.split_once(':')?;
            let (start, end) = span.split_once('-')?;
            Some(Range { start: u32::from_str_radix(start, 16).ok()?, end: u32::from_str_radix(end, 16).ok()?, loc: Loc(u32::from_str_radix(loc, 16).ok()?) })
        })
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use execdump_core::disasm::Architecture;

    #[test]
    fn locations() {
        let regs = RegisterFile::new(Architecture::X86_64);
        let rdi = regs.reg("rdi");

        assert_eq!(std::mem::size_of::<Range>(), 12);
        assert_eq!(Loc::register(rdi, 32, 0).unwrap().place(), Place::Register { reg: rdi, bits: 32, offset: 0 });
        assert_eq!(Loc::register(rdi, 32, 0).unwrap().describe(&regs), "edi");
        assert_eq!(Loc::register(regs.reg("rax"), 8, 1).unwrap().describe(&regs), "rax[15:8]");
        assert_eq!(Loc::stack(-0x18).unwrap().place(), Place::Stack { offset: -0x18, canary: false });
        assert_eq!(Loc::stack(-0x10).unwrap().canary().describe(&regs), "[sp-0x10] canary");
        assert_eq!(Loc::stack(1 << 27), None);
        assert_eq!(Loc::constant(-5).unwrap().place(), Place::Constant(-5));
        assert_eq!(Loc::register(rdi, 32, 0).unwrap().whole(), Loc::register(rdi, 64, 0).unwrap());

        let ranges = vec![Range { start: 0, end: 4, loc: Loc(1) }, Range { start: 8, end: 12, loc: Loc(2) }];
        assert_eq!(location_at(&ranges, 0), Some(Loc(1)));
        assert_eq!(location_at(&ranges, 2), Some(Loc(1)));
        assert_eq!(location_at(&ranges, 4), None);
        assert_eq!(location_at(&ranges, 11), Some(Loc(2)));
        assert_eq!(decode(&encode(&ranges)), ranges);

        let frame = vec![Range { start: 0, end: 1, loc: Loc::stack(0).unwrap() }, Range { start: 1, end: 9, loc: Loc::stack(-0x48).unwrap() }];
        assert_eq!(stack_offset_at(&frame, 0), Some(0));
        assert_eq!(stack_offset_at(&frame, 4), Some(-0x48));
        assert_eq!(stack_offset_at(&frame, 9), None);

        for shape in [Shape::Int { bytes: 2, signed: false }, Shape::Float { bytes: 8 }, Shape::Bool, Shape::Pointer { text: true }, Shape::Pointer { text: false }, Shape::Text(64), Shape::Bytes(24), Shape::Unknown] {
            assert_eq!(Shape::decode(&shape.encode()), shape);
        }
    }

    #[test]
    fn ranges_from_the_notes() {
        let regs = RegisterFile::new(Architecture::X86_64);
        let (rdi, rbx) = (regs.reg("rdi"), regs.reg("rbx"));
        let reg = |r: usize| Loc::register(r, 32, 0).unwrap();
        let slot = Loc::stack(-0x10).unwrap();

        // 0x100: v0 in edi at the start, copied to ebx (0x102), edi written (0x104), stored to a slot (0x106)
        // 0x108: v1 in ebx at the start (a phi), the slot written over (0x10a)
        let steps = |ends: &[(u64, u128)]| ends.iter().map(|&(end, kills)| Step { end, kills }).collect();
        let blocks = vec![
            Block { start: 0x100, end: 0x108, preds: vec![], steps: steps(&[(0x102, 1 << rbx), (0x104, 1 << rdi), (0x106, 0), (0x108, 0)]) },
            Block { start: 0x108, end: 0x10c, preds: vec![0], steps: steps(&[(0x10a, 0), (0x10c, 0)]) },
        ];
        let note = |var, loc, start, entry| VarNote { var, loc, start, entry, bits: 32 };
        let notes = vec![note(0, reg(rdi), 0x100, true), note(0, reg(rbx), 0x102, false), note(0, slot, 0x106, false), note(1, reg(rbx), 0x108, true)];
        let writes = vec![SlotWrite { at: 0x106, offset: -0x10, bytes: 4 }, SlotWrite { at: 0x10a, offset: -0x10, bytes: 8 }];

        let vars = ranges(0x100, &blocks, &notes, &writes);
        assert_eq!(vars[0], (0, vec![Range { start: 0, end: 4, loc: reg(rdi) }, Range { start: 4, end: 8, loc: reg(rbx) }, Range { start: 8, end: 10, loc: slot }]));
        assert_eq!(vars[1], (1, vec![Range { start: 8, end: 12, loc: reg(rbx) }]));
    }
}
