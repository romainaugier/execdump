/*
 * Copies at the joins: a phi is a variable assigned on the edges that lead to it, the value assigned
 * on an edge is often a variable itself (v1 = v7;). A phi and the variables flowing into it that are
 * never alive at the same time share one variable, and the copies between them disappear.
 *
 * Liveness is on the values that are variables (and the parameters): a value is used where the
 * statement that reads it is (an inlined expression is evaluated in the statement it is part of), a
 * phi reads its values at the end of the blocks they come from. Two values interfere when one is
 * alive where the other is defined.
 */

use super::ast::{Var, VarId};
use super::ir::{Func, Op, ValueId, ValueKind};

use std::collections::{HashMap, HashSet};

/// Position of a definition before the instructions of a block (phis, parameters)
const ENTRY: i64 = -1;

struct BitSet(Vec<u64>);

impl BitSet {
    fn new(size: usize) -> Self {
        return BitSet(vec![0; size.div_ceil(64)]);
    }

    fn get(&self, i: usize) -> bool {
        return self.0[i / 64] >> (i % 64) & 1 == 1;
    }

    fn set(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    /// self |= other & !mask, true when it changed
    fn union_without(&mut self, other: &BitSet, mask: &BitSet) -> bool {
        let mut changed = false;

        for ((word, &add), &without) in self.0.iter_mut().zip(other.0.iter()).zip(mask.0.iter()) {
            let new = *word | (add & !without);
            changed |= new != *word;
            *word = new;
        }

        return changed;
    }
}

struct Liveness {
    /// Tracked values: the variables and the parameters
    values: Vec<ValueId>,
    /// Definition of each tracked value: block and position
    defs: Vec<(usize, i64)>,
    /// Uses of each tracked value: block and position (the length of the block for the end of it)
    uses: Vec<Vec<(usize, i64)>>,
    live_out: Vec<BitSet>,
}

impl Liveness {
    fn new(f: &Func, var_of: &[Option<VarId>]) -> Self {
        let mut values = Vec::new();
        let mut defs = Vec::new();
        let mut position: HashMap<ValueId, (usize, i64)> = HashMap::new();

        for (b, block) in f.blocks.iter().enumerate() {
            for (i, &id) in block.insts.iter().enumerate() {
                position.insert(id, (b, if f.op(id) == Some(Op::Phi) { ENTRY } else { i as i64 }));
            }
        }

        for (id, value) in f.values.iter().enumerate() {
            let def = match value.kind {
                ValueKind::Param(_) => (0, ENTRY),
                _ if var_of[id].is_some() => match position.get(&id) {
                    Some(&p) => p,
                    None => continue,
                },
                _ => continue,
            };

            values.push(id);
            defs.push(def);
        }

        let mut liveness = Liveness { values, defs, uses: Vec::new(), live_out: Vec::new() };
        liveness.uses = liveness.values.iter().map(|&v| liveness.use_points(f, var_of, &position, v)).collect();
        liveness.solve(f);

        return liveness;
    }

    /// Where a value is read: the statements its uses are evaluated in, the end of the blocks a phi takes it from
    fn use_points(&self, f: &Func, var_of: &[Option<VarId>], position: &HashMap<ValueId, (usize, i64)>, value: ValueId) -> Vec<(usize, i64)> {
        let mut points = Vec::new();
        let mut stack: Vec<ValueId> = vec![value];
        let mut seen: HashSet<ValueId> = HashSet::new();

        while let Some(id) = stack.pop() {
            for &user in f.values[id].uses.iter() {
                match &f.values[user].kind {
                    ValueKind::Inst { op: Op::Phi, operands, blocks, .. } => {
                        for (operand, &from) in operands.iter().zip(blocks.iter()) {
                            if *operand == id {
                                points.push((from, f.blocks[from].insts.len() as i64));
                            }
                        }
                    }
                    // A variable, a statement: read where it is; an inlined expression: where its uses are
                    _ if var_of[user].is_some() || f.values[user].uses.is_empty() => points.extend(position.get(&user).copied()),
                    _ => {
                        if seen.insert(user) {
                            stack.push(user);
                        }
                    }
                }
            }
        }

        return points;
    }

    fn solve(&mut self, f: &Func) {
        let count = f.blocks.len();
        let size = self.values.len();
        let mut used = (0..count).map(|_| BitSet::new(size)).collect::<Vec<_>>();
        let mut kill = (0..count).map(|_| BitSet::new(size)).collect::<Vec<_>>();

        for (i, uses) in self.uses.iter().enumerate() {
            let (def_block, _) = self.defs[i];
            kill[def_block].set(i);

            for &(block, _) in uses.iter() {
                if block != def_block {
                    used[block].set(i);
                }
            }
        }

        let mut live_in: Vec<BitSet> = used.iter().map(|g| BitSet(g.0.clone())).collect();
        let mut live_out: Vec<BitSet> = (0..count).map(|_| BitSet::new(size)).collect();
        let empty = BitSet::new(size);
        let mut changed = true;

        while changed {
            changed = false;

            for b in (0..count).rev() {
                for &succ in f.blocks[b].succs.iter() {
                    changed |= live_out[b].union_without(&live_in[succ], &empty);
                }

                changed |= live_in[b].union_without(&live_out[b], &kill[b]);
            }
        }

        self.live_out = live_out;
    }

    /// Whether a value is alive right after a position of a block
    fn alive_after(&self, value: usize, block: usize, position: i64) -> bool {
        let (def_block, def_position) = self.defs[value];

        if def_block == block && def_position > position {
            return false;
        }

        // Alive at the start of the block when defined elsewhere: it reaches it (it is used in it or after it)
        return self.live_out[block].get(value) || self.uses[value].iter().any(|&(b, p)| b == block && p > position);
    }

    fn interfere(&self, a: usize, b: usize) -> bool {
        if a == b {
            return false;
        }

        let (block_a, position_a) = self.defs[a];
        let (block_b, position_b) = self.defs[b];

        return self.alive_after(a, block_b, position_b) || self.alive_after(b, block_a, position_a);
    }
}

/// Merges the variables of the phis with the variables flowing into them when they never interfere and
/// have the same type (a parameter keeps its variable)
pub fn coalesce(f: &Func, var_of: &mut [Option<VarId>], vars: &[Var], params: &[VarId]) {
    let liveness = Liveness::new(f, var_of);
    let var = |id: ValueId| -> Option<VarId> {
        match f.values[id].kind {
            ValueKind::Param(index) => params.get(index).copied(),
            _ => var_of[id],
        }
    };

    // Classes of values sharing a variable
    let mut class_of: HashMap<VarId, Vec<usize>> = HashMap::new();

    for (i, &id) in liveness.values.iter().enumerate() {
        if let Some(v) = var(id) {
            class_of.entry(v).or_default().push(i);
        }
    }

    let mut renamed: HashMap<VarId, VarId> = HashMap::new();
    let find = |renamed: &HashMap<VarId, VarId>, mut v: VarId| {
        while let Some(&next) = renamed.get(&v) {
            v = next;
        }

        v
    };

    for (phi, value) in f.values.iter().enumerate() {
        let ValueKind::Inst { op: Op::Phi, operands, .. } = &value.kind else {
            continue;
        };

        for &operand in operands.iter() {
            let (Some(a), Some(b)) = (var(phi).map(|v| find(&renamed, v)), var(operand).map(|v| find(&renamed, v))) else {
                continue;
            };

            if a == b || vars[a].ty != vars[b].ty {
                continue;
            }

            let (class_a, class_b) = (&class_of[&a], &class_of[&b]);

            if class_a.iter().any(|&x| class_b.iter().any(|&y| liveness.interfere(x, y))) {
                continue;
            }

            // The variable of a parameter stays, two parameters always interfere (both alive at the entry)
            let (keep, merged) = if params.contains(&b) { (b, a) } else { (a, b) };
            let moved = class_of.remove(&merged).unwrap_or_default();
            class_of.entry(keep).or_default().extend(moved);
            renamed.insert(merged, keep);
        }
    }

    for slot in var_of.iter_mut() {
        if let Some(v) = slot {
            *v = find(&renamed, *v);
        }
    }
}
