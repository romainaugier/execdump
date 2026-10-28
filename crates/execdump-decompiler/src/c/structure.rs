// SPDX-License-Identifier: Apache-2.0
/*
 * Control flow structuring: the blocks become if/else, loops and switches
 *
 * Conditions that only lead to the same targets are merged first (a && b, a || b). Natural loops
 * come from the back edges, a branch is closed where its paths join (its post dominator once the
 * paths that return early are left out), reaching the loop header is a continue and reaching the
 * loop follow a break. The other exits of a loop are emitted where the loop leaves to them. A block
 * several paths of a branch reach before they join follows the branch, guarded by the condition
 * under which they reach it (reaching conditions, as in "No More Gotos"). A block reached again is
 * copied when what follows it is small, anything else is a goto. Cleanups then give the loops
 * their condition (while, do while, for) and flatten the if/else chains.
 */

use super::ast::{BinaryOp, Case, Expr, Stmt, StmtKind, UnaryOp, Var, VarId};
use super::build::{SBlock, Term};
use super::reaching::{Atoms, Cond};
use crate::types::CType;

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

/*
 * Graph
 */

fn successors(term: &Term) -> Vec<usize> {
    return match term {
        Term::Jump(t) => vec![*t],
        Term::Branch(_, t, f) => vec![*t, *f],
        Term::Switch(_, cases, default) => cases.iter().map(|(_, t)| *t).chain(std::iter::once(*default)).collect(),
        Term::Return(_) | Term::Unreachable => Vec::new(),
    };
}

fn reverse_post_order(succs: &[Vec<usize>], entry: usize) -> Vec<usize> {
    let mut visited = vec![false; succs.len()];
    let mut order = Vec::new();
    let mut stack = vec![(entry, 0usize)];
    visited[entry] = true;

    while let Some((node, next)) = stack.pop() {
        if next < succs[node].len() {
            stack.push((node, next + 1));
            let to = succs[node][next];

            if !visited[to] {
                visited[to] = true;
                stack.push((to, 0));
            }
        } else {
            order.push(node);
        }
    }

    order.reverse();
    return order;
}

/// Immediate dominators (Cooper, Harvey, Kennedy), None for the entry and the unreachable nodes
fn dominators(succs: &[Vec<usize>], entry: usize) -> Vec<Option<usize>> {
    let order = reverse_post_order(succs, entry);
    let mut index = vec![usize::MAX; succs.len()];

    for (i, &node) in order.iter().enumerate() {
        index[node] = i;
    }

    let mut preds = vec![Vec::new(); succs.len()];

    for (node, targets) in succs.iter().enumerate() {
        for &t in targets {
            preds[t].push(node);
        }
    }

    let mut idom: Vec<Option<usize>> = vec![None; succs.len()];
    idom[entry] = Some(entry);

    let intersect = |idom: &[Option<usize>], mut a: usize, mut b: usize| -> usize {
        while a != b {
            while index[a] > index[b] {
                a = idom[a].unwrap();
            }

            while index[b] > index[a] {
                b = idom[b].unwrap();
            }
        }

        a
    };

    let mut changed = true;

    while changed {
        changed = false;

        for &node in order.iter().skip(1) {
            let mut new = None;

            for &p in preds[node].iter() {
                if idom[p].is_none() || index[p] == usize::MAX {
                    continue;
                }

                new = Some(match new {
                    None => p,
                    Some(current) => intersect(&idom, p, current),
                });
            }

            if new.is_some() && idom[node] != new {
                idom[node] = new;
                changed = true;
            }
        }
    }

    idom[entry] = None;
    return idom;
}

/// Natural loops of the back edges, merged by header: their header and their nodes
fn natural_loops(succs: &[Vec<usize>], order: &[usize], idom: &[Option<usize>], preds: &[Vec<usize>]) -> HashMap<usize, HashSet<usize>> {
    let mut loops: HashMap<usize, HashSet<usize>> = HashMap::default();
    let reachable: HashSet<usize> = order.iter().copied().collect();

    for &node in order.iter() {
        for &target in succs[node].iter() {
            if !dominates(idom, target, node) {
                continue;
            }

            let body = loops.entry(target).or_insert_with(|| HashSet::from_iter([target]));
            let mut stack = vec![node];

            while let Some(n) = stack.pop() {
                if reachable.contains(&n) && body.insert(n) {
                    stack.extend(preds[n].iter().copied());
                }
            }
        }
    }

    return loops;
}

fn dominates(idom: &[Option<usize>], a: usize, mut b: usize) -> bool {
    loop {
        if a == b {
            return true;
        }

        match idom[b] {
            Some(parent) => b = parent,
            None => return false,
        }
    }
}

struct Loop {
    body: HashSet<usize>,
    follow: Option<usize>,
}

/*
 * Structurer
 */

struct Structurer<'a> {
    blocks: Vec<SBlock>,
    /// Variables of the function, the conditions tested again are kept in new ones
    vars: &'a mut Vec<Var>,
    preds: Vec<Vec<usize>>,
    /// Where the branches of a block join (see Structurer::new)
    joins: Vec<Option<usize>>,
    loops: HashMap<usize, Loop>,
    emitted: Vec<bool>,
    /// Statements left while copying a region instead of jumping to it, None when not copying
    copy_budget: Option<usize>,
    copy_failed: bool,
    /// Blocks where the regions being emitted stop: the guarded blocks of the enclosing branches,
    /// with the loop they are guarded in (inside a nested loop the paths have to leave it first)
    stops: Vec<(usize, Option<usize>)>,
}

#[derive(Clone, Copy)]
struct Context<'l> {
    header: Option<usize>,
    follow: Option<usize>,
    /// Blocks the region can emit (the body of the current loop), all at the top level
    body: Option<&'l HashSet<usize>>,
    /// Blocks it cannot emit: the loop whose exit is emitted inside of it
    exclude: Option<&'l HashSet<usize>>,
    /// Body of the loop around the current one, where the exits of the current one are
    outer: Option<&'l HashSet<usize>>,
    /// Inside a switch a break leaves the switch, the loop follow is reached with a goto
    in_switch: bool,
}

const TOP: Context<'static> = Context { header: None, follow: None, body: None, exclude: None, outer: None, in_switch: false };

/// Statements a small region can have to be copied where it is reached again instead of jumped to
const MAX_COPY: usize = 8;

/// Size of the regions (in blocks) whose shared blocks are guarded by their reaching condition
const MAX_GUARDED_REGION: usize = 48;

/// Literals a guard can have (a longer one is less readable than a goto)
const MAX_GUARD_LITERALS: usize = 4;

/// Values of the switches that are tests instead
const MAX_IF_CASES: usize = 2;

/// Nodes given an exit when the left out tails cut them from it (each one costs a walk of the graph per
/// candidate)
const MAX_EXIT_LINKS: usize = 16;

/// A block that ends the function with at most a few statements
fn is_tail(b: &SBlock) -> bool {
    return matches!(b.term, Term::Return(_) | Term::Unreachable) && b.stmts.len() <= 3 && (b.stmts.len() < 3 || matches!(b.term, Term::Return(None)) || b.stmts.iter().all(|s| !matches!(s.kind, StmtKind::If(..))));
}

pub fn label(block: usize) -> String {
    return format!("label_{}", block);
}

impl<'a> Structurer<'a> {
    fn new(blocks: Vec<SBlock>, vars: &'a mut Vec<Var>) -> Self {
        let succs: Vec<Vec<usize>> = blocks.iter().map(|b| successors(&b.term)).collect();
        let order = reverse_post_order(&succs, 0);
        let idom = dominators(&succs, 0);
        let count = blocks.len();

        let mut preds = vec![Vec::new(); count];

        for (node, targets) in succs.iter().enumerate() {
            for &t in targets {
                preds[t].push(node);
            }
        }

        let mut loops: HashMap<usize, Loop> = natural_loops(&succs, &order, &idom, &preds).into_iter().map(|(h, body)| (h, Loop { body, follow: None })).collect();

        // Number of loops around each node
        let mut depth = vec![0usize; count];

        for l in loops.values() {
            l.body.iter().for_each(|&n| depth[n] += 1);
        }

        // Post dominators: dominators of the reversed graph from a virtual exit
        let post_dominators = |kept: &dyn Fn(usize) -> bool| -> Vec<Option<usize>> {
            let exit = count;
            let mut reversed = vec![Vec::new(); count + 1];

            for (node, targets) in succs.iter().enumerate().filter(|(n, _)| kept(*n)) {
                let mut sink = true;

                for &t in targets.iter().filter(|&&t| kept(t)) {
                    reversed[t].push(node);
                    sink = false;
                }

                if sink {
                    reversed[exit].push(node);
                }
            }

            // The nodes left without a path to the exit (a loop whose exits were all left out) leave from
            // one that led to the left out nodes: the one in the most loops (the exit of the innermost loop
            // is taken last), and that most of them reach, until they all reach one
            let mut reaches = vec![false; count + 1];

            // Marks what reaches a node, returns how many were not marked yet
            let mark = |reaches: &mut Vec<bool>, reversed: &[Vec<usize>], from: usize, apply: bool| -> usize {
                let mut seen = reaches.clone();
                let mut stack = vec![from];
                let mut new = (!seen[from]) as usize;
                seen[from] = true;

                while let Some(n) = stack.pop() {
                    for &p in reversed[n].iter() {
                        if !std::mem::replace(&mut seen[p], true) {
                            new += 1;
                            stack.push(p);
                        }
                    }
                }

                if apply {
                    *reaches = seen;
                }

                return new;
            };

            mark(&mut reaches, &reversed, exit, true);

            for _ in 0..MAX_EXIT_LINKS {
                let candidates: Vec<usize> = (0..count).filter(|&n| kept(n) && !reaches[n] && succs[n].iter().any(|&t| !kept(t))).collect();
                let best = candidates.iter().copied().max_by_key(|&c| (depth[c], mark(&mut reaches, &reversed, c, false), usize::MAX - c));

                let Some(best) = best else {
                    break;
                };

                reversed[exit].push(best);
                mark(&mut reaches, &reversed, best, true);
            }

            return dominators(&reversed, exit).into_iter().take(count).map(|d| d.filter(|&d| d != exit)).collect();
        };

        let ipdom = post_dominators(&|_| true);

        // Private tails: blocks of a single predecessor that only lead to other private tails (they
        // end the function). Without them the post dominators are where the other paths join, the
        // paths that return early do not make them the exit.
        let mut private = vec![false; count];

        for &node in order.iter().rev() {
            private[node] = preds[node].len() == 1 && succs[node].iter().all(|&s| private[s]);
        }

        let pruned = post_dominators(&|n| !private[n]);
        let joins: Vec<Option<usize>> = (0..count).map(|n| if private[n] { ipdom[n] } else { pruned[n].or(ipdom[n]) }).collect();

        let position: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &n)| (n, i)).collect();

        for (&header, l) in loops.iter_mut() {
            let mut exits: Vec<usize> = l.body.iter().flat_map(|&n| succs[n].iter().copied()).filter(|t| !l.body.contains(t)).collect();
            exits.sort_by_key(|t| position.get(t).copied().unwrap_or(usize::MAX));

            // Where the paths from the header join (without the early returns) when it leaves the loop and
            // does not end the function, else its post dominator, else the most targeted exit that is not a
            // small tail (those are repeated where they are reached)
            l.follow = match (joins[header], ipdom[header]) {
                (Some(j), _) if exits.contains(&j) && !private[j] && !is_tail(&blocks[j]) => Some(j),
                (_, Some(p)) if exits.contains(&p) => Some(p),
                _ => exits.iter().max_by_key(|&&t| (!is_tail(&blocks[t]), exits.iter().filter(|&&e| e == t).count(), usize::MAX - position.get(&t).copied().unwrap_or(0))).copied(),
            };
        }

        return Structurer { blocks, vars, preds, joins, loops, emitted: vec![false; count], copy_budget: None, copy_failed: false, stops: Vec::new() };
    }

    fn is_tail(&self, block: usize) -> bool {
        return is_tail(&self.blocks[block]);
    }

    fn goto(&self, target: usize, addr: Option<u64>) -> Stmt {
        return Stmt::new(StmtKind::Goto(label(target)), addr);
    }

    /// Where the branches of a block join, when it is inside the current loop
    fn merge(&self, block: usize, context: &Context) -> Option<usize> {
        let merge = self.joins[block]?;

        return match context.body {
            Some(body) if !body.contains(&merge) || Some(merge) == context.header => None,
            _ => Some(merge),
        };
    }

    /// A loop exit only the loop leads to: emitted where the loop leaves to it, it ends with a break
    /// when it reaches the loop follow
    fn owned_exit(&self, block: usize, context: &Context) -> bool {
        let Some(body) = context.body else {
            return false;
        };

        return context.exclude.is_none() && !body.contains(&block) && context.outer.is_none_or(|o| o.contains(&block)) && self.preds[block].iter().all(|p| body.contains(p));
    }

    /// The statements of a region emitted again where it is reached a second time, when it is small
    /// and has no loop
    fn copy(&mut self, block: usize, stop: Option<usize>, context: Context) -> Option<Vec<Stmt>> {
        self.copy_budget = Some(MAX_COPY);
        self.copy_failed = false;

        let stmts = self.region(block, stop, context, false);
        let failed = self.copy_failed;

        self.copy_budget = None;
        self.copy_failed = false;

        return (!failed).then_some(stmts);
    }

    /// The blocks several paths from a branch reach before they join, with the condition under which
    /// they are reached: the paths stop there and the blocks follow the branch, guarded by it. Only
    /// for a region of a single entry (its loops have a single exit), when the conditions are small
    /// and can be tested again there: nothing they depend on changed, or they are kept in a
    /// variable (the conditions with calls, or reading memory that changed). Returns the guarded
    /// blocks and the blocks whose condition goes to a new variable (the next ones of the function).
    fn guarded(&self, branch: usize, join: Option<usize>, context: &Context) -> (Vec<(usize, Expr)>, Vec<usize>) {
        if self.copy_budget.is_some() {
            return (Vec::new(), Vec::new());
        }

        let boundary = |n: usize| {
            n == branch
                || Some(n) == join
                || Some(n) == context.header
                || Some(n) == context.follow
                || self.stops.iter().any(|&(s, _)| s == n)
                || self.emitted[n]
                || self.is_tail(n)
                || context.body.is_some_and(|b| !b.contains(&n))
                || context.exclude.is_some_and(|e| e.contains(&n))
        };

        // The region: the blocks reached from the branch before the boundaries, a loop is one
        // block going to its follow (only when it has no other exit)
        let next = |n: usize| -> Option<Vec<usize>> {
            match self.loops.get(&n) {
                Some(l) if n != branch => {
                    let exits: HashSet<usize> = l.body.iter().flat_map(|&b| successors(&self.blocks[b].term)).filter(|t| !l.body.contains(t)).collect();
                    (exits.len() <= 1 && exits.iter().all(|&e| Some(e) == l.follow)).then(|| exits.into_iter().collect())
                }
                _ => Some(successors(&self.blocks[n].term)),
            }
        };

        // Reverse post order of the region from the branch (none when it is too large or has a cycle)
        let mut order = Vec::new();
        let mut state: HashMap<usize, bool> = HashMap::default();
        let mut stack = vec![(branch, 0usize)];
        state.insert(branch, false);

        while let Some((node, i)) = stack.pop() {
            let Some(succs) = next(node) else {
                return (Vec::new(), Vec::new());
            };

            match succs.get(i) {
                Some(&s) => {
                    stack.push((node, i + 1));

                    if boundary(s) {
                        continue;
                    }

                    match state.get(&s) {
                        Some(false) => return (Vec::new(), Vec::new()),
                        Some(true) => {}
                        None => {
                            state.insert(s, false);
                            stack.push((s, 0));
                        }
                    }
                }
                None => {
                    state.insert(node, true);
                    order.push(node);
                }
            }

            if state.len() > MAX_GUARDED_REGION {
                return (Vec::new(), Vec::new());
            }
        }

        order.reverse();
        let position: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let edges = |n: usize| next(n).unwrap_or_default().into_iter().filter(|s| position.contains_key(s) && *s != branch);

        // Shared blocks: reached from several blocks of the region
        let mut preds: HashMap<usize, usize> = HashMap::default();

        for &n in order.iter() {
            let mut targets: Vec<usize> = edges(n).collect();
            targets.dedup();

            for t in targets {
                *preds.entry(t).or_default() += 1;
            }
        }

        if !preds.values().any(|&c| c > 1) {
            return (Vec::new(), Vec::new());
        }

        // The region has a single entry: a path entering it elsewhere would test guards that are
        // not about it (the bodies of its loops are in it)
        let mut inside: HashSet<usize> = order.iter().copied().collect();

        for &n in order.iter().filter(|&&n| n != branch) {
            if let Some(l) = self.loops.get(&n) {
                inside.extend(l.body.iter().copied());
            }
        }

        if order.iter().filter(|&&n| n != branch).any(|n| self.preds[*n].iter().any(|p| !inside.contains(p))) {
            return (Vec::new(), Vec::new());
        }

        // What each block of the region changes: the variables it assigns, and whether it writes
        // memory (or calls); a loop block changes what its body changes
        let effects: HashMap<usize, Effects> = order
            .iter()
            .map(|&n| {
                let blocks: Vec<usize> = match self.loops.get(&n) {
                    Some(l) if n != branch => l.body.iter().copied().collect(),
                    _ => vec![n],
                };

                let mut effects = Effects::default();

                for b in blocks {
                    self.blocks[b].stmts.iter().for_each(|s| effects.stmt(s));
                    effects.term(&self.blocks[b].term);
                }

                (n, effects)
            })
            .collect();

        // The blocks already emitted the region leads to are copied there when they are small: what
        // they change can change before the guards too
        let mut copied = Effects::default();
        let mut seen: HashSet<usize> = HashSet::default();
        let mut stack: Vec<usize> = order.iter().flat_map(|&n| next(n).unwrap_or_default()).filter(|&t| self.emitted[t] && !position.contains_key(&t)).collect();

        while let Some(n) = stack.pop() {
            if Some(n) == join || self.stops.iter().any(|&(s, _)| s == n) || !seen.insert(n) {
                continue;
            }

            if seen.len() > MAX_GUARDED_REGION {
                copied.memory = true;
                copied.everything = true;
                break;
            }

            self.blocks[n].stmts.iter().for_each(|s| copied.stmt(s));
            copied.term(&self.blocks[n].term);
            stack.extend(successors(&self.blocks[n].term));
        }

        // Whether an expression has no call, and nothing after a block of the region changes what it
        // reads: tested anywhere after the block it has the same value
        let unchanged_after = |block: usize, expr: &Expr| -> bool {
            let (vars, memory, call) = reads(expr);
            let from = position[&block];
            let changes = |e: &Effects| e.everything || !e.vars.is_disjoint(&vars) || (memory && e.memory);

            return !call && !changes(&copied) && !order[from + 1..].iter().any(|n| changes(&effects[n]));
        };

        // The atoms are the conditions of the branches (the same unchanged condition tested by several
        // blocks is one atom, the blocks are its owners) and the cases of the switches
        let mut atoms = Atoms::default();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut first_atom: HashMap<usize, usize> = HashMap::default();

        for &n in order.iter().filter(|n| !self.loops.contains_key(n) || **n == branch) {
            match &self.blocks[n].term {
                Term::Branch(c, _, _) => match (0..atoms.exprs.len()).find(|&a| atoms.switch[a].is_none() && atoms.exprs[a] == *c && unchanged_after(owners[a][0], c)) {
                    Some(atom) => {
                        first_atom.insert(n, atom);
                        owners[atom].push(n);
                    }
                    None => {
                        first_atom.insert(n, atoms.add(c.clone(), None));
                        owners.push(vec![n]);
                    }
                },
                Term::Switch(value, cases, _) => {
                    first_atom.insert(n, atoms.exprs.len());

                    for (values, _) in cases.iter() {
                        let test = values.iter().map(|&v| Expr::binary(BinaryOp::Eq, value.clone(), Expr::Int(v))).reduce(|a, b| Expr::binary(BinaryOp::LogicalOr, a, b));
                        atoms.add(test.unwrap_or(Expr::Int(0)), Some(n));
                        owners.push(vec![n]);
                    }
                }
                _ => {}
            }
        }

        // The condition of the edge from a block to one of its successors (None when too large)
        let edge = |n: usize, to: usize| -> Option<Cond> {
            if self.loops.contains_key(&n) && n != branch {
                return Some(Cond::truth());
            }

            return match &self.blocks[n].term {
                Term::Branch(_, t, f) if t != f => Some(Cond::lit(first_atom[&n], to == *t)),
                Term::Switch(_, cases, default) => {
                    let first = first_atom[&n];
                    let mut cond = Cond::falsity();

                    for (i, (_, target)) in cases.iter().enumerate() {
                        if *target == to {
                            cond = cond.or(&Cond::lit(first + i, true))?;
                        }
                    }

                    if *default == to {
                        let mut none = Cond::truth();

                        for i in 0..cases.len() {
                            none = none.and(&Cond::lit(first + i, false), &atoms)?;
                        }

                        cond = cond.or(&none)?;
                    }

                    Some(cond)
                }
                _ => Some(Cond::truth()),
            };
        };

        // Reaching conditions, in the order of the region (None when unknown, too large)
        let mut reaching: HashMap<usize, Option<Cond>> = HashMap::default();
        reaching.insert(branch, Some(Cond::truth()));

        for &n in order.iter() {
            let from = reaching.get(&n).cloned().flatten();
            let mut targets: Vec<usize> = edges(n).collect();
            targets.dedup();

            for t in targets {
                let added = from.as_ref().and_then(|f| f.and(&edge(n, t)?, &atoms));
                let current = reaching.get(&t).cloned().unwrap_or(Some(Cond::falsity()));

                let merged = match (current, added) {
                    (Some(c), Some(a)) => c.or(&a),
                    _ => None,
                };

                reaching.insert(t, merged);
            }
        }

        // An atom can be tested again when it has no call and nothing after its (first) block changes
        // what it reads: its blocks then all test the same value
        let testable = |atom: usize| unchanged_after(owners[atom][0], &atoms.exprs[atom]);

        // A branch condition (not a case) tested by one block can be kept in a variable there
        let cacheable = |atom: usize| atoms.switch[atom].is_none() && owners[atom].len() == 1;

        // The shared blocks whose condition is small and can be tested
        let shared: Vec<usize> = order.iter().copied().filter(|n| preds.get(n).is_some_and(|&c| c > 1)).collect();
        let mut accepted: Vec<usize> = shared
            .iter()
            .copied()
            .filter(|n| match reaching.get(n) {
                Some(Some(cond)) => cond.atoms().iter().all(|&a| testable(a) || cacheable(a)) && cond.expr(&atoms).1 <= MAX_GUARD_LITERALS,
                _ => false,
            })
            .collect();

        // A guarded block reaching a shared block that is not guarded would jump back to it (it is
        // emitted in a path of the branch before), and run the guards after it again: it is not
        // guarded either
        loop {
            let rejected: Vec<usize> = shared.iter().copied().filter(|n| !accepted.contains(n)).collect();

            let reaches = |from: usize| -> bool {
                let mut seen = HashSet::from_iter([from]);
                let mut stack = vec![from];

                while let Some(n) = stack.pop() {
                    for t in edges(n) {
                        if rejected.contains(&t) {
                            return true;
                        }

                        if !accepted.contains(&t) && seen.insert(t) {
                            stack.push(t);
                        }
                    }
                }

                false
            };

            let mut kept: Vec<usize> = accepted.iter().copied().filter(|&n| !reaches(n)).collect();

            // After the branches of the region the paths go on to their join: the ones stopped at a
            // guarded block must not, the join is guarded too (or the end of the region)
            for &n in order.iter().filter(|&&n| n != branch && !self.loops.contains_key(&n)) {
                if !matches!(self.blocks[n].term, Term::Branch(..) | Term::Switch(..)) {
                    continue;
                }

                let join_ok = match self.merge(n, context) {
                    None => true,
                    Some(m) => Some(m) == join || kept.contains(&m),
                };

                if join_ok {
                    continue;
                }

                let mut seen = HashSet::from_iter([n]);
                let mut stack = vec![n];

                while let Some(x) = stack.pop() {
                    for t in edges(x) {
                        if seen.insert(t) {
                            stack.push(t);
                        }
                    }
                }

                kept.retain(|k| !seen.contains(k));
            }

            if kept.len() == accepted.len() {
                break;
            }

            accepted = kept;
        }

        // The guards, the atoms that cannot be tested again on their variable
        let mut guarded = Vec::new();
        let mut cached: Vec<usize> = Vec::new();

        for n in accepted {
            let Some(Some(cond)) = reaching.get(&n) else {
                continue;
            };

            let mut renamed = Atoms { exprs: atoms.exprs.clone(), switch: atoms.switch.clone() };

            for atom in cond.atoms().into_iter().filter(|&a| !testable(a)) {
                let owner = owners[atom][0];

                if !cached.contains(&owner) {
                    cached.push(owner);
                }

                let position = cached.iter().position(|&o| o == owner).unwrap();
                renamed.exprs[atom] = Expr::Var(self.vars.len() + position);
            }

            guarded.push((n, cond.expr(&renamed).0));
        }

        return (guarded, cached);
    }

    /// The conditions of the blocks are kept in new variables, the branches test them
    fn cache_conditions(&mut self, blocks: Vec<usize>) {
        for block in blocks {
            let var = self.vars.len();
            self.vars.push(Var { name: String::new(), ty: CType::Bool });

            let b = &mut self.blocks[block];

            if let Term::Branch(condition, _, _) = &mut b.term {
                let value = std::mem::replace(condition, Expr::Var(var));
                b.stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(var), value), b.addr));
            }
        }
    }

    /// Emits the guarded blocks of a branch after it, each stops at the next ones
    fn emit_guarded(&mut self, guarded: Vec<(usize, Expr)>, merge: Option<usize>, context: Context, out: &mut Vec<Stmt>) {
        for (block, guard) in guarded {
            if let Some(position) = self.stops.iter().rposition(|&s| s == (block, context.header)) {
                self.stops.remove(position);
            }

            let body = self.region(block, merge, context, false);

            match guard {
                Expr::Int(1) => out.extend(body),
                guard => out.push(Stmt::new(StmtKind::If(guard, body, Vec::new()), self.blocks[block].addr)),
            }
        }
    }

    fn region(&mut self, start: usize, stop: Option<usize>, context: Context, mut entering_loop: bool) -> Vec<Stmt> {
        let mut out = Vec::new();
        let mut current = Some(start);

        while let Some(block) = current {
            let addr = self.blocks[block].addr;

            if self.copy_failed || Some(block) == stop {
                break;
            }

            if !entering_loop {
                if Some(block) == context.header {
                    out.push(Stmt::new(StmtKind::Continue, addr));
                    break;
                }

                if Some(block) == context.follow {
                    let stmt = if context.in_switch { self.goto(block, addr) } else { Stmt::new(StmtKind::Break, addr) };
                    out.push(stmt);
                    break;
                }

                // A guarded block of an enclosing branch of the same loop: the paths stop there
                if self.stops.contains(&(block, context.header)) {
                    break;
                }

                // Small blocks that end the function are repeated instead of jumped to
                if self.is_tail(block) {
                    out.extend(self.blocks[block].stmts.iter().cloned());

                    if let Term::Return(value) = &self.blocks[block].term {
                        out.push(Stmt::new(StmtKind::Return(value.clone()), addr));
                    }

                    break;
                }

                if !self.emitted[block] && self.copy_budget.is_none() && self.owned_exit(block, &context) {
                    let exit = Context { body: context.outer, exclude: context.body, outer: None, ..context };
                    out.extend(self.region(block, None, exit, false));
                    break;
                }

                let outside = context.body.is_some_and(|body| !body.contains(&block)) || context.exclude.is_some_and(|e| e.contains(&block));

                if outside || (self.emitted[block] && self.copy_budget.is_none()) {
                    if !outside && !self.loops.contains_key(&block) {
                        if let Some(copy) = self.copy(block, stop, context) {
                            out.extend(copy);
                            break;
                        }
                    }

                    out.push(self.goto(block, addr));
                    break;
                }

                if self.loops.contains_key(&block) {
                    if self.copy_budget.is_some() {
                        self.copy_failed = true;
                        break;
                    }

                    let l = &self.loops[&block];
                    let (body, follow) = (l.body.clone(), l.follow);
                    let inner = Context { header: Some(block), follow, body: Some(&body), exclude: None, outer: context.body, in_switch: false };
                    let stmts = self.region(block, None, inner, true);

                    out.push(Stmt::new(StmtKind::While(Expr::Int(1), stmts), addr));
                    current = follow;
                    continue;
                }
            }

            entering_loop = false;

            match self.copy_budget {
                Some(budget) => match budget.checked_sub(self.blocks[block].stmts.len() + 1) {
                    Some(left) => self.copy_budget = Some(left),
                    None => {
                        self.copy_failed = true;
                        break;
                    }
                },
                None => {
                    self.emitted[block] = true;
                    out.push(Stmt::new(StmtKind::Label(label(block)), None));
                }
            }

            // The blocks shared by the paths of a branch, guarded after it (their conditions kept first)
            let guarded = match self.blocks[block].term {
                Term::Branch(..) | Term::Switch(..) => {
                    let (guarded, cached) = self.guarded(block, self.merge(block, &context), &context);
                    self.cache_conditions(cached);
                    guarded
                }
                _ => Vec::new(),
            };

            out.extend(self.blocks[block].stmts.iter().cloned());

            let term = self.blocks[block].term.clone();

            current = match &term {
                Term::Return(value) => {
                    out.push(Stmt::new(StmtKind::Return(value.clone()), addr));
                    None
                }
                Term::Unreachable => None,
                Term::Jump(target) => Some(*target),
                Term::Branch(condition, on_true, on_false) => {
                    let merge = self.merge(block, &context);
                    self.stops.extend(guarded.iter().map(|(b, _)| (*b, context.header)));

                    let then = self.region(*on_true, merge, context, false);
                    let otherwise = self.region(*on_false, merge, context, false);

                    out.push(Stmt::new(StmtKind::If(condition.clone(), then, otherwise), addr));
                    self.emit_guarded(guarded, merge, context, &mut out);
                    merge
                }
                Term::Switch(value, cases, default) => {
                    let merge = self.merge(block, &context);
                    self.stops.extend(guarded.iter().map(|(b, _)| (*b, context.header)));

                    let inner = Context { in_switch: true, ..context };
                    let mut c = Vec::new();

                    for (values, target) in cases.iter() {
                        let mut body = self.region(*target, merge, inner, false);

                        if !body.last().is_some_and(|s| s.is_jump()) {
                            body.push(Stmt::new(StmtKind::Break, None));
                        }

                        c.push(Case { values: values.clone(), body });
                    }

                    let default = if Some(*default) == merge { Vec::new() } else { self.region(*default, merge, inner, false) };
                    out.push(Stmt::new(StmtKind::Switch(value.clone(), c, default), addr));
                    self.emit_guarded(guarded, merge, context, &mut out);
                    merge
                }
            };
        }

        return out;
    }
}

/*
 * Effects of the statements, for the conditions tested again
 */

#[derive(Default)]
struct Effects {
    vars: HashSet<VarId>,
    /// Writes memory or calls a function
    memory: bool,
    /// Unknown, can change anything
    everything: bool,
}

impl Effects {
    fn expr(&mut self, e: &Expr) {
        e.visit(&mut |e| {
            if matches!(e, Expr::Call(..)) {
                self.memory = true;
            }
        });
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Assign(Expr::Var(v), value) => {
                self.vars.insert(*v);
                self.expr(value);
            }
            StmtKind::Assign(target, value) => {
                self.memory = true;
                self.expr(target);
                self.expr(value);
            }
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => self.expr(e),
            StmtKind::Comment(_) | StmtKind::Label(_) | StmtKind::Goto(_) | StmtKind::Break | StmtKind::Continue | StmtKind::Return(None) => {}
            // Anything else (not built before the structuring) changes everything
            _ => self.memory = true,
        }
    }

    fn term(&mut self, term: &Term) {
        match term {
            Term::Branch(c, ..) | Term::Switch(c, ..) | Term::Return(Some(c)) => self.expr(c),
            _ => {}
        }
    }
}

/// What an expression reads: its variables, whether it reads memory (or globals), whether it calls
fn reads(e: &Expr) -> (HashSet<VarId>, bool, bool) {
    let (mut vars, mut memory, mut call) = (HashSet::default(), false, false);

    e.visit(&mut |e| match e {
        Expr::Var(v) => {
            vars.insert(*v);
        }
        Expr::Call(..) => call = true,
        Expr::Name(name) if name == "NULL" => {}
        Expr::Name(_) | Expr::Index(..) | Expr::Member(..) | Expr::Unary(UnaryOp::Deref, _) => memory = true,
        _ => {}
    });

    return (vars, memory, call);
}

/// Short circuit conditions: a branch to a block that only branches again to one of the same targets
/// A switch of one or two values is tests of them (a break in its cases would leave the switch, not the
/// loop around it), when the value can be read again
fn small_switches(blocks: &mut Vec<SBlock>) {
    for b in 0..blocks.len() {
        let Term::Switch(value, cases, default) = &blocks[b].term else {
            continue;
        };

        let mut calls = false;
        value.visit(&mut |e| calls |= matches!(e, Expr::Call(..)));

        if calls || cases.iter().map(|(values, _)| values.len()).sum::<usize>() > MAX_IF_CASES {
            continue;
        }

        let test = |values: &[i128]| {
            let equal = |v: &i128| Expr::binary(BinaryOp::Eq, value.clone(), Expr::Int(*v));
            values.iter().skip(1).fold(equal(&values[0]), |e, v| Expr::binary(BinaryOp::LogicalOr, e, equal(v)))
        };

        let tests: Vec<(Expr, usize)> = cases.iter().filter(|(values, _)| !values.is_empty()).map(|(values, target)| (test(values), *target)).collect();
        let (default, addr) = (*default, blocks[b].addr);

        let Some(((first, target), rest)) = tests.split_first() else {
            blocks[b].term = Term::Jump(default);
            continue;
        };

        let mut next = default;

        for (condition, target) in rest.iter().rev() {
            blocks.push(SBlock { stmts: Vec::new(), term: Term::Branch(condition.clone(), *target, next), addr });
            next = blocks.len() - 1;
        }

        blocks[b].term = Term::Branch(first.clone(), *target, next);
    }
}

fn merge_conditions(blocks: &mut [SBlock]) {
    let mut changed = true;

    while changed {
        changed = false;

        let mut preds = vec![0usize; blocks.len()];

        for block in blocks.iter() {
            for t in successors(&block.term) {
                preds[t] += 1;
            }
        }

        for b in 0..blocks.len() {
            let Term::Branch(c, t, f) = blocks[b].term.clone() else {
                continue;
            };

            let condition_only = |n: usize, blocks: &[SBlock]| n != b && preds[n] == 1 && blocks[n].stmts.is_empty() && matches!(blocks[n].term, Term::Branch(..));

            let merged = if condition_only(t, blocks) {
                let Term::Branch(c2, t2, f2) = blocks[t].term.clone() else { unreachable!() };

                if f2 == f {
                    Some(Term::Branch(Expr::binary(BinaryOp::LogicalAnd, c.clone(), c2), t2, f))
                } else if t2 == f {
                    Some(Term::Branch(Expr::binary(BinaryOp::LogicalAnd, c.clone(), c2.not()), f2, f))
                } else {
                    None
                }
            } else {
                None
            };

            let merged = merged.or_else(|| {
                if !condition_only(f, blocks) {
                    return None;
                }

                let Term::Branch(c2, t2, f2) = blocks[f].term.clone() else { unreachable!() };

                if t2 == t {
                    Some(Term::Branch(Expr::binary(BinaryOp::LogicalOr, c.clone(), c2), t, f2))
                } else if f2 == t {
                    Some(Term::Branch(Expr::binary(BinaryOp::LogicalOr, c.clone(), c2.not()), t, t2))
                } else {
                    None
                }
            });

            if let Some(term) = merged {
                blocks[b].term = term;
                changed = true;
                break;
            }
        }
    }
}

/*
 * Cleanups
 */

fn walk(stmts: &mut Vec<Stmt>, f: &mut impl FnMut(&mut Vec<Stmt>)) {
    for stmt in stmts.iter_mut() {
        match &mut stmt.kind {
            StmtKind::If(_, a, b) => {
                walk(a, f);
                walk(b, f);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => walk(body, f),
            StmtKind::Switch(_, cases, default) => {
                cases.iter_mut().for_each(|c| walk(&mut c.body, f));
                walk(default, f);
            }
            _ => {}
        }
    }

    f(stmts);
}

/// Statements that jump to the enclosing loop (outside of the nested loops and switches for break)
fn has_loop_jump(stmts: &[Stmt], kind: &StmtKind) -> bool {
    return stmts.iter().any(|s| match &s.kind {
        k if k == kind => true,
        StmtKind::If(_, a, b) => has_loop_jump(a, kind) || has_loop_jump(b, kind),
        StmtKind::Switch(_, cases, default) if *kind == StmtKind::Continue => cases.iter().any(|c| has_loop_jump(&c.body, kind)) || has_loop_jump(default, kind),
        _ => false,
    });
}

/// Removes a jump at the end of a statement list (and of the branches of a final if)
fn strip_trailing(stmts: &mut Vec<Stmt>, kind: &StmtKind) {
    match stmts.last_mut().map(|s| &mut s.kind) {
        Some(k) if k == kind => {
            stmts.pop();
        }
        Some(StmtKind::If(_, a, b)) => {
            strip_trailing(a, kind);
            strip_trailing(b, kind);
        }
        _ => {}
    }
}

fn is_single(stmts: &[Stmt], kind: &StmtKind) -> bool {
    return stmts.len() == 1 && stmts[0].kind == *kind;
}

/// while (1) loops get their condition from a leading or trailing test
fn loop_conditions(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        // for (init;; step) { if (c) break; ... } -> for (init; !c; step) { ... }
        if let StmtKind::For(_, cond @ Expr::Int(1), _, body) = &mut stmt.kind {
            if let Some(StmtKind::If(c, then, otherwise)) = body.first().map(|s| &s.kind) {
                if is_single(then, &StmtKind::Break) && otherwise.is_empty() {
                    *cond = c.clone().not();
                    body.remove(0);
                }
            }

            continue;
        }

        let StmtKind::While(Expr::Int(1), body) = &mut stmt.kind else {
            continue;
        };

        strip_trailing(body, &StmtKind::Continue);

        // while (1) { if (c) break; ... } -> while (!c) { ... }
        if let Some(StmtKind::If(c, then, otherwise)) = body.first().map(|s| s.kind.clone()) {
            if is_single(&then, &StmtKind::Break) && otherwise.is_empty() {
                body.remove(0);
                stmt.kind = StmtKind::While(c.not(), std::mem::take(body));
                continue;
            }

            // while (1) { if (c) { x } else { break; } ... } -> while (c) { x ... }
            if is_single(&otherwise, &StmtKind::Break) {
                let rest = body.split_off(1);
                stmt.kind = StmtKind::While(c, then.into_iter().chain(rest).collect());
                continue;
            }
        }

        // while (1) { ...; if (c) break; } -> do { ... } while (!c)
        if let Some(StmtKind::If(c, then, otherwise)) = body.last().map(|s| s.kind.clone()) {
            let rest = &body[..body.len() - 1];

            if is_single(&then, &StmtKind::Break) && otherwise.is_empty() && !has_loop_jump(rest, &StmtKind::Continue) {
                // The address of a do while is the one of its test
                let test = body.pop().and_then(|s| s.addr);
                stmt.kind = StmtKind::DoWhile(std::mem::take(body), c.not());
                stmt.addr = test.or(stmt.addr);
            }
        }
    }
}

/// if (c) { } else { x } -> if (!c) { x }, and an if that jumps away does not need its else
fn simplify_ifs(stmts: &mut Vec<Stmt>) {
    let mut i = 0;

    while i < stmts.len() {
        if let StmtKind::If(c, then, otherwise) = &mut stmts[i].kind {
            if then.is_empty() && !otherwise.is_empty() {
                *c = c.clone().not();
                std::mem::swap(then, otherwise);
            }

            // Early exits: if (c) { return; } else { rest } -> if (c) { return; } rest
            if then.last().is_some_and(|s| s.is_jump()) && !otherwise.is_empty() && !matches!(otherwise.as_slice(), [Stmt { kind: StmtKind::If(..), .. }]) {
                let rest = std::mem::take(otherwise);
                stmts.splice(i + 1..i + 1, rest);
            }
        }

        i += 1;
    }

}

/// The jumps first: if (c) { x } else { break; } y -> if (!c) { break; } x y (an if alone in its list may be
/// an else if)
fn jumps_first(stmts: &mut Vec<Stmt>) {
    if stmts.len() < 2 {
        return;
    }

    for stmt in stmts.iter_mut() {
        if let StmtKind::If(c, then, otherwise) = &mut stmt.kind {
            if !then.last().is_some_and(|s| s.is_jump()) && otherwise.last().is_some_and(|s| s.is_jump()) {
                *c = c.clone().not();
                std::mem::swap(then, otherwise);
            }
        }
    }

    simplify_ifs(stmts);
}

/// The shorter exit first: if (c) { long; return a; } return b; -> if (!c) { return b; } long; return a;
/// (not in the lists with labels: the declarations would move out of them)
fn shorter_exits_first(stmts: &mut Vec<Stmt>) {
    if let [.., Stmt { kind: StmtKind::If(_, then, otherwise), .. }, last] = stmts.as_slice() {
        let length = |list: &[Stmt]| list.iter().map(size).sum::<usize>();

        if otherwise.is_empty() && last.is_jump() && then.last().is_some_and(|s| s.is_jump()) && length(then) > 2 * length(std::slice::from_ref(last)) && !stmts.iter().any(has_label) {
            let last = stmts.pop().unwrap();
            let Some(Stmt { kind: StmtKind::If(c, then, _), .. }) = stmts.last_mut() else {
                unreachable!();
            };

            *c = c.clone().not();
            let rest = std::mem::replace(then, vec![last]);
            stmts.extend(rest);
        }
    }
}

/// The statements both branches of an if end with follow it: if (c) { x; s; } else { y; s; } -> if (c) { x; }
/// else { y; } s; (the jump an if ends with is the one after it)
fn common_tails(stmts: &mut Vec<Stmt>) {
    let mut i = 0;

    while i < stmts.len() {
        let mut moved = Vec::new();

        // if (c) { x; return a; } return a; -> if (c) { x; } return a;
        if let (StmtKind::If(_, then, otherwise), Some(next)) = (&stmts[i].kind, stmts.get(i + 1)) {
            let same = |a: &Stmt| a.is_jump() && !has_label(next) && without_addresses(std::slice::from_ref(a)) == without_addresses(std::slice::from_ref(next));

            if otherwise.is_empty() && then.len() > 1 && then.last().is_some_and(same) {
                if let StmtKind::If(_, then, _) = &mut stmts[i].kind {
                    then.pop();
                }
            }
        }

        if let StmtKind::If(_, then, otherwise) = &mut stmts[i].kind {
            while let (Some(a), Some(b)) = (then.last(), otherwise.last()) {
                if has_label(a) || has_label(b) || without_addresses(std::slice::from_ref(a)) != without_addresses(std::slice::from_ref(b)) {
                    break;
                }

                otherwise.pop();
                moved.push(then.pop().unwrap());
            }
        }

        if moved.is_empty() {
            i += 1;
            continue;
        }

        // What is left of the if
        if let StmtKind::If(c, then, otherwise) = &mut stmts[i].kind {
            if then.is_empty() && otherwise.is_empty() {
                let mut calls = false;
                c.visit(&mut |e| calls |= matches!(e, Expr::Call(..)));
                stmts[i].kind = if calls { StmtKind::Expr(c.clone()) } else { StmtKind::Comment(String::new()) };
            } else if then.is_empty() {
                *c = c.clone().not();
                std::mem::swap(then, otherwise);
            }
        }

        moved.reverse();
        let count = moved.len();
        stmts.splice(i + 1..i + 1, moved);

        if matches!(&stmts[i].kind, StmtKind::Comment(text) if text.is_empty()) {
            stmts.remove(i);
            i += count;
        } else {
            i += count + 1;
        }
    }
}

/// A loop tested before it is entered and after each iteration with the same condition is a while:
/// if (c) { do { x } while (c); } -> while (c) { x }
fn rotated_loops(stmts: &mut Vec<Stmt>) {
    counted_loops(stmts);

    for stmt in stmts.iter_mut() {
        let StmtKind::If(c, then, otherwise) = &mut stmt.kind else {
            continue;
        };

        let [Stmt { kind: StmtKind::DoWhile(body, test), addr, .. }] = then.as_mut_slice() else {
            continue;
        };

        if otherwise.is_empty() && test == c {
            let addr = *addr;
            stmt.kind = StmtKind::While(c.clone(), std::mem::take(body));
            stmt.addr = addr.or(stmt.addr);
        }
    }
}

/// The next value of a loop variable computed in its own variable is the variable stepped where it is first
/// needed: while (1) { t = i + 8; a[i] = 0; if (t >= n) break; i = t; } -> while (1) { a[i] = 0; i += 8;
/// if (i >= n) break; } (the next value is only used in the loop, i is not read once it is stepped)
fn next_values(stmts: &mut Vec<Stmt>) {
    let size = super::ast::mentioned(stmts).into_iter().max().map_or(0, |v| v + 1);
    let (mut uses, mut assigns) = (vec![0; size], vec![0; size]);
    super::simplify::count(stmts, &mut uses, &mut assigns);

    walk(stmts, &mut |list: &mut Vec<Stmt>| {
        for stmt in list.iter_mut() {
            if let StmtKind::While(_, body) | StmtKind::DoWhile(body, _) = &mut stmt.kind {
                step_where_needed(body, &uses, &assigns);
            }
        }
    });
}

fn step_where_needed(body: &mut Vec<Stmt>, uses: &[usize], assigns: &[usize]) {
    let Some(StmtKind::Assign(Expr::Var(var), Expr::Var(next))) = body.last().map(|s| s.kind.clone()) else {
        return;
    };

    // next = var + c, the only assignment of next
    let Some(at) = body.iter().position(|s| matches!(&s.kind, StmtKind::Assign(Expr::Var(n), Expr::Binary(BinaryOp::Add | BinaryOp::Sub, a, b)) if *n == next && **a == Expr::Var(var) && matches!(**b, Expr::Int(_)))) else {
        return;
    };

    let end = body.len() - 1;

    let mut written = HashSet::default();
    assigned(&body[at + 1..end], &mut written);

    // Every read of next is in the loop after its assignment, var is not written there
    if assigns.get(next) != Some(&1) || uses.get(next) != Some(&reads_of(&body[at + 1..], next)) || written.contains(&var) || written.contains(&next) {
        return;
    }

    let first = (at + 1..=end).find(|&i| reads_of(&body[i..=i], next) > 0).unwrap_or(end);

    // var is not read once stepped (the final copy aside)
    if reads_of(&body[first..end], var) > 0 {
        return;
    }

    let StmtKind::Assign(_, step) = body[at].kind.clone() else {
        return;
    };

    let addr = body[at].addr;
    body.pop();

    for stmt in body[first..].iter_mut() {
        substitute_stmt(stmt, next, &Expr::Var(var));
    }

    body.insert(first, Stmt::new(StmtKind::Assign(Expr::Var(var), step), addr));
    body.remove(at);
}

/// Reads of a variable in statements (an assignment to it is not one)
fn reads_of(stmts: &[Stmt], var: VarId) -> usize {
    let mut count = 0;
    let mut expr = |e: &Expr| e.visit(&mut |e| count += (*e == Expr::Var(var)) as usize);

    let mut stack: Vec<&Stmt> = stmts.iter().collect();

    while let Some(stmt) = stack.pop() {
        match &stmt.kind {
            StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => expr(e),
            StmtKind::Assign(target, value) => {
                if !matches!(target, Expr::Var(_)) {
                    expr(target);
                }

                expr(value);
            }
            StmtKind::If(c, a, b) => {
                expr(c);
                stack.extend(a.iter().chain(b.iter()));
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                expr(c);
                stack.extend(body.iter());
            }
            StmtKind::For(init, c, step, body) => {
                expr(c);
                stack.extend([&**init, &**step].into_iter().chain(body.iter()));
            }
            StmtKind::Switch(c, cases, default) => {
                expr(c);
                stack.extend(cases.iter().flat_map(|c| c.body.iter()).chain(default.iter()));
            }
            _ => {}
        }
    }

    return count;
}

/// A statement with every read of a variable replaced by an expression
fn substitute_stmt(stmt: &mut Stmt, var: VarId, value: &Expr) {
    let e = |x: &mut Expr| *x = simplify_substitute(x, value, var);

    match &mut stmt.kind {
        StmtKind::Expr(x) | StmtKind::NoReturn(x) | StmtKind::Return(Some(x)) => e(x),
        StmtKind::Assign(target, x) => {
            if *target != Expr::Var(var) {
                e(target);
            }

            e(x);
        }
        StmtKind::If(c, a, b) => {
            e(c);
            a.iter_mut().chain(b.iter_mut()).for_each(|s| substitute_stmt(s, var, value));
        }
        StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
            e(c);
            body.iter_mut().for_each(|s| substitute_stmt(s, var, value));
        }
        StmtKind::For(init, c, step, body) => {
            substitute_stmt(init, var, value);
            e(c);
            substitute_stmt(step, var, value);
            body.iter_mut().for_each(|s| substitute_stmt(s, var, value));
        }
        StmtKind::Switch(c, cases, default) => {
            e(c);
            cases.iter_mut().flat_map(|c| c.body.iter_mut()).chain(default.iter_mut()).for_each(|s| substitute_stmt(s, var, value));
        }
        _ => {}
    }
}

/// Variables assigned by statements
fn assigned(stmts: &[Stmt], vars: &mut HashSet<VarId>) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Assign(Expr::Var(v), _) => {
                vars.insert(*v);
            }
            StmtKind::If(_, a, b) => {
                assigned(a, vars);
                assigned(b, vars);
            }
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) => assigned(body, vars),
            StmtKind::For(init, _, step, body) => {
                assigned(std::slice::from_ref(init), vars);
                assigned(std::slice::from_ref(step), vars);
                assigned(body, vars);
            }
            StmtKind::Switch(_, cases, default) => {
                cases.iter().for_each(|c| assigned(&c.body, vars));
                assigned(default, vars);
            }
            _ => {}
        }
    }
}

/// The step of a counted loop: v = v + k or v = v - k, its variable and its direction
fn loop_step(stmt: &Stmt) -> Option<(VarId, i128)> {
    let (var, value) = assigned_var(stmt)?;

    return match value {
        Expr::Binary(BinaryOp::Add, a, b) if **a == Expr::Var(var) => match **b {
            Expr::Int(k) if k != 0 => Some((var, k)),
            _ => None,
        },
        Expr::Binary(BinaryOp::Sub, a, b) if **a == Expr::Var(var) => match **b {
            Expr::Int(k) if k != 0 => Some((var, -k)),
            _ => None,
        },
        _ => None,
    };
}

/// A bound of a loop that the loop does not change: a constant, an address, a variable it does not assign
fn invariant(e: &Expr, written: &HashSet<VarId>) -> bool {
    return match e {
        Expr::Int(_) | Expr::Unary(UnaryOp::AddrOf, _) => true,
        Expr::Var(v) => !written.contains(v),
        Expr::Cast(_, inner) => invariant(inner, written),
        _ => false,
    };
}

/// Whether a comparison of constants holds: 3 != 10, &a != &b
fn holds(test: &Expr) -> bool {
    let Expr::Binary(op, a, b) = test else {
        return false;
    };

    return match (&**a, &**b) {
        (Expr::Int(x), Expr::Int(y)) => match op {
            BinaryOp::Lt => x < y,
            BinaryOp::Le => x <= y,
            BinaryOp::Gt => x > y,
            BinaryOp::Ge => x >= y,
            BinaryOp::Ne => x != y,
            BinaryOp::Eq => x == y,
            _ => false,
        },
        (Expr::Unary(UnaryOp::AddrOf, x), Expr::Unary(UnaryOp::AddrOf, y)) => *op == BinaryOp::Ne && matches!((&**x, &**y), (Expr::Name(m), Expr::Name(n)) if m != n),
        _ => false,
    };
}

/// The loops compilers rotate are for loops again:
/// - if (init < end) { v = init; do { ...; v++; } while (v != end); } -> for (v = init; v < end; v++) { ... }
///   (the guard tests the first value, the loop the next ones: with a step of one, < and != leave at the same
///   value)
/// - v = &table[0]; do { ...; v += 24; } while (v != &table_end); -> for (...; v != &table_end; v += 24) when
///   the test holds for the first value
fn counted_loops(stmts: &mut Vec<Stmt>) {
    let counted = |body: &[Stmt], test: &Expr, var: VarId| -> Option<i128> {
        let (stepped, k) = loop_step(body.last()?)?;
        let mut written = HashSet::default();
        assigned(&body[..body.len() - 1], &mut written);

        let Expr::Binary(_, a, b) = test else {
            return None;
        };

        let bound = if **a == Expr::Var(var) { b } else if **b == Expr::Var(var) { a } else { return None };
        let ok = stepped == var && !written.contains(&var) && invariant(bound, &written) && !has_loop_jump(body, &StmtKind::Continue);
        return ok.then_some(k);
    };

    let mut i = 0;

    while i < stmts.len() {
        // if (guard) { v = init; do { ... } while (test); ... }: the guard is the first test of a for loop, the if
        // goes away when it holds nothing else
        if let StmtKind::If(guard, then, otherwise) = &mut stmts[i].kind {
            if let [init, Stmt { kind: StmtKind::DoWhile(body, test), addr: loop_addr, .. }, ..] = then.as_slice() {
                if let Some((var, value)) = assigned_var(init) {
                    let condition = oriented(replaced(guard, value, &Expr::Var(var)), var);
                    let test = oriented(test.clone(), var);
                    let same_bound = |x: &Expr, y: &Expr| matches!((x, y), (Expr::Binary(_, _, b), Expr::Binary(_, _, d)) if b == d);

                    let unit = counted(body, &test, var).is_some_and(|k| match (&condition, &test) {
                        (Expr::Binary(BinaryOp::Lt, x, _), Expr::Binary(BinaryOp::Ne, y, _)) => k == 1 && **x == Expr::Var(var) && **y == Expr::Var(var),
                        (Expr::Binary(BinaryOp::Gt, x, _), Expr::Binary(BinaryOp::Ne, y, _)) => k == -1 && **x == Expr::Var(var) && **y == Expr::Var(var),
                        _ => false,
                    });

                    if condition.uses(var) && (condition == test && counted(body, &test, var).is_some() || unit && same_bound(&condition, &test)) && !value.uses(var) {
                        let mut body = body.clone();
                        let step = body.pop().unwrap();
                        let for_loop = Stmt::new(StmtKind::For(Box::new(init.clone()), condition, Box::new(step), body), *loop_addr);

                        if then.len() == 2 && otherwise.is_empty() {
                            let addr = stmts[i].addr;
                            stmts[i] = Stmt { addr: for_loop.addr.or(addr), ..for_loop };
                        } else {
                            then.splice(0..2, [for_loop]);
                        }
                    }
                }
            }
        }

        // v = init; do { ... } while (test); with the test holding for init
        if i + 1 < stmts.len() {
            if let (Some((var, value)), StmtKind::DoWhile(body, test)) = (assigned_var(&stmts[i]), &stmts[i + 1].kind) {
                if counted(body, test, var).is_some() && holds(&simplify_substitute(test, value, var)) {
                    let mut body = body.clone();
                    let (test, step) = (test.clone(), body.pop().unwrap());
                    let addr = stmts[i + 1].addr;
                    let init = stmts.remove(i);
                    stmts[i] = Stmt::new(StmtKind::For(Box::new(init), test, Box::new(step), body), addr);
                }
            }
        }

        i += 1;
    }
}

/// A comparison with a variable on its left: n > i is i < n
fn oriented(e: Expr, var: VarId) -> Expr {
    let flipped = |op: BinaryOp| match op {
        BinaryOp::Lt => Some(BinaryOp::Gt),
        BinaryOp::Gt => Some(BinaryOp::Lt),
        BinaryOp::Le => Some(BinaryOp::Ge),
        BinaryOp::Ge => Some(BinaryOp::Le),
        BinaryOp::Eq | BinaryOp::Ne => Some(op),
        _ => None,
    };

    return match e {
        Expr::Binary(op, a, b) if *b == Expr::Var(var) && *a != Expr::Var(var) && flipped(op).is_some() => Expr::Binary(flipped(op).unwrap(), b, a),
        other => other,
    };
}

/// An expression with a subexpression replaced by another (the first value of a loop by its variable)
fn replaced(e: &Expr, from: &Expr, to: &Expr) -> Expr {
    let s = |e: &Expr| Box::new(replaced(e, from, to));

    return match e {
        e if e == from => to.clone(),
        Expr::Unary(op, a) => Expr::Unary(*op, s(a)),
        Expr::Binary(op, a, b) => Expr::Binary(*op, s(a), s(b)),
        Expr::Cast(ty, a) => Expr::Cast(ty.clone(), s(a)),
        Expr::Index(a, b) => Expr::Index(s(a), s(b)),
        Expr::Member(a, field, arrow) => Expr::Member(s(a), field.clone(), *arrow),
        Expr::Ternary(a, b, c) => Expr::Ternary(s(a), s(b), s(c)),
        other => other.clone(),
    };
}

/// An expression with every use of a variable replaced by a value
fn simplify_substitute(e: &Expr, value: &Expr, var: VarId) -> Expr {
    let s = |e: &Expr| Box::new(simplify_substitute(e, value, var));

    return match e {
        Expr::Var(v) if *v == var => value.clone(),
        Expr::Unary(op, a) => Expr::Unary(*op, s(a)),
        Expr::Binary(op, a, b) => Expr::Binary(*op, s(a), s(b)),
        Expr::Cast(ty, a) => Expr::Cast(ty.clone(), s(a)),
        Expr::Index(a, b) => Expr::Index(s(a), s(b)),
        Expr::Member(a, field, arrow) => Expr::Member(s(a), field.clone(), *arrow),
        Expr::Ternary(a, b, c) => Expr::Ternary(s(a), s(b), s(c)),
        other => other.clone(),
    };
}

/// if (a) { if (b) { x } } -> if (a && b) { x }
fn nested_conditions(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        while let StmtKind::If(a, then, otherwise) = &mut stmt.kind {
            let [Stmt { kind: StmtKind::If(b, inner, inner_else), .. }] = then.as_mut_slice() else {
                break;
            };

            if !otherwise.is_empty() || !inner_else.is_empty() {
                break;
            }

            let inner = std::mem::take(inner);
            *a = Expr::binary(BinaryOp::LogicalAnd, a.clone(), b.clone());
            *then = inner;
        }
    }
}

/// Number of statements, the nested ones included
fn size(stmt: &Stmt) -> usize {
    return 1 + match &stmt.kind {
        StmtKind::If(_, a, b) => a.iter().chain(b.iter()).map(size).sum(),
        StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => body.iter().map(size).sum(),
        StmtKind::Switch(_, cases, default) => cases.iter().flat_map(|c| c.body.iter()).chain(default.iter()).map(size).sum(),
        _ => 0,
    };
}

fn assigned_var(stmt: &Stmt) -> Option<(VarId, &Expr)> {
    return match &stmt.kind {
        StmtKind::Assign(Expr::Var(v), value) => Some((*v, value)),
        _ => None,
    };
}

/// v = init; while (cond(v)) { ...; v = v + k; } -> for (v = init; cond(v); v += k) { ... }. The copies of the
/// variables joined at the loop come in no particular order: the init and the step of the counter are found among
/// the assignments right before the loop and at the end of its body, when they can move past the others.
fn for_loops(stmts: &mut Vec<Stmt>) {
    let mut i = 1;

    while i < stmts.len() {
        let StmtKind::While(cond, body) = &stmts[i].kind else {
            i += 1;
            continue;
        };

        let inits = (0..i).rev().take_while(|&p| assigned_var(&stmts[p]).is_some()).collect::<Vec<_>>();
        let found = inits.iter().find_map(|&p| {
            let (var, _) = assigned_var(&stmts[p])?;
            movable(&stmts[p], &stmts[p + 1..i]).then_some(())?;

            let steps = body.len() - body.iter().rev().take_while(|s| assigned_var(s).is_some()).count();
            let q = (steps..body.len()).rev().find(|&q| assigned_var(&body[q]).is_some_and(|(v, _)| v == var))?;
            let (_, step) = assigned_var(&body[q])?;
            (step.uses(var) && movable(&body[q], &body[q + 1..])).then_some(())?;

            // A loop left from its body counts in its header too: for (v = init;; v += k) { ...; if (c) break; ... }
            let rest: Vec<Stmt> = body.iter().enumerate().filter(|&(k, _)| k != q).map(|(_, s)| s.clone()).collect();
            let counted = *cond == Expr::Int(1) && super::ast::mentioned(&rest).contains(&var);

            ((cond.uses(var) || counted) && !has_loop_jump(body, &StmtKind::Continue)).then_some((p, q))
        });

        let Some((p, q)) = found else {
            i += 1;
            continue;
        };

        let addr = stmts[i].addr;
        let StmtKind::While(cond, body) = &mut stmts[i].kind else {
            unreachable!();
        };

        let step = body.remove(q);
        let (cond, body) = (cond.clone(), std::mem::take(body));
        let init = stmts.remove(p);
        stmts[i - 1] = Stmt::new(StmtKind::For(Box::new(init), cond, Box::new(step), body), addr);
    }
}

/// An assignment can move after the ones that follow it: none of them writes what it reads, reads or writes what it
/// assigns, or calls a function
fn movable(stmt: &Stmt, after: &[Stmt]) -> bool {
    let Some((var, value)) = assigned_var(stmt) else {
        return false;
    };

    let calls = |e: &Expr| {
        let mut found = false;
        e.visit(&mut |e| found |= matches!(e, Expr::Call(..)));
        found
    };

    return !calls(value)
        && after.iter().all(|other| match assigned_var(other) {
            Some((written, read)) => written != var && !read.uses(var) && !value.uses(written) && !calls(read),
            None => false,
        });
}

/// The statements without their addresses, to compare what they do
fn without_addresses(stmts: &[Stmt]) -> Vec<Stmt> {
    let strip = |list: &[Stmt]| without_addresses(list);

    return stmts
        .iter()
        .map(|s| {
            let kind = match &s.kind {
                StmtKind::If(c, a, b) => StmtKind::If(c.clone(), strip(a), strip(b)),
                StmtKind::While(c, body) => StmtKind::While(c.clone(), strip(body)),
                StmtKind::DoWhile(body, c) => StmtKind::DoWhile(strip(body), c.clone()),
                StmtKind::For(init, c, step, body) => StmtKind::For(Box::new(strip(std::slice::from_ref(init)).remove(0)), c.clone(), Box::new(strip(std::slice::from_ref(step)).remove(0)), strip(body)),
                StmtKind::Switch(v, cases, default) => StmtKind::Switch(v.clone(), cases.iter().map(|c| Case { values: c.values.clone(), body: strip(&c.body) }).collect(), strip(default)),
                other => other.clone(),
            };

            Stmt::new(kind, None)
        })
        .collect();
}

/// Cases with the same body are one, the cases that do what the default does are left to it. Only the
/// cases that end with a jump, and that the case before does not fall into, move.
fn merge_cases(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        let StmtKind::Switch(_, cases, default) = &mut stmt.kind else {
            continue;
        };

        // What a body does, without the break that ends it (the default does not need one)
        let action = |body: &[Stmt], last: bool| -> Option<Vec<Stmt>> {
            if body.iter().any(has_label) || !(last || body.last().is_some_and(|s| s.is_jump())) {
                return None;
            }

            let mut body = without_addresses(body);

            if body.last().is_some_and(|s| s.kind == StmtKind::Break) {
                body.pop();
            }

            return Some(body);
        };

        let default_action = action(default, true);
        let mut merged: Vec<(Option<Vec<Stmt>>, Case)> = Vec::new();
        let mut fallen_into = false;

        for case in std::mem::take(cases) {
            let this = action(&case.body, false).filter(|_| !fallen_into);
            fallen_into = !case.body.last().is_some_and(|s| s.is_jump());

            if this.is_some() && this == default_action {
                continue;
            }

            match merged.iter_mut().find(|(other, _)| this.is_some() && *other == this) {
                Some((_, existing)) => existing.values.extend(case.values),
                None => merged.push((this, case)),
            }
        }

        *cases = merged.into_iter().map(|(_, case)| case).collect();
    }
}

/// Labels nobody jumps to, and gotos to the label right after them
fn remove_labels(stmts: &mut Vec<Stmt>, gotos: &HashSet<String>) {
    stmts.retain(|s| !matches!(&s.kind, StmtKind::Label(l) if !gotos.contains(l)));
}

fn collect_gotos(stmts: &mut Vec<Stmt>) -> HashSet<String> {
    let mut gotos = HashSet::default();

    walk(stmts, &mut |list: &mut Vec<Stmt>| {
        for stmt in list.iter() {
            if let StmtKind::Goto(l) = &stmt.kind {
                gotos.insert(l.clone());
            }
        }
    });

    return gotos;
}

fn collect_labels(stmts: &mut Vec<Stmt>) -> HashSet<String> {
    let mut labels = HashSet::default();

    walk(stmts, &mut |list: &mut Vec<Stmt>| {
        for stmt in list.iter() {
            if let StmtKind::Label(l) = &stmt.kind {
                labels.insert(l.clone());
            }
        }
    });

    return labels;
}

/// Whether a statement is or contains a label (a loop whose header is jumped to)
fn has_label(stmt: &Stmt) -> bool {
    return match &stmt.kind {
        StmtKind::Label(_) => true,
        StmtKind::If(_, a, b) => a.iter().any(has_label) || b.iter().any(has_label),
        StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => body.iter().any(has_label),
        StmtKind::Switch(_, cases, default) => cases.iter().any(|c| c.body.iter().any(has_label)) || default.iter().any(has_label),
        _ => false,
    };
}

/// Statements after a jump are unreachable (unless they have labels)
fn remove_unreachable(stmts: &mut Vec<Stmt>) {
    if let Some(jump) = stmts.iter().position(|s| s.is_jump()) {
        let label = stmts[jump + 1..].iter().position(has_label).map_or(stmts.len(), |p| jump + 1 + p);
        stmts.drain(jump + 1..label);
    }
}

fn remove_goto_next(stmts: &mut Vec<Stmt>) {
    let mut i = 0;

    while i + 1 < stmts.len() {
        if let (StmtKind::Goto(a), StmtKind::Label(b)) = (&stmts[i].kind, &stmts[i + 1].kind) {
            if a == b {
                stmts.remove(i);
                continue;
            }
        }

        i += 1;
    }
}

/// After the copies are gone: the loops counting a variable are for loops (the start of the count is the
/// value it was copied from), the shorter exits go first
pub fn loops_and_exits(stmts: &mut Vec<Stmt>) {
    next_values(stmts);
    walk(stmts, &mut rotated_loops);
    walk(stmts, &mut for_loops);
    walk(stmts, &mut loop_conditions);
    walk(stmts, &mut jumps_first);
    walk(stmts, &mut loop_conditions);
    walk(stmts, &mut rotated_loops);
    walk(stmts, &mut for_loops);
    walk(stmts, &mut shorter_exits_first);
    walk(stmts, &mut common_tails);
    walk(stmts, &mut empty_branches);
    walk(stmts, &mut nested_conditions);
}

/// if (c) { } else { x } -> if (!c) { x }, an if doing nothing goes away (its condition stays when it calls)
fn empty_branches(stmts: &mut Vec<Stmt>) {
    let mut i = 0;

    while i < stmts.len() {
        if let StmtKind::If(c, then, otherwise) = &mut stmts[i].kind {
            if then.is_empty() && !otherwise.is_empty() {
                *c = c.clone().not();
                std::mem::swap(then, otherwise);
            } else if then.is_empty() && otherwise.is_empty() {
                let mut calls = false;
                c.visit(&mut |e| calls |= matches!(e, Expr::Call(..)));

                if calls {
                    stmts[i].kind = StmtKind::Expr(c.clone());
                } else {
                    stmts.remove(i);
                    continue;
                }
            }
        }

        i += 1;
    }
}

/// Structured statements of the blocks (block 0 is the entry)
pub fn structure(mut blocks: Vec<SBlock>, vars: &mut Vec<Var>) -> Vec<Stmt> {
    if blocks.is_empty() {
        return Vec::new();
    }

    small_switches(&mut blocks);
    merge_conditions(&mut blocks);

    let mut structurer = Structurer::new(blocks, vars);
    let mut stmts = structurer.region(0, None, TOP, false);

    // Blocks only jumped to that were never emitted with their label (left from inside the loops, or
    // small tails always repeated) go at the end, the statements before do not fall through to them
    let mut appended = HashSet::default();

    loop {
        let labels = collect_labels(&mut stmts);
        let missing = collect_gotos(&mut stmts).into_iter().filter(|g| !labels.contains(g)).filter_map(|g| g.strip_prefix("label_")?.parse::<usize>().ok());

        let Some(block) = missing.filter(|b| !appended.contains(b)).min() else {
            break;
        };

        appended.insert(block);

        // The small tails are repeated by region, without their label
        if structurer.is_tail(block) {
            let b = &structurer.blocks[block];
            stmts.push(Stmt::new(StmtKind::Label(label(block)), None));
            stmts.extend(b.stmts.iter().cloned());

            if let Term::Return(value) = &b.term {
                stmts.push(Stmt::new(StmtKind::Return(value.clone()), b.addr));
            }

            continue;
        }

        let region = structurer.region(block, None, TOP, false);
        stmts.extend(region);
    }

    for _ in 0..2 {
        walk(&mut stmts, &mut loop_conditions);
        walk(&mut stmts, &mut simplify_ifs);
        walk(&mut stmts, &mut remove_unreachable);
        walk(&mut stmts, &mut remove_goto_next);
        let gotos = collect_gotos(&mut stmts);
        walk(&mut stmts, &mut |list: &mut Vec<Stmt>| remove_labels(list, &gotos));
        walk(&mut stmts, &mut merge_cases);
    }

    // A function that ends with return; does not need it
    if matches!(stmts.last().map(|s| &s.kind), Some(StmtKind::Return(None))) {
        stmts.pop();
    }

    return stmts;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block whose statements are calls to b<id> (n of them), conditions are names c<id>
    fn block(id: usize, n: usize, term: Term) -> SBlock {
        let call = Stmt::new(StmtKind::Expr(Expr::Call(Box::new(Expr::Name(format!("b{}", id))), Vec::new())), None);
        return SBlock { stmts: vec![call; n], term, addr: None };
    }

    fn cond(id: usize) -> Expr {
        return Expr::Name(format!("c{}", id));
    }

    fn collect(stmts: &[Stmt], labels: &mut Vec<String>, gotos: &mut Vec<String>, calls: &mut Vec<String>) {
        for stmt in stmts {
            match &stmt.kind {
                StmtKind::Label(l) => labels.push(l.clone()),
                StmtKind::Goto(l) => gotos.push(l.clone()),
                StmtKind::Expr(Expr::Call(callee, _)) => {
                    if let Expr::Name(name) = &**callee {
                        calls.push(name.clone());
                    }
                }
                StmtKind::If(_, a, b) => {
                    collect(a, labels, gotos, calls);
                    collect(b, labels, gotos, calls);
                }
                StmtKind::While(_, body) | StmtKind::DoWhile(body, _) => collect(body, labels, gotos, calls),
                StmtKind::For(init, _, step, body) => {
                    collect(std::slice::from_ref(&**init), labels, gotos, calls);
                    collect(std::slice::from_ref(&**step), labels, gotos, calls);
                    collect(body, labels, gotos, calls);
                }
                StmtKind::Switch(_, cases, default) => {
                    cases.iter().for_each(|c| collect(&c.body, labels, gotos, calls));
                    collect(default, labels, gotos, calls);
                }
                _ => {}
            }
        }
    }

    /// Structures the blocks, checks that every block is emitted and every goto has its label,
    /// returns the number of gotos
    fn gotos(blocks: Vec<SBlock>) -> usize {
        let count = blocks.len();
        let stmts = structure(blocks, &mut Vec::new());
        let (mut labels, mut gotos, mut calls) = (Vec::new(), Vec::new(), Vec::new());
        collect(&stmts, &mut labels, &mut gotos, &mut calls);

        for id in 0..count {
            assert!(calls.contains(&format!("b{}", id)), "block {} is missing:\n{:#?}", id, stmts);
        }

        for goto in gotos.iter() {
            assert!(labels.contains(goto), "{} is not emitted:\n{:#?}", goto, stmts);
        }

        return gotos.len();
    }

    /*
     * Differential test: random control flow graphs, the structured statements executed by an
     * interpreter must run the blocks in the same order as the graph
     */

    /// Value of the condition of a block, a function of the number of times the block ran: tested
    /// again before the block runs again, a condition has the same value
    fn condition_value(block: usize, runs: usize, seed: u64) -> i128 {
        let mut x = seed ^ ((block as u64) << 32) ^ (runs as u64).wrapping_mul(0x9e3779b97f4a7c15);
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        return (x % 3) as i128;
    }

    struct Machine {
        runs: Vec<usize>,
        trace: Vec<usize>,
        vars: HashMap<VarId, i128>,
        seed: u64,
        steps: usize,
    }

    enum Flow {
        Next,
        Break,
        Continue,
        Return,
        Goto(String),
    }

    const MAX_STEPS: usize = 400;

    impl Machine {
        fn new(count: usize, seed: u64) -> Self {
            return Machine { runs: vec![0; count], trace: Vec::new(), vars: HashMap::default(), seed, steps: 0 };
        }

        fn eval(&mut self, e: &Expr) -> i128 {
            return match e {
                Expr::Int(v) => *v,
                Expr::Var(v) => self.vars.get(v).copied().unwrap_or(0),
                Expr::Name(name) => {
                    let block: usize = name[1..].parse().unwrap();
                    condition_value(block, self.runs[block], self.seed)
                }
                Expr::Unary(UnaryOp::LogicalNot, a) => (self.eval(a) == 0) as i128,
                Expr::Binary(op, a, b) => {
                    let a = self.eval(a);

                    match op {
                        BinaryOp::LogicalAnd => (a != 0 && self.eval(b) != 0) as i128,
                        BinaryOp::LogicalOr => (a != 0 || self.eval(b) != 0) as i128,
                        BinaryOp::Eq => (a == self.eval(b)) as i128,
                        BinaryOp::Ne => (a != self.eval(b)) as i128,
                        _ => panic!("operator {:?}", op),
                    }
                }
                Expr::Call(callee, _) => {
                    let Expr::Name(name) = &**callee else { panic!() };
                    let block: usize = name[1..].parse().unwrap();
                    self.trace.push(block);
                    self.runs[block] += 1;
                    self.steps += 1;
                    0
                }
                other => panic!("expression {:?}", other),
            };
        }

        /// Runs the statements (from the one with the label when given)
        fn run(&mut self, stmts: &[Stmt], mut label: Option<&str>) -> Flow {
            let start = match label {
                Some(l) => match stmts.iter().position(|s| contains_label(s, l)) {
                    Some(p) => p,
                    None => return Flow::Goto(l.to_string()),
                },
                None => 0,
            };

            for stmt in stmts[start..].iter() {
                if self.steps > MAX_STEPS {
                    return Flow::Return;
                }

                let flow = self.stmt(stmt, label.take());

                if !matches!(flow, Flow::Next) {
                    return flow;
                }
            }

            return Flow::Next;
        }

        fn stmt(&mut self, stmt: &Stmt, label: Option<&str>) -> Flow {
            match &stmt.kind {
                StmtKind::Expr(e) => {
                    self.eval(e);
                }
                StmtKind::Assign(Expr::Var(v), e) => {
                    let value = self.eval(e);
                    self.vars.insert(*v, value);
                }
                StmtKind::Label(_) | StmtKind::Comment(_) => {}
                StmtKind::Break => return Flow::Break,
                StmtKind::Continue => return Flow::Continue,
                StmtKind::Return(_) => return Flow::Return,
                StmtKind::Goto(l) => return Flow::Goto(l.clone()),
                StmtKind::If(c, a, b) => {
                    let inside = |s: &[Stmt]| label.is_some_and(|l| s.iter().any(|x| contains_label(x, l)));

                    return if inside(a) {
                        self.run(a, label)
                    } else if inside(b) {
                        self.run(b, label)
                    } else if self.eval(c) != 0 {
                        self.run(a, None)
                    } else {
                        self.run(b, None)
                    };
                }
                StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => {
                    let do_while = matches!(stmt.kind, StmtKind::DoWhile(..));
                    let mut label = label;

                    loop {
                        if label.is_none() && !do_while && self.eval(c) == 0 {
                            break;
                        }

                        match self.run(body, label.take()) {
                            Flow::Break => break,
                            Flow::Return => return Flow::Return,
                            Flow::Goto(l) => return Flow::Goto(l),
                            Flow::Next | Flow::Continue => {}
                        }

                        if self.steps > MAX_STEPS {
                            return Flow::Return;
                        }

                        if do_while && self.eval(c) == 0 {
                            break;
                        }
                    }
                }
                StmtKind::For(init, c, step, body) => {
                    let mut label = label;

                    if label.is_none() {
                        self.stmt(init, None);
                    }

                    loop {
                        if label.is_none() && self.eval(c) == 0 {
                            break;
                        }

                        match self.run(body, label.take()) {
                            Flow::Break => break,
                            Flow::Return => return Flow::Return,
                            Flow::Goto(l) => return Flow::Goto(l),
                            Flow::Next | Flow::Continue => {}
                        }

                        if self.steps > MAX_STEPS {
                            return Flow::Return;
                        }

                        self.stmt(step, None);
                    }
                }
                StmtKind::Switch(value, cases, default) => {
                    // The bodies in order (the default last), a case falls through to the next one
                    let mut bodies: Vec<&Vec<Stmt>> = cases.iter().map(|c| &c.body).collect();
                    bodies.push(default);

                    let start = match label.and_then(|l| bodies.iter().position(|b| b.iter().any(|s| contains_label(s, l)))) {
                        Some(i) => i,
                        None => {
                            let v = self.eval(value);
                            cases.iter().position(|c| c.values.contains(&v)).unwrap_or(cases.len())
                        }
                    };

                    let mut label = label;

                    for body in bodies[start..].iter() {
                        match self.run(body, label.take()) {
                            Flow::Next => {}
                            Flow::Break => break,
                            other => return other,
                        }
                    }
                }
                other => panic!("statement {:?}", other),
            }

            return Flow::Next;
        }

        /// Runs a function body, following its gotos
        fn function(&mut self, stmts: &[Stmt]) {
            let mut label: Option<String> = None;

            loop {
                match self.run(stmts, label.as_deref()) {
                    Flow::Goto(l) => label = Some(l),
                    _ => return,
                }

                if self.steps > MAX_STEPS {
                    return;
                }
            }
        }

        /// Runs the graph itself
        fn graph(&mut self, blocks: &[SBlock]) -> bool {
            let mut block = 0;

            loop {
                for stmt in blocks[block].stmts.iter() {
                    self.stmt(stmt, None);
                }

                if self.steps > MAX_STEPS {
                    return false;
                }

                block = match &blocks[block].term {
                    Term::Return(_) | Term::Unreachable => return true,
                    Term::Jump(t) => *t,
                    Term::Branch(c, t, f) => if self.eval(c) != 0 { *t } else { *f },
                    Term::Switch(v, cases, default) => {
                        let v = self.eval(v);
                        cases.iter().find(|(values, _)| values.contains(&v)).map_or(*default, |(_, t)| *t)
                    }
                };
            }
        }
    }

    fn show_expr(e: &Expr) -> String {
        return match e {
            Expr::Int(v) => v.to_string(),
            Expr::Var(v) => format!("v{}", v),
            Expr::Name(n) => n.clone(),
            Expr::Unary(UnaryOp::LogicalNot, a) => format!("!{}", show_expr(a)),
            Expr::Binary(op, a, b) => format!("({} {} {})", show_expr(a), op.symbol(), show_expr(b)),
            Expr::Call(c, _) => format!("{}()", show_expr(c)),
            other => format!("{:?}", other),
        };
    }

    fn show(stmts: &[Stmt], depth: usize) -> String {
        let pad = "  ".repeat(depth);
        let mut out = String::new();
        let mut i = 0;

        while i < stmts.len() {
            let stmt = &stmts[i];

            // Runs of the same call
            if let StmtKind::Expr(e) = &stmt.kind {
                let n = stmts[i..].iter().take_while(|s| s.kind == stmt.kind).count();
                out += &format!("{}{} x{}\n", pad, show_expr(e), n);
                i += n;
                continue;
            }

            match &stmt.kind {
                StmtKind::Assign(t, v) => out += &format!("{}{} = {}\n", pad, show_expr(t), show_expr(v)),
                StmtKind::If(c, a, b) => {
                    out += &format!("{}if {} {{\n{}", pad, show_expr(c), show(a, depth + 1));
                    if !b.is_empty() {
                        out += &format!("{}}} else {{\n{}", pad, show(b, depth + 1));
                    }
                    out += &format!("{}}}\n", pad);
                }
                StmtKind::While(c, body) => out += &format!("{}while {} {{\n{}{}}}\n", pad, show_expr(c), show(body, depth + 1), pad),
                StmtKind::DoWhile(body, c) => out += &format!("{}do {{\n{}{}}} while {}\n", pad, show(body, depth + 1), pad, show_expr(c)),
                StmtKind::Switch(v, cases, default) => {
                    out += &format!("{}switch {} {{\n", pad, show_expr(v));
                    for c in cases {
                        out += &format!("{}case {:?}:\n{}", pad, c.values, show(&c.body, depth + 1));
                    }
                    out += &format!("{}default:\n{}{}}}\n", pad, show(default, depth + 1), pad);
                }
                other => out += &format!("{}{:?}\n", pad, other),
            }

            i += 1;
        }

        return out;
    }

    fn show_graph(blocks: &[SBlock]) -> String {
        return blocks.iter().enumerate().map(|(i, b)| format!("{}: {} calls {:?}\n", i, b.stmts.len(), b.term)).collect();
    }

    fn contains_label(stmt: &Stmt, label: &str) -> bool {
        return match &stmt.kind {
            StmtKind::Label(l) => l == label,
            StmtKind::If(_, a, b) => a.iter().chain(b.iter()).any(|s| contains_label(s, label)),
            StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => body.iter().any(|s| contains_label(s, label)),
            StmtKind::Switch(_, cases, default) => cases.iter().flat_map(|c| c.body.iter()).chain(default.iter()).any(|s| contains_label(s, label)),
            _ => false,
        };
    }

    /// A random graph: blocks of 1 to 12 calls ending with a jump, a branch, a switch or a return.
    /// With locals, a block assigns its condition to one of 4 variables and tests it (the blocks
    /// share the variables and the conditions)
    fn random_graph(seed: u64, locals: bool) -> Vec<SBlock> {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut next = |n: usize| -> usize {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((state >> 33) % n as u64) as usize
        };

        let count = 3 + next(38);

        return (0..count)
            .map(|i| {
                // Mostly forward edges, some back edges
                let target = |next: &mut dyn FnMut(usize) -> usize| if next(5) == 0 { next(count) } else { (i + 1 + next(4)).min(count - 1) };
                let value = if locals { Expr::Var(i % 4) } else { cond(i) };
                let test = if locals { Expr::binary(BinaryOp::Eq, value.clone(), Expr::Int(1)) } else { cond(i) };

                let term = match next(10) {
                    _ if i == count - 1 => Term::Return(None),
                    0 => Term::Return(None),
                    1 | 2 => Term::Jump(target(&mut next)),
                    3 => Term::Switch(value, vec![(vec![0], target(&mut next)), (vec![1], target(&mut next))], target(&mut next)),
                    _ => Term::Branch(test, target(&mut next), target(&mut next)),
                };

                let mut b = block(i, 1 + next(8), term);

                if locals {
                    b.stmts.push(Stmt::new(StmtKind::Assign(Expr::Var(i % 4), cond(i)), None));
                }

                b
            })
            .collect();
    }

    #[test]
    fn random_graphs_keep_their_behavior() {
        for seed in 0..20000u64 {
            let blocks = random_graph(seed, seed % 2 == 1);
            let count = blocks.len();
            let mut locals = vec![Var { name: String::new(), ty: CType::Int { bits: 32, signed: true } }; 4];
            let stmts = structure(blocks.clone(), &mut locals);

            for run in 0..4 {
                let mut expected = Machine::new(count, run);

                if !expected.graph(&blocks) {
                    continue;
                }

                let mut actual = Machine::new(count, run);
                actual.function(&stmts);

                if expected.trace != actual.trace {
                    let mut first = 0;

                    while expected.trace.get(first) == actual.trace.get(first) {
                        first += 1;
                    }

                    let blocks_of = |t: &[usize]| {
                        let mut runs: Vec<usize> = t.to_vec();
                        runs.dedup();
                        runs
                    };

                    let from = first.saturating_sub(40);
                    panic!(
                        "seed {} run {}: diverge at {}\nexpected {:?}\nactual   {:?}\n{}\n{}",
                        seed,
                        run,
                        first,
                        blocks_of(&expected.trace[from..(first + 30).min(expected.trace.len())]),
                        blocks_of(&actual.trace[from..(first + 30).min(actual.trace.len())]),
                        show_graph(&blocks),
                        show(&stmts, 0)
                    );
                }
            }
        }
    }

    #[test]
    fn loop_with_two_exits() {
        // while (c1) { if (!c2) { b5 } b3 } b4 with the exit b5 joining b4
        let blocks = vec![
            block(0, 1, Term::Jump(1)),
            block(1, 1, Term::Branch(cond(1), 2, 4)),
            block(2, 1, Term::Branch(cond(2), 3, 5)),
            block(3, 1, Term::Jump(1)),
            block(4, 4, Term::Jump(6)),
            block(5, 4, Term::Jump(6)),
            block(6, 4, Term::Return(None)),
        ];

        gotos(blocks);
    }

    #[test]
    fn early_returns() {
        // if (c0) { b1; if (c1) return; } b3; return
        let blocks = vec![
            block(0, 1, Term::Branch(cond(0), 1, 3)),
            block(1, 1, Term::Branch(cond(1), 2, 3)),
            block(2, 4, Term::Return(None)),
            block(3, 4, Term::Return(None)),
        ];

        assert_eq!(gotos(blocks), 0);
    }

    #[test]
    fn loop_whose_exits_all_return() {
        // The paths of the outer loop (header b1) join at the inner loop (b2) before it, the exits of the
        // inner loop all return or go back to b1: the inner loop follows the branches
        let switch = |cases: Vec<(Vec<i128>, usize)>, default: usize| Term::Switch(Expr::Var(0), cases, default);
        let blocks = vec![
            block(0, 1, Term::Jump(1)),
            block(1, 1, Term::Branch(cond(1), 3, 6)),
            block(2, 1, switch(vec![(vec![47], 1), (vec![0], 8)], 7)),
            block(3, 1, Term::Branch(cond(3), 4, 9)),
            block(4, 1, switch(vec![(vec![0, 47], 5)], 10)),
            block(5, 1, Term::Return(None)),
            block(6, 1, Term::Jump(2)),
            block(7, 1, Term::Jump(2)),
            block(8, 1, Term::Return(None)),
            block(9, 1, Term::Jump(2)),
            block(10, 1, Term::Jump(2)),
        ];

        // The switch of the inner loop is two tests, its jump back to b1 is a break
        assert_eq!(gotos(blocks), 0);
    }

    #[test]
    fn next_values_stepped_where_needed() {
        let stmt = |kind: StmtKind| Stmt::new(kind, None);
        let call = |arg: Expr| stmt(StmtKind::Expr(Expr::Call(Box::new(Expr::Name("f".to_string())), vec![arg])));

        // v0 = 0; while (1) { v1 = v0 + 8; f(v0); if (v1 >= 16) break; v0 = v1; } -> do { f(v0); v0 += 8; } while (v0 < 16),
        // a for loop since the test holds for the first value
        let body = vec![
            stmt(StmtKind::Assign(Expr::Var(1), Expr::binary(BinaryOp::Add, Expr::Var(0), Expr::Int(8)))),
            call(Expr::Var(0)),
            stmt(StmtKind::If(Expr::binary(BinaryOp::Ge, Expr::Var(1), Expr::Int(16)), vec![stmt(StmtKind::Break)], Vec::new())),
            stmt(StmtKind::Assign(Expr::Var(0), Expr::Var(1))),
        ];
        let mut stmts = vec![stmt(StmtKind::Assign(Expr::Var(0), Expr::Int(0))), stmt(StmtKind::While(Expr::Int(1), body))];
        loops_and_exits(&mut stmts);

        let step = stmt(StmtKind::Assign(Expr::Var(0), Expr::binary(BinaryOp::Add, Expr::Var(0), Expr::Int(8))));
        let init = stmt(StmtKind::Assign(Expr::Var(0), Expr::Int(0)));
        let expected = StmtKind::For(Box::new(init), Expr::binary(BinaryOp::Lt, Expr::Var(0), Expr::Int(16)), Box::new(step), vec![call(Expr::Var(0))]);
        assert_eq!(stmts.iter().map(|s| &s.kind).collect::<Vec<_>>(), vec![&expected], "{:?}", stmts);
    }

    #[test]
    fn loops_and_exits_after_the_copies() {
        let call = |name: &str| Stmt::new(StmtKind::Expr(Expr::Call(Box::new(Expr::Name(name.to_string())), Vec::new())), None);
        let stmt = |kind: StmtKind| Stmt::new(kind, None);
        let increment = stmt(StmtKind::Assign(Expr::Var(0), Expr::binary(BinaryOp::Add, Expr::Var(0), Expr::Int(1))));
        let test = Expr::binary(BinaryOp::Gt, Expr::Var(0), Expr::Int(3));

        // v0 = 0; while (1) { b(v0); if (v0 > 3) break; v0 += 1; } -> for (v0 = 0;; v0 += 1) { ... }
        let body = vec![stmt(StmtKind::Assign(Expr::Var(1), Expr::Var(0))), stmt(StmtKind::If(test.clone(), vec![stmt(StmtKind::Break)], Vec::new())), increment.clone()];
        let mut stmts = vec![stmt(StmtKind::Assign(Expr::Var(0), Expr::Int(0))), stmt(StmtKind::While(Expr::Int(1), body))];
        loops_and_exits(&mut stmts);
        assert!(matches!(&stmts[..], [Stmt { kind: StmtKind::For(_, Expr::Int(1), _, body), .. }] if body.len() == 2), "{:?}", stmts);

        // while (1) { if (c) { b(); } else { break; } c(); } -> while (c) { b(); c(); }
        let body = vec![stmt(StmtKind::If(test.clone(), vec![call("b")], vec![stmt(StmtKind::Break)])), call("c")];
        let mut stmts = vec![stmt(StmtKind::While(Expr::Int(1), body))];
        loops_and_exits(&mut stmts);
        assert!(matches!(&stmts[..], [Stmt { kind: StmtKind::While(c, body), .. }] if *c == test && body.len() == 2), "{:?}", stmts);

        // if (c) { b(); b(); b(); return 1; } return 0; -> if (!c) { return 0; } b(); b(); b(); return 1;
        let returns = |v: i128| stmt(StmtKind::Return(Some(Expr::Int(v))));
        let mut stmts = vec![stmt(StmtKind::If(test.clone(), vec![call("b"), call("b"), call("b"), returns(1)], Vec::new())), returns(0)];
        loops_and_exits(&mut stmts);
        assert_eq!(stmts.len(), 5, "{:?}", stmts);
        assert!(matches!(&stmts[0].kind, StmtKind::If(c, then, _) if *c == test.clone().not() && then[..] == [returns(0)]), "{:?}", stmts);

        // if (c) { b(); d(); } else { e(); d(); } -> if (c) { b(); } else { e(); } d();
        let mut stmts = vec![stmt(StmtKind::If(test.clone(), vec![call("b"), call("d")], vec![call("e"), call("d")]))];
        loops_and_exits(&mut stmts);
        assert!(matches!(&stmts[..], [Stmt { kind: StmtKind::If(_, a, b), .. }, d] if a[..] == [call("b")] && b[..] == [call("e")] && *d == call("d")), "{:?}", stmts);

        // v0 = 0; if (v0 > 3) { do { b(v0); v0 += 1; } while (v0 > 3); } -> for (v0 = 0; v0 > 3; v0 += 1) { b(v0); }
        let body = vec![stmt(StmtKind::Assign(Expr::Var(1), Expr::Var(0))), increment.clone()];
        let rotated = stmt(StmtKind::If(test.clone(), vec![stmt(StmtKind::DoWhile(body, test.clone()))], Vec::new()));
        let mut stmts = vec![stmt(StmtKind::Assign(Expr::Var(0), Expr::Int(0))), rotated];
        loops_and_exits(&mut stmts);
        assert!(matches!(&stmts[..], [Stmt { kind: StmtKind::For(_, c, _, body), .. }] if *c == test && body.len() == 1), "{:?}", stmts);

        // if (c) { if (v0 > 3) { b(); } } -> if (c && v0 > 3) { b(); }
        let mut stmts = vec![stmt(StmtKind::If(Expr::Var(1), vec![stmt(StmtKind::If(test.clone(), vec![call("b")], Vec::new()))], Vec::new()))];
        loops_and_exits(&mut stmts);
        assert!(matches!(&stmts[..], [Stmt { kind: StmtKind::If(Expr::Binary(BinaryOp::LogicalAnd, ..), a, _), .. }] if a[..] == [call("b")]), "{:?}", stmts);
    }

    fn assign(var: VarId) -> Stmt {
        return Stmt::new(StmtKind::Assign(Expr::Var(var), Expr::Int(1)), None);
    }

    fn var_cond(var: VarId) -> Expr {
        return Expr::binary(BinaryOp::Eq, Expr::Var(var), Expr::Int(0));
    }

    #[test]
    fn switch_cases_sharing_a_block() {
        // Two cases continue in b4, the third one goes to the join; b4 is large and branches
        let blocks = vec![
            block(0, 1, Term::Switch(Expr::Var(0), vec![(vec![1], 1), (vec![2], 2)], 3)),
            block(1, 1, Term::Jump(4)),
            block(2, 1, Term::Jump(4)),
            block(3, 1, Term::Jump(6)),
            block(4, 10, Term::Branch(var_cond(1), 5, 6)),
            block(5, 10, Term::Jump(6)),
            block(6, 4, Term::Return(None)),
        ];

        assert_eq!(gotos(blocks), 0);
    }

    #[test]
    fn or_else_chain() {
        // if (v0 != 0 && v1 != 0 && v2 != 0) { b4 } else { b3 } with assignments between the tests
        let mut blocks = vec![
            block(0, 1, Term::Branch(var_cond(0), 3, 1)),
            block(1, 1, Term::Branch(var_cond(1), 3, 2)),
            block(2, 1, Term::Branch(var_cond(2), 3, 4)),
            block(3, 10, Term::Jump(5)),
            block(4, 10, Term::Jump(5)),
            block(5, 4, Term::Return(None)),
        ];

        blocks[1].stmts.push(assign(1));
        blocks[2].stmts.push(assign(2));

        assert_eq!(gotos(blocks), 0);
    }

    #[test]
    fn changed_conditions_are_not_tested_again() {
        // b4 is shared by the two arms of c0, but the arms change the variable it is tested on
        let mut blocks = vec![
            block(0, 1, Term::Branch(var_cond(1), 1, 2)),
            block(1, 1, Term::Jump(3)),
            block(2, 1, Term::Branch(cond(2), 3, 5)),
            block(3, 10, Term::Jump(4)),
            block(4, 10, Term::Jump(5)),
            block(5, 4, Term::Return(None)),
        ];

        blocks[1].stmts.push(assign(1));
        blocks[2].stmts.push(assign(1));

        let stmts = structure(blocks.clone(), &mut Vec::new());
        let printed = format!("{:?}", stmts);

        // b3 is not guarded by a test of v1 after the arms
        assert!(!printed.contains("If(Binary(Eq, Var(1), Int(0)), [Label(\"label_3"), "{}", printed);
        gotos(blocks);
    }

    #[test]
    fn identical_cases() {
        // Cases 1 and 3 return 5, case 2 returns 7 like the default, cases 4 and 5 join after the switch
        let ret = |value: i128| SBlock { stmts: Vec::new(), term: Term::Return(Some(Expr::Int(value))), addr: None };
        let blocks = vec![
            block(0, 1, Term::Switch(Expr::Var(0), vec![(vec![1], 1), (vec![2], 2), (vec![3], 3), (vec![4], 5), (vec![5], 6)], 4)),
            ret(5),
            ret(7),
            ret(5),
            ret(7),
            block(5, 1, Term::Jump(6)),
            block(6, 10, Term::Return(Some(Expr::Int(5)))),
        ];

        let stmts = structure(blocks, &mut Vec::new());
        let Some(StmtKind::Switch(_, cases, default)) = stmts.iter().map(|s| &s.kind).find(|k| matches!(k, StmtKind::Switch(..))) else {
            panic!("{:#?}", stmts);
        };

        let values: Vec<Vec<i128>> = cases.iter().map(|c| c.values.clone()).collect();
        assert_eq!(values, vec![vec![1, 3], vec![4], vec![5]], "{:#?}", stmts);
        assert_eq!(default.len(), 1);
    }

    #[test]
    fn shared_tail_of_returning_branches() {
        // The paths that do not return join at b5 (the post dominator is the exit)
        let blocks = vec![
            block(0, 1, Term::Branch(cond(0), 1, 2)),
            block(1, 1, Term::Branch(cond(1), 3, 5)),
            block(2, 1, Term::Branch(cond(2), 4, 5)),
            block(3, 4, Term::Return(None)),
            block(4, 4, Term::Return(None)),
            block(5, 4, Term::Return(None)),
        ];

        assert_eq!(gotos(blocks), 0);
    }
}
