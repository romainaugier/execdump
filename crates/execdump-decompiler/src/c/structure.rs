/*
 * Control flow structuring: the blocks become if/else, loops and switches
 *
 * Conditions that only lead to the same targets are merged first (a && b, a || b). Natural loops
 * come from the back edges, a branch is closed where its paths join (its post dominator once the
 * paths that return early are left out), reaching the loop header is a continue and reaching the
 * loop follow a break. The other exits of a loop are emitted where the loop leaves to them. A block
 * reached again is copied when what follows it is small, anything else is a goto. Cleanups then
 * give the loops their condition (while, do while, for) and flatten the if/else chains.
 */

use super::ast::{BinaryOp, Case, Expr, Stmt, StmtKind, VarId};
use super::build::{SBlock, Term};

use std::collections::{HashMap, HashSet};

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
    blocks: &'a [SBlock],
    preds: Vec<Vec<usize>>,
    /// Where the branches of a block join (see Structurer::new)
    joins: Vec<Option<usize>>,
    loops: HashMap<usize, Loop>,
    emitted: Vec<bool>,
    /// Statements left while copying a region instead of jumping to it, None when not copying
    copy_budget: Option<usize>,
    copy_failed: bool,
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

pub fn label(block: usize) -> String {
    return format!("label_{}", block);
}

impl<'a> Structurer<'a> {
    fn new(blocks: &'a [SBlock]) -> Self {
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
        let joins = (0..count).map(|n| if private[n] { ipdom[n] } else { pruned[n].or(ipdom[n]) }).collect();

        // Natural loops of the back edges, merged by header
        let mut loops: HashMap<usize, Loop> = HashMap::new();
        let reachable: HashSet<usize> = order.iter().copied().collect();

        for &node in order.iter() {
            for &target in succs[node].iter() {
                if !dominates(&idom, target, node) {
                    continue;
                }

                let body = &mut loops.entry(target).or_insert_with(|| Loop { body: HashSet::from([target]), follow: None }).body;
                let mut stack = vec![node];

                while let Some(n) = stack.pop() {
                    if reachable.contains(&n) && body.insert(n) {
                        stack.extend(preds[n].iter().copied());
                    }
                }
            }
        }

        let position: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &n)| (n, i)).collect();

        for (&header, l) in loops.iter_mut() {
            let mut exits: Vec<usize> = l.body.iter().flat_map(|&n| succs[n].iter().copied()).filter(|t| !l.body.contains(t)).collect();
            exits.sort_by_key(|t| position.get(t).copied().unwrap_or(usize::MAX));

            // The post dominator of the header when it leaves the loop, else the most targeted exit
            l.follow = match ipdom[header] {
                Some(p) if exits.contains(&p) => Some(p),
                _ => exits.iter().max_by_key(|t| (exits.iter().filter(|e| e == t).count(), usize::MAX - position.get(t).copied().unwrap_or(0))).copied(),
            };
        }

        return Structurer { blocks, preds, joins, loops, emitted: vec![false; count], copy_budget: None, copy_failed: false };
    }

    /// A block that ends the function with at most a few statements
    fn is_tail(&self, block: usize) -> bool {
        let b = &self.blocks[block];
        return matches!(b.term, Term::Return(_) | Term::Unreachable) && b.stmts.len() <= 3 && (b.stmts.len() < 3 || matches!(b.term, Term::Return(None)) || b.stmts.iter().all(|s| !matches!(s.kind, StmtKind::If(..))));
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

            out.extend(self.blocks[block].stmts.iter().cloned());

            current = match &self.blocks[block].term {
                Term::Return(value) => {
                    out.push(Stmt::new(StmtKind::Return(value.clone()), addr));
                    None
                }
                Term::Unreachable => None,
                Term::Jump(target) => Some(*target),
                Term::Branch(condition, on_true, on_false) => {
                    let merge = self.merge(block, &context);
                    let then = self.region(*on_true, merge, context, false);
                    let otherwise = self.region(*on_false, merge, context, false);

                    out.push(Stmt::new(StmtKind::If(condition.clone(), then, otherwise), addr));
                    merge
                }
                Term::Switch(value, cases, default) => {
                    let merge = self.merge(block, &context);
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
                    merge
                }
            };
        }

        return out;
    }
}

/// Short circuit conditions: a branch to a block that only branches again to one of the same targets
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
        }

        // while (1) { ...; if (c) break; } -> do { ... } while (!c)
        if let Some(StmtKind::If(c, then, otherwise)) = body.last().map(|s| s.kind.clone()) {
            let rest = &body[..body.len() - 1];

            if is_single(&then, &StmtKind::Break) && otherwise.is_empty() && !has_loop_jump(rest, &StmtKind::Continue) {
                body.pop();
                stmt.kind = StmtKind::DoWhile(std::mem::take(body), c.not());
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

fn assigned_var(stmt: &Stmt) -> Option<(VarId, &Expr)> {
    return match &stmt.kind {
        StmtKind::Assign(Expr::Var(v), value) => Some((*v, value)),
        _ => None,
    };
}

/// v = init; while (cond(v)) { ...; v = v + k; } -> for (v = init; cond(v); v += k) { ... }
fn for_loops(stmts: &mut Vec<Stmt>) {
    let mut i = 1;

    while i < stmts.len() {
        let (before, after) = stmts.split_at_mut(i);
        let init = &before[i - 1];

        let StmtKind::While(cond, body) = &mut after[0].kind else {
            i += 1;
            continue;
        };

        let Some((var, _)) = assigned_var(init) else {
            i += 1;
            continue;
        };

        let step = body.last().and_then(|s| assigned_var(s)).filter(|(v, value)| *v == var && value.uses(var)).is_some();

        if step && cond.uses(var) && !has_loop_jump(body, &StmtKind::Continue) {
            let step = body.pop().unwrap();
            let (cond, body) = (cond.clone(), std::mem::take(body));
            let addr = after[0].addr;
            let init = stmts.remove(i - 1);
            stmts[i - 1] = Stmt::new(StmtKind::For(Box::new(init), cond, Box::new(step), body), addr);
            continue;
        }

        i += 1;
    }
}

/// Labels nobody jumps to, and gotos to the label right after them
fn remove_labels(stmts: &mut Vec<Stmt>, gotos: &HashSet<String>) {
    stmts.retain(|s| !matches!(&s.kind, StmtKind::Label(l) if !gotos.contains(l)));
}

fn collect_gotos(stmts: &mut Vec<Stmt>) -> HashSet<String> {
    let mut gotos = HashSet::new();

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
    let mut labels = HashSet::new();

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

/// Structured statements of the blocks (block 0 is the entry)
pub fn structure(mut blocks: Vec<SBlock>) -> Vec<Stmt> {
    if blocks.is_empty() {
        return Vec::new();
    }

    merge_conditions(&mut blocks);

    let mut structurer = Structurer::new(&blocks);
    let mut stmts = structurer.region(0, None, TOP, false);

    // Blocks only jumped to that were never emitted with their label (left from inside the loops, or
    // small tails always repeated) go at the end, the statements before do not fall through to them
    let mut appended = HashSet::new();

    loop {
        let labels = collect_labels(&mut stmts);
        let missing = collect_gotos(&mut stmts).into_iter().filter(|g| !labels.contains(g)).filter_map(|g| g.strip_prefix("label_")?.parse::<usize>().ok());

        let Some(block) = missing.filter(|b| !appended.contains(b)).min() else {
            break;
        };

        appended.insert(block);

        // The small tails are repeated by region, without their label
        if structurer.is_tail(block) {
            let b = &blocks[block];
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
        walk(&mut stmts, &mut for_loops);
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
        let stmts = structure(blocks);
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
