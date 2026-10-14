/*
 * Type inference on the IR: pointers are found from the memory accesses they address (their
 * pointee is the accessed type) and propagated through arithmetic, phis and casts, signedness
 * comes from the operations values are used by, known prototypes give the types of calls
 */

use super::ir::{Allocated, Func, Op, Pred, Ty, ValueId, ValueKind};
use super::Context;

use crate::types::CType;

const ROUNDS: usize = 6;

pub fn base_type(ty: Ty) -> CType {
    return match ty {
        Ty::Int(1) => CType::Bool,
        Ty::Int(8) => CType::Char,
        Ty::Int(bits) => CType::int(bits as u16),
        Ty::Float(bits) => CType::Float { bits: bits as u16 },
        Ty::Ptr => CType::ptr(CType::Void),
        Ty::Void => CType::Void,
        Ty::Other => CType::Unknown(0),
    };
}

/// Type of the value loaded or stored by an access of this IR type
fn access_type(ty: Ty) -> CType {
    return match ty {
        Ty::Int(8) => CType::Char,
        _ => base_type(ty),
    };
}

pub fn is_pointer(ty: &CType) -> bool {
    return matches!(ty.unqualified(), CType::Pointer(_));
}

pub fn pointee(ty: &CType) -> Option<&CType> {
    return match ty.unqualified() {
        CType::Pointer(to) => Some(to),
        _ => None,
    };
}

struct Inference<'a> {
    f: &'a Func,
    ctx: &'a Context<'a>,
    types: Vec<CType>,
    /// Values joined by phis and selects, with each other (they become one variable)
    webs: Vec<Vec<ValueId>>,
    /// (used as signed, used as unsigned)
    signs: Vec<(bool, bool)>,
    changed: bool,
}

impl Inference<'_> {
    /// Pointer types replace integers, a known pointee replaces void
    fn set_pointer(&mut self, id: ValueId, to: CType) {
        if self.f.is_constant(id) && !matches!(self.f.values[id].kind, ValueKind::Inst { .. }) {
            return;
        }

        let better = match pointee(&self.types[id]) {
            None => true,
            Some(CType::Void) | Some(CType::Unknown(_)) => !matches!(to, CType::Void | CType::Unknown(_)),
            Some(current) if is_pointer(&to) && !is_pointer(current) && matches!(current, CType::Int { bits: 64, .. }) => true,
            _ => false,
        };

        let width_ok = matches!(self.f.values[id].ty, Ty::Ptr | Ty::Int(64) | Ty::Int(32));

        if better && width_ok && pointee(&self.types[id]) != Some(&to) {
            self.types[id] = CType::ptr(to);
            self.changed = true;
        }
    }

    fn set(&mut self, id: ValueId, ty: CType) {
        if self.types[id] != ty && !self.f.is_constant(id) {
            self.types[id] = ty;
            self.changed = true;
        }
    }

    /// Signedness votes, applied at the end: unsigned only when never used as signed
    fn set_signed(&mut self, id: ValueId, signed: bool) {
        let votes = &mut self.signs[id];

        if signed && !votes.0 || !signed && !votes.1 {
            self.changed = true;
        }

        if signed {
            votes.0 = true;
        } else {
            votes.1 = true;
        }
    }

    /// Address operand of a load or store: the integer behind inttoptr, or the pointer itself
    fn address_root(&self, id: ValueId) -> ValueId {
        return match self.f.inst(id) {
            Some((Op::IntToPtr, [x])) => *x,
            _ => id,
        };
    }

    /// Base of an indexed access (base + i * size): the base points to elements of the accessed size
    fn indexed_base(&self, address: ValueId, size: i64) -> Option<ValueId> {
        let f = self.f;

        let scale_of = |v: ValueId| -> i64 {
            match f.inst(v) {
                Some((Op::Shl, [_, k])) => f.int(*k).map_or(1, |k| 1i64 << k),
                Some((Op::Mul, [_, c])) => f.int(*c).map_or(1, |c| c as i64),
                _ => 1,
            }
        };

        return match f.inst(self.address_root(address)) {
            Some((Op::Gep, [base, index])) if f.int(*index).is_none() => {
                let ValueKind::Inst { scales, .. } = &f.values[self.address_root(address)].kind else {
                    return None;
                };
                (scales.first().copied().unwrap_or(1) * scale_of(*index) == size).then_some(*base)
            }
            Some((Op::Add, [x, y])) if f.int(*x).is_none() && f.int(*y).is_none() => {
                if scale_of(*y) == size && size > 1 {
                    Some(*x)
                } else if scale_of(*x) == size && size > 1 {
                    Some(*y)
                } else {
                    None
                }
            }
            _ => None,
        };
    }

    /// A memory access types its address, and the base of an indexed address
    fn access(&mut self, address: ValueId, accessed: CType, bits: u32) {
        let root = self.address_root(address);
        self.set_pointer(root, accessed.clone());

        if let Some(base) = self.indexed_base(address, bits as i64 / 8) {
            self.set_pointer(base, accessed);
        }
    }

    /// The values of a web share one pointer type. While inferring, the ones that do not know theirs get
    /// the first known one, at the end all get the one of most uses among them (the first one for a tie),
    /// else a pointer to void when one is a pointer.
    fn unify(&mut self, end: bool) {
        let known = |ty: &CType| pointee(ty).is_some_and(|p| !matches!(p, CType::Void | CType::Unknown(_)));

        for w in 0..self.webs.len() {
            let web = &self.webs[w];
            let mut counts: Vec<(&CType, usize)> = Vec::new();

            for &v in web.iter() {
                let ty = &self.types[v];

                if known(ty) {
                    let uses = if end { self.f.values[v].uses.len() } else { 1 };

                    match counts.iter_mut().find(|(t, _)| *t == ty) {
                        Some((_, n)) => *n += uses,
                        None => counts.push((ty, uses)),
                    }

                    if !end {
                        break;
                    }
                }
            }

            let best = counts.iter().enumerate().max_by_key(|&(i, &(_, n))| (n, std::cmp::Reverse(i))).map(|(_, &(t, _))| t.clone());
            let pointer = best.or_else(|| web.iter().any(|&v| is_pointer(&self.types[v])).then(|| CType::ptr(CType::Void)));

            // A web is written through more often than not, it does not keep a const of one of its values
            let Some(ty) = pointer.map(|ty| CType::ptr(pointee(&ty).map_or(CType::Void, |p| p.unqualified().clone()))) else {
                continue;
            };

            for i in 0..self.webs[w].len() {
                let v = self.webs[w][i];

                if end && is_pointer(&self.types[v]) && known(&self.types[v]) {
                    self.set(v, ty.clone());
                } else {
                    self.set_pointer(v, pointee(&ty).cloned().unwrap_or(CType::Void));
                }
            }
        }
    }

    fn round(&mut self) {
        let f = self.f;

        for id in 0..f.values.len() {
            let ValueKind::Inst { op, operands, callee, pred, .. } = &f.values[id].kind else {
                continue;
            };

            match (op, operands.as_slice()) {
                (Op::Load, [address]) => {
                    let accessed = if is_pointer(&self.types[id]) { self.types[id].clone() } else { access_type(f.values[id].ty) };
                    self.access(*address, accessed, f.values[id].ty.bits());
                }
                (Op::Store, [value, address]) => {
                    let accessed = if is_pointer(&self.types[*value]) { self.types[*value].clone() } else { access_type(f.values[*value].ty) };
                    self.access(*address, accessed, f.values[*value].ty.bits());
                }
                (Op::IntToPtr, [x]) | (Op::PtrToInt, [x]) | (Op::Freeze, [x]) => {
                    if let Some(to) = pointee(&self.types[id]).cloned() {
                        self.set_pointer(*x, to);
                    }

                    if let Some(to) = pointee(&self.types[*x]).cloned() {
                        self.set_pointer(id, to);
                    }
                }
                // A field at a constant offset of a pointer to unknown data: the pointer is to that type
                (Op::Gep, [base, rest @ ..]) => {
                    if !is_pointer(&self.types[*base]) {
                        self.set_pointer(*base, CType::Void);
                    }

                    if rest.iter().all(|&i| f.int(i).is_some()) {
                        if let Some(to) = pointee(&self.types[id]).cloned() {
                            self.set_pointer(*base, to);
                        }
                    }
                }
                // Pointer plus or minus an offset is a pointer (to unknown data unless the offset is 0), a
                // pointer to unknown data plus a constant offset points to the type of that field
                (Op::Add | Op::Sub, [x, y]) => {
                    let (pointer, offset) = if is_pointer(&self.types[*x]) { (*x, *y) } else { (*y, *x) };

                    if is_pointer(&self.types[pointer]) && !is_pointer(&self.types[offset]) && (*op == Op::Add || pointer == *x) {
                        let to = pointee(&self.types[pointer]).cloned().unwrap_or(CType::Void);
                        self.set_pointer(id, to);
                    }

                    if is_pointer(&self.types[id]) && f.int(*y).is_some() {
                        let to = pointee(&self.types[id]).cloned().unwrap_or(CType::Void);
                        self.set_pointer(*x, to);
                    }
                }
                (Op::Call, args) => {
                    let Some(prototype) = callee.as_ref().and_then(|c| self.ctx.prototypes.get(c)) else {
                        continue;
                    };

                    for (arg, param) in args.iter().zip(prototype.ty.params.iter()) {
                        let ty = self.ctx.resolve(&param.ty);

                        if let Some(to) = pointee(&ty) {
                            self.set_pointer(*arg, to.clone());
                        }
                    }

                    let ret = self.ctx.resolve(&prototype.ty.ret);

                    if f.values[id].ty.bits() > 0 && !ret.is_unknown() && ret != CType::Void {
                        match pointee(&ret) {
                            Some(to) => self.set_pointer(id, to.clone()),
                            None if f.values[id].ty.bits() == self.ctx.size_bits(&ret) => self.set(id, prototype.ty.ret.clone()),
                            None => {}
                        }
                    }
                }
                // Signedness from the operations
                (Op::UDiv | Op::URem | Op::LShr, [x, y]) => {
                    self.set_signed(*x, false);

                    if *op != Op::LShr {
                        self.set_signed(*y, false);
                    }
                }
                (Op::SDiv | Op::SRem | Op::AShr, [x, _]) => self.set_signed(*x, true),
                (Op::ICmp, [x, y]) => {
                    let signed = match pred {
                        Some(Pred::Slt | Pred::Sle | Pred::Sgt | Pred::Sge) => Some(true),
                        Some(Pred::Ult | Pred::Ule | Pred::Ugt | Pred::Uge) => Some(false),
                        _ => None,
                    };

                    // Unsigned comparisons with constants are mostly range checks (switches, bounds)
                    let constant = f.int(*x).is_some() || f.int(*y).is_some();

                    if let Some(signed) = signed.filter(|&s| s || !constant) {
                        self.set_signed(*x, signed);
                        self.set_signed(*y, signed);
                    }

                    // Comparing an integer with a pointer makes it a pointer
                    if let Some(to) = pointee(&self.types[*x]).cloned() {
                        self.set_pointer(*y, to);
                    }

                    if let Some(to) = pointee(&self.types[*y]).cloned() {
                        self.set_pointer(*x, to);
                    }
                }
                (Op::ZExt, [x]) => self.set_signed(*x, false),
                _ => {}
            }
        }
    }
}

/// C type of every value of the function
pub fn infer(f: &Func, ctx: &Context, params: &[CType]) -> Vec<CType> {
    let mut types: Vec<CType> = f.values.iter().map(|v| base_type(v.ty)).collect();

    // Variables of the stack frame: buffers of chars, the type of the scalars comes from their accesses
    for (&id, allocated) in f.allocated.iter() {
        types[id] = CType::ptr(match allocated {
            Allocated::Bytes(_) => CType::Char,
            Allocated::Scalar(ty) => CType::Unknown(ty.bits() as u16),
        });
    }

    for (&param, ty) in f.params.iter().zip(params.iter()) {
        types[param] = if pointee(ty).is_some_and(|p| p.is_unknown()) { CType::ptr(CType::Void) } else { ty.clone() };
    }

    let signs = vec![(false, false); f.values.len()];
    let mut inference = Inference { f, ctx, types, webs: webs(f), signs, changed: true };

    for _ in 0..ROUNDS {
        if !inference.changed {
            break;
        }

        inference.changed = false;
        inference.round();
        inference.unify(false);
    }

    inference.unify(true);

    writable(f, &mut inference.types);

    for (id, &(signed, unsigned)) in inference.signs.iter().enumerate() {
        if let CType::Int { bits, .. } = inference.types[id] {
            if unsigned && !signed {
                inference.types[id] = CType::uint(bits);
            }
        }
    }

    // Typed parameters keep their declared type (a discovered prototype only knows the integers and the
    // pointers, what they point to comes from the accesses)
    for (&param, ty) in f.params.iter().zip(params.iter()) {
        if !ty.is_unknown() && !matches!(ty, CType::Int { .. }) && pointee(ty).is_none_or(|p| !p.is_unknown()) {
            inference.types[param] = ty.clone();
        }
    }

    return inference.types;
}

/// The pointers stored through, and the ones they are computed from, do not point to const data (a const
/// comes from the prototype of a function they are passed to)
fn writable(f: &Func, types: &mut [CType]) {
    let mut seen = vec![false; f.values.len()];

    for value in f.values.iter() {
        let ValueKind::Inst { op: Op::Store, operands, .. } = &value.kind else {
            continue;
        };

        let mut stack = vec![operands[1]];

        while let Some(id) = stack.pop() {
            if std::mem::replace(&mut seen[id], true) {
                continue;
            }

            if let Some(CType::Const(inner)) = pointee(&types[id]) {
                types[id] = CType::ptr((**inner).clone());
            }

            match &f.values[id].kind {
                ValueKind::Inst { op: Op::Add | Op::Sub | Op::Gep | Op::IntToPtr | Op::PtrToInt | Op::BitCast | Op::Freeze | Op::Phi, operands, .. } => stack.extend(operands.iter().copied()),
                ValueKind::Inst { op: Op::Select, operands, .. } => stack.extend(operands[1..].iter().copied()),
                _ => {}
            }
        }
    }
}

/// Groups of values joined by phis and selects (the constants among them are left out)
fn webs(f: &Func) -> Vec<Vec<ValueId>> {
    let mut parent: Vec<ValueId> = (0..f.values.len()).collect();

    fn find(parent: &mut [ValueId], mut v: ValueId) -> ValueId {
        while parent[v] != v {
            parent[v] = parent[parent[v]];
            v = parent[v];
        }

        return v;
    }

    for (id, value) in f.values.iter().enumerate() {
        let joined = match &value.kind {
            ValueKind::Inst { op: Op::Phi, operands, .. } => &operands[..],
            ValueKind::Inst { op: Op::Select, operands, .. } => &operands[1..],
            _ => continue,
        };

        for &v in joined.iter().filter(|&&v| !f.is_constant(v)) {
            let (a, b) = (find(&mut parent, id), find(&mut parent, v));
            parent[a.max(b)] = a.min(b);
        }
    }

    let mut groups: Vec<Vec<ValueId>> = vec![Vec::new(); f.values.len()];

    for v in 0..f.values.len() {
        let root = find(&mut parent, v);
        groups[root].push(v);
    }

    return groups.into_iter().filter(|g| g.len() > 1).collect();
}
