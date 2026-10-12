/*
 * Type inference on the IR: pointers are found from the memory accesses they address (their
 * pointee is the accessed type) and propagated through arithmetic, phis and casts, signedness
 * comes from the operations values are used by, known prototypes give the types of calls
 */

use super::ir::{Func, Op, Pred, Ty, ValueId, ValueKind};
use super::Context;

use crate::types::CType;

const ROUNDS: usize = 6;

fn base_type(ty: Ty) -> CType {
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

    fn round(&mut self) {
        let f = self.f;

        for id in 0..f.values.len() {
            let ValueKind::Inst { op, operands, callee, pred, .. } = &f.values[id].kind else {
                continue;
            };

            match (op, operands.as_slice()) {
                (Op::Load, [address]) => {
                    let accessed = if is_pointer(&self.types[id]) { self.types[id].clone() } else { access_type(f.values[id].ty) };
                    let root = self.address_root(*address);
                    self.set_pointer(root, accessed);
                }
                (Op::Store, [value, address]) => {
                    let accessed = if is_pointer(&self.types[*value]) { self.types[*value].clone() } else { access_type(f.values[*value].ty) };
                    let root = self.address_root(*address);
                    self.set_pointer(root, accessed);
                }
                (Op::IntToPtr, [x]) | (Op::PtrToInt, [x]) | (Op::Freeze, [x]) => {
                    if let Some(to) = pointee(&self.types[id]).cloned() {
                        self.set_pointer(*x, to);
                    }

                    if let Some(to) = pointee(&self.types[*x]).cloned() {
                        self.set_pointer(id, to);
                    }
                }
                (Op::Gep, [base, ..]) => {
                    if !is_pointer(&self.types[*base]) {
                        self.set_pointer(*base, CType::Void);
                    }
                }
                // Pointer plus or minus an offset is a pointer (to unknown data unless the offset is 0)
                (Op::Add | Op::Sub, [x, y]) => {
                    let (pointer, offset) = if is_pointer(&self.types[*x]) { (*x, *y) } else { (*y, *x) };

                    if is_pointer(&self.types[pointer]) && !is_pointer(&self.types[offset]) && (*op == Op::Add || pointer == *x) {
                        let to = pointee(&self.types[pointer]).cloned().unwrap_or(CType::Void);
                        self.set_pointer(id, to);
                    } else if is_pointer(&self.types[id]) && f.int(*y).is_some() {
                        let to = pointee(&self.types[id]).cloned().unwrap_or(CType::Void);
                        self.set_pointer(*x, to);
                    }
                }
                (Op::Phi | Op::Select, values) => {
                    let values = if *op == Op::Select { &values[1..] } else { values };
                    let pointer = values.iter().chain(std::iter::once(&id)).find_map(|v| pointee(&self.types[*v]).cloned());

                    if let Some(to) = pointer {
                        for &v in values.iter().chain(std::iter::once(&id)) {
                            self.set_pointer(v, to.clone());
                        }
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

                    if let Some(signed) = signed {
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

    for (&param, ty) in f.params.iter().zip(params.iter()) {
        types[param] = ty.clone();
    }

    let signs = vec![(false, false); f.values.len()];
    let mut inference = Inference { f, ctx, types, signs, changed: true };

    for _ in 0..ROUNDS {
        if !inference.changed {
            break;
        }

        inference.changed = false;
        inference.round();
    }

    for (id, &(signed, unsigned)) in inference.signs.iter().enumerate() {
        if let CType::Int { bits, .. } = inference.types[id] {
            if unsigned && !signed {
                inference.types[id] = CType::uint(bits);
            }
        }
    }

    // Typed parameters keep their declared type
    for (&param, ty) in f.params.iter().zip(params.iter()) {
        if !ty.is_unknown() && !matches!(ty, CType::Int { .. }) {
            inference.types[param] = ty.clone();
        }
    }

    return inference.types;
}
