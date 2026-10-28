// SPDX-License-Identifier: Apache-2.0
/*
 * Structs from the access patterns: the offsets, sizes and types accessed through a pointer (and the
 * values joined with it by phis) make a struct when they are not the elements of an array (a single type,
 * at multiples of its size). The pointer points to the struct, its accesses are fields (p->f18), the
 * fields hold the types of the values loaded and stored (pointers to other structs included). A buffer of
 * the stack frame accessed at constant offsets with several types is a struct of its size (v20.f8).
 */

use super::ir::{Allocated, Func, Op, Ty, ValueId, ValueKind};
use super::typing::{pointee, webs};
use super::Context;

use crate::typedb::{Aggregate, Field};
use crate::types::CType;

use std::collections::BTreeMap;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

/// Rounds of merging the pointers loaded from the same places (a merge can make two places one)
const MAX_MERGE_ROUNDS: usize = 8;

/// Base of an address and its constant offset, None when an index is added to it (the operands of that
/// addition are indexed: arrays, not structs)
fn decompose(f: &Func, mut id: ValueId, indexed: &mut HashSet<ValueId>) -> Option<(ValueId, i64)> {
    let mut offset = 0i64;

    loop {
        match f.inst(id) {
            Some((Op::IntToPtr | Op::PtrToInt | Op::BitCast | Op::Freeze, [x])) => id = *x,
            Some((Op::Add, [x, y])) => match (f.int(*x), f.int(*y)) {
                (_, Some(c)) => {
                    offset = offset.wrapping_add(c as i64);
                    id = *x;
                }
                (Some(c), _) => {
                    offset = offset.wrapping_add(c as i64);
                    id = *y;
                }
                _ => {
                    indexed.insert(*x);
                    indexed.insert(*y);
                    return None;
                }
            },
            Some((Op::Sub, [x, y])) if f.int(*y).is_some() => {
                offset = offset.wrapping_sub(f.int(*y).unwrap() as i64);
                id = *x;
            }
            Some((Op::Gep, [base, indices @ ..])) => {
                let ValueKind::Inst { scales, .. } = &f.values[id].kind else {
                    return None;
                };

                for (index, scale) in indices.iter().zip(scales.iter()) {
                    match f.int(*index) {
                        Some(c) => offset = offset.wrapping_add(c as i64 * scale),
                        None => {
                            indexed.insert(*base);
                            return None;
                        }
                    }
                }

                id = *base;
            }
            _ => return Some((id, offset)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Access {
    offset: i64,
    bytes: u64,
    /// The value loaded or stored, its type gives the type of the field
    value: ValueId,
    /// The value is the address of the field (passed to a function), it points to the type of the field
    address: bool,
    /// The type of a field a callee knows (the struct of its parameter)
    known: Option<CType>,
}

impl Access {
    fn ty(&self, types: &[CType]) -> CType {
        if let Some(known) = &self.known {
            return known.clone();
        }

        return match self.address {
            true => pointee(&types[self.value]).cloned().unwrap_or(CType::Unknown(0)),
            false => types[self.value].clone(),
        };
    }
}

/// Type of a field from the value accessed, of the size accessed
fn field_type(ctx: &Context, ty: &CType, bytes: u64) -> CType {
    // A field is written where its value is read: not const
    let ty = ty.unqualified();

    let ty = match pointee(ty) {
        Some(CType::Unknown(_)) => CType::ptr(CType::Void),
        _ => ty.clone(),
    };

    if ctx.size_of(&ty) == Some(bytes) && !matches!(ty, CType::Bool) {
        return ty;
    }

    return if bytes == 1 { CType::Char } else { CType::int(bytes as u16 * 8) };
}

/// The fields of a struct: the accesses that do not overlap the ones at a lower offset (the widest first), the ones
/// before its start (container_of) are not fields
fn layout(ctx: &Context, accesses: &[Access], types: &[CType]) -> Aggregate {
    // At an offset the widest access, of the most precise type: a pointer to a struct, to something else,
    // a number, a pointer to anything
    let mut sorted: Vec<&Access> = accesses.iter().filter(|a| a.offset >= 0).collect();
    let precision = |a: &Access| match pointee(&a.ty(types)) {
        Some(CType::Struct(_)) => 0,
        Some(p) if !p.is_unknown() && !matches!(p, CType::Void) => 1,
        Some(_) => 3,
        None => 2,
    };
    sorted.sort_by_key(|a| (a.offset, std::cmp::Reverse(a.bytes), precision(a), a.value));

    let mut fields: Vec<Field> = Vec::new();
    let mut end = 0u64;
    let mut align = 1u64;
    let mut packed = false;

    for (i, access) in sorted.iter().enumerate() {
        let offset = access.offset as u64;

        if offset < end {
            continue;
        }

        // A wide access over several narrower ones (a copy of two fields at once) is not a field: a narrower
        // access at its offset is, or an integer up to the next field
        let next = sorted[i..].iter().map(|a| a.offset as u64).find(|&o| o > offset).unwrap_or(u64::MAX);
        let narrower = sorted[i + 1..].iter().take_while(|a| a.offset as u64 == offset).any(|a| offset + a.bytes <= next);
        let covers = offset + access.bytes > next;

        let aggregate = matches!(ctx.resolve(&access.ty(types)).unqualified(), CType::Struct(_) | CType::Union(_));

        if covers && narrower && !aggregate {
            continue;
        }

        let (ty, bytes) = match next - offset {
            gap @ (1 | 2 | 4 | 8) if covers && !aggregate => (field_type(ctx, &CType::Unknown(0), gap), gap),
            _ => (field_type(ctx, &access.ty(types), access.bytes), access.bytes),
        };
        let field_align = ctx.typedb.align_of(&ty).unwrap_or(1).max(1);

        packed |= offset % field_align != 0;
        align = align.max(field_align);

        // The bytes not accessed between the fields
        if offset > end {
            fields.push(Field { name: format!("pad_{:x}", end), ty: CType::Array(Box::new(CType::Char), Some(offset - end)), offset: end, bits: None });
        }

        end = offset + bytes;
        fields.push(Field { name: format!("f{:x}", offset), ty, offset, bits: None });
    }

    let align = if packed { 1 } else { align };
    return Aggregate { fields, size: end.div_ceil(align) * align, align, union: false, pack: packed.then_some(1) };
}

/// Recovers the structs of a function: the pointers whose accesses make one point to it. The structs are
/// named after the function (st_<address>_<n>), they are added to the context.
pub fn recover(f: &Func, ctx: &Context, types: &mut [CType], declared: &[CType], ret: Option<&CType>, addr: u64) {
    let mut indexed: HashSet<ValueId> = HashSet::default();
    let mut accesses: BTreeMap<ValueId, Vec<Access>> = BTreeMap::new();
    let returned: HashSet<ValueId> = f.values.iter().filter_map(|v| match &v.kind {
        ValueKind::Inst { op: Op::Ret, operands, .. } => operands.first().copied(),
        _ => None,
    }).collect();

    for (id, value) in f.values.iter().enumerate() {
        let (address, accessed) = match &value.kind {
            ValueKind::Inst { op: Op::Load, operands, .. } => (operands[0], id),
            ValueKind::Inst { op: Op::Store, operands, .. } => (operands[1], operands[0]),
            _ => continue,
        };

        let bytes = f.values[accessed].ty.bits().div_ceil(8) as u64;

        if let Some((base, offset)) = decompose(f, address, &mut indexed).filter(|_| bytes > 0) {
            accesses.entry(base).or_default().push(Access { offset, bytes, value: accessed, address: false, known: None });
        }
    }

    // Addresses of fields passed to functions: fields of the type they point to (a struct stat at 0x58 of a
    // pointer passed to fstat)
    for value in f.values.iter() {
        let ValueKind::Inst { op: Op::Call, operands, .. } = &value.kind else {
            continue;
        };

        for &arg in operands.iter() {
            let ty = pointee(&types[arg]).cloned().unwrap_or(CType::Char);
            let bytes = match ctx.resolve(&ty).unqualified() {
                CType::Char | CType::Void | CType::Bool | CType::Unknown(_) | CType::Function(..) => continue,
                // A struct recovered by a callee knows the part of it the callee accesses, not its size
                CType::Struct(name) if ctx.imported.contains_key(name) => continue,
                _ => ctx.size_of(&ty).unwrap_or(0),
            };

            if let Some((base, offset)) = decompose(f, arg, &mut indexed).filter(|&(base, offset)| base != arg && offset > 0 && bytes > 0) {
                accesses.entry(base).or_default().push(Access { offset, bytes, value: arg, address: true, known: None });
            }
        }
    }

    // One pointer: the values joined by phis, and the pointers loaded from or stored to the same place (a
    // global, a field of a pointer), until the places stop merging
    let pointer_bits = ctx.program.pointer_size.max(4) as u32 * 8;
    let pointer_sized = |v: ValueId| matches!(f.values[v].ty, Ty::Ptr) || f.values[v].ty == Ty::Int(pointer_bits);
    let mut parent: Vec<ValueId> = (0..f.values.len()).collect();

    fn find(parent: &mut [ValueId], mut v: ValueId) -> ValueId {
        while parent[v] != v {
            parent[v] = parent[parent[v]];
            v = parent[v];
        }

        return v;
    }

    let union = |parent: &mut [ValueId], a: ValueId, b: ValueId| -> bool {
        let (a, b) = (find(parent, a), find(parent, b));
        parent[a.max(b)] = a.min(b);
        return a != b;
    };

    for web in webs(f) {
        web.windows(2).for_each(|pair| {
            union(&mut parent, pair[0], pair[1]);
        });
    }

    // A pointer converted to join others is the same pointer (p = p->next through a phi of pointers)
    for id in 0..f.values.len() {
        if let Some((Op::IntToPtr | Op::PtrToInt | Op::BitCast, [x])) = f.inst(id) {
            if f.values[id].uses.iter().any(|&u| f.op(u) == Some(Op::Phi)) && !f.allocated.contains_key(x) {
                union(&mut parent, id, *x);
            }
        }
    }

    for _ in 0..MAX_MERGE_ROUNDS {
        let mut changed = false;
        let mut places: HashMap<(ValueId, i64), ValueId> = HashMap::default();

        for (&base, list) in accesses.iter().filter(|(base, _)| matches!(f.values[**base].kind, ValueKind::Global(_))) {
            for access in list.iter().filter(|a| pointer_sized(a.value) && !f.is_constant(a.value)) {
                let place = (find(&mut parent, base), access.offset);

                match places.get(&place) {
                    Some(&other) => changed |= union(&mut parent, other, access.value),
                    None => {
                        places.insert(place, access.value);
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    // The structs the callees take, by the pointer passed to them
    let mut passed: BTreeMap<ValueId, Vec<String>> = BTreeMap::new();

    for value in f.values.iter() {
        let ValueKind::Inst { op: Op::Call, operands, callee: Some(callee), .. } = &value.kind else {
            continue;
        };

        let Some(prototype) = ctx.prototype(callee) else {
            continue;
        };

        for (&arg, param) in operands.iter().zip(prototype.ty.params.iter()) {
            if let Some(CType::Struct(name)) = pointee(&param.ty).map(|p| p.unqualified()) {
                if ctx.imported.contains_key(name) {
                    let base = decompose(f, arg, &mut HashSet::default()).filter(|&(_, offset)| offset == 0).map_or(arg, |(base, _)| base);
                    passed.entry(find(&mut parent, base)).or_default().push(name.clone());
                }
            }
        }
    }

    let mut members: BTreeMap<ValueId, Vec<ValueId>> = BTreeMap::new();

    for v in 0..f.values.len() {
        let root = find(&mut parent, v);
        members.entry(root).or_default().push(v);
    }

    let groups: Vec<Vec<ValueId>> = members.into_values().filter(|g| g.iter().any(|v| accesses.contains_key(v))).collect();

    let mut structs: Vec<Recovered> = Vec::new();

    for group in groups.iter() {
        let mut found: Vec<Access> = group.iter().flat_map(|v| accesses.get(v).into_iter().flatten().cloned()).collect();

        if found.is_empty() {
            continue;
        }

        // A buffer of the frame, alone in its group. Its first bytes never accessed and passed as text, it is a
        // string followed by other variables (char copy[32] then an int), not a struct
        // The structs of the callees the pointer is passed to: one whose fields cover the accesses is its type,
        // else their fields are part of a struct of the function with its own accesses (its callers use that one)
        let mut callee_structs: Vec<String> = group.iter().filter_map(|&v| match pointee(&types[v]) {
            Some(CType::Struct(name)) if ctx.imported.contains_key(name) => Some(name.clone()),
            _ => None,
        }).collect();
        callee_structs.extend(passed.get(&find(&mut parent, group[0])).into_iter().flatten().cloned());
        callee_structs.sort();
        callee_structs.dedup();
        let callee_struct = callee_structs.first().cloned();

        let frame_size = match group.as_slice() {
            [v] => match f.allocated.get(v) {
                Some(Allocated::Bytes(size)) => Some(*size),
                _ => None,
            },
            _ => None,
        };

        if let [name] = callee_structs.as_slice() {
            let known = &ctx.imported[name];
            let field = |a: &Access| known.fields.iter().any(|f| f.offset as i64 == a.offset && !matches!(f.ty, CType::Array(..)) && ctx.size_of(&f.ty) == Some(a.bytes));

            if found.iter().all(|a| field(a)) && frame_size.is_none_or(|size| size == known.size) {
                continue;
            }
        }

        for name in callee_structs.iter() {
            let fits = |offset: u64, bytes: u64| frame_size.is_none_or(|size| offset + bytes <= size);
            let fields = ctx.imported[name].fields.iter().filter(|f| !matches!(f.ty, CType::Array(..))).map(|f| (f, ctx.size_of(&f.ty).unwrap_or(1))).filter(|(f, bytes)| fits(f.offset, *bytes));
            let extra: Vec<Access> = fields.map(|(f, bytes)| Access { offset: f.offset as i64, bytes, value: group[0], address: false, known: Some(f.ty.clone()) }).collect();
            found.extend(extra);
        }

        // The structs of the headers (a callee's struct is one of the function too)
        let aggregate = |v: ValueId| callee_struct.is_none() && pointee(&types[v]).is_some_and(|p| matches!(ctx.resolve(p).unqualified(), CType::Struct(_) | CType::Union(_)));

        // A struct of the headers of the buffer's size is its type, a smaller one (passed to a function) is its
        // first field
        let header = |v: ValueId| pointee(&types[v]).filter(|_| aggregate(v)).cloned();

        let frame = match (group.as_slice(), group.iter().find_map(|v| f.allocated.get(v))) {
            ([v], Some(Allocated::Bytes(size))) if !indexed.contains(v) && header(*v).is_none_or(|h| ctx.size_of(&h).is_some_and(|s| s < *size)) => {
                if let Some(h) = header(*v) {
                    found.push(Access { offset: 0, bytes: ctx.size_of(&h).unwrap_or(1), value: *v, address: false, known: Some(h) });
                }

                Some(*size)
            }
            (_, Some(_)) => continue,
            _ => None,
        };

        if let Some(size) = frame {
            found.sort_by_key(|a| (a.offset, a.bytes, a.value));
            found.dedup_by(|a, b| a.offset == b.offset && a.bytes == b.bytes && a.ty(types) == b.ty(types));

            let inside = found.iter().all(|a| a.offset >= 0 && a.offset as u64 + a.bytes <= size);
            let typed = found.iter().any(|a| a.bytes > 1);
            let v = group[0];

            // Accessed whole only, it is a variable of the type of the accesses (char *endptr)
            let whole = layout(ctx, &found, types).fields.into_iter().next().filter(|field| ctx.size_of(&field.ty) == Some(size) && field.ty != CType::Char);

            // Accessed inside a struct of the type database only, the buffer is a variable of that struct (the bytes
            // after it are the frame's)
            let declared = |h: &CType| matches!(h.unqualified(), CType::Struct(name) | CType::Union(name) if ctx.typedb.aggregates.contains_key(name));
            let within = header(v).filter(|h| declared(h)).filter(|h| ctx.size_of(h).is_some_and(|bytes| found.iter().all(|a| a.offset >= 0 && a.offset as u64 + a.bytes <= bytes)));

            // Accessed as the elements of an array of it (the []interface{} of Go), each access inside an element
            let elements = header(v).filter(|h| declared(h)).filter(|h| {
                ctx.size_of(h).is_some_and(|bytes| bytes > 1 && size % bytes == 0 && found.iter().all(|a| a.offset >= 0 && (a.offset as u64 % bytes) + a.bytes <= bytes && (a.known.is_none() || a.offset == 0)))
            });

            if let (Some(field), true) = (whole, found.iter().all(|a| a.offset == 0)) {
                types[v] = CType::ptr(field.ty);
            } else if let Some(header) = within.or(elements) {
                types[v] = CType::ptr(header);
            } else if inside && typed && (found.iter().any(|a| a.offset == 0) || !passed_as_text(f, ctx, v)) {
                structs.push(Recovered { name: format!("st_{:x}_{}", addr, structs.len()), group: group.clone(), found, frame });
            }

            continue;
        }

        // A pointer the function returns, declared to point to a struct of the database (its debug information)
        let known_struct = ret.filter(|r| pointee(r).is_some_and(|p| matches!(ctx.resolve(p).unqualified(), CType::Struct(name) | CType::Union(name) if ctx.typedb.aggregates.contains_key(name))));

        if let Some(known) = known_struct.filter(|_| group.iter().any(|v| returned.contains(v))) {
            for &v in group.iter() {
                types[v] = known.clone();
            }

            continue;
        }

        // Pointers known to point to something else: the frame, globals, typed parameters, the structs of
        // the headers
        let excluded = group.iter().any(|&v| {
            let declared_pointer = match f.values[v].kind {
                ValueKind::Param(index) => declared.get(index).and_then(pointee).is_some_and(|p| !matches!(p, CType::Unknown(_) | CType::Void)),
                _ => false,
            };
            indexed.contains(&v) || f.is_constant(v) || declared_pointer || aggregate(v) || !pointer_sized(v)
        });

        found.sort_by_key(|a| (a.offset, a.bytes, a.value));
        found.dedup_by(|a, b| a.offset == b.offset && a.bytes == b.bytes && a.ty(types) == b.ty(types));

        let offsets: HashSet<i64> = found.iter().map(|a| a.offset).collect();
        // The elements of an array have one type: the pointers to the same data (const or not) or to anything are one
        let first = found[0].ty(types);
        let element = |ty: &CType| match (pointee(ty), pointee(&first)) {
            (Some(a), Some(b)) => a.unqualified() == b.unqualified() || [a, b].iter().any(|p| matches!(p.unqualified(), CType::Void) || p.is_unknown()),
            _ => *ty == first,
        };
        let array = found.iter().all(|a| element(&a.ty(types)) && a.bytes == found[0].bytes && a.offset % a.bytes as i64 == 0);

        if excluded || offsets.len() < 2 || array || found.iter().any(|a| a.offset < 0) {
            continue;
        }

        structs.push(Recovered { name: format!("st_{:x}_{}", addr, structs.len()), group: group.clone(), found, frame: None });
    }

    // The pointers first, then the fields: a field loaded from one struct can point to another
    for recovered in structs.iter() {
        for &v in recovered.group.iter() {
            types[v] = CType::ptr(CType::Struct(recovered.name.clone()));
        }
    }

    let mut aggregates: Vec<Option<Aggregate>> = structs.iter().map(|s| Some(s.layout(ctx, types))).collect();

    // The structs of the same layout are one (the levels of a tree walked by unrolled code, the same object
    // reached from several places): the merged one gets the accesses of both. Buffers of the frame keep
    // their size, they merge with the ones of the same size only.
    loop {
        let pair = (0..structs.len()).flat_map(|i| (i + 1..structs.len()).map(move |j| (i, j))).find(|&(i, j)| match (&aggregates[i], &aggregates[j]) {
            (Some(a), Some(b)) => structs[i].frame == structs[j].frame && compatible(ctx, a, b),
            _ => false,
        });

        let Some((keep, merged)) = pair else {
            break;
        };

        let (from, to) = (CType::Struct(structs[merged].name.clone()), CType::Struct(structs[keep].name.clone()));
        types.iter_mut().for_each(|ty| *ty = renamed(ty, &from, &to));

        let moved = std::mem::take(&mut structs[merged].found);
        structs[keep].found.extend(moved);
        aggregates[merged] = None;

        for i in 0..structs.len() {
            if aggregates[i].is_some() {
                aggregates[i] = Some(structs[i].layout(ctx, types));
            }
        }
    }

    // Numbered in order once merged
    let kept: Vec<usize> = (0..structs.len()).filter(|&i| aggregates[i].is_some()).collect();

    for (n, &i) in kept.iter().enumerate() {
        let name = format!("st_{:x}_{}", addr, n);
        let (from, to) = (CType::Struct(structs[i].name.clone()), CType::Struct(name.clone()));

        if from != to {
            types.iter_mut().for_each(|ty| *ty = renamed(ty, &from, &to));
            structs[i].name = name;
        }
    }

    let layouts: Vec<(String, Aggregate)> = kept.iter().map(|&i| (structs[i].name.clone(), structs[i].layout(ctx, types))).collect();
    ctx.structs.borrow_mut().extend(layouts);
}

struct Recovered {
    name: String,
    /// The pointers to the struct
    group: Vec<ValueId>,
    found: Vec<Access>,
    /// Size of the buffer of the frame it types
    frame: Option<u64>,
}

impl Recovered {
    /// Layout of the accesses, a buffer of the frame keeps its size (the bytes after the fields are padding)
    fn layout(&self, ctx: &Context, types: &[CType]) -> Aggregate {
        let mut aggregate = layout(ctx, &self.found, types);

        let Some(size) = self.frame else {
            return aggregate;
        };

        let end = aggregate.fields.last().map(|f| f.offset + ctx.size_of(&f.ty).unwrap_or(0)).unwrap_or(0);

        if end < size {
            aggregate.fields.push(Field { name: format!("pad_{:x}", end), ty: CType::Array(Box::new(CType::Char), Some(size - end)), offset: end, bits: None });
        }

        if size % aggregate.align != 0 {
            aggregate.align = 1;
            aggregate.pack = Some(1);
        }

        aggregate.size = size;
        return aggregate;
    }
}

/// A value passed to parameters of known functions that point to chars (strcpy(buffer, ...)), never to structs
fn passed_as_text(f: &Func, ctx: &Context, v: ValueId) -> bool {
    let mut values = vec![v];
    values.extend(f.values[v].uses.iter().copied().filter(|&u| matches!(f.op(u), Some(Op::PtrToInt | Op::IntToPtr | Op::BitCast))));

    let pointees: Vec<CType> = values
        .iter()
        .flat_map(|&value| f.values[value].uses.iter().map(move |&u| (value, u)))
        .filter_map(|(value, user)| match &f.values[user].kind {
            ValueKind::Inst { op: Op::Call, operands, callee: Some(callee), .. } => Some((value, operands, ctx.prototype(callee)?)),
            _ => None,
        })
        .flat_map(|(value, operands, prototype)| operands.iter().zip(prototype.ty.params.iter()).filter(move |(arg, _)| **arg == value).filter_map(|(_, param)| pointee(&ctx.resolve(&param.ty)).map(|p| ctx.resolve(p).unqualified().clone())))
        .collect();

    return pointees.iter().any(|p| matches!(p, CType::Char)) && !pointees.iter().any(|p| matches!(p, CType::Struct(_) | CType::Union(_)));
}

/// A type with a struct replaced by another
fn renamed(ty: &CType, from: &CType, to: &CType) -> CType {
    return match ty {
        t if t == from => to.clone(),
        CType::Pointer(inner) => CType::ptr(renamed(inner, from, to)),
        CType::Const(inner) => CType::Const(Box::new(renamed(inner, from, to))),
        other => other.clone(),
    };
}

/// Two layouts of the same struct: their fields that overlap are at the same offset, of the same size and of
/// compatible types (the same type, two pointers, two integers)
fn compatible(ctx: &Context, a: &Aggregate, b: &Aggregate) -> bool {
    let fields = |aggregate: &Aggregate| -> Vec<(u64, u64, CType)> {
        aggregate.fields.iter().filter(|f| !matches!(f.ty, CType::Array(..))).map(|f| (f.offset, ctx.size_of(&f.ty).unwrap_or(1).max(1), f.ty.clone())).collect()
    };

    let (a, b) = (fields(a), fields(b));

    return a.iter().all(|(offset, size, ty)| {
        b.iter().filter(|(o, s, _)| o < &(offset + size) && offset < &(o + s)).all(|(o, s, t)| {
            let integers = matches!((ctx.resolve(ty), ctx.resolve(t)), (CType::Int { .. } | CType::Char, CType::Int { .. } | CType::Char));
            o == offset && s == size && (t == ty || pointee(t).is_some() && pointee(ty).is_some() || integers)
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_without_overlaps() {
        let program = execdump_core::program::Program { pointer_size: 8, ..Default::default() };
        let typedb = crate::typedb::TypeDb::bundled(crate::typedb::Platform::Unix, crate::types::DataModel::new(execdump_core::disasm::Architecture::X86_64, false));
        let (globals, prototypes, noreturn) = (HashMap::default(), HashMap::default(), HashSet::default());
        let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None), structs: Default::default(), callees: Default::default(), imported: Default::default(), sized: Default::default(), language: &crate::lang::c::C };

        let types = vec![CType::ptr(CType::Char), CType::int(32), CType::int(64), CType::int(16), CType::int(128)];
        let access = |offset, bytes, value| Access { offset, bytes, value, address: false, known: None };
        let names = |aggregate: &Aggregate| -> Vec<(String, u64)> { aggregate.fields.iter().map(|f| (f.name.clone(), f.offset)).collect() };

        // The widest access at an offset, unless narrower ones are the fields it covers (a copy of two fields)
        let aggregate = layout(&ctx, &[access(8, 8, 0), access(16, 8, 2), access(24, 4, 1), access(24, 8, 2), access(28, 2, 3)], &types);
        assert_eq!(names(&aggregate), vec![("pad_0".to_string(), 0), ("f8".to_string(), 8), ("f10".to_string(), 16), ("f18".to_string(), 24), ("f1c".to_string(), 28)]);
        assert_eq!((aggregate.fields[2].ty.clone(), aggregate.fields[3].ty.clone()), (CType::int(64), CType::int(32)));
        assert_eq!((aggregate.size, aggregate.align, aggregate.pack), (32, 8, None));

        let copied = layout(&ctx, &[access(0, 16, 4), access(8, 8, 2)], &types);
        assert_eq!(names(&copied), vec![("f0".to_string(), 0), ("f8".to_string(), 8)]);
        assert_eq!(copied.fields[0].ty, CType::int(64));

        let packed = layout(&ctx, &[access(0, 1, 0), access(1, 8, 2)], &types);
        assert_eq!((packed.size, packed.pack), (9, Some(1)));
        assert_eq!(packed.fields[0].ty, CType::Char);
    }
}
