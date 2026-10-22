/*
 * DWARF debug information, format neutral: the functions (their names, prototypes and source files), the global
 * variables and the types of the compile units (base types, pointers, qualifiers, typedefs, structs, unions, enums,
 * arrays, function types), and the line table. The decompiler turns them into C declarations.
 *
 * The sections are given by name (.debug_info), already decompressed (see decompress). The types are read when a
 * function, a variable or another type refers to them, each once.
 */

use gimli::{AttributeValue, EndianSlice, Operation, RunTimeEndian, Unit, UnitOffset};

use std::borrow::Cow;
use std::collections::HashMap;

type R<'a> = EndianSlice<'a, RunTimeEndian>;
pub type TypeId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Signed,
    Unsigned,
    Float,
    Bool,
    Char,
    UnsignedChar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: Option<String>,
    pub offset: u64,
    pub ty: Option<TypeId>,
    /// Width of a bitfield
    pub bits: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugType {
    /// A type not read yet, or of a kind not described (pointers to members)
    Unknown,
    Base { name: String, size: u64, encoding: Encoding },
    /// None: void *
    Pointer(Option<TypeId>),
    Const(Option<TypeId>),
    Volatile(Option<TypeId>),
    Typedef { name: String, ty: Option<TypeId> },
    Aggregate { name: Option<String>, size: u64, members: Vec<Member>, union: bool, declaration: bool },
    Enum { name: Option<String>, size: u64, values: Vec<(String, i64)> },
    Array { ty: Option<TypeId>, count: Option<u64> },
    Function { ret: Option<TypeId>, params: Vec<Option<TypeId>>, variadic: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub name: Option<String>,
    pub ty: Option<TypeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugFunction {
    pub name: String,
    pub linkage_name: Option<String>,
    /// Entry and end of its code (its first range when it has several)
    pub low: u64,
    pub high: u64,
    /// None: void
    pub ret: Option<TypeId>,
    pub params: Vec<Parameter>,
    pub variadic: bool,
    pub noreturn: bool,
    /// The source file of its compile unit
    pub file: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugVariable {
    pub name: String,
    pub addr: u64,
    pub ty: Option<TypeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineRow {
    pub addr: u64,
    pub file: u32,
    pub line: u32,
}

#[derive(Clone, Debug, Default)]
pub struct DebugInfo {
    pub types: Vec<DebugType>,
    pub functions: Vec<DebugFunction>,
    pub variables: Vec<DebugVariable>,
    pub files: Vec<String>,
    /// Sorted by address
    pub lines: Vec<LineRow>,
}

impl DebugInfo {
    /// Source file and line of the code at an address
    pub fn line_at(&self, addr: u64) -> Option<(&str, u32)> {
        let index = self.lines.partition_point(|r| r.addr <= addr).checked_sub(1)?;
        let row = self.lines[index];
        return Some((self.files.get(row.file as usize)?.as_str(), row.line));
    }
}

/// The data of a compressed section (SHF_COMPRESSED with zlib, or .zdebug: "ZLIB" and the size, big endian)
pub fn decompress(data: &[u8], compressed: bool, is_64: bool, little_endian: bool) -> Option<Vec<u8>> {
    let read_u32 = |at: usize| data.get(at..at + 4).map(|b| if little_endian { u32::from_le_bytes(b.try_into().unwrap()) } else { u32::from_be_bytes(b.try_into().unwrap()) });

    let stream = if compressed {
        // Elf_Chdr: the type (1: zlib), the size and the alignment of the data
        if read_u32(0)? != 1 {
            return None;
        }

        data.get(if is_64 { 24 } else { 12 }..)?
    } else if data.starts_with(b"ZLIB") {
        data.get(12..)?
    } else {
        return Some(data.to_vec());
    };

    return miniz_oxide::inflate::decompress_to_vec_zlib(stream).ok();
}

/// Reads the debug information of the sections a function gives by name (.debug_info, .debug_abbrev...)
pub fn read<'s>(section: &dyn Fn(&str) -> Option<Cow<'s, [u8]>>, little_endian: bool) -> Option<DebugInfo> {
    let data: HashMap<&'static str, Cow<'s, [u8]>> = ALL_SECTIONS.iter().filter_map(|&id| section(id.name()).map(|d| (id.name(), d))).collect();

    if !data.contains_key(".debug_info") {
        return None;
    }

    let endian = if little_endian { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let empty: &[u8] = &[];
    let load = |id: gimli::SectionId| -> Result<R<'_>, gimli::Error> { Ok(EndianSlice::new(data.get(id.name()).map_or(empty, |d| d.as_ref()), endian)) };
    let dwarf = gimli::Dwarf::load(load).ok()?;

    let mut units = Vec::new();
    let mut headers = dwarf.units();

    while let Ok(Some(header)) = headers.next() {
        if let Ok(unit) = dwarf.unit(header) {
            units.push(unit);
        }
    }

    let mut reader = Reader { dwarf: &dwarf, units: &units, info: DebugInfo::default(), ids: HashMap::new(), files: HashMap::new() };

    for index in 0..units.len() {
        let _ = reader.read_unit(index);
        let _ = reader.read_lines(index);
    }

    let mut info = reader.info;
    info.lines.sort_by_key(|r| r.addr);
    info.functions.sort_by_key(|f| f.low);
    info.functions.dedup_by_key(|f| f.low);

    return Some(info);
}

const ALL_SECTIONS: [gimli::SectionId; 12] = [
    gimli::SectionId::DebugAbbrev,
    gimli::SectionId::DebugAddr,
    gimli::SectionId::DebugInfo,
    gimli::SectionId::DebugLine,
    gimli::SectionId::DebugLineStr,
    gimli::SectionId::DebugLoc,
    gimli::SectionId::DebugLocLists,
    gimli::SectionId::DebugRanges,
    gimli::SectionId::DebugRngLists,
    gimli::SectionId::DebugStr,
    gimli::SectionId::DebugStrOffsets,
    gimli::SectionId::DebugTypes,
];

type Entry<'a, 'b, 'c> = gimli::DebuggingInformationEntry<'b, 'c, R<'a>>;

struct Reader<'a, 'u> {
    dwarf: &'u gimli::Dwarf<R<'a>>,
    units: &'u [Unit<R<'a>>],
    info: DebugInfo,
    /// Type of a DIE: its unit and its offset there
    ids: HashMap<(usize, UnitOffset), TypeId>,
    files: HashMap<String, u32>,
}

impl<'a> Reader<'a, '_> {
    fn string(&self, unit: usize, entry: &Entry<'a, '_, '_>, name: gimli::DwAt) -> Option<String> {
        let value = entry.attr_value(name).ok()??;
        let text = self.dwarf.attr_string(&self.units[unit], value).ok()?;
        return Some(text.to_string_lossy().into_owned());
    }

    fn udata(entry: &Entry<'a, '_, '_>, name: gimli::DwAt) -> Option<u64> {
        return entry.attr_value(name).ok()??.udata_value();
    }

    fn flag(entry: &Entry<'a, '_, '_>, name: gimli::DwAt) -> bool {
        return matches!(entry.attr_value(name), Ok(Some(AttributeValue::Flag(true))));
    }

    /// The DIE an attribute refers to: its unit and its offset there
    fn reference(&self, unit: usize, entry: &Entry<'a, '_, '_>, name: gimli::DwAt) -> Option<(usize, UnitOffset)> {
        return match entry.attr_value(name).ok()?? {
            AttributeValue::UnitRef(offset) => Some((unit, offset)),
            AttributeValue::DebugInfoRef(offset) => self.units.iter().enumerate().find_map(|(i, u)| offset.to_unit_offset(&u.header).map(|o| (i, o))),
            _ => None,
        };
    }

    fn type_of(&mut self, unit: usize, entry: &Entry<'a, '_, '_>) -> Option<TypeId> {
        let (unit, offset) = self.reference(unit, entry, gimli::DW_AT_type)?;
        return self.type_at(unit, offset);
    }

    /// The type of a DIE, read once (the types that refer to themselves get their id before their content)
    fn type_at(&mut self, unit: usize, offset: UnitOffset) -> Option<TypeId> {
        if let Some(&id) = self.ids.get(&(unit, offset)) {
            return Some(id);
        }

        let id = self.info.types.len();
        self.info.types.push(DebugType::Unknown);
        self.ids.insert((unit, offset), id);

        let units = self.units;
        let mut tree = units[unit].entries_tree(Some(offset)).ok()?;
        let node = tree.root().ok()?;
        let entry = node.entry().clone();
        let name = self.string(unit, &entry, gimli::DW_AT_name);
        let size = Self::udata(&entry, gimli::DW_AT_byte_size).unwrap_or(0);

        let ty = match entry.tag() {
            gimli::DW_TAG_base_type => {
                let encoding = match entry.attr_value(gimli::DW_AT_encoding).ok().flatten() {
                    Some(AttributeValue::Encoding(gimli::DW_ATE_float)) => Encoding::Float,
                    Some(AttributeValue::Encoding(gimli::DW_ATE_boolean)) => Encoding::Bool,
                    Some(AttributeValue::Encoding(gimli::DW_ATE_signed_char)) => Encoding::Char,
                    Some(AttributeValue::Encoding(gimli::DW_ATE_unsigned_char)) => Encoding::UnsignedChar,
                    Some(AttributeValue::Encoding(gimli::DW_ATE_unsigned | gimli::DW_ATE_UTF)) => Encoding::Unsigned,
                    _ => Encoding::Signed,
                };

                DebugType::Base { name: name.unwrap_or_default(), size, encoding }
            }
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => DebugType::Pointer(self.type_of(unit, &entry)),
            gimli::DW_TAG_const_type => DebugType::Const(self.type_of(unit, &entry)),
            gimli::DW_TAG_volatile_type => DebugType::Volatile(self.type_of(unit, &entry)),
            // Qualifiers that do not change the type in the C
            gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type | gimli::DW_TAG_immutable_type => {
                let inner = self.type_of(unit, &entry);
                inner.map_or(DebugType::Unknown, |i| self.info.types[i].clone())
            }
            gimli::DW_TAG_typedef => DebugType::Typedef { name: name.unwrap_or_default(), ty: self.type_of(unit, &entry) },
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                let mut members = Vec::new();
                let mut children = node.children();

                while let Ok(Some(child)) = children.next() {
                    let member = child.entry().clone();

                    if !matches!(member.tag(), gimli::DW_TAG_member | gimli::DW_TAG_inheritance) || Self::flag(&member, gimli::DW_AT_external) || Self::flag(&member, gimli::DW_AT_declaration) {
                        continue;
                    }

                    let bits = Self::udata(&member, gimli::DW_AT_bit_size).map(|b| b as u16);
                    let offset = match member.attr_value(gimli::DW_AT_data_member_location).ok().flatten() {
                        Some(AttributeValue::Exprloc(expr)) => match expr.operations(units[unit].encoding()).next() {
                            Ok(Some(Operation::PlusConstant { value })) => value,
                            _ => 0,
                        },
                        Some(value) => value.udata_value().unwrap_or(0),
                        None => Self::udata(&member, gimli::DW_AT_data_bit_offset).map_or(0, |b| b / 8),
                    };

                    let name = match member.tag() {
                        gimli::DW_TAG_inheritance => Some(format!("base_{}", members.len())),
                        _ => self.string(unit, &member, gimli::DW_AT_name),
                    };

                    let ty = self.type_of(unit, &member);
                    members.push(Member { name, offset, ty, bits });
                }

                DebugType::Aggregate { name, size, members, union: entry.tag() == gimli::DW_TAG_union_type, declaration: Self::flag(&entry, gimli::DW_AT_declaration) }
            }
            gimli::DW_TAG_enumeration_type => {
                let mut values = Vec::new();
                let mut children = node.children();

                while let Ok(Some(child)) = children.next() {
                    let value = child.entry().clone();

                    if value.tag() != gimli::DW_TAG_enumerator {
                        continue;
                    }

                    let number = match value.attr_value(gimli::DW_AT_const_value).ok().flatten() {
                        Some(AttributeValue::Sdata(v)) => v,
                        Some(other) => other.udata_value().map_or(0, |v| v as i64),
                        None => 0,
                    };

                    values.push((self.string(unit, &value, gimli::DW_AT_name).unwrap_or_default(), number));
                }

                DebugType::Enum { name, size: if size == 0 { 4 } else { size }, values }
            }
            gimli::DW_TAG_array_type => {
                let element = self.type_of(unit, &entry);
                let mut dimensions = Vec::new();
                let mut children = node.children();

                while let Ok(Some(child)) = children.next() {
                    let range = child.entry();

                    if range.tag() != gimli::DW_TAG_subrange_type {
                        continue;
                    }

                    let count = Self::udata(range, gimli::DW_AT_count).or_else(|| Self::udata(range, gimli::DW_AT_upper_bound).map(|u| u + 1));
                    dimensions.push(count);
                }

                // int a[2][3] is an array of 2 arrays of 3
                let mut ty = element;

                for count in dimensions.iter().skip(1).rev() {
                    self.info.types.push(DebugType::Array { ty, count: *count });
                    ty = Some(self.info.types.len() - 1);
                }

                DebugType::Array { ty, count: dimensions.first().copied().flatten() }
            }
            gimli::DW_TAG_subroutine_type => {
                let ret = self.type_of(unit, &entry);
                let mut params = Vec::new();
                let mut variadic = false;
                let mut children = node.children();

                while let Ok(Some(child)) = children.next() {
                    let param = child.entry().clone();

                    match param.tag() {
                        gimli::DW_TAG_formal_parameter => params.push(self.type_of(unit, &param)),
                        gimli::DW_TAG_unspecified_parameters => variadic = true,
                        _ => {}
                    }
                }

                DebugType::Function { ret, params, variadic }
            }
            _ => DebugType::Unknown,
        };

        self.info.types[id] = ty;
        return Some(id);
    }

    /// The entry with the name, the type and the parameters of a function or a variable: itself, or the declaration it
    /// completes (C++ members) or the abstract one it is an instance of (inlining)
    fn origin(&self, unit: usize, entry: &Entry<'a, '_, '_>) -> Option<(usize, UnitOffset)> {
        return self.reference(unit, entry, gimli::DW_AT_abstract_origin).or_else(|| self.reference(unit, entry, gimli::DW_AT_specification));
    }

    /// The functions and the variables of a unit, of its namespaces and classes
    fn read_unit(&mut self, unit: usize) -> gimli::Result<()> {
        let units = self.units;
        let file = units[unit].name.map(|n| n.to_string_lossy().into_owned());
        let mut tree = units[unit].entries_tree(None)?;
        return self.read_scope(unit, tree.root()?, file);
    }

    fn read_scope(&mut self, unit: usize, node: gimli::EntriesTreeNode<'_, '_, '_, R<'a>>, file: Option<String>) -> gimli::Result<()> {
        let mut children = node.children();

        while let Some(child) = children.next()? {
            let entry = child.entry().clone();

            match entry.tag() {
                gimli::DW_TAG_subprogram => self.read_function(unit, &entry, &child, file.clone()),
                gimli::DW_TAG_variable => self.read_variable(unit, &entry),
                gimli::DW_TAG_namespace | gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => self.read_scope(unit, child, file.clone())?,
                _ => {}
            }
        }

        return Ok(());
    }

    fn read_function(&mut self, unit: usize, entry: &Entry<'a, '_, '_>, node: &gimli::EntriesTreeNode<'_, '_, '_, R<'a>>, file: Option<String>) {
        let units = self.units;
        let dwarf = self.dwarf;

        let low = match entry.attr_value(gimli::DW_AT_low_pc) {
            Ok(Some(value)) => dwarf.attr_address(&units[unit], value).ok().flatten(),
            _ => None,
        };

        let (low, high) = match low {
            Some(low) => {
                let high = match entry.attr_value(gimli::DW_AT_high_pc) {
                    Ok(Some(AttributeValue::Udata(size))) => low + size,
                    Ok(Some(value)) => dwarf.attr_address(&units[unit], value).ok().flatten().unwrap_or(low),
                    _ => low,
                };

                (low, high)
            }
            // Functions split in parts (hot and cold): their first range
            None => {
                let Ok(mut ranges) = dwarf.die_ranges(&units[unit], entry) else {
                    return;
                };

                match ranges.next() {
                    Ok(Some(range)) => (range.begin, range.end),
                    _ => return,
                }
            }
        };

        if low == 0 || Self::flag(entry, gimli::DW_AT_declaration) {
            return;
        }

        // The name, the type and the parameters of the declaration the definition completes, or of the abstract
        // function this one is an instance of
        let origin = self.origin(unit, entry).and_then(|(u, o)| {
            let found = units[u].entry(o).ok()?;
            let further = self.origin(u, &found).and_then(|(u2, o2)| units[u2].entry(o2).ok().map(|e| (u2, e)));
            Some(((u, found), further))
        });

        let named = |reader: &Self, attr: gimli::DwAt| {
            reader.string(unit, entry, attr).or_else(|| origin.as_ref().and_then(|((u, e), further)| reader.string(*u, e, attr).or_else(|| further.as_ref().and_then(|(u2, e2)| reader.string(*u2, e2, attr)))))
        };

        let Some(name) = named(self, gimli::DW_AT_name) else {
            return;
        };

        let linkage_name = named(self, gimli::DW_AT_linkage_name).or_else(|| named(self, gimli::DW_AT_MIPS_linkage_name));
        let noreturn = Self::flag(entry, gimli::DW_AT_noreturn) || origin.as_ref().is_some_and(|((_, e), _)| Self::flag(e, gimli::DW_AT_noreturn));

        let ret = match entry.attr_value(gimli::DW_AT_type) {
            Ok(Some(_)) => self.type_of(unit, entry),
            _ => origin.as_ref().and_then(|((u, e), further)| {
                let (u, e) = if e.attr_value(gimli::DW_AT_type).ok().flatten().is_some() { (*u, e.clone()) } else { further.clone()? };
                self.type_of(u, &e)
            }),
        };

        let (mut params, mut variadic) = self.parameters(unit, node.entry().offset());

        // An instance without its parameters described: the ones of its declaration
        if let Some(((u, e), _)) = origin.as_ref().filter(|_| params.is_empty()) {
            (params, variadic) = self.parameters(*u, e.offset());
        }

        self.info.functions.push(DebugFunction { name, linkage_name, low, high, ret, params, variadic, noreturn, file });
    }

    fn parameters(&mut self, unit: usize, offset: UnitOffset) -> (Vec<Parameter>, bool) {
        let units = self.units;
        let mut params = Vec::new();
        let mut variadic = false;

        let Ok(mut tree) = units[unit].entries_tree(Some(offset)) else {
            return (params, variadic);
        };

        let Ok(root) = tree.root() else {
            return (params, variadic);
        };

        let mut children = root.children();

        while let Ok(Some(child)) = children.next() {
            let param = child.entry().clone();

            match param.tag() {
                gimli::DW_TAG_formal_parameter => {
                    let origin = self.origin(unit, &param).and_then(|(u, o)| units[u].entry(o).ok().map(|e| (u, e)));
                    let name = self.string(unit, &param, gimli::DW_AT_name).or_else(|| origin.as_ref().and_then(|(u, e)| self.string(*u, e, gimli::DW_AT_name)));

                    let ty = match param.attr_value(gimli::DW_AT_type) {
                        Ok(Some(_)) => self.type_of(unit, &param),
                        _ => origin.as_ref().and_then(|(u, e)| self.type_of(*u, e)),
                    };

                    params.push(Parameter { name, ty });
                }
                gimli::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }

        return (params, variadic);
    }

    fn read_variable(&mut self, unit: usize, entry: &Entry<'a, '_, '_>) {
        let units = self.units;

        let Ok(Some(AttributeValue::Exprloc(expression))) = entry.attr_value(gimli::DW_AT_location) else {
            return;
        };

        let addr = match expression.operations(units[unit].encoding()).next() {
            Ok(Some(Operation::Address { address })) => address,
            Ok(Some(Operation::AddressIndex { index })) => match self.dwarf.address(&units[unit], index) {
                Ok(address) => address,
                Err(_) => return,
            },
            _ => return,
        };

        let origin = self.reference(unit, entry, gimli::DW_AT_specification).and_then(|(u, o)| units[u].entry(o).ok().map(|e| (u, e)));
        let name = self.string(unit, entry, gimli::DW_AT_name).or_else(|| origin.as_ref().and_then(|(u, e)| self.string(*u, e, gimli::DW_AT_name)));

        let ty = match entry.attr_value(gimli::DW_AT_type) {
            Ok(Some(_)) => self.type_of(unit, entry),
            _ => origin.as_ref().and_then(|(u, e)| self.type_of(*u, e)),
        };

        if let Some(name) = name.filter(|_| addr != 0) {
            self.info.variables.push(DebugVariable { name, addr, ty });
        }
    }

    fn read_lines(&mut self, unit: usize) -> gimli::Result<()> {
        let units = self.units;

        let Some(program) = units[unit].line_program.clone() else {
            return Ok(());
        };

        let mut rows = program.rows();
        let mut file_ids: HashMap<u64, u32> = HashMap::new();

        while let Some((header, row)) = rows.next_row()? {
            if row.end_sequence() || !row.is_stmt() {
                continue;
            }

            let Some(line) = row.line() else {
                continue;
            };

            let file = match file_ids.get(&row.file_index()) {
                Some(&id) => id,
                None => {
                    let path = header.file(row.file_index()).map(|f| {
                        let name = self.dwarf.attr_string(&units[unit], f.path_name()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                        let directory = f.directory(header).and_then(|d| self.dwarf.attr_string(&units[unit], d).ok()).map(|s| s.to_string_lossy().into_owned());

                        match directory {
                            Some(directory) if !name.starts_with('/') && !directory.is_empty() => format!("{}/{}", directory, name),
                            _ => name,
                        }
                    });

                    let path = path.unwrap_or_default();
                    let next = self.files.len() as u32;
                    let id = *self.files.entry(path.clone()).or_insert(next);

                    if id == next {
                        self.info.files.push(path);
                    }

                    file_ids.insert(row.file_index(), id);
                    id
                }
            };

            self.info.lines.push(LineRow { addr: row.address(), file, line: line.get() as u32 });
        }

        return Ok(());
    }
}
