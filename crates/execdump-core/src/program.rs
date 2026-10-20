/*
 * Program: a format-agnostic view of an executable (memory map, symbols, imports, function hints)
 * built once from the parsed PE/ELF/Mach-O and used by the analysis and the TUI.
 */

use crate::demangle::{demangle, detect_mangling_scheme, ManglingScheme};
use crate::disasm::Architecture;
use crate::eh_frame::parse_eh_frame;
use crate::elf::{ELF, ELFFileType, SectionFlags as ELFSectionFlags, SectionType as ELFSectionType, SymbolBinding, SymbolType as ELFSymbolType, SHN_UNDEF};
use crate::exec::Exec;
use crate::macho::{MachOBinary, SectionType as MachOSectionType};
use crate::pe::{ExcFunctionEntry, SectionFlags as PESectionFlags, PE};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Perms {
    pub fn as_string(&self) -> String {
        return format!(
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' },
        );
    }
}

/// A contiguous piece of the address space (usually a section)
#[derive(Clone, Debug, Default)]
pub struct Region {
    pub name: String,
    pub vaddr: u64,
    /// Size in memory, can be greater than data.len() (zero-filled sections)
    pub size: u64,
    pub data: Vec<u8>,
    pub perms: Perms,
}

impl Region {
    pub fn end(&self) -> u64 {
        return self.vaddr + self.size;
    }

    pub fn contains(&self, addr: u64) -> bool {
        return addr >= self.vaddr && addr < self.end();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SymbolKind {
    Function,
    Import,
    Object,
    Label,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub addr: u64,
    pub name: String,
    pub demangled: String,
    pub kind: SymbolKind,
    pub size: u64,
}

impl Symbol {
    pub fn new(addr: u64, name: &str, kind: SymbolKind, size: u64) -> Self {
        return Self {
            addr,
            name: name.to_string(),
            demangled: demangle(name).unwrap_or(name.to_string()),
            kind,
            size,
        };
    }
}

/// Where a function start hint comes from, ordered by reliability
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeedSource {
    Entry,
    Export,
    Symbol,
    /// The function table of the Go runtime
    GoPclntab,
    ExceptionTable,
    FunctionStarts,
    EhFrame,
    InitArray,
}

impl SeedSource {
    pub fn name(&self) -> &'static str {
        match self {
            SeedSource::Entry => "entry",
            SeedSource::Export => "export",
            SeedSource::Symbol => "symbol",
            SeedSource::GoPclntab => "go pclntab",
            SeedSource::ExceptionTable => "exception table",
            SeedSource::FunctionStarts => "function starts",
            SeedSource::EhFrame => "eh_frame",
            SeedSource::InitArray => "init array",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FunctionSeed {
    pub addr: u64,
    pub size: Option<u64>,
    pub source: SeedSource,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Elf,
    Pe,
    MachO,
}

/// Language the program was written in, when it changes how its data is laid out
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    #[default]
    Unknown,
    Rust,
    Go,
    /// A .NET assembly: its code is CIL bytecode in the CLR metadata, the machine code is the stub that starts the runtime
    DotNet,
}

impl Language {
    /// Strings are a pointer and a length (&str, Go strings), not NUL terminated
    pub fn has_sized_strings(self) -> bool {
        return matches!(self, Language::Rust | Language::Go);
    }
}

/// Longest string a (pointer, length) pair is taken for
pub const MAX_SIZED_STRING: u64 = 4096;

/// Valid UTF-8 text without control characters other than tabs and line breaks
pub fn is_text(bytes: &[u8]) -> bool {
    return std::str::from_utf8(bytes).is_ok_and(|text| text.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')));
}

#[derive(Clone, Debug, Default)]
pub struct Program {
    /// Short description, e.g. "ELF x86_64"
    pub name: String,
    pub format: Format,
    pub arch: Option<Architecture>,
    pub pointer_size: u8,
    pub big_endian: bool,
    pub entry: Option<u64>,
    /// Regions sorted by address
    pub regions: Vec<Region>,
    pub symbols: BTreeMap<u64, Symbol>,
    /// Pointer slots filled by the loader (GOT, IAT, Mach-O symbol pointers), slot address -> imported name
    pub import_slots: HashMap<u64, String>,
    pub seeds: Vec<FunctionSeed>,
    /// Source file of the local symbols, from the ELF FILE symbols preceding them (address -> file name)
    pub source_files: BTreeMap<u64, String>,
    /// Source files named by the symbol tables, in their order
    pub source_names: Vec<String>,
    pub language: Language,
    /// Go programs: the arguments and the results are passed in registers (Go 1.17 and later), else on the stack
    pub go_register_abi: bool,
    /// Go programs: the size of the arguments and results of the functions (by entry), as the pclntab gives it (not for
    /// the functions known to be written in assembly)
    pub go_args: HashMap<u64, u32>,
    /// Data the format puts in the sections of code (the import tables, the CLR header and metadata of PE), sorted
    pub data: Vec<(u64, u64)>,
    /// Strings the data points to with (pointer, length) pairs (tables of &str, panic locations), address ->
    /// length. Only for the languages whose strings are not NUL terminated.
    pub sized_strings: BTreeMap<u64, u64>,
}

impl Program {
    pub fn architecture(&self) -> Architecture {
        return self.arch.unwrap_or(Architecture::Unsupported);
    }

    pub fn region_at(&self, addr: u64) -> Option<&Region> {
        let idx = self.regions.partition_point(|r| r.vaddr <= addr);

        // Regions can overlap (ELF .tbss for example), look back a few regions, the ones with data first
        let mut candidates = self.regions[..idx].iter().rev().take(4).filter(|r| r.contains(addr));
        let first = candidates.next()?;

        if !first.data.is_empty() {
            return Some(first);
        }

        return candidates.find(|r| !r.data.is_empty()).or(Some(first));
    }

    pub fn is_executable(&self, addr: u64) -> bool {
        return self.region_at(addr).map_or(false, |r| r.perms.exec && !r.data.is_empty());
    }

    /// Data of the format in a section of code: not code, even when an instruction refers to it
    pub fn is_data(&self, addr: u64) -> bool {
        let index = self.data.partition_point(|&(start, _)| start <= addr);
        return index > 0 && addr < self.data[index - 1].1;
    }

    /// Returns the bytes from addr to the end of the region containing it
    pub fn bytes_from(&self, addr: u64) -> Option<&[u8]> {
        let region = self.region_at(addr)?;
        let offset = (addr - region.vaddr) as usize;

        return region.data.get(offset..);
    }

    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        return self.bytes_from(addr)?.get(..len);
    }

    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let bytes: [u8; 2] = self.read(addr, 2)?.try_into().ok()?;
        return Some(if self.big_endian { u16::from_be_bytes(bytes) } else { u16::from_le_bytes(bytes) });
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let bytes: [u8; 4] = self.read(addr, 4)?.try_into().ok()?;
        return Some(if self.big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) });
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let bytes: [u8; 8] = self.read(addr, 8)?.try_into().ok()?;
        return Some(if self.big_endian { u64::from_be_bytes(bytes) } else { u64::from_le_bytes(bytes) });
    }

    pub fn read_pointer(&self, addr: u64) -> Option<u64> {
        if self.pointer_size == 4 {
            return self.read_u32(addr).map(|v| v as u64);
        }

        return self.read_u64(addr);
    }

    /// Bytes of the NUL terminated string at an address (without the NUL)
    pub fn c_string_bytes(&self, addr: u64, max_len: usize) -> Option<&[u8]> {
        let bytes = self.bytes_from(addr)?;
        let bytes = &bytes[..bytes.len().min(max_len)];
        let nul = bytes.iter().position(|&b| b == 0)?;

        return Some(&bytes[..nul]);
    }

    /// Read-only data (not code) of at least len bytes at an address
    pub fn constant_bytes(&self, addr: u64, len: u64) -> Option<&[u8]> {
        let region = self.region_at(addr).filter(|r| !r.perms.write && !r.perms.exec && !r.data.is_empty())?;
        let offset = (addr - region.vaddr) as usize;
        return region.data.get(offset..offset.checked_add(len as usize)?);
    }

    /// Text of len bytes of read-only data, the string of a (pointer, length) pair
    pub fn sized_string(&self, addr: u64, len: u64) -> Option<&[u8]> {
        if len == 0 || len > MAX_SIZED_STRING {
            return None;
        }

        return self.constant_bytes(addr, len).filter(|bytes| is_text(bytes));
    }

    pub fn read_c_string(&self, addr: u64, max_len: usize) -> Option<String> {
        let bytes = self.bytes_from(addr)?;
        let bytes = &bytes[..bytes.len().min(max_len)];
        let nul = bytes.iter().position(|&b| b == 0)?;

        return Some(String::from_utf8_lossy(&bytes[..nul]).to_string());
    }

    pub fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
        return self.symbols.get(&addr);
    }

    /// Returns the closest symbol at or before addr within the same region, and the offset from it
    pub fn symbol_near(&self, addr: u64) -> Option<(&Symbol, u64)> {
        let (_, symbol) = self.symbols.range((Bound::Unbounded, Bound::Included(addr))).next_back()?;

        if symbol.size > 0 && addr >= symbol.addr + symbol.size {
            return None;
        }

        let region = self.region_at(addr)?;

        if !region.contains(symbol.addr) {
            return None;
        }

        return Some((symbol, addr - symbol.addr));
    }

    fn add_symbol(&mut self, symbol: Symbol) {
        if symbol.name.is_empty() {
            return;
        }

        match self.symbols.get(&symbol.addr) {
            // Keep the "best" symbol for an address: functions/imports over objects/labels, global names over local ones
            Some(existing) if existing.kind <= symbol.kind => {}
            _ => {
                self.symbols.insert(symbol.addr, symbol);
            }
        }
    }

    fn add_seed(&mut self, addr: u64, size: Option<u64>, source: SeedSource) {
        if addr != 0 {
            self.seeds.push(FunctionSeed { addr, size, source });
        }
    }

    fn finalize(&mut self) {
        // The name breaks the ties: overlapping regions (TLS sections) are found in the same order every time
        self.regions.sort_by(|a, b| (a.vaddr, a.size, &a.name).cmp(&(b.vaddr, b.size, &b.name)));

        if let Some(go) = crate::golang::read(self) {
            self.language = Language::Go;
            self.go_register_abi = go.register_abi;
            self.add_go_functions(go.functions);
        }

        if self.language == Language::Unknown && self.is_rust() {
            self.language = Language::Rust;
        }

        if self.language.has_sized_strings() {
            self.sized_strings = self.scan_sized_strings();
        }

        let mut seen = HashSet::new();
        self.seeds.sort_by_key(|s| (s.source, s.addr));
        self.seeds.retain(|s| seen.insert(s.addr));

        let seeds = std::mem::take(&mut self.seeds);
        self.seeds = seeds.into_iter().filter(|s| self.is_executable(s.addr)).collect();

        if let Some(entry) = self.entry {
            if !self.symbols.contains_key(&entry) {
                self.add_symbol(Symbol::new(entry, "entry0", SymbolKind::Function, 0));
            }
        }
    }
}

/*
 * Languages
 */

/// Paths of the standard library in the panic locations every Rust binary keeps, stripped or not
const RUST_MARKERS: [&[u8]; 3] = [b"/rustc/", b"library/core/src/", b"library/std/src/"];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };

    let mut from = 0;

    while let Some(position) = haystack[from..].iter().position(|&b| b == first) {
        let start = from + position;

        if haystack[start + 1..].starts_with(rest) {
            return true;
        }

        from = start + 1;
    }

    return false;
}

impl Program {
    /// A Rust symbol (legacy with its hash, or v0 that demangles), or the paths of the standard library in the
    /// read-only data
    fn is_rust(&self) -> bool {
        let rust_symbol = |s: &Symbol| match detect_mangling_scheme(&s.name) {
            ManglingScheme::RustLegacy => true,
            ManglingScheme::RustV0 => s.demangled != s.name,
            _ => false,
        };

        if self.symbols.values().any(rust_symbol) {
            return true;
        }

        return self.regions.iter().filter(|r| !r.perms.exec && !r.perms.write).any(|r| RUST_MARKERS.iter().any(|marker| contains(&r.data, marker)));
    }

    /// The functions of the Go runtime table: symbols (their names stay when the binary is stripped), seeds with
    /// their size, and the source file of each
    fn add_go_functions(&mut self, functions: Vec<crate::golang::GoFunction>) {
        for function in functions {
            if let Some(args) = function.args.filter(|_| !function.assembly) {
                self.go_args.insert(function.entry, args);
            }

            self.add_symbol(Symbol::new(function.entry, &function.name, SymbolKind::Function, function.end - function.entry));
            self.add_seed(function.entry, Some(function.end - function.entry), SeedSource::GoPclntab);

            if let Some(file) = function.file {
                if !self.source_names.contains(&file) {
                    self.source_names.push(file.clone());
                }

                self.source_files.entry(function.entry).or_insert(file);
            }
        }
    }

    /// (pointer, length) pairs of the data whose pointer is to read-only text of that length
    fn scan_sized_strings(&self) -> BTreeMap<u64, u64> {
        let size = self.pointer_size.max(4) as u64;
        let mut strings = BTreeMap::new();

        for region in self.regions.iter().filter(|r| !r.perms.exec && !r.data.is_empty()) {
            let start = region.vaddr.next_multiple_of(size);
            let mut slot = start;

            while slot + 2 * size <= region.vaddr + region.data.len() as u64 {
                let (Some(pointer), Some(len)) = (self.read_pointer(slot), self.read_pointer(slot + size)) else {
                    break;
                };

                if len > 0 && len <= MAX_SIZED_STRING && self.sized_string(pointer, len).is_some() {
                    let known = strings.entry(pointer).or_insert(len);
                    *known = (*known).max(len);
                    slot += 2 * size;
                    continue;
                }

                slot += size;
            }
        }

        return strings;
    }
}

/*
 * ELF
 */

/// What the loader writes in the slot of a relocation
#[derive(Clone, Copy, PartialEq)]
enum Relocated {
    /// The load address plus the addend
    Relative,
    /// The address of the symbol, plus the addend for the absolute ones
    Symbol { absolute: bool },
}

fn relocated(machine: u16, r_type: u32) -> Option<Relocated> {
    use crate::elf::ELFTargetISA;

    let symbol = |absolute: bool| Some(Relocated::Symbol { absolute });

    return match (ELFTargetISA::from_repr(machine)?, r_type) {
        (ELFTargetISA::AMDX86_64 | ELFTargetISA::X86, 8) | (ELFTargetISA::Arm64bits, 1027) | (ELFTargetISA::Arm, 23) => Some(Relocated::Relative),
        (ELFTargetISA::AMDX86_64 | ELFTargetISA::X86, 1) | (ELFTargetISA::Arm64bits, 257) | (ELFTargetISA::Arm, 2) => symbol(true),
        (ELFTargetISA::AMDX86_64 | ELFTargetISA::X86, 6 | 7) | (ELFTargetISA::Arm64bits, 1025 | 1026) | (ELFTargetISA::Arm, 21 | 22) => symbol(false),
        _ => None,
    };
}

/// Writes the pointers the loader writes at the load address of the file: the relative ones (PIE pointer
/// tables, the GOT slots of the local functions) and the ones to the symbols the file defines. The slots of
/// the imports stay as they are.
fn apply_relocations(program: &mut Program, elf: &ELF) {
    let size = program.pointer_size as usize;

    for table in elf.relocation_tables.iter() {
        for reloc in table.relocations.iter() {
            let Some(kind) = relocated(table.machine, reloc.relocation_type(&table.class)) else {
                continue;
            };

            let Some(region) = program.regions.iter_mut().find(|r| r.contains(reloc.r_offset) && !r.data.is_empty()) else {
                continue;
            };

            let offset = (reloc.r_offset - region.vaddr) as usize;

            let Some(slot) = region.data.get_mut(offset..offset + size) else {
                continue;
            };

            let in_place = match size {
                4 if program.big_endian => u32::from_be_bytes(slot.try_into().unwrap()) as i64,
                4 => u32::from_le_bytes(slot.try_into().unwrap()) as i32 as i64,
                _ if program.big_endian => u64::from_be_bytes(slot.try_into().unwrap()) as i64,
                _ => u64::from_le_bytes(slot.try_into().unwrap()) as i64,
            };

            // The relocations without addend have it in place
            let addend = reloc.r_addend.unwrap_or(in_place);

            let value = match kind {
                Relocated::Relative => addend as u64,
                Relocated::Symbol { absolute } => match reloc.symbol_value {
                    Some(value) if absolute => value.wrapping_add(addend as u64),
                    Some(value) => value.wrapping_add(reloc.r_addend.unwrap_or(0) as u64),
                    None => continue,
                },
            };

            match size {
                4 if program.big_endian => slot.copy_from_slice(&(value as u32).to_be_bytes()),
                4 => slot.copy_from_slice(&(value as u32).to_le_bytes()),
                _ if program.big_endian => slot.copy_from_slice(&value.to_be_bytes()),
                _ => slot.copy_from_slice(&value.to_le_bytes()),
            }
        }
    }
}

fn program_from_elf(elf: &ELF) -> Program {
    let mut program = Program::default();

    program.arch = Some(elf.architecture());
    program.pointer_size = if matches!(elf.class(), crate::elf::ELFClass::ELF32) { 4 } else { 8 };
    program.big_endian = elf.is_big_endian();
    program.name = format!("ELF {:?}", elf.architecture());

    let relocatable = matches!(elf.get_elf_header().file_type(), ELFFileType::ETRel);

    let mut sections: Vec<_> = elf.sections.values()
        .filter(|s| (s.header.flags() & ELFSectionFlags::Alloc as u64) != 0 && s.size() > 0)
        .collect();

    sections.sort_by(|a, b| (a.offset(), a.header.virtual_address(), &a.name).cmp(&(b.offset(), b.header.virtual_address(), &b.name)));

    // Relocatable objects have all their sections at address 0, lay them out one after the other
    let mut next_address = 0u64;

    for section in sections.iter() {
        let flags = section.header.flags();
        let vaddr = if relocatable { next_address.next_multiple_of(16) } else { section.header.virtual_address() };

        next_address = vaddr + section.size();

        program.regions.push(Region {
            name: section.name.clone(),
            vaddr,
            size: section.size(),
            data: if section.header.section_type() == ELFSectionType::Nobits { Vec::new() } else { section.data.clone() },
            perms: Perms {
                read: true,
                write: (flags & ELFSectionFlags::Write as u64) != 0,
                exec: (flags & ELFSectionFlags::ExecInstr as u64) != 0,
            },
        });
    }

    // No section headers (stripped with sstrip for example), fall back on the loadable segments
    if program.regions.is_empty() {
        for (i, ph) in elf.headers.program_headers.iter().enumerate() {
            if ph.program_type() != crate::elf::ProgramHeaderType::Load || ph.memory_size() == 0 {
                continue;
            }

            let flags = ph.flags();
            let file_start = ph.offset() as usize;
            let file_end = file_start + ph.file_size() as usize;

            program.regions.push(Region {
                name: format!("segment.{}", i),
                vaddr: ph.virtual_address(),
                size: ph.memory_size(),
                data: elf.raw.get(file_start..file_end).map_or(Vec::new(), |d| d.to_vec()),
                perms: Perms { read: flags & 0x4 != 0, write: flags & 0x2 != 0, exec: flags & 0x1 != 0 },
            });
        }
    }

    if !relocatable {
        let entry = elf.get_elf_header().entry();

        if entry != 0 {
            program.entry = Some(entry);
            program.add_seed(entry, None, SeedSource::Entry);
        }
    }

    program.regions.sort_by_key(|r| r.vaddr);

    if !relocatable {
        for table in elf.symbol_tables.iter() {
            // Local symbols follow the FILE symbol of their object file
            let mut file: Option<&str> = None;

            for symbol in table.symbols.iter() {
                if symbol.symbol_type() == Some(ELFSymbolType::File) {
                    file = Some(symbol.name.as_str()).filter(|n| !n.is_empty());

                    if let Some(name) = file.filter(|n| !program.source_names.iter().any(|s| s == n)) {
                        program.source_names.push(name.to_string());
                    }

                    continue;
                }

                if symbol.binding() == Some(SymbolBinding::Local) && symbol.st_value != 0 && symbol.st_shndx != SHN_UNDEF {
                    if let Some(file) = file {
                        program.source_files.entry(symbol.st_value).or_insert_with(|| file.to_string());
                    }
                }

                if symbol.st_shndx == SHN_UNDEF || symbol.st_value == 0 || symbol.name.is_empty() || symbol.name.starts_with('$') {
                    continue;
                }

                let in_code = program.is_executable(symbol.st_value);

                let kind = match symbol.symbol_type() {
                    Some(ELFSymbolType::Func | ELFSymbolType::GnuIFunc) => SymbolKind::Function,
                    Some(ELFSymbolType::Object | ELFSymbolType::Tls | ELFSymbolType::Common) => SymbolKind::Object,
                    Some(ELFSymbolType::NoType) if in_code && symbol.binding() != Some(SymbolBinding::Local) => SymbolKind::Function,
                    Some(ELFSymbolType::NoType) => SymbolKind::Label,
                    _ => continue,
                };

                // Thumb bit is not relevant for the supported architectures, but keep addresses clean anyway
                let addr = symbol.st_value;

                program.add_symbol(Symbol::new(addr, &symbol.name, kind, symbol.st_size));

                if kind == SymbolKind::Function && in_code {
                    program.add_seed(addr, if symbol.st_size > 0 { Some(symbol.st_size) } else { None }, SeedSource::Symbol);
                }
            }
        }

        apply_relocations(&mut program, elf);

        let imports: HashSet<&str> = elf.imported_symbols().iter().map(|s| s.name.as_str()).collect();

        for table in elf.relocation_tables.iter() {
            for reloc in table.relocations.iter() {
                if !reloc.symbol_name.is_empty() && imports.contains(reloc.symbol_name.as_str()) {
                    program.import_slots.insert(reloc.r_offset, reloc.symbol_name.clone());
                }
            }
        }

        // Constructors and destructors
        for name in [".preinit_array", ".init_array", ".fini_array"] {
            let Some(section) = elf.sections.get(name) else {
                continue;
            };

            let base = section.header.virtual_address();

            for i in 0..section.size() / program.pointer_size as u64 {
                if let Some(addr) = program.read_pointer(base + i * program.pointer_size as u64) {
                    program.add_seed(addr, None, SeedSource::InitArray);
                }
            }
        }

        if let Some(eh_frame) = elf.sections.get(".eh_frame") {
            let fdes = parse_eh_frame(&eh_frame.data, eh_frame.header.virtual_address(), program.pointer_size, program.big_endian);

            for fde in fdes {
                program.add_seed(fde.pc_begin, Some(fde.pc_range), SeedSource::EhFrame);
            }
        }
    }

    program.finalize();

    return program;
}

/*
 * PE
 */

fn pe_import_slots(program: &mut Program, pe: &PE, image_base: u64) {
    let import_dir = pe.get_optional_header().get_import_table_idd();

    if import_dir.virtual_address == 0 {
        return;
    }

    let pointer_size = program.pointer_size as u64;
    let ordinal_flag = if pointer_size == 4 { 0x8000_0000u64 } else { 0x8000_0000_0000_0000u64 };

    let mut descriptor = image_base + import_dir.virtual_address as u64;
    let mut slots = Vec::new();

    for _ in 0..4096 {
        let (Some(ilt_rva), Some(name_rva), Some(iat_rva)) = (
            program.read_u32(descriptor),
            program.read_u32(descriptor + 12),
            program.read_u32(descriptor + 16),
        ) else {
            break;
        };

        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        let dll = program.read_c_string(image_base + name_rva as u64, 256).unwrap_or_default();
        let dll = dll.trim_end_matches(".dll").trim_end_matches(".DLL").to_string();

        let lookup = if ilt_rva != 0 { ilt_rva } else { iat_rva };

        for i in 0..65536u64 {
            let Some(thunk) = program.read_pointer(image_base + lookup as u64 + i * pointer_size) else {
                break;
            };

            if thunk == 0 {
                break;
            }

            let name = if thunk & ordinal_flag != 0 {
                format!("{}!#{}", dll, thunk & 0xffff)
            } else {
                let function = program.read_c_string(image_base + (thunk & 0x7fff_ffff) + 2, 512).unwrap_or_default();
                format!("{}!{}", dll, function)
            };

            slots.push((image_base + iat_rva as u64 + i * pointer_size, name));
        }

        descriptor += 20;
    }

    program.import_slots.extend(slots);
}

fn pe_exports(program: &mut Program, pe: &PE, image_base: u64) {
    let export_dir = pe.get_optional_header().get_export_table_idd();

    if export_dir.virtual_address == 0 {
        return;
    }

    let dir = image_base + export_dir.virtual_address as u64;
    let dir_end = dir + export_dir.size as u64;

    let (Some(base), Some(number_of_functions), Some(number_of_names), Some(functions), Some(names), Some(ordinals)) = (
        program.read_u32(dir + 16),
        program.read_u32(dir + 20),
        program.read_u32(dir + 24),
        program.read_u32(dir + 28),
        program.read_u32(dir + 32),
        program.read_u32(dir + 36),
    ) else {
        return;
    };

    let mut names_by_index: HashMap<u32, String> = HashMap::new();

    for i in 0..number_of_names.min(65536) as u64 {
        let (Some(name_rva), Some(ordinal)) = (program.read_u32(image_base + names as u64 + i * 4), program.read_u16(image_base + ordinals as u64 + i * 2)) else {
            break;
        };

        if let Some(name) = program.read_c_string(image_base + name_rva as u64, 512) {
            names_by_index.insert(ordinal as u32, name);
        }
    }

    for i in 0..number_of_functions.min(65536) {
        let Some(rva) = program.read_u32(image_base + functions as u64 + i as u64 * 4) else {
            break;
        };

        let addr = image_base + rva as u64;

        // Forwarders point inside the export directory
        if rva == 0 || (addr >= dir && addr < dir_end) {
            continue;
        }

        let name = names_by_index.get(&i).cloned().unwrap_or(format!("ordinal_{}", base + i));
        let is_code = program.is_executable(addr);

        program.add_symbol(Symbol::new(addr, &name, if is_code { SymbolKind::Function } else { SymbolKind::Object }, 0));

        if is_code {
            program.add_seed(addr, None, SeedSource::Export);
        }
    }
}

fn pe_exception_table(program: &mut Program, pe: &PE, image_base: u64) {
    let Some(table) = &pe.exception_table else {
        return;
    };

    for entry in table.entries.iter() {
        match entry {
            ExcFunctionEntry::X64(e) => {
                // Chained unwind info describes a fragment of a function, not its start
                let flags = program.read_u32(image_base + e.unwind_information as u64).map_or(0, |v| (v as u8) >> 3);

                if flags & 0x4 != 0 {
                    continue;
                }

                let size = e.end_address.saturating_sub(e.begin_address) as u64;
                program.add_seed(image_base + e.begin_address as u64, Some(size), SeedSource::ExceptionTable);
            }
            ExcFunctionEntry::Arm64(e) => {
                let size = if e.is_packed() {
                    Some((((e.unwind_data >> 2) & 0x7ff) * 4) as u64)
                } else {
                    e.xdata_header.map(|h| ((h & 0x3ffff) * 4) as u64)
                };

                // Packed unwind data with flag 2 describes a fragment without prolog
                if e.flag() == 2 {
                    continue;
                }

                program.add_seed(image_base + e.begin_address as u64, size, SeedSource::ExceptionTable);
            }
            _ => {}
        }
    }
}

/// The data directories linkers put in the sections of code (imports, debug directory, CLR header and metadata), and
/// the language of a .NET assembly
fn pe_data(program: &mut Program, pe: &PE, image_base: u64) {
    let header = pe.get_optional_header();
    let directories = [header.get_import_table_idd(), header.get_import_address_table_idd(), header.get_debug_idd(), header.get_load_config_table_idd(), header.get_delay_import_descriptor_idd(), header.get_bound_import_idd()];

    for directory in directories.into_iter().filter(|d| d.virtual_address != 0 && d.size != 0) {
        let start = image_base + directory.virtual_address as u64;
        program.data.push((start, start + directory.size as u64));
    }

    let clr = header.get_clr_runtime_header_idd();

    if clr.virtual_address != 0 && clr.size != 0 {
        let start = image_base + clr.virtual_address as u64;
        program.data.push((start, start + clr.size as u64));
        program.language = Language::DotNet;

        // The metadata: its address and its size follow the size of the header and the versions of the runtime
        if let (Some(rva), Some(size)) = (program.read_u32(start + 8), program.read_u32(start + 12)) {
            if rva != 0 {
                program.data.push((image_base + rva as u64, image_base + rva as u64 + size as u64));
            }
        }
    }

    program.data.sort_unstable();
}

fn program_from_pe(pe: &PE) -> Program {
    let mut program = Program { format: Format::Pe, ..Default::default() };

    let image_base = pe.get_optional_header().image_base();

    program.arch = Some(pe.architecture());
    program.pointer_size = if pe.is_32_bits() { 4 } else { 8 };
    program.name = format!("PE {:?}", pe.architecture());

    for section in pe.sections.values() {
        let characteristics = section.header.characteristics;
        let size = (section.header.virtual_size as u64).max(section.data.len() as u64);

        if size == 0 {
            continue;
        }

        program.regions.push(Region {
            name: section.header.name.clone(),
            vaddr: image_base + section.header.virtual_address as u64,
            size,
            data: section.data.clone(),
            perms: Perms {
                read: characteristics & PESectionFlags::MemRead as u32 != 0,
                write: characteristics & PESectionFlags::MemWrite as u32 != 0,
                exec: characteristics & (PESectionFlags::MemExecute as u32 | PESectionFlags::CntCode as u32) != 0,
            },
        });
    }

    program.regions.sort_by_key(|r| r.vaddr);

    let entry_rva = pe.get_optional_header().address_of_entry_point();

    if entry_rva != 0 {
        program.entry = Some(image_base + entry_rva as u64);
        program.add_seed(image_base + entry_rva as u64, None, SeedSource::Entry);
    }

    pe_import_slots(&mut program, pe, image_base);
    pe_exports(&mut program, pe, image_base);
    pe_exception_table(&mut program, pe, image_base);
    pe_data(&mut program, pe, image_base);

    program.finalize();

    return program;
}

/*
 * Mach-O
 */

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

fn program_from_macho(binary: &MachOBinary) -> Program {
    let mut program = Program { format: Format::MachO, ..Default::default() };

    program.arch = Some(binary.architecture());
    program.pointer_size = if binary.header.is_64() { 8 } else { 4 };
    program.name = format!("Mach-O {}", binary.cpu_name());

    for segment in binary.segments() {
        for header in segment.sections.iter() {
            let Some(section) = binary.sections.get(&header.full_name()) else {
                continue;
            };

            if header.size == 0 {
                continue;
            }

            program.regions.push(Region {
                name: header.full_name(),
                vaddr: header.addr,
                size: header.size,
                data: section.data.clone(),
                perms: Perms {
                    read: segment.initprot & 0x1 != 0 || segment.initprot == 0,
                    write: segment.initprot & 0x2 != 0,
                    exec: section.contains_code() || (segment.initprot & 0x4 != 0 && header.sectname == "__text"),
                },
            });
        }
    }

    program.regions.sort_by_key(|r| r.vaddr);

    if let Some(entry) = binary.entry_point {
        program.entry = Some(entry);
        program.add_seed(entry, None, SeedSource::Entry);
    }

    for symbol in binary.symbols.iter() {
        // N_SECT symbols only
        if symbol.is_debug() || (symbol.n_type & 0x0e) != 0x0e || symbol.name.is_empty() {
            continue;
        }

        let in_code = program.is_executable(symbol.n_value);
        let kind = if in_code { SymbolKind::Function } else { SymbolKind::Object };

        program.add_symbol(Symbol::new(symbol.n_value, &symbol.name, kind, 0));

        if in_code {
            program.add_seed(symbol.n_value, None, SeedSource::Symbol);
        }
    }

    for &addr in binary.function_starts.iter() {
        program.add_seed(addr, None, SeedSource::FunctionStarts);
    }

    let pointer_size = program.pointer_size as u64;

    for segment in binary.segments() {
        for header in segment.sections.iter() {
            let indirect_name = |index: u64| -> Option<String> {
                let symbol_index = *binary.indirect_symbols.get(header.reserved1 as usize + index as usize)?;

                if symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    return None;
                }

                return binary.symbols.get(symbol_index as usize).map(|s| s.name.clone());
            };

            match header.section_type() {
                Some(MachOSectionType::SNonLazySymbolPointers | MachOSectionType::SLazySymbolPointers | MachOSectionType::SLazyDylibSymbolPointers) => {
                    for i in 0..header.size / pointer_size {
                        if let Some(name) = indirect_name(i) {
                            program.import_slots.insert(header.addr + i * pointer_size, name);
                        }
                    }
                }
                Some(MachOSectionType::SSymbolStubs) if header.reserved2 > 0 => {
                    let stub_size = header.reserved2 as u64;

                    for i in 0..header.size / stub_size {
                        if let Some(name) = indirect_name(i) {
                            program.add_symbol(Symbol::new(header.addr + i * stub_size, &name, SymbolKind::Import, stub_size));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    program.finalize();

    return program;
}

/// Builds one Program per binary in the executable (Mach-O fat binaries contain several)
pub fn programs_from_exec(exec: &Exec) -> Vec<Program> {
    match exec {
        Exec::ELF(elf) => vec![program_from_elf(elf)],
        Exec::PE(pe) => vec![program_from_pe(pe)],
        Exec::MachO(macho) => macho.binaries.iter().map(program_from_macho).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::parse_elf;
    use crate::macho::parse_macho;
    use crate::pe::parse_pe;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data").join(name);
    }

    #[test]
    fn elf_relocations_applied() {
        let elf = parse_elf(&fixture("elf_x86_64_rust")).unwrap();
        let program = programs_from_exec(&Exec::ELF(elf.clone())).remove(0);
        let relative: Vec<_> = elf.relocation_tables.iter().flat_map(|t| t.relocations.iter()).filter(|r| r.relocation_type(&crate::elf::ELFClass::ELF64) == 8).collect();

        // The GOT slot of core::str::from_utf8 holds its address, as the loader writes it
        assert!(!relative.is_empty());

        for reloc in relative {
            assert_eq!(program.read_pointer(reloc.r_offset), reloc.r_addend.map(|a| a as u64));
        }

        let from_utf8 = program.symbols.values().find(|s| s.name.contains("from_utf8")).unwrap().addr;
        assert!(elf.relocation_tables.iter().flat_map(|t| t.relocations.iter()).any(|r| program.read_pointer(r.r_offset) == Some(from_utf8)));
    }

    #[test]
    fn elf_x86_64_dyn() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_dyn")).unwrap())).remove(0);

        assert_eq!(program.architecture(), Architecture::X86_64);
        assert!(program.entry.is_some());
        assert!(program.is_executable(program.entry.unwrap()));
        assert!(program.import_slots.values().any(|n| n == "lib_add"));
        assert!(program.seeds.iter().any(|s| s.source == SeedSource::Entry));

        let analysis = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_analysis")).unwrap())).remove(0);
        assert_eq!(analysis.source_names, ["analysis.c"]);
    }

    #[test]
    fn languages_and_sized_strings() {
        let rust = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_rust_strings")).unwrap())).remove(0);
        assert_eq!(rust.language, Language::Rust);

        // The &str of a static table: pointers in .data.rel.ro to strings of .rodata that are not NUL terminated
        let colors: Vec<&[u8]> = rust.sized_strings.iter().filter_map(|(&addr, &len)| rust.sized_string(addr, len)).collect();
        assert!(colors.contains(&&b"crimson"[..]) && colors.contains(&&b"teal"[..]) && colors.contains(&&b"ochre"[..]), "{:?}", colors);

        let c = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_dyn")).unwrap())).remove(0);
        assert_eq!(c.language, Language::Unknown);
        assert!(c.sized_strings.is_empty());

        assert!(is_text("héllo\tworld\n".as_bytes()) && !is_text(b"a\x01b") && !is_text(b"\xc3"));
    }

    #[test]
    fn data_in_code() {
        let program = Program { data: vec![(0x2000, 0x2008), (0x2008, 0x2050)], ..Default::default() };
        assert!(!program.is_data(0x1fff));
        assert!(program.is_data(0x2000) && program.is_data(0x2049));
        assert!(!program.is_data(0x2050));

        // The x86 code of the PE fixture is code
        let pe = programs_from_exec(&Exec::PE(parse_pe(&fixture("pe_arm64.exe")).unwrap())).remove(0);
        assert!(pe.language != Language::DotNet && !pe.is_data(pe.entry.unwrap()));
    }

    #[test]
    fn overlapping_regions() {
        let mut program = Program::default();
        program.regions.push(Region { name: ".tbss".to_string(), vaddr: 0x1000, size: 0x10, ..Default::default() });
        program.regions.push(Region { name: ".init_array".to_string(), vaddr: 0x1000, size: 8, data: vec![1; 8], ..Default::default() });
        program.regions.push(Region { name: ".fini_array".to_string(), vaddr: 0x1008, size: 8, data: vec![2; 8], ..Default::default() });
        program.finalize();

        assert_eq!(program.regions.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), [".init_array", ".tbss", ".fini_array"]);
        assert_eq!(program.region_at(0x1000).unwrap().name, ".init_array");
        assert_eq!(program.region_at(0x1008).unwrap().name, ".fini_array");
        assert_eq!(program.read_u64(0x1000), Some(0x0101010101010101));
    }

    #[test]
    fn elf_aarch64_static() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_aarch64_static")).unwrap())).remove(0);

        let entry = program.entry.unwrap();

        assert_eq!(program.symbol_at(entry).unwrap().name, "_start");
        assert_eq!(program.read_u32(entry), Some(0xd2800020));
    }

    #[test]
    fn pe_arm64() {
        let program = programs_from_exec(&Exec::PE(parse_pe(&fixture("pe_arm64.exe")).unwrap())).remove(0);

        assert_eq!(program.architecture(), Architecture::Aarch64);
        assert!(program.seeds.iter().any(|s| s.source == SeedSource::ExceptionTable && s.addr & 0xffff == 0x1008));
    }

    #[test]
    fn macho_x86_64() {
        let macho = parse_macho(&fixture("macho_x86_64")).unwrap();
        let function_starts = macho.binaries[0].function_starts.clone();
        let program = programs_from_exec(&Exec::MachO(macho)).remove(0);

        let entry = program.entry.unwrap();

        assert!(program.is_executable(entry));
        assert!(!function_starts.is_empty());
        assert!(function_starts.iter().all(|addr| program.seeds.iter().any(|s| s.addr == *addr)));
        assert!(program.symbols.values().any(|s| s.kind == SymbolKind::Import));
    }
}
