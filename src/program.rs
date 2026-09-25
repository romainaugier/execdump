/*
 * Program: a format-agnostic view of an executable (memory map, symbols, imports, function hints)
 * built once from the parsed PE/ELF/Mach-O and used by the analysis and the TUI.
 */

use crate::demangle::demangle;
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

#[derive(Clone, Debug, Default)]
pub struct Program {
    /// Short description, e.g. "ELF x86_64"
    pub name: String,
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
}

impl Program {
    pub fn architecture(&self) -> Architecture {
        return self.arch.unwrap_or(Architecture::Unsupported);
    }

    pub fn region_at(&self, addr: u64) -> Option<&Region> {
        let idx = self.regions.partition_point(|r| r.vaddr <= addr);

        // Regions can overlap (ELF .tbss for example), look back a few regions
        return self.regions[..idx].iter().rev().take(4).find(|r| r.contains(addr));
    }

    pub fn is_executable(&self, addr: u64) -> bool {
        return self.region_at(addr).map_or(false, |r| r.perms.exec && !r.data.is_empty());
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
        self.regions.sort_by_key(|r| (r.vaddr, r.size));

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
 * ELF
 */

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

    sections.sort_by_key(|s| s.offset());

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
            for symbol in table.symbols.iter() {
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

fn program_from_pe(pe: &PE) -> Program {
    let mut program = Program::default();

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

    program.finalize();

    return program;
}

/*
 * Mach-O
 */

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

fn program_from_macho(binary: &MachOBinary) -> Program {
    let mut program = Program::default();

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
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    }

    #[test]
    fn elf_x86_64_dyn() {
        let program = programs_from_exec(&Exec::ELF(parse_elf(&fixture("elf_x86_64_dyn")).unwrap())).remove(0);

        assert_eq!(program.architecture(), Architecture::X86_64);
        assert!(program.entry.is_some());
        assert!(program.is_executable(program.entry.unwrap()));
        assert!(program.import_slots.values().any(|n| n == "lib_add"));
        assert!(program.seeds.iter().any(|s| s.source == SeedSource::Entry));
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
