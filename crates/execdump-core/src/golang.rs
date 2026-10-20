/*
 * Go binaries: the pclntab every Go binary keeps for its runtime (stack traces, the garbage collector) names
 * every function, gives its bounds and the source file it was compiled from, stripped binaries included.
 *
 * It is found by its section (.gopclntab, __gopclntab), else by its header in the data: a magic number per
 * layout, then the size of the instructions and of the pointers. The layouts read:
 * - Go 1.18 and later (0xfffffff0, 0xfffffff1): the entries of the functions are 32-bit offsets from the
 *   start of the text, the header has the offsets of the tables
 * - Go 1.16 and 1.17 (0xfffffffa): the same tables, the entries are addresses
 * - Go 1.2 to 1.15 (0xfffffffb): the functions follow the header, their names are offsets in the table
 */

use crate::program::{Program, Region};

/// A function of the pclntab
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoFunction {
    pub entry: u64,
    pub end: u64,
    pub name: String,
    /// Source file of its first instruction
    pub file: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// 1.2 to 1.15
    Go12,
    /// 1.16 and 1.17
    Go116,
    /// 1.18 and later
    Go118,
}

const MAX_NAME: usize = 4096;

fn layout(magic: u32) -> Option<Layout> {
    return match magic {
        0xfffffffb => Some(Layout::Go12),
        0xfffffffa => Some(Layout::Go116),
        0xfffffff0 | 0xfffffff1 => Some(Layout::Go118),
        _ => None,
    };
}

/// The pclntab of the program, its address
fn find(program: &Program) -> Option<u64> {
    let named = program.regions.iter().find(|r| r.name == ".gopclntab" || r.name.ends_with("__gopclntab"));

    if let Some(region) = named.filter(|r| header_at(program, r.vaddr).is_some()) {
        return Some(region.vaddr);
    }

    // Stripped of its section names (PE, ELF without section headers): the first valid header in the data
    let candidates = program.regions.iter().filter(|r| !r.perms.write && !r.data.is_empty());
    return candidates.flat_map(|r| headers_in(program, r)).next();
}

fn headers_in<'a>(program: &'a Program, region: &'a Region) -> impl Iterator<Item = u64> + 'a {
    return (0..region.data.len().saturating_sub(16)).step_by(4).filter_map(move |offset| {
        let bytes = &region.data[offset..offset + 8];
        (bytes[0] & 0xf0 == 0xf0 && bytes[1..4] == [0xff, 0xff, 0xff] && bytes[4] == 0 && bytes[5] == 0).then_some(region.vaddr + offset as u64).filter(|&addr| header_at(program, addr).is_some())
    });
}

/// Layout of the header at an address, checked against the program: its pointer size, a first function in
/// the code
fn header_at(program: &Program, addr: u64) -> Option<Layout> {
    let header = program.read(addr, 8)?;
    let layout = layout(u32::from_le_bytes(header[..4].try_into().ok()?))?;
    let (quantum, pointer_size) = (header[6], header[7]);

    if header[4] != 0 || header[5] != 0 || !matches!(quantum, 1 | 2 | 4) || pointer_size != program.pointer_size {
        return None;
    }

    let table = Table::new(program, addr, layout)?;
    let first = table.function(0)?;

    return (table.count > 0 && program.is_executable(first.entry) && first.end > first.entry).then_some(layout);
}

struct Table<'a> {
    program: &'a Program,
    base: u64,
    layout: Layout,
    pointer_size: u64,
    count: u64,
    text_start: u64,
    names: u64,
    cus: u64,
    files: u64,
    pcs: u64,
    functab: u64,
}

impl<'a> Table<'a> {
    fn new(program: &'a Program, base: u64, layout: Layout) -> Option<Self> {
        let header = program.read(base, 8)?;
        let pointer_size = header[7] as u64;
        let field = |index: u64| program.read_pointer(base + 8 + index * pointer_size);

        let mut table = Table { program, base, layout, pointer_size, count: field(0)?, text_start: 0, names: 0, cus: 0, files: 0, pcs: 0, functab: 0 };

        match layout {
            Layout::Go118 => {
                table.text_start = field(2)?;
                table.names = base + field(3)?;
                table.cus = base + field(4)?;
                table.files = base + field(5)?;
                table.pcs = base + field(6)?;
                table.functab = base + field(7)?;
            }
            Layout::Go116 => {
                table.names = base + field(2)?;
                table.cus = base + field(3)?;
                table.files = base + field(4)?;
                table.pcs = base + field(5)?;
                table.functab = base + field(6)?;
            }
            Layout::Go12 => {
                table.names = base;
                table.pcs = base;
                table.functab = base + 8 + pointer_size;
            }
        }

        // The entries of the text before it is known: the start of the region of the first function (1.18 and
        // later binaries written without the relocation of the field)
        if layout == Layout::Go118 && table.text_start == 0 {
            table.text_start = program.regions.iter().find(|r| r.perms.exec && !r.data.is_empty())?.vaddr;
        }

        return (table.count > 0 && table.count < 1 << 24).then_some(table);
    }

    /// Size of an entry of the function table
    fn entry_size(&self) -> u64 {
        return if self.layout == Layout::Go118 { 8 } else { 2 * self.pointer_size };
    }

    /// Entry address and offset of the _func of the function at an index (the one after the last function holds the
    /// end of the text)
    fn entry(&self, index: u64) -> Option<(u64, u64)> {
        let at = self.functab + index * self.entry_size();

        return match self.layout {
            Layout::Go118 => Some((self.text_start + self.program.read_u32(at)? as u64, self.program.read_u32(at + 4)? as u64)),
            _ => Some((self.program.read_pointer(at)?, self.program.read_pointer(at + self.pointer_size)?)),
        };
    }

    fn function(&self, index: u64) -> Option<GoFunction> {
        let (entry, offset) = self.entry(index)?;
        let (end, _) = self.entry(index + 1)?;

        // _func: its entry (32-bit offset, or an address), then the offset of its name, args, deferreturn, pcsp, pcfile
        let func = if self.layout == Layout::Go12 { self.base + offset } else { self.functab + offset };
        let after_entry = func + if self.layout == Layout::Go118 { 4 } else { self.pointer_size };
        let name_offset = self.program.read_u32(after_entry)? as u64;
        let name = self.program.read_c_string(self.names + name_offset, MAX_NAME)?;

        if name.is_empty() || end <= entry {
            return None;
        }

        let file = self.file(after_entry).filter(|f| !f.is_empty());
        return Some(GoFunction { entry, end, name, file });
    }

    /// Source file at the entry of a function: the first value of its pcfile table, an index in the files of its
    /// compilation unit
    fn file(&self, after_entry: u64) -> Option<String> {
        if self.layout == Layout::Go12 {
            return None;
        }

        // pcfile is the fifth field after the entry, the offset of the compilation unit the eighth
        let pcfile = self.program.read_u32(after_entry + 16)? as u64;
        let cu = self.program.read_u32(after_entry + 28)? as u64;
        let index = u64::try_from(self.first_value(self.pcs + pcfile)?).ok()?;
        let offset = self.program.read_u32(self.cus + (cu + index) * 4)?;

        return self.program.read_c_string(self.files + offset as u64, MAX_NAME);
    }

    /// First value of a pc-value table: a zigzag varint added to -1
    fn first_value(&self, at: u64) -> Option<i64> {
        let (raw, _) = varint(self.program.bytes_from(at)?)?;
        let delta = ((raw >> 1) as i64) ^ -((raw & 1) as i64);
        return Some(delta - 1);
    }
}

/// Unsigned LEB128 varint and its size
fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;

    for (index, &byte) in bytes.iter().enumerate().take(10) {
        value |= ((byte & 0x7f) as u64) << (7 * index);

        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }

    return None;
}

/// The functions of the pclntab of a Go program, in address order
pub fn functions(program: &Program) -> Vec<GoFunction> {
    let Some(base) = find(program) else {
        return Vec::new();
    };

    let Some(table) = header_at(program, base).and_then(|layout| Table::new(program, base, layout)) else {
        return Vec::new();
    };

    return (0..table.count).filter_map(|index| table.function(index)).collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::Perms;

    /// A pclntab of Go 1.18 and later with two functions of /src/app/main.go
    fn pclntab(text: u64) -> Vec<u8> {
        let names = b"main.main\0main.helper\0".to_vec();
        let cus = 0u32.to_le_bytes().to_vec();
        let files = b"/src/app/main.go\0".to_vec();
        // pcfile: file 0 (-1 + zigzag 2) for 0x10 bytes, then the end
        let pcs = vec![0u8, 0x02, 0x10, 0x00];

        let header_size = 8 + 8 * 8;
        let names_at = header_size;
        let cus_at = names_at + names.len();
        let files_at = cus_at + cus.len();
        let pcs_at = files_at + files.len();
        let functab_at = (pcs_at + pcs.len()).next_multiple_of(4);

        let mut functab = Vec::new();

        // The _func of each function follow the table of 3 entries, 44 bytes each
        for (entry, func) in [(0u32, 24u32), (0x20, 24 + 44), (0x40, 0)] {
            functab.extend(entry.to_le_bytes());
            functab.extend(func.to_le_bytes());
        }

        // _func: entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln, npcdata, cuOffset, startLine, then 4 bytes
        for (entry, name) in [(0u32, 0u32), (0x20, 10)] {
            for field in [entry, name, 0, 0, 0, 1, 0, 0, 0, 1] {
                functab.extend(field.to_le_bytes());
            }

            functab.extend([0u8; 4]);
        }

        let mut data = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];

        for field in [2, 1, text, names_at as u64, cus_at as u64, files_at as u64, pcs_at as u64, functab_at as u64] {
            data.extend(field.to_le_bytes());
        }

        data.extend(names);
        data.extend(cus);
        data.extend(files);
        data.extend(pcs);
        data.resize(functab_at, 0);
        data.extend(functab);

        return data;
    }

    #[test]
    fn go118_functions() {
        let mut program = Program { pointer_size: 8, ..Default::default() };
        program.regions.push(Region { name: ".text".to_string(), vaddr: 0x1000, size: 0x40, data: vec![0xc3; 0x40], perms: Perms { read: true, write: false, exec: true } });
        let data = pclntab(0x1000);
        program.regions.push(Region { name: ".rodata".to_string(), vaddr: 0x8000, size: data.len() as u64, data, perms: Perms { read: true, write: false, exec: false } });

        let functions = functions(&program);

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0], GoFunction { entry: 0x1000, end: 0x1020, name: "main.main".to_string(), file: Some("/src/app/main.go".to_string()) });
        assert_eq!((functions[1].entry, functions[1].end, functions[1].name.as_str()), (0x1020, 0x1040, "main.helper"));
    }

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x05]), Some((5, 1)));
        assert_eq!(varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(varint(&[0x80]), None);
    }
}
