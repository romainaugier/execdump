/*
 * PE data directories read for the analysis: the delay load imports (the functions of a DLL loaded at their first
 * call), the TLS directory (its callbacks run before the entry point) and the load configuration (the security cookie,
 * the Control Flow Guard functions table: every function called through a pointer, the SEH handlers of 32-bit code).
 *
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */

use crate::dump::Dump;
use crate::pe::PE;

/// Bit of the attributes of a delay load descriptor: its addresses are RVAs (the first ones were VAs)
const DELAY_RVA_BASED: u32 = 1;
/// Number of bytes after each RVA of the guard functions table, in the high bits of the guard flags
const GUARD_TABLE_STRIDE_MASK: u32 = 0xf000_0000;
const GUARD_TABLE_STRIDE_SHIFT: u32 = 28;

const MAX_ENTRIES: usize = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DelayImportedFunction {
    /// The slot of the import address table the call goes through
    pub slot: u64,
    pub name: String,
    /// What the slot holds until the first call: the thunk that loads the DLL
    pub thunk: u64,
}

#[derive(Clone, Debug, Default)]
pub struct DelayImport {
    pub dll: String,
    pub functions: Vec<DelayImportedFunction>,
}

#[derive(Clone, Debug, Default)]
pub struct TlsDirectory {
    pub raw_data: (u64, u64),
    pub index: u64,
    /// The functions called when a thread starts and ends, and before the entry point
    pub callbacks: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct LoadConfig {
    pub size: u32,
    pub security_cookie: u64,
    /// The SEH handlers of 32-bit code
    pub se_handlers: Vec<u64>,
    /// The pointers the calls through a pointer are checked with (Control Flow Guard)
    pub guard_check: u64,
    pub guard_dispatch: u64,
    /// The functions that can be called through a pointer
    pub guard_functions: Vec<u64>,
    pub guard_flags: u32,
}

/// Reads the PE at its RVAs (the virtual addresses are the image base plus an RVA)
struct Image<'a> {
    pe: &'a PE,
    base: u64,
    pointer_size: usize,
}

impl Image<'_> {
    fn bytes(&self, rva: u64, len: usize) -> Option<&[u8]> {
        let rva = u32::try_from(rva).ok()?;

        let section = self.pe.sections.values().find(|s| rva >= s.header.virtual_address && ((rva - s.header.virtual_address) as usize) < s.data.len())?;
        let offset = (rva - section.header.virtual_address) as usize;
        return section.data.get(offset..offset + len);
    }

    fn u32(&self, rva: u64) -> Option<u32> {
        return self.bytes(rva, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    }

    fn u64(&self, rva: u64) -> Option<u64> {
        return self.bytes(rva, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    }

    fn pointer(&self, rva: u64) -> Option<u64> {
        return if self.pointer_size == 4 { self.u32(rva).map(|v| v as u64) } else { self.u64(rva) };
    }

    fn c_string(&self, rva: u64) -> Option<String> {
        let mut text = Vec::new();

        for i in 0..512 {
            match *self.bytes(rva + i, 1)?.first()? {
                0 => return Some(String::from_utf8_lossy(&text).into_owned()),
                byte => text.push(byte),
            }
        }

        return None;
    }

    /// An RVA from a virtual address
    fn rva(&self, va: u64) -> Option<u64> {
        return va.checked_sub(self.base);
    }
}

fn image(pe: &PE) -> Image<'_> {
    return Image { pe, base: pe.get_optional_header().image_base(), pointer_size: if pe.is_32_bits() { 4 } else { 8 } };
}

pub fn delay_imports(pe: &PE) -> Vec<DelayImport> {
    let image = image(pe);
    let directory = pe.get_optional_header().get_delay_import_descriptor_idd();
    let mut imports = Vec::new();

    if directory.virtual_address == 0 {
        return imports;
    }

    let ordinal_flag = 1u64 << (image.pointer_size * 8 - 1);
    let mut descriptor = directory.virtual_address as u64;

    for _ in 0..4096 {
        let fields: Option<Vec<u32>> = (0..8).map(|i| image.u32(descriptor + 4 * i)).collect();

        let Some(fields) = fields else {
            break;
        };

        let (attributes, name, iat, int) = (fields[0], fields[1] as u64, fields[3] as u64, fields[4] as u64);

        if name == 0 && iat == 0 {
            break;
        }

        // The first descriptors hold virtual addresses
        let rva = |address: u64| if attributes & DELAY_RVA_BASED != 0 { Some(address) } else { image.rva(address) };
        let dll = rva(name).and_then(|r| image.c_string(r)).unwrap_or_default();
        let dll_stem = dll.trim_end_matches(".dll").trim_end_matches(".DLL").to_string();
        let mut functions = Vec::new();

        if let (Some(iat), Some(int)) = (rva(iat), rva(int)) {
            for i in 0..MAX_ENTRIES as u64 {
                let at = i * image.pointer_size as u64;

                let Some(entry) = image.pointer(int + at).filter(|&e| e != 0) else {
                    break;
                };

                let function = if entry & ordinal_flag != 0 {
                    format!("#{}", entry & 0xffff)
                } else {
                    rva(entry & 0x7fff_ffff).and_then(|r| image.c_string(r + 2)).unwrap_or_default()
                };

                let thunk = image.pointer(iat + at).unwrap_or(0);
                functions.push(DelayImportedFunction { slot: image.base + iat + at, name: format!("{}!{}", dll_stem, function), thunk });
            }
        }

        imports.push(DelayImport { dll, functions });
        descriptor += 32;
    }

    return imports;
}

pub fn tls_directory(pe: &PE) -> Option<TlsDirectory> {
    let image = image(pe);
    let directory = pe.get_optional_header().get_tls_table_idd();

    if directory.virtual_address == 0 {
        return None;
    }

    let rva = directory.virtual_address as u64;
    let size = image.pointer_size as u64;
    let field = |i: u64| image.pointer(rva + i * size);

    let mut tls = TlsDirectory { raw_data: (field(0)?, field(1)?), index: field(2)?, callbacks: Vec::new() };

    if let Some(mut at) = field(3).and_then(|va| image.rva(va)) {
        for _ in 0..MAX_ENTRIES {
            match image.pointer(at) {
                Some(callback) if callback != 0 => tls.callbacks.push(callback),
                _ => break,
            }

            at += size;
        }
    }

    return Some(tls);
}

pub fn load_config(pe: &PE) -> Option<LoadConfig> {
    let image = image(pe);
    let directory = pe.get_optional_header().get_load_config_table_idd();

    if directory.virtual_address == 0 {
        return None;
    }

    let rva = directory.virtual_address as u64;
    let size = image.u32(rva)?;
    let wide = image.pointer_size == 8;

    // The fields after the size of this version of the structure are not there
    let field = |offset32: u64, offset64: u64| -> Option<u64> {
        let (offset, width) = if wide { (offset64, 8) } else { (offset32, 4) };
        return if offset + width <= size as u64 { image.pointer(rva + offset) } else { None };
    };

    let mut config = LoadConfig { size, ..LoadConfig::default() };

    config.security_cookie = field(0x3c, 0x58).unwrap_or(0);
    config.guard_check = field(0x48, 0x70).unwrap_or(0);
    config.guard_dispatch = field(0x4c, 0x78).unwrap_or(0);
    let flags = if wide { 0x90 } else { 0x58 };
    config.guard_flags = if flags + 4 <= size as u64 { image.u32(rva + flags).unwrap_or(0) } else { 0 };

    if !wide {
        if let (Some(table), Some(count)) = (field(0x40, 0x60).and_then(|va| image.rva(va)), field(0x44, 0x68)) {
            config.se_handlers = (0..count.min(MAX_ENTRIES as u64)).map_while(|i| image.u32(table + 4 * i)).map(|r| image.base + r as u64).collect();
        }
    }

    if let (Some(table), Some(count)) = (field(0x50, 0x80).and_then(|va| image.rva(va)), field(0x54, 0x88)) {
        let stride = 4 + ((config.guard_flags & GUARD_TABLE_STRIDE_MASK) >> GUARD_TABLE_STRIDE_SHIFT) as u64;
        config.guard_functions = (0..count.min(MAX_ENTRIES as u64)).map_while(|i| image.u32(table + stride * i)).map(|r| image.base + r as u64).collect();
    }

    return Some(config);
}

impl DelayImport {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("{} ({} functions)", self.dll, self.functions.len()));

        for function in self.functions.iter() {
            dump.push_field("", format!("{:#018x} {} (thunk {:#x})", function.slot, function.name, function.thunk), None);
        }

        return dump;
    }
}

impl TlsDirectory {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("TLS Directory");

        dump.push_field("RawData", format!("{:#x} - {:#x}", self.raw_data.0, self.raw_data.1), None);
        dump.push_field("AddressOfIndex", format!("{:#x}", self.index), None);

        for callback in self.callbacks.iter() {
            dump.push_field("Callback", format!("{:#x}", callback), None);
        }

        return dump;
    }
}

impl LoadConfig {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Load Configuration");

        dump.push_field("Size", format!("{:#x}", self.size), None);
        dump.push_field("SecurityCookie", format!("{:#x}", self.security_cookie), None);
        dump.push_field("GuardCFCheckFunctionPointer", format!("{:#x}", self.guard_check), None);
        dump.push_field("GuardCFDispatchFunctionPointer", format!("{:#x}", self.guard_dispatch), None);
        dump.push_field("GuardFlags", format!("{:#x}", self.guard_flags), None);
        dump.push_field("SEHandlers", self.se_handlers.len().to_string(), None);
        dump.push_field("GuardCFFunctions", self.guard_functions.len().to_string(), None);

        let mut functions = Dump::new("Guard CF Functions");

        for function in self.guard_functions.iter() {
            functions.push_field("", format!("{:#x}", function), None);
        }

        dump.push_child(functions);
        return dump;
    }
}
