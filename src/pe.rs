use byteorder::{LittleEndian, ReadBytesExt};
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::{collections::HashMap, io::Read};

use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};

use capstone::prelude::*;

use crate::args::Args;
use crate::dump::{dump_field, dump_instruction};

/*
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */

/*
 * MS-DOS Header present in every PE file
 */

/* Magic number for MS-DOS executable */
const DOS_MAGIC: u16 = 0x5a4d;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct DOSHeader {
    e_magic: u16,      // Magic number: 0x5A4D or MZ
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header, in paragraphs
    e_minalloc: u16,   // Min - extra paragraphs needed
    e_maxalloc: u16,   // Max - extra paragraphs needed
    e_ss: u16,         // Initial (relative) SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial (relative) CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res: [u16; 4],   // Reserved words
    e_oemid: u16,      // OEM identifier
    e_oeminfo: u16,    // OEM information
    e_res2: [u16; 10], // Reserved words
    e_lfanew: u32,     // Offset to NT header
}

impl DOSHeader {
    fn new() -> DOSHeader {
        return DOSHeader::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<DOSHeader, Box<dyn Error>> {
        let mut header: DOSHeader = DOSHeader::new();
        header.e_magic = cursor.read_u16::<LittleEndian>()?;

        if header.e_magic != DOS_MAGIC {
            return Err("Invalid DOS magic number".into());
        }

        cursor.set_position(0x3C);

        header.e_lfanew = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("DOS Header", "", label_pad, 0);

        let field_pad = (pad + 1) * pad_sz;
        let field_align = 12;

        dump_field(
            "e_magic",
            format!("{:#x}", self.e_magic),
            field_pad,
            field_align,
        );
        dump_field(
            "e_cblp",
            format!("{:#x}", self.e_cblp),
            field_pad,
            field_align,
        );
        dump_field("e_cp", format!("{:#x}", self.e_cp), field_pad, field_align);
        dump_field(
            "e_crlc",
            format!("{:#x}", self.e_crlc),
            field_pad,
            field_align,
        );
        dump_field(
            "e_cparhdr",
            format!("{:#x}", self.e_cparhdr),
            field_pad,
            field_align,
        );
        dump_field(
            "e_minalloc",
            format!("{:#x}", self.e_minalloc),
            field_pad,
            field_align,
        );
        dump_field(
            "e_maxalloc",
            format!("{:#x}", self.e_maxalloc),
            field_pad,
            field_align,
        );
        dump_field("e_ss", format!("{:#x}", self.e_ss), field_pad, field_align);
        dump_field("e_sp", format!("{:#x}", self.e_sp), field_pad, field_align);
        dump_field(
            "e_csum",
            format!("{:#x}", self.e_csum),
            field_pad,
            field_align,
        );
        dump_field("e_ip", format!("{:#x}", self.e_ip), field_pad, field_align);
        dump_field("e_cs", format!("{:#x}", self.e_cs), field_pad, field_align);
        dump_field(
            "e_lfarlc",
            format!("{:#x}", self.e_lfarlc),
            field_pad,
            field_align,
        );
        dump_field(
            "e_ovno",
            format!("{:#x}", self.e_ovno),
            field_pad,
            field_align,
        );
        dump_field("e_res", format!("{:?}", self.e_res), field_pad, field_align);
        dump_field(
            "e_oemid",
            format!("{:#x}", self.e_oemid),
            field_pad,
            field_align,
        );
        dump_field(
            "e_oeminfo",
            format!("{:#x}", self.e_oeminfo),
            field_pad,
            field_align,
        );
        dump_field(
            "e_res2",
            format!("{:?}", self.e_res2),
            field_pad,
            field_align,
        );
        dump_field(
            "e_lfanew",
            format!("{:#x}", self.e_lfanew),
            field_pad,
            field_align,
        );

        println!("");
    }
}

/*
 * Machine Types (machine field in COFF Header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    Unknown = 0x0, // The content of this field is assumed to be applicable to any machine type
    Alpha = 0x184, // Alpha AXP, 32-bit address space
    Alpha64 = 0x284, // Alpha 64, 64-bit address space
    AM33 = 0x1d3,  // Matsushita AM33
    AMD64 = 0x8664, // x64
    ARM = 0x1c0,   // ARM little endian
    ARM64 = 0xaa64, // ARM64 little endian
    ARM64EC = 0xA641, // ABI that enables interoperability between native ARM64 and emulated x64 code.
    ARM64X = 0xA64E, // Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.
    ARMNT = 0x1c4,   // ARM Thumb-2 little endian
    EBC = 0xebc,     // EFI byte code
    I386 = 0x14c,    // Intel 386 or later processors and compatible processors
    IA64 = 0x200,    // Intel Itanium processor family
    LOONGARCH32 = 0x6232, // LoongArch 32-bit processor family
    LOONGARCH64 = 0x6264, // LoongArch 64-bit processor family
    M32R = 0x9041,   // Mitsubishi M32R little endian
    MIPS16 = 0x266,  // MIPS16
    MIPSFPU = 0x366, // MIPS with FPU
    MIPSFPU16 = 0x466, // MIPS16 with FPU
    POWERPC = 0x1f0, // Power PC little endian
    POWERPCFP = 0x1f1, // Power PC with floating point support
    R3000BE = 0x160, // MIPS I compatible 32-bit big endian
    R3000 = 0x162,   // MIPS I compatible 32-bit little endian
    R4000 = 0x166,   // MIPS III compatible 64-bit little endian
    R10000 = 0x168,  // MIPS IV compatible 64-bit little endian
    RISCV32 = 0x5032, // RISC-V 32-bit address space
    RISCV64 = 0x5064, // RISC-V 64-bit address space
    RISCV128 = 0x5128, // RISC-V 128-bit address space
    SH3 = 0x1a2,     // Hitachi SH3
    SH3DSP = 0x1a3,  // Hitachi SH3 DSP
    SH4 = 0x1a6,     // Hitachi SH4
    SH5 = 0x1a8,     // Hitachi SH5
    THUMB = 0x1c2,   // Thumb
    WCEMIPSV2 = 0x169, // MIPS little-endian WCE v2
}

impl From<u16> for MachineType {
    fn from(value: u16) -> Self {
        match value {
            v if v == MachineType::Unknown as u16 => MachineType::Unknown,
            v if v == MachineType::Alpha as u16 => MachineType::Alpha,
            v if v == MachineType::Alpha64 as u16 => MachineType::Alpha64,
            v if v == MachineType::AM33 as u16 => MachineType::AM33,
            v if v == MachineType::AMD64 as u16 => MachineType::AMD64,
            v if v == MachineType::ARM as u16 => MachineType::ARM,
            v if v == MachineType::ARM64 as u16 => MachineType::ARM64,
            v if v == MachineType::ARM64EC as u16 => MachineType::ARM64EC,
            v if v == MachineType::ARM64X as u16 => MachineType::ARM64X,
            v if v == MachineType::ARMNT as u16 => MachineType::ARMNT,
            v if v == MachineType::EBC as u16 => MachineType::EBC,
            v if v == MachineType::I386 as u16 => MachineType::I386,
            v if v == MachineType::IA64 as u16 => MachineType::IA64,
            v if v == MachineType::LOONGARCH32 as u16 => MachineType::LOONGARCH32,
            v if v == MachineType::LOONGARCH64 as u16 => MachineType::LOONGARCH64,
            v if v == MachineType::M32R as u16 => MachineType::M32R,
            v if v == MachineType::MIPS16 as u16 => MachineType::MIPS16,
            v if v == MachineType::MIPSFPU as u16 => MachineType::MIPSFPU,
            v if v == MachineType::MIPSFPU16 as u16 => MachineType::MIPSFPU16,
            v if v == MachineType::POWERPC as u16 => MachineType::POWERPC,
            v if v == MachineType::POWERPCFP as u16 => MachineType::POWERPCFP,
            v if v == MachineType::R3000BE as u16 => MachineType::R3000BE,
            v if v == MachineType::R3000 as u16 => MachineType::R3000,
            v if v == MachineType::R4000 as u16 => MachineType::R4000,
            v if v == MachineType::R10000 as u16 => MachineType::R10000,
            v if v == MachineType::RISCV32 as u16 => MachineType::RISCV32,
            v if v == MachineType::RISCV64 as u16 => MachineType::RISCV64,
            v if v == MachineType::RISCV128 as u16 => MachineType::RISCV128,
            v if v == MachineType::SH3 as u16 => MachineType::SH3,
            v if v == MachineType::SH3DSP as u16 => MachineType::SH3DSP,
            v if v == MachineType::SH4 as u16 => MachineType::SH4,
            v if v == MachineType::SH5 as u16 => MachineType::SH5,
            v if v == MachineType::THUMB as u16 => MachineType::THUMB,
            v if v == MachineType::WCEMIPSV2 as u16 => MachineType::WCEMIPSV2,
            _ => MachineType::Unknown,
        }
    }
}

/*
 * Characteristics Flags (characteristics field in COFF header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CharacteristicsFlag {
    RelocsStripped = 0x0001, // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    ExecutableImage = 0x0002, // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    LineNumsStripped = 0x0004, // COFF line numbers have been removed. This flag is deprecated and should be zero.
    LocalSymsStripped = 0x0008, // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    AggressiveWSTrim = 0x0010, // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    LargeAddressAware = 0x0020, // Application can handle > 2-GB addresses.
    UnusedFlag = 0x0040,       // This flag is reserved for future use.
    BytesReversedLo = 0x0080, // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    Bit32Machine = 0x0100,    // Machine is based on a 32-bit-word architecture.
    DebugStripped = 0x0200,   // Debugging information is removed from the image file.
    RemovableRunFromSwap = 0x0400, // If the image is on removable media, fully load it and copy it to the swap file.
    NetRunFromSwap = 0x0800, // If the image is on network media, fully load it and copy it to the swap file.
    System = 0x1000,         // The image file is a system file, not a user program.
    DLL = 0x2000, // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    UPSystemOnly = 0x4000, // The file should be run only on a uniprocessor machine.
    BytesReversedHi = 0x8000, // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
}

/*
 * COFF Header
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct COFFHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

impl COFFHeader {
    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<COFFHeader, Box<dyn Error>> {
        let mut header: COFFHeader = COFFHeader::default();

        header.machine = cursor.read_u16::<LittleEndian>()?;
        header.number_of_sections = cursor.read_u16::<LittleEndian>()?;
        header.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_symbol_table = cursor.read_u32::<LittleEndian>()?;
        header.number_of_symbols = cursor.read_u32::<LittleEndian>()?;
        header.size_of_optional_header = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u16::<LittleEndian>()?;

        return Ok(header);
    }

    fn characteristics_as_string(&self) -> String {
        let flags: Vec<&'static str> = CharacteristicsFlag::iter()
            .filter(|&flag| (flag as u16 & self.characteristics) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("COFF Header", "", label_pad, 0);

        let field_pad = (pad + 1) * pad_sz;
        let field_align = 22;

        dump_field(
            "Machine",
            format!(
                "{:#x} ({:#?})",
                self.machine,
                MachineType::from(self.machine)
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfSections",
            format!("{:#x}", self.number_of_sections),
            field_pad,
            field_align,
        );
        dump_field(
            "TimeDateStamp",
            format!("{:#x}", self.time_date_stamp),
            field_pad,
            field_align,
        );
        dump_field(
            "PointerToSymbolTable",
            format!("{:#x}", self.pointer_to_symbol_table),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfSymbols",
            format!("{:#x}", self.number_of_symbols),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfOptionalHeader",
            format!("{:#x}", self.size_of_optional_header),
            field_pad,
            field_align,
        );
        dump_field(
            "Characteristics",
            format!(
                "{:#x} ({})",
                self.characteristics,
                self.characteristics_as_string()
            ),
            field_pad,
            field_align,
        );

        println!("");
    }
}

const NT_PE_SIGNATURE: u32 = 0x4550;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct NTHeader {
    signature: u32,
    coff_header: COFFHeader,
}

impl NTHeader {
    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<NTHeader, Box<dyn Error>> {
        let mut header: NTHeader = NTHeader::default();
        header.signature = cursor.read_u32::<LittleEndian>()?;

        if header.signature != NT_PE_SIGNATURE {
            return Err("Invalid PE signature in NT Header".into());
        }

        header.coff_header = COFFHeader::from_parser(cursor)?;

        return Ok(header);
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("NT Header", "", label_pad, 0);

        let field_pad = (pad + 1) * pad_sz;

        dump_field("Signature", format!("{:#x}", self.signature), field_pad, 0);

        self.coff_header.dump(pad + 1, pad_sz);
    }
}

/*
 * Image Data Directory (Last 16 members of the Optional Header)
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

impl ImageDataDirectory {
    pub fn new() -> ImageDataDirectory {
        return ImageDataDirectory::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ImageDataDirectory, Box<dyn std::error::Error>> {
        let mut idd = ImageDataDirectory::new();

        idd.virtual_address = cursor.read_u32::<LittleEndian>()?;
        idd.size = cursor.read_u32::<LittleEndian>()?;

        return Ok(idd);
    }
}

/*
 * Windows Subsystem
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum Subsystem {
    Unknown = 0,                 // An unknown subsystem
    Native = 1,                  // Device drivers and native Windows processes
    WindowsGui = 2,              // The Windows graphical user interface (GUI) subsystem
    WindowsCui = 3,              // The Windows character subsystem
    Os2Cui = 5,                  // The OS/2 character subsystem
    PosixCui = 7,                // The Posix character subsystem
    NativeWindows = 8,           // Native Win9x driver
    WindowsCEGui = 9,            // Windows CE
    EfiApplication = 10,         // An Extensible Firmware Interface (EFI) application
    EfiBootServiceDriver = 11,   // An EFI driver with boot services
    EfiRuntimeDriver = 12,       // An EFI driver with run-time services
    EfiRom = 13,                 // An EFI ROM image
    XBOX = 14,                   // XBOX
    WindowsBootApplication = 16, // Windows boot application.
}

impl From<u16> for Subsystem {
    fn from(value: u16) -> Self {
        match value {
            v if v == Subsystem::Unknown as u16 => Subsystem::Unknown,
            v if v == Subsystem::Native as u16 => Subsystem::Native,
            v if v == Subsystem::WindowsGui as u16 => Subsystem::WindowsGui,
            v if v == Subsystem::WindowsCui as u16 => Subsystem::WindowsCui,
            v if v == Subsystem::Os2Cui as u16 => Subsystem::Os2Cui,
            v if v == Subsystem::PosixCui as u16 => Subsystem::PosixCui,
            v if v == Subsystem::NativeWindows as u16 => Subsystem::NativeWindows,
            v if v == Subsystem::WindowsCEGui as u16 => Subsystem::WindowsCEGui,
            v if v == Subsystem::EfiApplication as u16 => Subsystem::EfiApplication,
            v if v == Subsystem::EfiBootServiceDriver as u16 => Subsystem::EfiBootServiceDriver,
            v if v == Subsystem::EfiRuntimeDriver as u16 => Subsystem::EfiRuntimeDriver,
            v if v == Subsystem::EfiRom as u16 => Subsystem::EfiRom,
            v if v == Subsystem::XBOX as u16 => Subsystem::XBOX,
            v if v == Subsystem::WindowsBootApplication as u16 => Subsystem::WindowsBootApplication,
            _ => Subsystem::Unknown,
        }
    }
}

impl Subsystem {
    pub fn as_static_str(&self) -> &'static str {
        return self.into();
    }
}

/*
 * DLL Characteristics
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DLLCharacteristicsFlags {
    Reserved1 = 0x0001,           // Reserved, must be zero.
    Reserved2 = 0x0002,           // Reserved, must be zero
    Reserved4 = 0x0004,           // Reserved, must be zero.
    Reserved8 = 0x0008,           // Reserved, must be zero.
    HighEntropyVA = 0x0020,       // Image can handle a high entropy 64-bit virtual address space.
    DynamicBase = 0x0040,         // DLL can be relocated at load time.
    ForceIntegrity = 0x0080,      // Code Integrity checks are enforced.
    NXCompat = 0x0100,            // Image is NX compatible.
    NoIsolation = 0x0200,         // Isolation aware, but do not isolate the image.
    NoSeh = 0x0400, // Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NoBind = 0x0800, // Do not bind the image.
    AppContainer = 0x1000, // Image must execute in an AppContainer.
    WdmDriver = 0x2000, // A WDM driver.
    GuardCf = 0x4000, // Image supports Control Flow Guard.
    TerminalServerAware = 0x8000, // Terminal Server
}

impl DLLCharacteristicsFlags {
    pub fn flags_as_string(characteristics: u16) -> String {
        let flags: Vec<&'static str> = DLLCharacteristicsFlags::iter()
            .filter(|&flag| (flag as u16 & characteristics) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }
}

/*
 * Optional Header for 32/32+ images
 */

/* Magic number for 32 bits PE */
const PE_FORMAT_32_MAGIC: u16 = 0x10b;

/* Magic number for 64 bits PE (PE32+ in the doc) */
const PE_FORMAT_64_MAGIC: u16 = 0x20b;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader32 {
    /* Standard Fields */
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,

    /* Windows Specific Fields */
    image_base: u32,
    section_alignment: u32,
    file_alignement: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32, /* reserved field */
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory, /* reserved field */
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    import_address_table: ImageDataDirectory, /* IAT */
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    zero: ImageDataDirectory, /* reserved field */
}

impl OptionalHeader32 {
    fn new() -> OptionalHeader32 {
        return OptionalHeader32::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<OptionalHeader32, Box<dyn Error>> {
        let mut header: OptionalHeader32 = OptionalHeader32::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.base_of_data = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u32::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u32::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

        return Ok(header);
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("Optional Header (32-bits)", "", label_pad, 0);

        let field_name_pad = (pad + 1) * pad_sz;
        let field_pad = (pad + 2) * pad_sz;
        let field_align = 30;

        dump_field("Standard Fields", "", field_name_pad, 0);

        dump_field(
            "Magic",
            format!("{:#x}", self.magic),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorLinkerVersion",
            format!("{:#x}", self.major_linker_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorLinkerVersion",
            format!("{:#x}", self.minor_linker_version),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfCode",
            format!("{:#x}", self.size_of_code),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfInitializedData",
            format!("{:#x}", self.size_of_initialized_data),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfUninitializedData",
            format!("{:#x}", self.size_of_uninitialized_data),
            field_pad,
            field_align,
        );
        dump_field(
            "AddressOfEntryPoint",
            format!("{:#x}", self.address_of_entry_point),
            field_pad,
            field_align,
        );
        dump_field(
            "BaseOfCode",
            format!("{:#x}", self.base_of_code),
            field_pad,
            field_align,
        );
        dump_field(
            "BaseOfData",
            format!("{:#x}", self.base_of_data),
            field_pad,
            field_align,
        );

        dump_field("Windows Specific Fields", "", field_name_pad, 0);

        dump_field(
            "ImageBase",
            format!("{:#x}", self.image_base),
            field_pad,
            field_align,
        );
        dump_field(
            "SectionAlignment",
            format!("{:#x}", self.section_alignment),
            field_pad,
            field_align,
        );
        dump_field(
            "FileAlignement",
            format!("{:#x}", self.file_alignement),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorOperatingSystemVersion",
            format!("{:#x}", self.major_operating_system_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorOperatingSystemVersion",
            format!("{:#x}", self.minor_operating_system_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorImageVersion",
            format!("{:#x}", self.major_image_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorImageVersion",
            format!("{:#x}", self.minor_image_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorSubsystemVersion",
            format!("{:#x}", self.major_subsystem_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorSubsystemVersion",
            format!("{:#x}", self.minor_subsystem_version),
            field_pad,
            field_align,
        );
        dump_field(
            "Win32VersionValue",
            format!("{:#x}", self.win32_version_value),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfImage",
            format!("{:#x}", self.size_of_image),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeaders",
            format!("{:#x}", self.size_of_headers),
            field_pad,
            field_align,
        );
        dump_field(
            "Checksum",
            format!("{:#x}", self.checksum),
            field_pad,
            field_align,
        );
        dump_field(
            "Subsystem",
            format!(
                "{:#x} ({})",
                self.subsystem,
                Subsystem::from(self.subsystem).as_static_str()
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "DLLCharacteristics",
            format!(
                "{:#x} ({})",
                self.dll_characteristics,
                DLLCharacteristicsFlags::flags_as_string(self.dll_characteristics)
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfStackReserve",
            format!("{:#x}", self.size_of_stack_reserve),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfStackCommit",
            format!("{:#x}", self.size_of_stack_commit),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeapReserve",
            format!("{:#x}", self.size_of_heap_reserve),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeapCommit",
            format!("{:#x}", self.size_of_heap_commit),
            field_pad,
            field_align,
        );
        dump_field(
            "LoaderFlags",
            format!("{:#x}", self.loader_flags),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfRvaAndSizes",
            format!("{:#x}", self.number_of_rva_and_sizes),
            field_pad,
            field_align,
        );

        dump_field("Data Directories", "", field_name_pad, 0);

        dump_field(
            "ExportTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.export_table.virtual_address, self.export_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ImportTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.import_table.virtual_address, self.import_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ResourceTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.resource_table.virtual_address, self.resource_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ExceptionTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.exception_table.virtual_address, self.exception_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "CertificateTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.certificate_table.virtual_address, self.certificate_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "BaseRelocationTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.base_relocation_table.virtual_address, self.base_relocation_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Debug",
            format!(
                "address: {:#x} sz: {:#x}",
                self.debug.virtual_address, self.debug.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Architecture",
            format!(
                "address: {:#x} sz: {:#x}",
                self.architecture.virtual_address, self.architecture.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "GlobalPtr",
            format!(
                "address: {:#x} sz: {:#x}",
                self.global_ptr.virtual_address, self.global_ptr.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "TLSTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.tls_table.virtual_address, self.tls_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "LoadConfigTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.load_config_table.virtual_address, self.load_config_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "BoundImport",
            format!(
                "address: {:#x} sz: {:#x}",
                self.bound_import.virtual_address, self.bound_import.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ImportAddressTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.import_address_table.virtual_address, self.import_address_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "DelayImportDescriptor",
            format!(
                "address: {:#x} sz: {:#x}",
                self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "CLRRuntimeHeader",
            format!(
                "address: {:#x} sz: {:#x}",
                self.clr_runtime_header.virtual_address, self.clr_runtime_header.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Zero",
            format!(
                "address: {:#x} sz: {:#x}",
                self.zero.virtual_address, self.zero.size
            ),
            field_pad,
            field_align,
        );
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader64 {
    /* Standard Fieds */
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,

    /* Windows Specific Fields */
    image_base: u64,
    section_alignment: u32,
    file_alignement: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32, /* reserved field */
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory, /* reserved field */
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    import_address_table: ImageDataDirectory, /* IAT */
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    zero: ImageDataDirectory, /* reserved field */
}

impl OptionalHeader64 {
    fn new() -> OptionalHeader64 {
        return OptionalHeader64::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<OptionalHeader64, Box<dyn Error>> {
        let mut header: OptionalHeader64 = OptionalHeader64::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u64::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u64::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

        return Ok(header);
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("Optional Header (64-bits)", "", label_pad, 0);

        let field_name_pad = (pad + 1) * pad_sz;
        let field_pad = (pad + 2) * pad_sz;
        let field_align = 30;

        dump_field("Standard Fields", "", field_name_pad, 0);

        dump_field(
            "Magic",
            format!("{:#x}", self.magic),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorLinkerVersion",
            format!("{:#x}", self.major_linker_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorLinkerVersion",
            format!("{:#x}", self.minor_linker_version),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfCode",
            format!("{:#x}", self.size_of_code),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfInitializedData",
            format!("{:#x}", self.size_of_initialized_data),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfUninitializedData",
            format!("{:#x}", self.size_of_uninitialized_data),
            field_pad,
            field_align,
        );
        dump_field(
            "AddressOfEntryPoint",
            format!("{:#x}", self.address_of_entry_point),
            field_pad,
            field_align,
        );
        dump_field(
            "BaseOfCode",
            format!("{:#x}", self.base_of_code),
            field_pad,
            field_align,
        );

        dump_field("Windows Specific Fields", "", field_name_pad, 0);

        dump_field(
            "ImageBase",
            format!("{:#x}", self.image_base),
            field_pad,
            field_align,
        );
        dump_field(
            "SectionAlignment",
            format!("{:#x}", self.section_alignment),
            field_pad,
            field_align,
        );
        dump_field(
            "FileAlignement",
            format!("{:#x}", self.file_alignement),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorOperatingSystemVersion",
            format!("{:#x}", self.major_operating_system_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorOperatingSystemVersion",
            format!("{:#x}", self.minor_operating_system_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorImageVersion",
            format!("{:#x}", self.major_image_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorImageVersion",
            format!("{:#x}", self.minor_image_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MajorSubsystemVersion",
            format!("{:#x}", self.major_subsystem_version),
            field_pad,
            field_align,
        );
        dump_field(
            "MinorSubsystemVersion",
            format!("{:#x}", self.minor_subsystem_version),
            field_pad,
            field_align,
        );
        dump_field(
            "Win32VersionValue",
            format!("{:#x}", self.win32_version_value),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfImage",
            format!("{:#x}", self.size_of_image),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeaders",
            format!("{:#x}", self.size_of_headers),
            field_pad,
            field_align,
        );
        dump_field(
            "Checksum",
            format!("{:#x}", self.checksum),
            field_pad,
            field_align,
        );
        dump_field(
            "Subsystem",
            format!(
                "{:#x} ({})",
                self.subsystem,
                Subsystem::from(self.subsystem).as_static_str()
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "DLLCharacteristics",
            format!(
                "{:#x} ({})",
                self.dll_characteristics,
                DLLCharacteristicsFlags::flags_as_string(self.dll_characteristics)
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfStackReserve",
            format!("{:#x}", self.size_of_stack_reserve),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfStackCommit",
            format!("{:#x}", self.size_of_stack_commit),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeapReserve",
            format!("{:#x}", self.size_of_heap_reserve),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfHeapCommit",
            format!("{:#x}", self.size_of_heap_commit),
            field_pad,
            field_align,
        );
        dump_field(
            "LoaderFlags",
            format!("{:#x}", self.loader_flags),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfRvaAndSizes",
            format!("{:#x}", self.number_of_rva_and_sizes),
            field_pad,
            field_align,
        );

        dump_field("Data Directories", "", field_name_pad, 0);

        dump_field(
            "ExportTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.export_table.virtual_address, self.export_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ImportTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.import_table.virtual_address, self.import_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ResourceTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.resource_table.virtual_address, self.resource_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ExceptionTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.exception_table.virtual_address, self.exception_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "CertificateTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.certificate_table.virtual_address, self.certificate_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "BaseRelocationTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.base_relocation_table.virtual_address, self.base_relocation_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Debug",
            format!(
                "address: {:#x} sz: {:#x}",
                self.debug.virtual_address, self.debug.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Architecture",
            format!(
                "address: {:#x} sz: {:#x}",
                self.architecture.virtual_address, self.architecture.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "GlobalPtr",
            format!(
                "address: {:#x} sz: {:#x}",
                self.global_ptr.virtual_address, self.global_ptr.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "TLSTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.tls_table.virtual_address, self.tls_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "LoadConfigTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.load_config_table.virtual_address, self.load_config_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "BoundImport",
            format!(
                "address: {:#x} sz: {:#x}",
                self.bound_import.virtual_address, self.bound_import.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "ImportAddressTable",
            format!(
                "address: {:#x} sz: {:#x}",
                self.import_address_table.virtual_address, self.import_address_table.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "DelayImportDescriptor",
            format!(
                "address: {:#x} sz: {:#x}",
                self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "CLRRuntimeHeader",
            format!(
                "address: {:#x} sz: {:#x}",
                self.clr_runtime_header.virtual_address, self.clr_runtime_header.size
            ),
            field_pad,
            field_align,
        );
        dump_field(
            "Zero",
            format!(
                "address: {:#x} sz: {:#x}",
                self.zero.virtual_address, self.zero.size
            ),
            field_pad,
            field_align,
        );
    }
}

#[derive(Debug, Clone)]
pub enum OptionalHeader {
    PE32(OptionalHeader32),
    PE64(OptionalHeader64),
}

impl Default for OptionalHeader {
    fn default() -> Self {
        return OptionalHeader::PE64(OptionalHeader64::default());
    }
}

impl OptionalHeader {
    pub fn dump(&self, pad: usize, pad_sz: usize) {
        match self {
            OptionalHeader::PE32(h) => h.dump(pad, pad_sz),
            OptionalHeader::PE64(h) => h.dump(pad, pad_sz),
        }
    }
}

/*
 * Section Flags
 */

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionFlags {
    Reserved0 = 0x00000000,           // Reserved for future use.
    Reserved1 = 0x00000001,           // Reserved for future use.
    Reserved2 = 0x00000002,           // Reserved for future use.
    Reserved4 = 0x00000004,           // Reserved for future use.
    TypeNoPad = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    Reserved10 = 0x00000010, // Reserved for future use.
    CntCode = 0x00000020,   // The section contains executable code.
    CntInitializedData = 0x00000040, // The section contains initialized data.
    CntUninitializedData = 0x0000080, // The section contains uninitialized data.
    LnkOther = 0x00000100,  // Reserved for future use.
    LnkInfo = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    Reserved400 = 0x00000400, // Reserved for future use.
    LnkRemove = 0x00000800, // The section will not become part of the image. This is valid only for object files.
    LnkComdat = 0x00001000, // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    GPRel = 0x00008000,     // The section contains data referenced through the global pointer (GP).
    MemPurgeable = 0x00020000, // Reserved for future use.
    MemLocked = 0x00040000, // Reserved for future use.
    MemPreload = 0x00080000, // Reserved for future use.
    Align1Bytes = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
    Align2Bytes = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
    Align4Bytes = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
    Align8Bytes = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
    Align16Bytes = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
    Align32Bytes = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
    Align64Bytes = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
    Align128Bytes = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
    Align256Bytes = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
    Align512Bytes = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
    Align1024Bytes = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
    Align2048Bytes = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
    Align4096Bytes = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
    Align8192Bytes = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
    LnkNRelocOVFL = 0x01000000,  // The section contains extended relocations.
    MemDiscardable = 0x02000000, // The section can be discarded as needed.
    MemNotCached = 0x04000000,   // The section cannot be cached.
    MemNotPaged = 0x08000000,    // The section is not pageable.
    MemShared = 0x10000000,      // The section can be shared in memory.
    MemExecute = 0x20000000,     // The section can be executed as code.
    MemRead = 0x40000000,        // The section can be read.
    MemWrite = 0x80000000,       // The section can be written to.
}

impl SectionFlags {
    pub fn flags_as_string(section_flags: u32) -> String {
        let flags: Vec<&'static str> = SectionFlags::iter()
            .filter(|&flag| (flag as u32 & section_flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }
}

/*
 * Section
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub ptr_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    fn new() -> SectionHeader {
        return SectionHeader::default();
    }

    fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<SectionHeader, Box<dyn std::error::Error>> {
        let mut header = SectionHeader::new();

        let first_name_byte = cursor.read_u8()?;

        if first_name_byte == 0x2F as u8 {
            // "/"
            todo!("Need to implement section header name finding in string table");
        } else if first_name_byte == 0x0 as u8 {
            // "\0"
            header.name = "empty".to_string();
            cursor.set_position(cursor.position() + 39);

            return Ok(header);
        } else {
            let mut name_buffer: Vec<u8> = Vec::new();

            name_buffer.push(first_name_byte);

            for _ in 0..7 {
                let c = cursor.read_u8()?;

                if c == '\0' as u8 {
                    continue;
                }

                name_buffer.push(c);
            }

            header.name = String::from_utf8(name_buffer).expect("Invalid section name found in PE");
        }

        header.virtual_size = cursor.read_u32::<LittleEndian>()?;
        header.virtual_address = cursor.read_u32::<LittleEndian>()?;
        header.size_of_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.ptr_to_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_relocations = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_line_numbers = cursor.read_u32::<LittleEndian>()?;
        header.number_of_relocations = cursor.read_u16::<LittleEndian>()?;
        header.number_of_line_numbers = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }

    pub fn dump(&self, pad: usize, pad_sz: usize) {
        let label_pad = pad * pad_sz;

        dump_field("Section Header", &self.name, label_pad, 0);

        let field_pad = (pad + 1) * pad_sz;
        let field_align = 30;

        dump_field(
            "VirtualSize",
            format!("{:#x}", self.virtual_size),
            field_pad,
            field_align,
        );
        dump_field(
            "VirtualAddress",
            format!("{:#x}", self.virtual_address),
            field_pad,
            field_align,
        );
        dump_field(
            "SizeOfRawData",
            format!("{:#x}", self.size_of_raw_data),
            field_pad,
            field_align,
        );
        dump_field(
            "PtrToRawData",
            format!("{:#x}", self.ptr_to_raw_data),
            field_pad,
            field_align,
        );
        dump_field(
            "PointerToRelocations",
            format!("{:#x}", self.pointer_to_relocations),
            field_pad,
            field_align,
        );
        dump_field(
            "PointerToLineNumbers",
            format!("{:#x}", self.pointer_to_line_numbers),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfRelocations",
            format!("{:#x}", self.number_of_relocations),
            field_pad,
            field_align,
        );
        dump_field(
            "NumberOfLineNumbers",
            format!("{:#x}", self.number_of_line_numbers),
            field_pad,
            field_align,
        );
        dump_field(
            "Characteristics",
            format!(
                "{:#x} ({})",
                self.characteristics,
                SectionFlags::flags_as_string(self.characteristics)
            ),
            field_pad,
            field_align,
        );
    }
}

/*
* Typical segment names:
* .text: Code
* .data: Initialized data
* .bss: Uninitialized data
* .rdata: Const/read-only (and initialized) data
* .edata: Export descriptors
* .idata: Import descriptors
* .pdata: Exception information
* .xdata: Stack unwinding information
* .reloc: Relocation table (for code instructions with absolute addressing when the module could not be loaded at its preferred base address)
* .rsrc: Resources (icon, bitmap, dialog, ...)
* .tls: __declspec(thread) data
*/

#[derive(Default, Clone)]
#[repr(C)]
pub struct Section {
    pub header: SectionHeader,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return f
            .debug_struct("Section")
            .field("header", &self.header)
            .finish();
    }
}

impl Section {
    pub fn new(header: SectionHeader, data: Vec<u8>) -> Section {
        return Section {
            header: header,
            data: data,
        };
    }

    pub fn dump(&self, pad: usize, pad_sz: usize, options: &Args) {
        dump_field("Section", "", pad, pad_sz);

        self.header.dump(pad + 1, pad_sz);

        if options.sections_data {
            dump_field("Section Data", "", pad + 1, pad_sz);
            println!("{:?}", self.data);
        }

        if options.disasm {
            if self.header.characteristics & SectionFlags::CntCode as u32 > 0 {
                let label_pad = (pad + 1) * pad_sz;
                let instruction_pad = (pad + 2) * pad_sz;
                dump_field("Section Code", "", label_pad, 0);

                /* TODO: find a way to initialize a global capstone object */
                let cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .detail(false)
                    .build()
                    .expect("Failed to initialized Capstone disasm");

                let instructions = cs.disasm_all(&self.data, 0x0).expect("Failed to disassemble");

                for instruction in instructions.as_ref() {
                    dump_instruction(instruction, instruction_pad);
                }
            }
        }

        println!("");
    }
}

/*
 * Image Import Descriptor (struct found in the Import Table (IDT))
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImageImportDescriptor {
    import_lookup_table_rva: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    import_address_table_rva: u32,
}

impl ImageImportDescriptor {
    pub fn new() -> ImageImportDescriptor {
        return ImageImportDescriptor::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ImageImportDescriptor, Box<dyn std::error::Error>> {
        let mut descriptor = ImageImportDescriptor::new();

        descriptor.import_lookup_table_rva = cursor.read_u32::<LittleEndian>()?;
        descriptor.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        descriptor.forwarder_chain = cursor.read_u32::<LittleEndian>()?;
        descriptor.name_rva = cursor.read_u32::<LittleEndian>()?;
        descriptor.import_address_table_rva = cursor.read_u32::<LittleEndian>()?;

        return Ok(descriptor);
    }

    pub fn is_zeroed_out(&self) -> bool {
        return self.import_lookup_table_rva == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.import_address_table_rva == 0;
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImportLookupEntry {
    by_ordinal: bool,
    ordinal_number: u16,
    hint_name_table_rva: u32,
}

impl ImportLookupEntry {
    pub fn new() -> ImportLookupEntry {
        return ImportLookupEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
        is_32_bits: bool,
    ) -> Result<ImportLookupEntry, Box<dyn std::error::Error>> {
        let mut entry = ImportLookupEntry::new();

        if is_32_bits {
            let data = cursor.read_u32::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x80000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        } else {
            let data = cursor.read_u64::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x8000000000000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        }

        return Ok(entry);
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct HintNameEntry {
    hint: u16,
    name: String,
    pad: bool,
}

impl HintNameEntry {
    pub fn new() -> HintNameEntry {
        return HintNameEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<HintNameEntry, Box<dyn std::error::Error>> {
        let mut entry = HintNameEntry::new();

        entry.hint = cursor.read_u16::<LittleEndian>()?;

        let mut name_buffer: Vec<u8> = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        if (name_buffer.len() % 2) != 0 {
            cursor.read_u8()?;
            entry.pad = true;
        } else {
            entry.pad = false;
        }

        entry.name = String::from_utf8(name_buffer).expect("Invalid name found in Hint/Name Table");

        return Ok(entry);
    }
}

/*
 * PE Header
 */

#[derive(Clone, Debug, Default)]
pub struct PEHeader {
    dos: DOSHeader,
    nt: NTHeader,
    optional: OptionalHeader,
}

/*
 * PE
 */

pub enum PEArchitecture {
    PE32,
    PE64,
}

#[derive(Default, Debug)]
pub struct PE {
    pub header: PEHeader,
    pub sections: HashMap<String, Section>,
    pub import_descriptors: Vec<ImageImportDescriptor>,
    pub dll_names: Vec<String>,
    pub data: Vec<u8>,
}

impl PE {
    pub fn new() -> PE {
        return PE::default();
    }

    pub fn get_architecture(&self) -> PEArchitecture {
        match &self.header.optional {
            OptionalHeader::PE32(_) => return PEArchitecture::PE32,
            OptionalHeader::PE64(_) => return PEArchitecture::PE64,
        }
    }

    pub fn is_32_bits(&self) -> bool {
        match &self.header.optional {
            OptionalHeader::PE32(_) => return true,
            OptionalHeader::PE64(_) => return false,
        }
    }

    pub fn get_size_of_optional_header(&self) -> u64 {
        return self.header.nt.coff_header.size_of_optional_header as u64;
    }

    pub fn get_dos_header(&self) -> &DOSHeader {
        return &self.header.dos;
    }

    pub fn get_optional_header(&self) -> &OptionalHeader {
        return &self.header.optional;
    }

    pub fn get_nt_header(&self) -> &NTHeader {
        return &self.header.nt;
    }

    pub fn get_number_of_sections(&self) -> usize {
        return self.header.nt.coff_header.number_of_sections as usize;
    }

    pub fn get_import_table_idd(&self) -> ImageDataDirectory {
        match &self.header.optional {
            OptionalHeader::PE32(header) => {
                return header.import_table.clone();
            }
            OptionalHeader::PE64(header) => {
                return header.import_table.clone();
            }
        }
    }

    pub fn convert_rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        for section in self.sections.values() {
            let start = section.header.virtual_address;
            let end = start + section.header.virtual_size;

            if rva >= start && rva < end {
                let offset_in_section = (rva - start) as u64;
                return Some(section.header.ptr_to_raw_data as u64 + offset_in_section);
            }
        }

        return None;
    }
}

/*
 * Parse import descriptors. Returns an empty vector if there are no import descriptors
 */
fn parse_import_descriptors(
    pe: &PE,
    cursor: &mut io::Cursor<&Vec<u8>>,
) -> Result<Vec<ImageImportDescriptor>, Box<dyn std::error::Error>> {
    let mut descriptors: Vec<ImageImportDescriptor> = Vec::new();

    let import_table_idd = pe.get_import_table_idd();

    let file_offset = match pe.convert_rva_to_file_offset(import_table_idd.virtual_address) {
        Some(offset) => offset,
        _ => {
            return Ok(descriptors);
        }
    };

    cursor.set_position(file_offset as u64);

    loop {
        let descriptor = ImageImportDescriptor::from_parser(cursor)
            .expect("Cannot parse ImageImportDescriptor from the Import Table");

        if descriptor.is_zeroed_out() {
            break;
        }

        descriptors.push(descriptor);

        if descriptors.len() > 256 {
            break;
        }
    }

    return Ok(descriptors);
}

/*
 * Parse dll names
 */
fn parse_dll_names(
    pe: &PE,
    cursor: &mut io::Cursor<&Vec<u8>>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut dlls: Vec<String> = Vec::new();

    for import_descriptor in &pe.import_descriptors {
        cursor.set_position(
            pe.convert_rva_to_file_offset(import_descriptor.name_rva)
                .ok_or("Import Descriptor Name RVA does not map to any section")?,
        );

        let mut name_buffer: Vec<u8> = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        dlls.push(String::from_utf8(name_buffer).expect("Invalid name found in import names"));
    }

    return Ok(dlls);
}

/*
 * Main parse method that reads from a file, tests if it's a PE file or not, and returns the parsed PE
 */
pub fn parse_pe(file_path: &PathBuf) -> Result<PE, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_path_str: &str = file_path.to_str().expect("Cannot convert file_path to str");

    if !file_path_str.ends_with(".exe") && !file_path_str.ends_with(".dll") {
        return Err("File is not a Portable Executable (.exe | .dll)".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open file");

    let mut pe: PE = PE::new();
    pe.data = file_bytes;

    let mut cursor = io::Cursor::new(&pe.data);

    let dos_header = DOSHeader::from_parser(&mut cursor)?;

    cursor.set_position(dos_header.e_lfanew as u64);

    let nt_header = NTHeader::from_parser(&mut cursor)?;

    let optional_magic: u16 = cursor.read_u16::<LittleEndian>()?;
    cursor.set_position(cursor.position() - 2);

    let start_of_optional_position = cursor.position();

    match optional_magic {
        PE_FORMAT_32_MAGIC => {
            let optional_header: OptionalHeader32 = OptionalHeader32::from_parser(&mut cursor)?;

            pe.header = PEHeader {
                dos: dos_header,
                nt: nt_header,
                optional: OptionalHeader::PE32(optional_header),
            };
        }
        PE_FORMAT_64_MAGIC => {
            let optional_header: OptionalHeader64 = OptionalHeader64::from_parser(&mut cursor)?;

            pe.header = PEHeader {
                dos: dos_header,
                nt: nt_header,
                optional: OptionalHeader::PE64(optional_header),
            };
        }
        _ => {
            return Err("Invalid PE optional header magic".into());
        }
    }

    let end_of_optional_position = cursor.position();
    let optional_size = end_of_optional_position - start_of_optional_position;

    cursor.set_position(cursor.position() + (pe.get_size_of_optional_header() - optional_size));

    for _ in 0..pe.get_number_of_sections() {
        let section_header = SectionHeader::from_parser(&mut cursor)?;

        let previous_position = cursor.position();

        let mut section_data: Vec<u8> = vec![0; section_header.size_of_raw_data as usize];

        cursor.set_position(section_header.ptr_to_raw_data as u64);
        cursor.read_exact(&mut section_data)?;

        pe.sections.insert(
            section_header.name.clone(),
            Section {
                header: section_header,
                data: section_data,
            },
        );

        cursor.set_position(previous_position);
    }

    pe.import_descriptors = parse_import_descriptors(&pe, &mut cursor)?;
    pe.dll_names = parse_dll_names(&pe, &mut cursor)?;

    return Ok(pe);
}
