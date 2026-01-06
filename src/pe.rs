use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::path::PathBuf;

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
    e_res: [u16; 4],     // Reserved words
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
}

/*
 * Machine Types (machine field in COFF Header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,   // The content of this field is assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_ALPHA = 0x184,        // Alpha AXP, 32-bit address space
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284,      // Alpha 64, 64-bit address space
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,         // Matsushita AM33
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,       // x64
    IMAGE_FILE_MACHINE_ARM = 0x1c0,          // ARM little endian
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,       // ARM64 little endian
    IMAGE_FILE_MACHINE_ARM64EC = 0xA641,     // ABI that enables interoperability between native ARM64 and emulated x64 code.
    IMAGE_FILE_MACHINE_ARM64X = 0xA64E,      // Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,        // ARM Thumb-2 little endian
    // IMAGE_FILE_MACHINE_AXP64 = 0x284,        // AXP 64 (Same as Alpha 64)
    IMAGE_FILE_MACHINE_EBC = 0xebc,          // EFI byte code
    IMAGE_FILE_MACHINE_I386 = 0x14c,         // Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_IA64 = 0x200,         // Intel Itanium processor family
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232, // LoongArch 32-bit processor family
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264, // LoongArch 64-bit processor family
    IMAGE_FILE_MACHINE_M32R = 0x9041,        // Mitsubishi M32R little endian
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,       // MIPS16
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,      // MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,    // MIPS16 with FPU
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,      // Power PC little endian
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,    // Power PC with floating point support
    IMAGE_FILE_MACHINE_R3000BE = 0x160,      // MIPS I compatible 32-bit big endian
    IMAGE_FILE_MACHINE_R3000 = 0x162,        // MIPS I compatible 32-bit little endian
    IMAGE_FILE_MACHINE_R4000 = 0x166,        // MIPS III compatible 64-bit little endian
    IMAGE_FILE_MACHINE_R10000 = 0x168,       // MIPS IV compatible 64-bit little endian
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,     // RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,     // RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,    // RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_SH3 = 0x1a2,          // Hitachi SH3
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,       // Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,          // Hitachi SH4
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,          // Hitachi SH5
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,        // Thumb
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,    // MIPS little-endian WCE v2
}

/*
 * Characteristics Flags (characteristics field in COFF header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharacteristicsFlag {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,          // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,         // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,       // COFF line numbers have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,      // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,       // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,      // Application can handle > 2-GB addresses.
	IMAGE_FILE_UNUSED_FLAG = 0x0040,              // This flag is reserved for future use.
	IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,        // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
	IMAGE_FILE_32BIT_MACHINE = 0x0100,            // Machine is based on a 32-bit-word architecture.
	IMAGE_FILE_DEBUG_STRIPPED = 0x0200,           // Debugging information is removed from the image file.
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,  // If the image is on removable media, fully load it and copy it to the swap file.
	IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,        // If the image is on network media, fully load it and copy it to the swap file.
	IMAGE_FILE_SYSTEM = 0x1000,                   // The image file is a system file, not a user program.
	IMAGE_FILE_DLL = 0x2000,                      // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
	IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,           // The file should be run only on a uniprocessor machine.
	IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,        // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
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

    pub fn dump(&self) {

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
    pub fn new(header: SectionHeader) -> Section {
        return Section { header: header };
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

        pe.sections.insert(
            section_header.name.clone(),
            Section {
                header: section_header,
            },
        );
    }

    pe.import_descriptors = parse_import_descriptors(&pe, &mut cursor)?;
    pe.dll_names = parse_dll_names(&pe, &mut cursor)?;

    return Ok(pe);
}
