use clap::Parser;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Parser/Dumper for portable executable files on Windows")]
pub struct Args {
    /// Opens the executable in the terminal-based user interface for exploration
    #[arg(long, short, default_value_t = false)]
    pub tui: bool,

    /// Dumps the PE legacy MS-DOS compatible header
    #[arg(long, default_value_t = false)]
    pub pe_dos_header: bool,

    /// Dumps the PE NT Header (most recent)
    #[arg(long, default_value_t = false)]
    pub pe_nt_header: bool,

    /// Dumps the PE Optional (either 32/64) header
    #[arg(long, default_value_t = false)]
    pub pe_optional_header: bool,

    /// Dumps the Sections
    #[arg(long, default_value_t = false)]
    pub sections: bool,

    /// Regulax expresion to filter the Sections to display
    #[arg(long, default_value = ".*")]
    pub sections_filter: String,

    /// Dumps the Sections data along with the headers
    #[arg(long, default_value_t = false)]
    pub sections_data: bool,

    /// Disassemble the code found in the Sections containing code
    #[arg(long, default_value_t = false)]
    pub disasm: bool,

    /// Dump all the PE data related to imports, if any
    #[arg(long, default_value_t = false)]
    pub pe_import: bool,

    /// Dump the Import Directory Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_import_directory_table: bool,

    /// Dump the Hint/Name Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_hint_name_table: bool,

    /// Dump the DLLs names imported, if any
    #[arg(long, default_value_t = false)]
    pub pe_dlls: bool,

    /// Dump the debug information from the Debug Directory, if any
    #[arg(long, default_value_t = false)]
    pub pe_debug_directory: bool,

    /// Dump the exception information from the Exception Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_exc_table: bool,

    /// Padding size to apply when dumping information for better readability
    #[arg(long, default_value_t = 4)]
    pub padding_size: usize,

    pub file_path: PathBuf,
}
