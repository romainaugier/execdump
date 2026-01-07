use clap::Parser;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Parser/Dumper for portable executable files on Windows")]
pub struct Args {
    /// Dumps the legacy MS-DOS compatible header
    #[arg(long, default_value_t = false)]
    pub dos_header: bool,

    /// Dumps the NT Header (most recent)
    #[arg(long, default_value_t = false)]
    pub nt_header: bool,

    /// Dumps the Optional (either 32/64) header
    #[arg(long, default_value_t = false)]
    pub optional_header: bool,

    /// Dumps the Sections
    #[arg(long, default_value_t = false)]
    pub sections: bool,

    /// Regulax expresion to filter the Sections to display
    #[arg(long, default_value = ".*")]
    pub sections_filter: String,

    /// Dumps the Sections data along with the headers
    #[arg(long, default_value_t = false)]
    pub sections_data: bool,

    /// Disassemble the code found in the sections
    #[arg(long, default_value_t = false)]
    pub disasm: bool,

    /// Padding size to apply when dumping information for better readability
    #[arg(long, default_value_t = 4)]
    pub padding_size: usize,

    pub file_path: PathBuf,
}
