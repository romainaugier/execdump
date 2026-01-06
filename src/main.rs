use clap::Parser;
use crate::pe::{parse_pe, OptionalHeader};

use std::path::PathBuf;

pub mod pe;

#[derive(Parser, Debug)]
#[command(version, about = "Parser/Dumper for portable executable files on Windows")]
struct Args {
    /// Dumps the legacy MS-DOS compatible header
    #[arg(long, default_value_t = false)]
    dos_header: bool,

    /// Dumps the NT Header (most recent)
    #[arg(long, default_value_t = false)]
    nt_header: bool,

    /// Dumps the Optional (either 32/64) header
    #[arg(long, default_value_t = false)]
    optional_header: bool,

    file_path: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let pe = parse_pe(&args.file_path)?;

    if args.dos_header {
        println!("{:#?}", pe.get_dos_header());
    }

    if args.nt_header {
        println!("{:#?}", pe.get_nt_header());
    }

    if args.optional_header {
        match pe.get_optional_header() {
            OptionalHeader::PE32(header) => println!("{:#?}", header),
            OptionalHeader::PE64(header) => println!("{:#?}", header),
        }
    }

    return Ok(());
}
