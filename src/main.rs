use crate::dump::dump_exec;
use crate::pe::parse_pe;
use crate::elf::parse_elf;
use crate::args::Args;
use crate::exec::{ExecType, guess_exectype, Exec};

use clap::Parser;

pub mod pe;
pub mod elf;
pub mod dump;
pub mod args;
pub mod disasm;
pub mod tui;
pub mod format;
pub mod exec;
pub mod reader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let exectype = guess_exectype(&args.file_path)?;

    let exec = match exectype {
        ExecType::PE => Exec::PE(parse_pe(&args.file_path)?),
        ExecType::ELF => Exec::ELF(parse_elf(&args.file_path)?),
    };

    if args.tui {
        return tui::main(&args.file_path, exec);
    } else {
        dump_exec(&exec, &args);
    }


    return Ok(());
}
