use crate::args::Args;
use crate::config::Config;
use crate::dump::dump_exec;

use execdump_core::elf::parse_elf;
use execdump_core::exec::{ExecType, guess_exectype, Exec};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;

use clap::Parser;

mod args;
mod config;
mod dump;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let exectype = guess_exectype(&args.file_path)?;

    let exec = match exectype {
        ExecType::PE => Exec::PE(parse_pe(&args.file_path)?),
        ExecType::ELF => Exec::ELF(parse_elf(&args.file_path)?),
        ExecType::MachO => Exec::MachO(parse_macho(&args.file_path)?),
    };

    let config = Config::load()?;

    if args.tui {
        return execdump_tui::main(&args.file_path, exec, config.keys, config.llm);
    } else {
        dump_exec(&exec, &args, &config);
    }

    return Ok(());
}
