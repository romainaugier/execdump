use crate::args::Args;
use crate::config::Config;
use crate::dump::dump_exec;

use execdump_core::elf::parse_elf;
use execdump_core::exec::{ExecType, guess_exectype, Exec};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;

use execdump_core::program::{programs_from_exec, Program};
use execdump_decompiler::analysis::analyze;
use execdump_project::{default_workers, Project};

use clap::Parser;

use std::sync::Arc;

mod args;
mod config;
mod dump;

// Linked for its malloc: the decompiler (LLVM above all) makes many small short lived allocations
#[cfg(target_os = "linux")]
use mimalloc as _;

/// Decompiles every function of the programs with their project and writes the source trees
fn export(exec: &Exec, args: &Args, dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let programs: Vec<Arc<Program>> = programs_from_exec(exec).into_iter().map(Arc::new).collect();
    let count = programs.len();

    for (index, program) in programs.into_iter().enumerate() {
        let analysis = Arc::new(analyze(&program, None)?);
        let name = program.name.clone();
        let mut project = Project::open(index, count, program, analysis, &args.file_path, args.project.clone(), default_workers() + 1);
        let out = if count > 1 { dir.join(format!("p{}", index)) } else { dir.to_path_buf() };

        let (_, total) = project.progress();
        eprintln!("Decompiling {} functions ({})...", total, name);
        project.wait_idle();

        let report = project.export(&out)?;
        eprintln!("Exported {} functions in {} files to {}", report.functions, report.files, report.dir.display());

        for function in report.conflicts {
            eprintln!("  {}: unresolved conflict between its edits and the decompiled code", function);
        }
    }

    return Ok(());
}

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
        return execdump_tui::main(&args.file_path, exec, config.keys, config.llm, args.project.clone());
    } else {
        dump_exec(&exec, &args, &config);
    }

    if let Some(dir) = args.export.as_ref() {
        export(&exec, &args, dir)?;
    }

    return Ok(());
}
