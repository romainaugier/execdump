// SPDX-License-Identifier: Apache-2.0

use crate::args::Args;
use crate::config::Config;
use crate::dump::dump_exec;

use anyhow::{Context, Result};

use daedale_core::crash;
use daedale_core::elf::parse_elf;
use daedale_core::exec::{ExecType, guess_exectype, Exec};
use daedale_core::macho::parse_macho;
use daedale_core::pe::parse_pe;

use daedale_core::program::{programs_from_exec, Program};
use daedale_decompiler::analysis::analyze;
use daedale_project::{default_workers, Project};

use clap::Parser;

use std::path::{Path, PathBuf};
use std::sync::Arc;

mod args;
mod config;
mod dump;
mod specs;

// Linked for its malloc: the decompiler (LLVM above all) makes many small short lived allocations
#[cfg(target_os = "linux")]
use mimalloc as _;

/// Decompiles every function of the programs with their project and writes the source trees
fn export(exec: &Exec, path: &PathBuf, args: &Args, dir: &Path) -> Result<()> {
    let programs: Vec<Arc<Program>> = programs_from_exec(exec).into_iter().map(Arc::new).collect();
    let count = programs.len();

    for (index, program) in programs.into_iter().enumerate() {
        let analysis = Arc::new(analyze(&program, None)?);
        let name = program.name.clone();
        let mut project = Project::open(index, count, program, analysis, path, args.project.clone(), default_workers() + 1);
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

fn main() {
    crash::install();

    // The work runs on a thread with a large stack (the decompiler recurses on big functions)
    let main = crash::thread("main").spawn(|| run()).expect("cannot start the main thread");

    match main.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("Error: {:#}", error);
            std::process::exit(1);
        }
        Err(_) => std::process::exit(101),
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    if args.specs {
        return specs::print();
    }

    let path = args.file_path.as_ref().context("missing FILE_PATH")?;

    let exec = match guess_exectype(path).with_context(|| path.display().to_string())? {
        ExecType::PE => parse_pe(path).map(Exec::PE),
        ExecType::ELF => parse_elf(path).map(Exec::ELF),
        ExecType::MachO => parse_macho(path).map(Exec::MachO),
    }
    .with_context(|| format!("cannot parse {}", path.display()))?;

    let config = Config::load()?;

    if args.tui {
        return daedale_tui::main(path, exec, config.keys, config.llm, config.debugger, args.project.clone());
    } else {
        dump_exec(&exec, &args, &config);
    }

    if let Some(dir) = args.export.as_ref() {
        export(&exec, path, &args, dir)?;
    }

    return Ok(());
}
