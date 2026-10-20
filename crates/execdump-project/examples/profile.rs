/*
 * Timings of the stages of a project on a binary: analysis, background decompilation, cache reload,
 * module grouping, fingerprints and export.
 *
 * cargo run --release -p execdump-project --example profile -- <binary> [workers] [max seconds of decompilation]
 */

use anyhow::{Context, Result};

use execdump_core::elf::parse_elf;
use execdump_core::exec::{guess_exectype, Exec, ExecType};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;
use execdump_core::program::programs_from_exec;
use execdump_decompiler::analysis::analyze;
use execdump_project::Project;

use std::path::PathBuf;

// Same allocator as execdump
#[cfg(target_os = "linux")]
use mimalloc as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(args.next().context("usage: profile <binary> [workers] [seconds]")?);
    let workers: usize = args.next().map_or(Ok(execdump_project::default_workers()), |a| a.parse())?;
    let budget = Duration::from_secs(args.next().map_or(Ok(60), |a| a.parse())?);

    let start = Instant::now();
    let exec = match guess_exectype(&path)? {
        ExecType::PE => Exec::PE(parse_pe(&path)?),
        ExecType::ELF => Exec::ELF(parse_elf(&path)?),
        ExecType::MachO => Exec::MachO(parse_macho(&path)?),
    };
    let program = Arc::new(programs_from_exec(&exec).remove(0));
    println!("parse            {:>8.2?}  ({} symbols)", start.elapsed(), program.symbols.len());

    let start = Instant::now();
    let analysis = Arc::new(analyze(&program, None)?);
    println!("analysis         {:>8.2?}  ({} functions)", start.elapsed(), analysis.functions.len());

    let location = std::env::temp_dir().join("execdump-profile-project");
    let _ = std::fs::remove_dir_all(&location);

    let start = Instant::now();
    let mut project = Project::open(0, 1, program.clone(), analysis.clone(), &path, Some(location.clone()), workers);
    println!("project open     {:>8.2?}  ({} modules, {} functions to decompile)", start.elapsed(), project.modules.len(), project.progress().1);

    let start = Instant::now();
    let mut last = Instant::now();

    while !project.is_idle() && start.elapsed() < budget {
        std::thread::sleep(Duration::from_millis(20));
        project.poll();

        if last.elapsed() > Duration::from_secs(5) {
            let (done, total) = project.progress();
            println!("  ... {}/{} ({:.1}/s)", done, total, done as f64 / start.elapsed().as_secs_f64());
            last = Instant::now();
        }
    }

    let (done, total) = project.progress();
    println!("decompilation    {:>8.2?}  ({}/{} functions, {:.1}/s, {} workers)", start.elapsed(), done, total, done as f64 / start.elapsed().as_secs_f64(), workers);

    let start = Instant::now();
    let mut fingerprints = 0u64;

    for &addr in analysis.functions.keys() {
        fingerprints ^= project.fingerprint(addr);
    }

    println!("fingerprints     {:>8.2?}  ({:x})", start.elapsed(), fingerprints & 0xff);

    let start = Instant::now();
    let mut lines = 0;

    for module in project.modules.names().cloned().collect::<Vec<_>>() {
        for &addr in project.modules.functions(&module) {
            lines += project.line_count(addr).unwrap_or(0);
        }
    }

    println!("line counts      {:>8.2?}  ({} lines)", start.elapsed(), lines);

    let start = Instant::now();
    let mut bytes = 0;

    for &addr in analysis.functions.keys().take(20000) {
        if let Some((rendered, _)) = project.shown(addr) {
            bytes += rendered.text.len();
        }
    }

    println!("shown (20k)      {:>8.2?}  ({} bytes)", start.elapsed(), bytes);

    drop(project);

    // Reopening reads the cache back
    let start = Instant::now();
    let mut project = Project::open(0, 1, program.clone(), analysis.clone(), &path, Some(location.clone()), workers);
    println!("reopen           {:>8.2?}  ({}/{} cached)", start.elapsed(), project.progress().0, project.progress().1);

    if project.is_idle() {
        let start = Instant::now();
        let out = std::env::temp_dir().join("execdump-profile-export");
        let _ = std::fs::remove_dir_all(&out);
        let report = project.export(&out)?;
        println!("export           {:>8.2?}  ({} files)", start.elapsed(), report.files);
        let _ = std::fs::remove_dir_all(&out);
    }

    project.poll();
    let _ = std::fs::remove_dir_all(&location);

    return Ok(());
}
