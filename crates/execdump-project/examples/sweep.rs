/*
 * Decompiles every function of binaries and reports the panics (by location) and the errors. Built with
 * overflow checks, it finds the arithmetic that overflows:
 *
 * CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
 *     cargo run --release --target-dir target/checked -p execdump-project --example sweep -- <binaries...>
 *
 * SWEEP_TRACE=1 prints each function before it is decompiled (the last ones printed hang or crash),
 * SWEEP_WORKERS sets the number of threads, SWEEP_STACK their stack size in bytes (a small one finds the
 * deepest recursions).
 */

use execdump_core::crash;
use execdump_core::elf::parse_elf;
use execdump_core::exec::{guess_exectype, Exec, ExecType};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;
use execdump_core::program::programs_from_exec;
use execdump_decompiler::analysis::analyze;
use execdump_decompiler::Decompiler;
use execdump_project::annotations::FunctionNotes;
use execdump_project::service::render;

#[cfg(target_os = "linux")]
use mimalloc as _;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
struct Report {
    functions: usize,
    failed: usize,
    /// Panic message to the number of functions and the first of them
    panics: BTreeMap<String, (usize, String)>,
    /// Same for the errors, without the words with digits (addresses, values)
    errors: BTreeMap<String, (usize, String)>,
}

fn error_kind(text: &str) -> String {
    let message = text.split("decompilation failed: ").nth(1).unwrap_or(text).trim();
    let mut kind = String::new();

    for word in message.split_whitespace() {
        let number = word.chars().any(|c| c.is_ascii_digit());
        kind.push_str(if number { "N" } else { word });
        kind.push(' ');
    }

    return kind.trim_end().chars().take(120).collect();
}

fn main() {
    crash::install();

    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    let workers = std::env::var("SWEEP_WORKERS").ok().and_then(|w| w.parse().ok()).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let mut total = Report::default();

    for path in paths.iter() {
        let start = Instant::now();
        let report = match crash::catch(|| sweep(path, workers)) {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                println!("{}: {}", path.display(), error);
                continue;
            }
            Err(panic) => {
                println!("{}: {}", path.display(), panic);
                total.panics.entry(panic).or_insert((0, path.display().to_string())).0 += 1;
                continue;
            }
        };

        let panics: usize = report.panics.values().map(|(count, _)| count).sum();
        println!("{}: {} functions, {} failed, {} panics, {:.2?}", path.display(), report.functions, report.failed, panics, start.elapsed());

        total.functions += report.functions;
        total.failed += report.failed;

        for (message, (count, first)) in report.panics {
            total.panics.entry(message).or_insert((0, first)).0 += count;
        }

        for (message, (count, first)) in report.errors {
            total.errors.entry(message).or_insert((0, first)).0 += count;
        }
    }

    println!("\n{} functions, {} failed", total.functions, total.failed);

    let mut errors: Vec<_> = total.errors.iter().collect();
    errors.sort_by(|a, b| b.1.0.cmp(&a.1.0));

    for (message, (count, first)) in errors {
        println!("{:>6} x error: {} (first: {})", count, message, first);
    }

    for (message, (count, first)) in total.panics.iter() {
        println!("{:>6} x {} (first: {})", count, message, first);
    }
}

fn sweep(path: &PathBuf, workers: usize) -> Result<Report, String> {
    let exec = match guess_exectype(path).map_err(|e| e.to_string())? {
        ExecType::PE => Exec::PE(parse_pe(path).map_err(|e| e.to_string())?),
        ExecType::ELF => Exec::ELF(parse_elf(path).map_err(|e| e.to_string())?),
        ExecType::MachO => Exec::MachO(parse_macho(path).map_err(|e| e.to_string())?),
    };

    let report = Mutex::new(Report::default());

    for program in programs_from_exec(&exec) {
        let analysis = analyze(&program, None).map_err(|e| e.to_string())?;
        let functions: Vec<u64> = analysis.functions.keys().copied().collect();
        let next = AtomicUsize::new(0);
        let trace = std::env::var_os("SWEEP_TRACE").is_some();

        std::thread::scope(|scope| {
            for _ in 0..workers {
                let stack = std::env::var("SWEEP_STACK").ok().and_then(|s| s.parse().ok()).unwrap_or(crash::STACK_SIZE);

                std::thread::Builder::new().stack_size(stack).spawn_scoped(scope, || {
                    let mut decompiler = Decompiler::new(&program, &analysis);

                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&addr) = functions.get(index) else { break };
                        let name = &analysis.functions[&addr].name;

                        if trace {
                            eprintln!("{} {:#x}", name, addr);
                        }

                        let result = crash::catch(|| render(decompiler.as_ref(), addr, &FunctionNotes::default(), None));
                        let mut report = report.lock().unwrap();

                        report.functions += 1;

                        match result {
                            Ok(rendered) if rendered.ok => {}
                            Ok(rendered) => {
                                report.failed += 1;
                                report.errors.entry(error_kind(&rendered.text)).or_insert((0, format!("{} {:#x}", name, addr))).0 += 1;
                            }
                            Err(panic) => {
                                report.failed += 1;
                                report.panics.entry(panic).or_insert((0, format!("{} {:#x}", name, addr))).0 += 1;
                                drop(report);
                                decompiler = Decompiler::new(&program, &analysis);
                            }
                        }
                    }
                }).expect("cannot start a sweep thread");
            }
        });
    }

    return Ok(report.into_inner().unwrap());
}
