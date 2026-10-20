/*
 * Decompiles every function of binaries and reports the panics (by location), the errors and the
 * quality of the C code (lines, copies, gotos, casts, declarations, inline assembly). Built with
 * overflow checks, it finds the arithmetic that overflows:
 *
 * CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
 *     cargo run --release --target-dir target/checked -p execdump-project --example sweep -- <binaries...>
 *
 * SWEEP_TRACE=1 prints each function before it is decompiled (the last ones printed hang or crash),
 * SWEEP_WORKERS sets the number of threads, SWEEP_STACK their stack size in bytes (a small one finds the
 * deepest recursions).
 *
 * SWEEP_COMPILE=1 checks that the C of each function compiles (SWEEP_CC is the compiler, cc by default,
 * SWEEP_SOURCE=file.c keeps the source given to it).
 * SWEEP_REPORT=file.tsv writes the counts of every function, SWEEP_BASELINE=file.tsv compares them with
 * the ones of an earlier report: the totals that changed and the functions that got worse.
 */

use anyhow::{anyhow, Context, Result};

use execdump_core::crash;
use execdump_core::elf::parse_elf;
use execdump_core::exec::{guess_exectype, Exec, ExecType};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;
use execdump_core::program::programs_from_exec;
use execdump_decompiler::analysis::analyze;
use execdump_decompiler::c::quality::Quality;
use execdump_decompiler::types::CType;
use execdump_decompiler::Decompiler;
use execdump_project::annotations::FunctionNotes;
use execdump_project::cache::Rendered;
use execdump_project::service::render_function;

#[cfg(target_os = "linux")]
use mimalloc as _;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Counts of a decompiled function, and whether its C compiles (None when not checked)
#[derive(Clone)]
struct Measured {
    binary: String,
    addr: u64,
    name: String,
    quality: Quality,
    compiles: Option<bool>,
}

#[derive(Default)]
struct Report {
    functions: usize,
    failed: usize,
    /// Panic message to the number of functions and the first of them
    panics: BTreeMap<String, (usize, String)>,
    /// Same for the errors, without the words with digits (addresses, values)
    errors: BTreeMap<String, (usize, String)>,
    measured: Vec<Measured>,
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

fn total(measured: &[Measured]) -> Quality {
    return measured.iter().fold(Quality::default(), |total, m| total + m.quality);
}

fn compiled(measured: &[Measured]) -> Option<(usize, usize)> {
    let checked: Vec<bool> = measured.iter().filter_map(|m| m.compiles).collect();
    return (!checked.is_empty()).then(|| (checked.iter().filter(|&&ok| ok).count(), checked.len()));
}

fn print_quality(measured: &[Measured]) {
    let compiles = compiled(measured).map_or(String::new(), |(ok, checked)| format!(", {} of {} compile", ok, checked));
    println!("    {}{}", total(measured), compiles);
}

fn main() {
    crash::install();

    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    let workers = std::env::var("SWEEP_WORKERS").ok().and_then(|w| w.parse().ok()).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let compiler = match (std::env::var("SWEEP_COMPILE").ok().filter(|v| v != "0"), std::env::var("SWEEP_CC").ok()) {
        (_, Some(cc)) => Some(cc),
        (Some(_), None) => Some("cc".to_string()),
        _ => None,
    };
    let mut total_report = Report::default();

    for path in paths.iter() {
        let start = Instant::now();
        let report = match crash::catch(|| sweep(path, workers, compiler.as_deref())) {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                println!("{}: {:#}", path.display(), error);
                continue;
            }
            Err(panic) => {
                println!("{}: {}", path.display(), panic);
                total_report.panics.entry(panic.to_string()).or_insert((0, path.display().to_string())).0 += 1;
                continue;
            }
        };

        let panics: usize = report.panics.values().map(|(count, _)| count).sum();
        println!("{}: {} functions, {} failed, {} panics, {:.2?}", path.display(), report.functions, report.failed, panics, start.elapsed());
        print_quality(&report.measured);

        total_report.functions += report.functions;
        total_report.failed += report.failed;
        total_report.measured.extend(report.measured);

        for (message, (count, first)) in report.panics {
            total_report.panics.entry(message).or_insert((0, first)).0 += count;
        }

        for (message, (count, first)) in report.errors {
            total_report.errors.entry(message).or_insert((0, first)).0 += count;
        }
    }

    println!("\n{} functions, {} failed", total_report.functions, total_report.failed);
    print_quality(&total_report.measured);

    let mut errors: Vec<_> = total_report.errors.iter().collect();
    errors.sort_by(|a, b| b.1.0.cmp(&a.1.0));

    for (message, (count, first)) in errors {
        println!("{:>6} x error: {} (first: {})", count, message, first);
    }

    for (message, (count, first)) in total_report.panics.iter() {
        println!("{:>6} x {} (first: {})", count, message, first);
    }

    if let Ok(baseline) = std::env::var("SWEEP_BASELINE") {
        match std::fs::read_to_string(&baseline) {
            Ok(text) => compare(&read_report(&text), &total_report.measured),
            Err(error) => println!("{}: {}", baseline, error),
        }
    }

    if let Ok(output) = std::env::var("SWEEP_REPORT") {
        if let Err(error) = std::fs::write(&output, write_report(&total_report.measured)) {
            println!("{}: {}", output, error);
        }
    }
}

fn sweep(path: &PathBuf, workers: usize, compiler: Option<&str>) -> Result<Report> {
    let exec = match guess_exectype(path)? {
        ExecType::PE => Exec::PE(parse_pe(path)?),
        ExecType::ELF => Exec::ELF(parse_elf(path)?),
        ExecType::MachO => Exec::MachO(parse_macho(path)?),
    };

    let report = Mutex::new(Report::default());
    let binary = path.display().to_string();

    for program in programs_from_exec(&exec) {
        let analysis = analyze(&program, None)?;
        let functions: Vec<u64> = analysis.functions.keys().copied().collect();
        let next = AtomicUsize::new(0);
        let trace = std::env::var_os("SWEEP_TRACE").is_some();
        // Texts of the functions to compile and the types of their globals, by index in the measured functions
        let texts: Mutex<Vec<(usize, Rendered, Globals)>> = Mutex::new(Vec::new());
        let types: Mutex<Option<String>> = Mutex::new(None);

        let shared = execdump_decompiler::decompiler::SharedSignatures::default();

        std::thread::scope(|scope| {
            for _ in 0..workers {
                let stack = std::env::var("SWEEP_STACK").ok().and_then(|s| s.parse().ok()).unwrap_or(crash::STACK_SIZE);

                std::thread::Builder::new().stack_size(stack).spawn_scoped(scope, || {
                    let mut decompiler = Decompiler::new(&program, &analysis).map(|d| d.with_shared_signatures(shared.clone()));

                    if let (Ok(decompiler), Some(_)) = (decompiler.as_ref(), compiler) {
                        types.lock().unwrap().get_or_insert_with(|| decompiler.typedb.to_c());
                    }

                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&addr) = functions.get(index) else { break };
                        let name = &analysis.functions[&addr].name;

                        if trace {
                            eprintln!("{} {:#x}", name, addr);
                        }

                        let result = crash::catch(|| {
                            let decompiler = decompiler.as_ref().map_err(|e| anyhow!("{:#}", e))?;
                            let function = decompiler.c_function(addr)?;
                            let rendered = render_function(decompiler, function.clone(), &FunctionNotes::default(), None);
                            let quality = function.quality(rendered.line_count());
                            Ok::<_, anyhow::Error>((rendered, quality, function.globals))
                        });

                        let mut report = report.lock().unwrap();
                        report.functions += 1;

                        match result {
                            Ok(Ok((rendered, quality, globals))) => {
                                report.measured.push(Measured { binary: binary.clone(), addr, name: name.clone(), quality, compiles: None });

                                if compiler.is_some() {
                                    texts.lock().unwrap().push((report.measured.len() - 1, rendered, globals));
                                }
                            }
                            Ok(Err(error)) => {
                                report.failed += 1;
                                report.errors.entry(error_kind(&format!("{:#}", error))).or_insert((0, format!("{} {:#x}", name, addr))).0 += 1;
                            }
                            Err(panic) => {
                                report.failed += 1;
                                report.panics.entry(panic.to_string()).or_insert((0, format!("{} {:#x}", name, addr))).0 += 1;
                                drop(report);
                                decompiler = Decompiler::new(&program, &analysis).map(|d| d.with_shared_signatures(shared.clone()));
                            }
                        }
                    }
                }).expect("cannot start a sweep thread");
            }
        });

        if let (Some(compiler), Some(types)) = (compiler, types.into_inner().unwrap()) {
            let mut texts = texts.into_inner().unwrap();
            texts.sort_by_key(|(index, ..)| *index);

            let results = compile(compiler, &types, program.pointer_size, &texts)?;
            let mut report = report.lock().unwrap();

            for ((index, ..), ok) in texts.iter().zip(results) {
                report.measured[*index].compiles = Some(ok);
            }
        }
    }

    return Ok(report.into_inner().unwrap());
}

/*
 * Compilation of the C code: every function in one translation unit, after the types of the type
 * database, the prototypes of the functions they use and their globals (as byte arrays, like the
 * export). A function compiles when the compiler reports no error in its lines.
 */

const BASE_TYPES: &str = "typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
typedef uint8_t undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef struct { uint8_t bytes[16]; } undefined16;
#define bool _Bool
#define true 1
#define false 0
#define NULL ((void *)0)
";

/// The helpers the decompiler calls for what C cannot express
const HELPERS: &str = "uint8_t __readfsbyte(unsigned long);
uint16_t __readfsword(unsigned long);
uint32_t __readfsdword(unsigned long);
uint64_t __readfsqword(unsigned long);
uint8_t __readgsbyte(unsigned long);
uint16_t __readgsword(unsigned long);
uint32_t __readgsdword(unsigned long);
uint64_t __readgsqword(unsigned long);
void __writefsbyte(unsigned long, uint8_t);
void __writefsword(unsigned long, uint16_t);
void __writefsdword(unsigned long, uint32_t);
void __writefsqword(unsigned long, uint64_t);
void __writegsbyte(unsigned long, uint8_t);
void __writegsword(unsigned long, uint16_t);
void __writegsdword(unsigned long, uint32_t);
void __writegsqword(unsigned long, uint64_t);
void __indirect_jump();
";

type Globals = Vec<(String, Option<CType>)>;

/// Whether the C of each function compiles. The globals of a function are declared with the type it
/// accesses them with (as bytes when its accesses disagree), under a name of their own for each function.
fn compile(compiler: &str, types: &str, pointer_size: u8, texts: &[(usize, Rendered, Globals)]) -> Result<Vec<bool>> {
    let mut source = format!("{}{}\n{}\n", BASE_TYPES, types, HELPERS);
    let defined: BTreeSet<String> = texts.iter().filter_map(|(_, r, _)| defined_name(&r.meta.signature)).collect();

    // Like the export: the functions of the program are declared by their definition, the others by the
    // prototypes their callers use
    let mut decls: BTreeSet<&str> = texts.iter().flat_map(|(_, r, _)| r.meta.decls.iter().map(|d| d.as_str())).filter(|d| defined_name(d).is_none_or(|n| !defined.contains(&n))).collect();
    let declared: BTreeSet<String> = decls.iter().filter_map(|d| defined_name(d)).chain(defined.iter().cloned()).collect();
    let signatures: Vec<String> = texts.iter().map(|(_, r, _)| format!("{};", r.meta.signature)).collect();
    decls.extend(signatures.iter().map(|s| s.as_str()));

    // The structs recovered by the functions appear in their prototypes before their definition
    let tags: BTreeSet<String> = decls.iter().flat_map(|d| execdump_decompiler::c::ast::struct_tags(d)).collect();
    tags.iter().for_each(|tag| source.push_str(&format!("struct {};\n", tag)));
    decls.iter().for_each(|d| source.push_str(&format!("{}\n", d)));

    // The structs are defined once before the functions: a function uses the ones of its callees
    let split: Vec<(Vec<(String, String)>, String)> = texts.iter().map(|(_, r, _)| execdump_decompiler::c::ast::split_struct_definitions(&r.text)).collect();
    let definitions: BTreeMap<&str, &str> = split.iter().flat_map(|(d, _)| d.iter().map(|(n, t)| (n.as_str(), t.as_str()))).collect();
    definitions.keys().filter(|n| !tags.contains(**n)).for_each(|tag| source.push_str(&format!("struct {};\n", tag)));
    definitions.values().for_each(|d| source.push_str(d));

    // Lines of each function (1 based, end excluded)
    let mut ranges = Vec::new();

    for (number, (_, rendered, accessed)) in texts.iter().enumerate() {
        let mut globals: BTreeMap<&str, Option<&CType>> = accessed.iter().map(|(name, ty)| (name.as_str(), ty.as_ref())).collect();

        for (name, _) in rendered.meta.globals.iter() {
            globals.entry(name.as_str()).or_insert(None);
        }

        globals.retain(|name, _| !defined.contains(*name) && !declared.contains(*name));

        let start = source.lines().count() + 1;

        for (name, ty) in globals.iter() {
            let local = format!("{}__{}", name, number);

            match ty {
                Some(ty) => source.push_str(&format!("extern {};\n", ty.declare(&local))),
                None => source.push_str(&format!("extern undefined {}[];\n", local)),
            }

            source.push_str(&format!("#define {} {}\n", name, local));
        }

        source.push_str(&split[number].1);
        source.push('\n');
        ranges.push((start, source.lines().count() + 1));
        globals.keys().for_each(|name| source.push_str(&format!("#undef {}\n", name)));
    }

    if let Ok(path) = std::env::var("SWEEP_SOURCE") {
        let _ = std::fs::write(path, &source);
    }

    let clang = Command::new(compiler).arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("clang")).unwrap_or(false);
    let mut command = Command::new(compiler);
    command.args(["-x", "c", "-std=gnu11", "-fsyntax-only", "-w", "-Wno-error=implicit-function-declaration", "-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types"]);
    command.arg(if clang { "-ferror-limit=0" } else { "-fmax-errors=0" });

    if pointer_size == 4 {
        command.arg("-m32");
    }

    let mut child = command.arg("-").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().with_context(|| compiler.to_string())?;
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(source.as_bytes()));
    let output = child.wait_with_output().with_context(|| compiler.to_string())?;
    let _ = writer.join();

    let mut errors: Vec<usize> = Vec::new();

    for line in String::from_utf8_lossy(&output.stderr).lines() {
        let mut parts = line.splitn(4, ':');

        if let (Some("<stdin>"), Some(number), Some(_), Some(message)) = (parts.next(), parts.next(), parts.next(), parts.next()) {
            if message.trim_start().starts_with("error") {
                errors.extend(number.parse::<usize>().ok());
            }
        }
    }

    return Ok(ranges.iter().map(|(start, end)| !errors.iter().any(|line| line >= start && line < end)).collect());
}

fn defined_name(signature: &str) -> Option<String> {
    let before = &signature[..signature.find('(')?];
    let start = before.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |i| i + 1);
    return Some(before[start..].to_string()).filter(|n| !n.is_empty());
}

/*
 * Reports: one line per function, compared by binary and address
 */

fn write_report(measured: &[Measured]) -> String {
    let mut out = format!("binary\taddr\tname\t{}\tcompiles\n", Quality::NAMES.join("\t"));

    for m in measured.iter() {
        let values: Vec<String> = m.quality.values().iter().map(|v| v.to_string()).collect();
        let compiles = m.compiles.map_or("-", |ok| if ok { "1" } else { "0" });
        out.push_str(&format!("{}\t{:#x}\t{}\t{}\t{}\n", m.binary, m.addr, m.name, values.join("\t"), compiles));
    }

    return out;
}

fn read_report(text: &str) -> Vec<Measured> {
    let mut measured = Vec::new();

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();

        let [binary, addr, name, rest @ ..] = fields.as_slice() else {
            continue;
        };

        let Some(addr) = addr.strip_prefix("0x").and_then(|a| u64::from_str_radix(a, 16).ok()) else {
            continue;
        };

        let values: Vec<usize> = rest.iter().take(Quality::NAMES.len()).filter_map(|v| v.parse().ok()).collect();
        let Some(quality) = Quality::from_values(&values) else {
            continue;
        };

        let compiles = match rest.get(Quality::NAMES.len()) {
            Some(&"1") => Some(true),
            Some(&"0") => Some(false),
            _ => None,
        };

        measured.push(Measured { binary: binary.to_string(), addr, name: name.to_string(), quality, compiles });
    }

    return measured;
}

/// Totals of the functions in both reports, and the functions that got worse
fn compare(baseline: &[Measured], current: &[Measured]) {
    let before: HashMap<(&str, u64), &Measured> = baseline.iter().map(|m| ((m.binary.as_str(), m.addr), m)).collect();
    let pairs: Vec<(&Measured, &Measured)> = current.iter().filter_map(|m| Some((*before.get(&(m.binary.as_str(), m.addr))?, m))).collect();

    let old = pairs.iter().fold(Quality::default(), |total, (b, _)| total + b.quality);
    let new = pairs.iter().fold(Quality::default(), |total, (_, c)| total + c.quality);

    println!("\ncompared with the baseline ({} functions in both):", pairs.len());

    for ((name, a), b) in Quality::NAMES.iter().zip(old.values()).zip(new.values()) {
        let change = if a == 0 { String::new() } else { format!(" ({:+.1}%)", (b as f64 - a as f64) * 100.0 / a as f64) };
        println!("    {:<13} {:>8} -> {:<8}{}", name, a, b, change);
    }

    let compiles = |side: usize| pairs.iter().filter(|p| if side == 0 { p.0.compiles } else { p.1.compiles } == Some(true)).count();
    let broken: Vec<&&Measured> = pairs.iter().filter(|(b, c)| b.compiles == Some(true) && c.compiles == Some(false)).map(|(_, c)| c).collect();

    if pairs.iter().any(|(b, c)| b.compiles.is_some() && c.compiles.is_some()) {
        println!("    {:<13} {:>8} -> {:<8} ({} no longer compile)", "compile", compiles(0), compiles(1), broken.len());
    }

    // Worse: a count went up, sorted by how much
    let mut worse: Vec<(usize, String)> = pairs
        .iter()
        .filter_map(|(b, c)| {
            let increases: Vec<String> = Quality::NAMES.iter().zip(b.quality.values()).zip(c.quality.values()).filter(|((_, a), b)| b > a).map(|((n, a), b)| format!("{} {} -> {}", n, a, b)).collect();
            let amount: usize = b.quality.values().iter().zip(c.quality.values()).map(|(a, b)| b.saturating_sub(*a)).sum();
            (!increases.is_empty()).then(|| (amount, format!("{} {:#x} {}: {}", c.binary, c.addr, c.name, increases.join(", "))))
        })
        .collect();

    worse.sort_by(|a, b| b.0.cmp(&a.0));

    if !worse.is_empty() {
        println!("\n{} functions got worse, the first ones:", worse.len());
        worse.iter().take(20).for_each(|(_, text)| println!("    {}", text));
    }

    broken.iter().take(20).for_each(|m| println!("    no longer compiles: {} {:#x} {}", m.binary, m.addr, m.name));
}
