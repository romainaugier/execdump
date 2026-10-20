/*
 * Debugger: runs a program under gdb (GDB/MI) or lldb (its command line driven with formats of its own), stops it
 * at breakpoints, steps it by instructions, reads its registers, its memory and its call stack.
 *
 * A Backend is a debugger process answering one command at a time. A Session runs a backend on a thread of its
 * own: the interface sends it requests and gets the stops back without waiting for a running program, and the
 * stepping by lines of C is temporary breakpoints at the addresses of the lines (see Until).
 *
 * The addresses are the ones of the running process: the interface adds the load bias (PIE, ASLR) to the
 * addresses of the binary, Started gives it.
 */

mod gdb;
mod lldb;
pub mod mi;
mod pipe;
pub mod session;

pub use session::{Event, Request, Run, Session, Snapshot, Until};

use anyhow::Result;

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Gdb,
    Lldb,
}

impl Kind {
    pub fn name(self) -> &'static str {
        return match self {
            Kind::Gdb => "gdb",
            Kind::Lldb => "lldb",
        };
    }

    pub fn from_name(name: &str) -> Option<Kind> {
        return match name {
            "gdb" => Some(Kind::Gdb),
            "lldb" => Some(Kind::Lldb),
            _ => None,
        };
    }

    /// The debuggers to try, the one of the system first (lldb on macOS, gdb elsewhere)
    fn preferred() -> [Kind; 2] {
        return if cfg!(target_os = "macos") { [Kind::Lldb, Kind::Gdb] } else { [Kind::Gdb, Kind::Lldb] };
    }

    /// Executables of the debugger, versioned ones included (lldb-18 of the LLVM packages)
    fn executables(self) -> &'static [&'static str] {
        return match self {
            Kind::Gdb => &["gdb"],
            Kind::Lldb => &["lldb", "lldb-20", "lldb-19", "lldb-18", "lldb-17"],
        };
    }
}

/// A debugger to run: the one asked for (by kind, at a path) or the first one found in the PATH
pub fn find(kind: Option<Kind>, path: Option<&Path>) -> Option<(Kind, PathBuf)> {
    if let Some(path) = path {
        let name = path.file_name()?.to_string_lossy().to_string();
        let kind = kind.or_else(|| if name.starts_with("lldb") { Some(Kind::Lldb) } else { Some(Kind::Gdb) })?;
        return Some((kind, path.to_path_buf()));
    }

    let kinds: Vec<Kind> = match kind {
        Some(kind) => vec![kind],
        None => Kind::preferred().to_vec(),
    };

    for kind in kinds {
        for name in kind.executables() {
            if let Some(path) = in_path(name) {
                return Some((kind, path));
            }
        }
    }

    return None;
}

fn in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    let suffixes: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };

    return std::env::split_paths(&paths).flat_map(|dir| suffixes.iter().map(move |s| dir.join(format!("{}{}", name, s)))).find(|p| p.is_file());
}

/// Why the program stopped
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    Breakpoint,
    /// End of a step (an instruction, a finish)
    Step,
    Signal(String),
    /// The program is gone, with its exit code (None when killed by a signal)
    Exited(Option<i32>),
    Other(String),
}

impl StopReason {
    pub fn describe(&self) -> String {
        return match self {
            StopReason::Breakpoint => "breakpoint".to_string(),
            StopReason::Step => "step".to_string(),
            StopReason::Signal(name) => format!("signal {}", name),
            StopReason::Exited(Some(code)) => format!("exited with code {}", code),
            StopReason::Exited(None) => "killed".to_string(),
            StopReason::Other(text) => text.clone(),
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub pc: Option<u64>,
    pub reason: StopReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub pc: u64,
    /// Name the debugger gives to the function (its symbols), empty when it has none
    pub function: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    Continue,
    /// One instruction, into the calls
    StepInstruction,
    /// One instruction, over the calls
    NextInstruction,
    /// Until the function of the selected frame returns
    Finish,
}

/// A debugger process, one command at a time
pub trait Backend: Send {
    /// Starts the program stopped at its first instruction, its output (and its errors) written to a file, its
    /// input empty
    fn launch(&mut self, program: &Path, args: &[String], output: &Path) -> Result<Stop>;

    /// Where the binary was loaded: the address of its entry point in the process minus the one of the binary
    fn load_bias(&mut self, link_entry: u64) -> Result<u64>;

    fn insert_breakpoint(&mut self, addr: u64) -> Result<u32>;

    fn delete_breakpoint(&mut self, id: u32) -> Result<()>;

    fn resume(&mut self, how: Resume) -> Result<Stop>;

    /// Values of registers in the selected frame (None for the ones the debugger does not know)
    fn registers(&mut self, names: &[&str]) -> Result<Vec<Option<u128>>>;

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>;

    fn backtrace(&mut self, max: usize) -> Result<Vec<Frame>>;

    fn select_frame(&mut self, index: usize) -> Result<()>;

    fn kill(&mut self);

    /// Process id of the debugger (it is interrupted with a signal while the program runs)
    fn pid(&self) -> u32;
}

/// Starts a debugger
pub fn backend(kind: Kind, path: &Path) -> Result<Box<dyn Backend>> {
    return Ok(match kind {
        Kind::Gdb => Box::new(gdb::Gdb::start(path)?),
        Kind::Lldb => Box::new(lldb::Lldb::start(path)?),
    });
}

/// Hexadecimal number of the debuggers (0x prefix optional)
pub(crate) fn hex(text: &str) -> Option<u64> {
    let text = text.trim();
    return u64::from_str_radix(text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text), 16).ok();
}

/// Words quoted for a POSIX shell (gdb starts the program with one)
pub(crate) fn shell_quote(text: &str) -> String {
    if !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c)) {
        return text.to_string();
    }

    return format!("'{}'", text.replace('\'', "'\\''"));
}
