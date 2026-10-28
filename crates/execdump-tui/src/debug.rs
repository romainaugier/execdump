// SPDX-License-Identifier: Apache-2.0
/*
 * Debugging: the program runs under gdb or lldb (execdump-debugger). Each stop moves the C code to the line the
 * program is at, in the module of its function (another module when a step leaves it), the linear disassembly and
 * the graph of the function follow. The debug view shows the variables of the function with their values, read
 * where the decompiler says they are at that address (a register, a stack slot from the stack pointer at the entry
 * of the function), the registers, the call stack, the breakpoints and the output of the program.
 *
 * The program runs on a pseudo-terminal: its output is there as it writes it (the C library flushes a terminal at
 * each line, a file only when its buffer is full), what :input sends is its input. Without one (Windows) its output
 * goes to a file and its input is empty.
 *
 * Steps go by lines of C: the program continues to the addresses of the lines of the function (in its frame, not in
 * a recursive call) and to the return address; a step into the calls also stops at the entry of the functions it
 * calls. A function not decompiled yet has no lines: its steps are instructions.
 *
 * The breakpoints are addresses of the binary: the load bias of the process (PIE, ASLR) is added when they are
 * given to the debugger.
 */

use super::*;

use crate::views::debug::DebugView;

use anyhow::bail;

use execdump_debugger::session::Config as SessionConfig;
use execdump_debugger::{find, Event, Kind, Request, Run, Session, Snapshot, Until};
use execdump_decompiler::analysis::function::CallTarget;
use execdump_decompiler::lang::Languages;
use execdump_decompiler::lift::regs::RegisterFile;
use execdump_decompiler::storage::{location_at, stack_offset_at, Place, Shape};

use std::collections::{BTreeSet, HashSet};

/// Bytes read at the address of a pointer to text
const TEXT_READ: usize = 96;
/// Lines of the output of the program kept for the view
const OUTPUT_LINES: usize = 200;
/// Bytes of the end of the output the lines are read from
const OUTPUT_TAIL: usize = 64 << 10;

/// The [debugger] section of ~/.execdumprc
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct DebuggerConfig {
    /// gdb or lldb (the one of the system without it: lldb on macOS, gdb elsewhere)
    pub backend: Option<String>,
    /// Executable of the debugger
    pub path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DebugAction {
    Continue,
    Step,
    StepOver,
    Finish,
    StepInstruction,
    NextInstruction,
    Interrupt,
    Kill,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DebugState {
    Starting,
    Running,
    Stopped,
    Exited(Option<i32>),
    Ended,
}

pub(crate) struct Debugger {
    session: Session,
    pub kind: Kind,
    pub program: usize,
    pub bias: u64,
    pub state: DebugState,
    pub snapshot: Option<Snapshot>,
    /// Memory read since the stop
    memory: Vec<(u64, Vec<u8>)>,
    requested: HashSet<u64>,
    /// The memory of the process of the program (/proc/<pid>/mem): read while it runs too
    #[cfg(target_os = "linux")]
    process_memory: Option<std::fs::File>,
    /// When the watches read the memory of the program last
    pub last_live: Option<std::time::Instant>,
    /// The file the output goes to without a terminal
    pub output: Option<PathBuf>,
    #[cfg(unix)]
    terminal: Option<execdump_debugger::terminal::Terminal>,
    /// The end of the output
    output_bytes: Vec<u8>,
    pub output_tail: Vec<String>,
    output_len: u64,
    pub regs: RegisterFile,
    /// Registers of the register view, the stack pointer and the program counter among them
    pub shown_registers: Vec<String>,
    /// The first stop: at the breakpoints, or at main (the entry without it)
    first_stop: Option<u64>,
    pub last_error: Option<String>,
    /// The languages of the program: the calls a step goes over
    languages: Languages,
}

/// A variable of the function of the selected frame, its location and its value there
pub(crate) struct Variable {
    pub name: String,
    pub location: String,
    pub value: Option<String>,
}

/// What the views mark: the line of the program counter, the breakpoints (addresses of a program)
#[derive(Clone, Debug, Default)]
pub(crate) struct Marks {
    pub pc: Option<u64>,
    pub breakpoints: Vec<u64>,
}

impl Marks {
    pub fn is_empty(&self) -> bool {
        return self.pc.is_none() && self.breakpoints.is_empty();
    }

    pub fn breakpoint(&self, addr: u64) -> bool {
        return self.breakpoints.binary_search(&addr).is_ok();
    }
}

/// Registers read at each stop: the general ones, then the vector ones (the variables in them)
fn register_names(regs: &RegisterFile) -> (Vec<String>, Vec<String>, String) {
    let (shown, sp): (Vec<&str>, &str) = match regs.arch {
        execdump_core::disasm::Architecture::X86 => (vec!["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"], "esp"),
        execdump_core::disasm::Architecture::Aarch64 => {
            let mut names: Vec<&str> = regs.regs.iter().map(|r| r.name).filter(|n| n.starts_with('x')).collect();
            names.extend(["sp", "pc", "cpsr"]);
            (names, "sp")
        }
        _ => (vec!["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"], "rsp"),
    };

    let vectors = regs.regs.iter().filter(|r| r.bits == 128).map(|r| r.name.to_string());
    let read: Vec<String> = shown.iter().map(|s| s.to_string()).chain(vectors).collect();

    return (read, shown.iter().map(|s| s.to_string()).collect(), sp.to_string());
}

impl Debugger {
    /// Program address of an address of the process (None in the libraries)
    pub fn program_addr(&self, program: &Program, addr: u64) -> Option<u64> {
        let local = addr.wrapping_sub(self.bias);
        return program.region_at(local).filter(|r| r.perms.exec).map(|_| local);
    }

    /// A frame the debugger unwound to code: the program, or a function it knows (the unwinding of the first functions of
    /// a process, or of code without unwind information, gives values of the stack that are not return addresses)
    pub fn is_code(&self, program: &Program, frame: &execdump_debugger::Frame) -> bool {
        return self.program_addr(program, frame.pc).is_some() || (frame.pc >= 0x1000 && !frame.function.is_empty() && frame.function != "??");
    }

    /// Program counter of the selected frame
    pub fn frame_pc(&self) -> Option<u64> {
        let snapshot = self.snapshot.as_ref().filter(|_| self.state == DebugState::Stopped)?;
        return snapshot.frames.get(snapshot.frame).map(|f| f.pc);
    }

    /// Bytes of the memory of the process, from the stack read at the stop or the reads since
    pub fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let snapshot = self.snapshot.as_ref()?;

        if addr >= snapshot.sp && addr + len as u64 <= snapshot.sp + snapshot.stack.len() as u64 {
            let start = (addr - snapshot.sp) as usize;
            return Some(&snapshot.stack[start..start + len]);
        }

        return self.memory.iter().find(|(start, bytes)| addr >= *start && addr + len as u64 <= start + bytes.len() as u64).map(|(start, bytes)| {
            let offset = (addr - start) as usize;
            &bytes[offset..offset + len]
        });
    }

    fn read(&mut self, addr: u64, len: usize) {
        if self.bytes(addr, len).is_none() && self.requested.insert(addr) {
            self.session.send(Request::Read { addr, len });
        }
    }

    /// Asks the debugger for memory (an event brings it)
    pub fn request_read(&mut self, addr: u64, len: usize) {
        self.read(addr, len);
    }

    /// Whether the memory of the program can be read from its process, while it runs too
    pub fn can_read_process(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.process_memory.is_some();

        #[cfg(not(target_os = "linux"))]
        return false;
    }

    /// Bytes from an address to the end of its page, at most 256 (the text a pointer points to), from the process or
    /// what was read: no read is asked for
    pub fn bytes_from(&self, addr: u64) -> Option<Vec<u8>> {
        let len = (0x1000 - (addr & 0xfff) as usize).min(256);

        if let Some(bytes) = self.read_process(addr, len) {
            return Some(bytes);
        }

        let stack = self.snapshot.as_ref().map(|s| (s.sp, s.stack.as_slice()));
        let mut blocks = stack.into_iter().chain(self.memory.iter().map(|(start, bytes)| (*start, bytes.as_slice())));

        return blocks.find(|(start, bytes)| addr >= *start && addr < start + bytes.len() as u64).map(|(start, bytes)| {
            let offset = (addr - start) as usize;
            bytes[offset..(offset + len).min(bytes.len())].to_vec()
        });
    }

    /// Memory read from the process of the program (Linux), None when it cannot be (not mapped)
    pub fn read_process(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::FileExt;

            let file = self.process_memory.as_ref()?;
            let mut bytes = vec![0u8; len];
            let read = file.read_at(&mut bytes, addr).ok()?;
            return (read == len).then_some(bytes);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (addr, len);
            return None;
        }
    }

    /// The last lines of the output of the program, when it wrote some
    fn refresh_output(&mut self) {
        #[cfg(unix)]
        if let Some(terminal) = self.terminal.as_ref() {
            let bytes = terminal.read();

            if bytes.is_empty() {
                return;
            }

            self.output_bytes.extend(bytes);
            let excess = self.output_bytes.len().saturating_sub(OUTPUT_TAIL);
            self.output_bytes.drain(..excess);
            self.output_tail = terminal_lines(&self.output_bytes, OUTPUT_LINES);
            return;
        }

        let Some(output) = self.output.as_ref() else {
            return;
        };

        let Ok(len) = std::fs::metadata(output).map(|m| m.len()) else {
            return;
        };

        if len == self.output_len {
            return;
        }

        self.output_len = len;

        let Ok(bytes) = std::fs::read(output) else {
            return;
        };

        self.output_tail = terminal_lines(&bytes[bytes.len().saturating_sub(OUTPUT_TAIL)..], OUTPUT_LINES);
    }

    /// A line of input of the program
    pub fn input(&mut self, text: &str) -> Result<()> {
        #[cfg(unix)]
        if let Some(terminal) = self.terminal.as_mut() {
            return terminal.write(format!("{}\n", text).as_bytes());
        }

        let _ = text;
        bail!("the program has no terminal to send its input to");
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        if let Some(output) = self.output.as_ref() {
            let _ = std::fs::remove_file(output);
        }
    }
}

/// The last lines of what a program wrote to its terminal: the escape sequences (colors, cursor moves) left out, a
/// carriage return starts its line again (progress bars), the line not ended yet (a prompt) is the last one
pub(crate) fn terminal_lines(bytes: &[u8], max: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\n' => lines.push(std::mem::take(&mut line)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\r' => line.clear(),
            // CSI: ESC [ parameters, then a final byte; OSC: ESC ] text, then BEL or ESC \
            '\x1b' => match chars.next() {
                Some('[') => {
                    while chars.next().is_some_and(|c| !('@'..='~').contains(&c)) {}
                }
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\t' => line.push_str("    "),
            c if c.is_control() => {}
            c => line.push(c),
        }
    }

    if !line.is_empty() {
        lines.push(line);
    }

    return lines.split_off(lines.len().saturating_sub(max));
}

/// A value of a shape from its little endian bytes
fn format_value(shape: Shape, raw: &[u8], text: Option<&[u8]>) -> String {
    let mut bytes = [0u8; 16];
    let n = raw.len().min(16);
    bytes[..n].copy_from_slice(&raw[..n]);
    let value = u128::from_le_bytes(bytes);

    return match shape {
        Shape::Bool => (value & 0xff != 0).to_string(),
        Shape::Int { bytes: 1, signed: true } => {
            let c = value as u8;
            let shown = if c.is_ascii_graphic() || c == b' ' { format!(" '{}'", c as char) } else { String::new() };
            format!("{}{}", c as i8, shown)
        }
        Shape::Int { bytes, signed } => {
            let bits = (bytes as u32 * 8).min(128);
            let masked = if bits >= 128 { value } else { value & ((1u128 << bits) - 1) };

            if signed && bits < 128 && masked >> (bits - 1) & 1 == 1 {
                format!("{}", masked as i128 - (1i128 << bits))
            } else if masked > 0xffff {
                format!("{} ({:#x})", masked, masked)
            } else {
                masked.to_string()
            }
        }
        Shape::Float { bytes: 4 } => format!("{}", f32::from_bits(value as u32)),
        Shape::Float { bytes: 8 } => format!("{}", f64::from_bits(value as u64)),
        Shape::Float { .. } => format!("{:#x}", value),
        Shape::Pointer { text: true } if value != 0 => match text {
            Some(bytes) => {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let more = if end == bytes.len() { "..." } else { "" };
                format!("{:#x} \"{}\"{}", value, String::from_utf8_lossy(&bytes[..end]).escape_debug(), more)
            }
            None => format!("{:#x}", value),
        },
        Shape::Pointer { .. } if value == 0 => "NULL".to_string(),
        Shape::Pointer { .. } | Shape::Unknown => format!("{:#x}", value),
        Shape::Text(_) => {
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            format!("\"{}\"", String::from_utf8_lossy(&raw[..end]).escape_debug())
        }
        Shape::Bytes(_) => raw.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ") + if raw.len() > 32 { " ..." } else { "" },
    };
}

impl App {
    /*
     * Session
     */

    pub(crate) fn start_debugger(&mut self, args: Vec<String>) {
        if let Some(debugger) = self.debugger.take() {
            debugger.session.stop();
        }

        let program = 0;
        let program_ref = self.programs[program].clone();

        let Some(entry) = program_ref.entry else {
            return self.error("The binary has no entry point to start it from".to_string());
        };

        let kind = self.debugger_config.backend.as_deref().and_then(Kind::from_name);

        let Some((kind, path)) = find(kind, self.debugger_config.path.as_deref()) else {
            return self.error("No debugger found: install gdb or lldb, or set [debugger] path in ~/.execdumprc".to_string());
        };

        let regs = RegisterFile::new(program_ref.architecture());
        let (read, shown, stack_pointer) = register_names(&regs);
        // A terminal for the program, else a file for its output
        #[cfg(unix)]
        let terminal = execdump_debugger::terminal::Terminal::open().ok();
        #[cfg(unix)]
        let tty = terminal.as_ref().map(|t| t.path.clone());
        #[cfg(not(unix))]
        let tty: Option<PathBuf> = None;

        let file = tty.is_none().then(|| std::env::temp_dir().join(format!("execdump-{}-output.txt", std::process::id())));

        if let Some(file) = file.as_ref() {
            let _ = std::fs::remove_file(file);
        }

        let output = tty.clone().or(file.clone()).unwrap_or_default();
        let config = SessionConfig { kind, debugger: path, program: self.exec_path.clone(), args, output, input: tty, link_entry: entry, registers: read, stack_pointer };

        // At the first breakpoint, or at main (the entry point without it): the main of the language (main.main of Go:
        // its main is the entry of the runtime), else the one of C
        let languages = Languages::new(&program_ref);
        let names = languages.entry_points();
        let main = names.iter().find_map(|name| self.analyses[program].as_ref().and_then(|a| a.function_by_name(name))).map(|f| f.addr);
        let first_stop = if self.breakpoints.iter().any(|(p, _)| *p == program) { None } else { Some(main.unwrap_or(entry)) };

        self.debugger = Some(Debugger {
            session: Session::start(config),
            kind,
            program,
            bias: 0,
            state: DebugState::Starting,
            snapshot: None,
            memory: Vec::new(),
            requested: HashSet::new(),
            #[cfg(target_os = "linux")]
            process_memory: None,
            last_live: None,
            output: file,
            #[cfg(unix)]
            terminal,
            output_bytes: Vec::new(),
            output_tail: Vec::new(),
            output_len: 0,
            regs,
            shown_registers: shown,
            first_stop,
            last_error: None,
            languages,
        });

        self.show_debug_view();
        self.info(format!("Starting the program under {}...", kind.name()));
    }

    /// The debug view on the right of the code, the code in the current split (main when it is not code)
    fn show_debug_view(&mut self) {
        let shown = self.workspace.group_ids().into_iter().any(|g| {
            let group = self.workspace.group(g);
            matches!(group.tabs[group.active].view, View::Debug(_))
        });

        if shown {
            return;
        }

        if !matches!(self.view(), View::Source(_)) {
            let program = self.debugger.as_ref().map_or(0, |d| d.program);
            let target = self.debugger.as_ref().and_then(|d| d.first_stop).or(self.programs[program].entry);

            if let Some(addr) = target {
                self.open_code(program, addr);
            }
        }

        self.workspace.split(Dir::Right, View::Debug(DebugView::default()));
        self.focus = Focus::Content;
    }

    pub(crate) fn debug_action(&mut self, action: DebugAction) {
        let Some(debugger) = self.debugger.as_ref() else {
            return match action {
                DebugAction::Continue => self.start_debugger(Vec::new()),
                _ => self.error("No program under the debugger: :debug [arguments] starts it".to_string()),
            };
        };

        match action {
            DebugAction::Interrupt => return debugger.session.interrupt(),
            DebugAction::Kill => {
                self.debugger = None;
                return self.info("Program killed".to_string());
            }
            _ => {}
        }

        match &debugger.state {
            DebugState::Stopped => {}
            DebugState::Exited(_) | DebugState::Ended => return self.error("The program is not running: :debug starts it again".to_string()),
            DebugState::Starting | DebugState::Running => return self.error("The program is running: F6 (:interrupt) stops it".to_string()),
        }

        let run = match action {
            DebugAction::Continue => Run::Continue,
            DebugAction::StepInstruction => Run::StepInstruction,
            DebugAction::NextInstruction => Run::NextInstruction,
            DebugAction::Finish => Run::Finish,
            DebugAction::Step => self.line_step(true),
            DebugAction::StepOver => self.line_step(false),
            DebugAction::Interrupt | DebugAction::Kill => return,
        };

        if let Some(debugger) = self.debugger.as_mut() {
            debugger.state = DebugState::Running;
            debugger.session.send(Request::Run(run));
        }
    }

    /// The run of a step to the next line of C of the function (and into its calls)
    fn line_step(&mut self, into: bool) -> Run {
        let App { debugger, projects, programs, .. } = self;

        let Some(debugger) = debugger.as_ref() else {
            return Run::NextInstruction;
        };

        let Some(snapshot) = debugger.snapshot.as_ref() else {
            return Run::NextInstruction;
        };

        // A caller selected in the call stack: until the program is back in it
        if snapshot.frame > 0 {
            let pc = snapshot.frames.get(snapshot.frame).map(|f| f.pc);
            return Run::Until(Until { returns: pc.into_iter().collect(), ..Until::default() });
        }

        let program = &programs[debugger.program];

        // In a library: back to the code of the program
        let Some(pc) = debugger.program_addr(program, snapshot.pc) else {
            return Run::Finish;
        };

        let Some(project) = projects[debugger.program].as_mut() else {
            return Run::NextInstruction;
        };

        let Some(function) = project.analysis.function_containing(pc).cloned() else {
            return Run::NextInstruction;
        };

        let Some((rendered, _)) = project.shown(function.addr) else {
            project.prioritize(&[function.addr], execdump_project::Priority::Visible);
            return if into { Run::StepInstruction } else { Run::NextInstruction };
        };

        let frame = &rendered.meta.frame;
        let offset = |a: u64| stack_offset_at(frame, a.wrapping_sub(function.addr) as u32);
        let bias = debugger.bias;

        let mut stops: Vec<(u64, Option<i64>)> = Vec::new();

        // The functions it calls (their entry in any frame: a recursive call is a step into it), not the growth of the
        // stack of Go
        if into {
            for call in function.calls.iter() {
                if let CallTarget::Function(callee) = call.target {
                    let code = project.analysis.functions.get(&callee).is_some_and(|f| f.thunk.is_none() && !debugger.languages.steps_over(&f.name));

                    if code && !stops.iter().any(|(a, _)| *a == callee + bias) {
                        stops.push((callee + bias, None));
                    }
                }
            }
        }

        let lines: BTreeSet<u64> = rendered.lines.iter().flatten().copied().filter(|&a| function.blocks.values().any(|b| a >= b.start && a < b.end)).collect();
        stops.extend(lines.into_iter().map(|a| (a + bias, offset(a))));

        let entry_sp = offset(pc).map(|o| (snapshot.sp).wrapping_sub(o as u64));
        let returns = snapshot.frames.get(1).filter(|f| debugger.is_code(program, f)).map(|f| f.pc).into_iter().collect();

        return Run::Until(Until { stops, entry_sp, returns });
    }

    /// The frame of the caller of the selected one (up the stack), or of its callee
    pub(crate) fn move_frame(&mut self, up: bool) {
        let Some(snapshot) = self.debugger.as_ref().filter(|d| d.state == DebugState::Stopped).and_then(|d| d.snapshot.as_ref()) else {
            return self.error("The program is not stopped".to_string());
        };

        let frame = snapshot.frame;

        match (up, frame) {
            (true, f) if f + 1 >= snapshot.frames.len() => self.info("At the outermost frame".to_string()),
            (false, 0) => self.info("At the innermost frame".to_string()),
            (true, f) => self.select_frame(f + 1),
            (false, f) => self.select_frame(f - 1),
        }
    }

    /// The frames of the call stack in a popup, Enter selects one
    pub(crate) fn stack_popup(&mut self) {
        let Some(snapshot) = self.debugger.as_ref().filter(|d| d.state == DebugState::Stopped).and_then(|d| d.snapshot.clone()) else {
            return self.error("The program is not stopped".to_string());
        };

        let items: Vec<(String, Target)> = snapshot
            .frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                let marker = if index == snapshot.frame { "▶" } else { " " };
                let module = self.frame_module(frame.pc).map_or(String::new(), |m| format!("  {}", m));
                (format!("{}#{:<2} {:<40} {:#014x}{}", marker, index, self.frame_name(frame.pc, &frame.function), frame.pc, module), Target::Frame(index))
            })
            .collect();

        let cursor = snapshot.frame.min(items.len().saturating_sub(1));
        self.popup = Some(crate::popup::Popup { title: "Call stack (Enter selects the frame)".to_string(), items, cursor });
    }

    /// Module of the function of an address of the process (in the program)
    pub(crate) fn frame_module(&self, pc: u64) -> Option<String> {
        let debugger = self.debugger.as_ref()?;
        let addr = debugger.program_addr(&self.programs[debugger.program], pc)?;
        let function = self.analyses[debugger.program].as_ref()?.function_containing(addr)?.addr;
        return self.projects[debugger.program].as_ref()?.module_of(function).map(|m| m.to_string());
    }

    pub(crate) fn select_frame(&mut self, index: usize) {
        let Some(debugger) = self.debugger.as_mut().filter(|d| d.state == DebugState::Stopped) else {
            return self.error("The program is not stopped".to_string());
        };

        if debugger.snapshot.as_ref().is_some_and(|s| index < s.frames.len()) {
            debugger.state = DebugState::Running;
            debugger.session.send(Request::SelectFrame(index));
        } else {
            self.error(format!("No frame {}", index));
        }
    }

    /*
     * Breakpoints
     */

    pub(crate) fn toggle_breakpoint(&mut self, target: Option<&str>) {
        let program = self.debugger.as_ref().map_or(0, |d| d.program);

        let addr = match target {
            Some(text) => self.resolve_address(program, text),
            None => {
                let App { workspace, projects, .. } = self;
                Self::view_addr(workspace.view(), projects).filter(|(p, _)| *p == program).map(|(_, a)| a)
            }
        };

        let Some(addr) = addr else {
            return self.error(match target {
                Some(text) => format!("Unknown function or address: {}", text),
                None => "No line or instruction of the program under the cursor".to_string(),
            });
        };

        let name = self.address_name(program, addr);

        if self.breakpoints.remove(&(program, addr)) {
            self.info(format!("Breakpoint removed at {}", name));
        } else {
            self.breakpoints.insert((program, addr));
            self.info(format!("Breakpoint at {}", name));
        }

        self.send_breakpoints();
    }

    fn send_breakpoints(&mut self) {
        let Some(debugger) = self.debugger.as_ref().filter(|d| !matches!(d.state, DebugState::Starting | DebugState::Exited(_) | DebugState::Ended)) else {
            return;
        };

        let addrs = self.breakpoints.iter().filter(|(p, _)| *p == debugger.program).map(|(_, a)| a + debugger.bias).collect();
        debugger.session.send(Request::Breakpoints(addrs));
    }

    /// function+0x12 of an address of a program
    pub(crate) fn address_name(&self, program: usize, addr: u64) -> String {
        let function = self.analyses[program].as_ref().and_then(|a| a.function_containing(addr)).map(|f| f.addr);

        return match (function, self.projects[program].as_ref()) {
            (Some(f), Some(project)) if f == addr => project.function_name(f),
            (Some(f), Some(project)) => format!("{}+{:#x}", project.function_name(f), addr - f),
            _ => format!("{:#x}", addr),
        };
    }

    /// Marks of the views of a program: the line of the program counter of the selected frame, the breakpoints
    pub(crate) fn marks(debugger: &Option<Debugger>, breakpoints: &BTreeSet<(usize, u64)>, programs: &[Arc<Program>], program: usize) -> Marks {
        let pc = debugger.as_ref().filter(|d| d.program == program).and_then(|d| d.frame_pc().and_then(|pc| d.program_addr(&programs[program], pc)));
        return Marks { pc, breakpoints: breakpoints.iter().filter(|(p, _)| *p == program).map(|(_, a)| *a).collect() };
    }

    /*
     * Events
     */

    pub(crate) fn poll_debugger(&mut self) {
        let mut stopped = false;
        let mut read = false;
        let mut started = false;

        if let Some(debugger) = self.debugger.as_mut() {
            debugger.refresh_output();

            while let Some(event) = debugger.session.poll() {
                match event {
                    Event::Started { bias, pid, .. } => {
                        debugger.bias = bias;

                        #[cfg(target_os = "linux")]
                        {
                            debugger.process_memory = pid.and_then(|pid| std::fs::File::open(format!("/proc/{}/mem", pid)).ok());
                        }

                        #[cfg(not(target_os = "linux"))]
                        let _ = pid;

                        debugger.state = DebugState::Stopped;
                        started = true;
                    }
                    Event::Running => debugger.state = DebugState::Running,
                    Event::Stopped(snapshot) => {
                        if self.message.as_ref().is_some_and(|(m, _)| m.starts_with("Starting the program")) {
                            self.message = None;
                        }

                        debugger.snapshot = Some(snapshot);
                        debugger.memory.clear();
                        debugger.requested.clear();
                        debugger.state = DebugState::Stopped;
                        stopped = true;
                    }
                    Event::Exited(code) => {
                        debugger.state = DebugState::Exited(code);
                        debugger.snapshot = None;
                        self.message = Some((format!("The program exited{}", code.map_or(" (killed by a signal)".to_string(), |c| format!(" with code {}", c))), false));
                    }
                    Event::Memory { addr, bytes } => {
                        debugger.requested.remove(&addr);
                        debugger.memory.push((addr, bytes));
                        read = true;
                    }
                    Event::Error(error) => {
                        if debugger.state == DebugState::Running {
                            debugger.state = if debugger.snapshot.is_some() { DebugState::Stopped } else { DebugState::Ended };
                        }

                        self.message = Some((format!("{}: {}", debugger.kind.name(), error), true));
                        debugger.last_error = Some(error);
                    }
                    Event::Ended => debugger.state = DebugState::Ended,
                }
            }
        }

        if started {
            self.send_breakpoints();
            let first = self.debugger.as_mut().and_then(|d| d.first_stop.take().map(|a| (a + d.bias, d)));

            if let Some((first, debugger)) = first {
                debugger.state = DebugState::Running;
                debugger.session.send(Request::Run(Run::Until(Until { returns: vec![first], ..Until::default() })));
            } else if let Some(debugger) = self.debugger.as_mut() {
                debugger.state = DebugState::Running;
                debugger.session.send(Request::Run(Run::Continue));
            }
        }

        if stopped || read {
            self.after_stop(stopped);
            self.evaluate_watches(stopped);
            self.value_read(stopped);
        }

        self.watch_live();
    }

    /// The views follow the program counter (at a stop), the memory the variables need is read
    fn after_stop(&mut self, stopped: bool) {
        let Some(debugger) = self.debugger.as_ref() else {
            return;
        };

        let program = debugger.program;
        let pc = debugger.frame_pc().and_then(|pc| debugger.program_addr(&self.programs[program], pc));

        if let (Some(pc), true) = (pc, stopped) {
            self.follow_pc(program, pc);
        }

        // Variables in the memory outside the stack read at the stop, the text of the pointers to text
        let reads: Vec<(u64, usize)> = self.variable_reads();

        if let Some(debugger) = self.debugger.as_mut() {
            for (addr, len) in reads {
                debugger.read(addr, len);
            }
        }
    }

    /// The code, the linear disassembly and the graph shown move to the line of the program counter, the code of
    /// another module replaces the code shown
    fn follow_pc(&mut self, program: usize, pc: u64) {
        let function = self.analyses[program].as_ref().and_then(|a| a.function_containing(pc)).map(|f| f.addr);
        let mut code_shown = false;
        let mut replace: Option<crate::workspace::GroupId> = None;

        for group_id in self.workspace.group_ids() {
            let App { workspace, projects, .. } = self;
            let group = workspace.group_mut(group_id);
            let active = group.active;

            match &mut group.tabs[active].view {
                View::Source(source) if source.program == program => {
                    code_shown = true;

                    if let Some(project) = projects[program].as_mut() {
                        if !source.goto(project, pc) && replace.is_none() {
                            replace = Some(group_id);
                        }
                    }
                }
                View::Disasm(disasm) if disasm.program == program => {
                    disasm.goto(pc);
                }
                View::Graph(graph) if graph.program == program && matches!(graph.kind, GraphKind::Cfg { function: shown } if Some(shown) == function) => {
                    graph.select_addr(pc);
                }
                _ => {}
            }
        }

        // The code of another module: in the split of the code shown, on its jumplist
        if let Some(group_id) = replace {
            if let Some(view) = self.source_view(program, pc) {
                let group = self.workspace.group_mut(group_id);
                let active = group.active;
                let previous = std::mem::replace(&mut group.tabs[active].view, View::Source(view));
                group.tabs[active].back.push(previous);
                group.tabs[active].forward.clear();
            }
        } else if !code_shown && function.is_some() {
            if let Some(view) = self.source_view(program, pc) {
                let focused = self.workspace.focused;
                self.workspace.split(Dir::Left, View::Source(view));
                self.workspace.focused = focused;
            }
        }
    }

    /*
     * Variables
     */

    /// Function and offset of the program counter of the selected frame, in the program
    pub(crate) fn frame_function(&self) -> Option<(u64, u64)> {
        let debugger = self.debugger.as_ref()?;
        let pc = debugger.program_addr(&self.programs[debugger.program], debugger.frame_pc()?)?;
        let function = self.analyses[debugger.program].as_ref()?.function_containing(pc)?.addr;
        return Some((function, pc));
    }

    /// Where a variable is at the program counter, its address in memory (stack slots) or its value (registers,
    /// constants), and its shape
    pub(crate) fn variable_places(&mut self) -> Vec<(String, String, Shape, Option<Result<u128, u64>>)> {
        let Some((function, pc)) = self.frame_function() else {
            return Vec::new();
        };

        let App { debugger, projects, .. } = self;
        let (Some(debugger), Some(project)) = (debugger.as_ref(), projects.get_mut(debugger.as_ref().map_or(0, |d| d.program)).and_then(|p| p.as_mut())) else {
            return Vec::new();
        };

        let Some(snapshot) = debugger.snapshot.as_ref() else {
            return Vec::new();
        };

        let Some((rendered, _)) = project.shown(function) else {
            project.prioritize(&[function], execdump_project::Priority::Visible);
            return Vec::new();
        };

        let meta = &rendered.meta;
        let offset = pc.wrapping_sub(function) as u32;
        let entry_sp = stack_offset_at(&meta.frame, offset).map(|o| snapshot.sp.wrapping_sub(o as u64));
        let mut places = Vec::new();

        for (var, ranges) in meta.storage.iter() {
            let name = meta.vars.get(*var).map_or(format!("v{}", var), |(_, shown)| shown.clone());
            let shape = meta.shapes.get(*var).copied().unwrap_or_default();
            let loc = location_at(ranges, offset);
            let location = loc.map_or("not here".to_string(), |l| l.describe(&debugger.regs));

            let place = loc.and_then(|loc| match loc.place() {
                Place::Register { reg, bits, offset } => {
                    let name = debugger.regs.regs.get(reg)?.name;
                    let value = snapshot.register(name)? >> (offset * 8);
                    let value = if bits >= 128 { value } else { value & ((1u128 << bits) - 1) };
                    Some(Ok(value))
                }
                Place::Stack { offset, .. } => entry_sp.map(|sp| Err(sp.wrapping_add(offset as u64))),
                Place::Constant(value) => Some(Ok(value as u128)),
                Place::None => None,
            });

            places.push((name, location, shape, place));
        }

        return places;
    }

    fn variable_reads(&mut self) -> Vec<(u64, usize)> {
        let pointer_size = self.debugger.as_ref().map_or(8, |d| self.programs[d.program].pointer_size);
        let places = self.variable_places();
        let Some(debugger) = self.debugger.as_ref() else {
            return Vec::new();
        };

        let mut reads = Vec::new();

        for (_, _, shape, place) in places {
            let size = shape.size(pointer_size).clamp(1, 256);

            let value = match place {
                Some(Ok(value)) => Some(value as u64),
                Some(Err(addr)) => match debugger.bytes(addr, size) {
                    Some(bytes) => Some(bytes.iter().take(8).rev().fold(0u64, |v, &b| v << 8 | b as u64)),
                    None => {
                        reads.push((addr, size));
                        None
                    }
                },
                None => None,
            };

            if let (Shape::Pointer { text: true }, Some(pointer)) = (shape, value.filter(|&v| v != 0)) {
                if debugger.bytes(pointer, 1).is_none() {
                    reads.push((pointer, TEXT_READ));
                }
            }
        }

        return reads;
    }

    /// The variables of the function of the selected frame with their values
    pub(crate) fn variables(&mut self) -> Vec<Variable> {
        let pointer_size = self.debugger.as_ref().map_or(8, |d| self.programs[d.program].pointer_size);
        let places = self.variable_places();

        let Some(debugger) = self.debugger.as_ref() else {
            return Vec::new();
        };

        return places
            .into_iter()
            .map(|(name, location, shape, place)| {
                let size = shape.size(pointer_size).clamp(1, 256);

                let raw: Option<Vec<u8>> = match place {
                    Some(Ok(value)) => Some(value.to_le_bytes()[..size.min(16)].to_vec()),
                    Some(Err(addr)) => debugger.bytes(addr, size).map(|b| b.to_vec()),
                    None => None,
                };

                let value = raw.map(|raw| {
                    let pointer = raw.iter().take(pointer_size as usize).rev().fold(0u64, |v, &b| v << 8 | b as u64);
                    let text = debugger.memory.iter().find(|(a, _)| *a == pointer).map(|(_, b)| b.as_slice());
                    format_value(shape, &raw, text)
                });

                Variable { name, location, value }
            })
            .collect();
    }

    /// Name of a frame: the function of the program, or the one the debugger gives (libraries)
    pub(crate) fn frame_name(&self, pc: u64, function: &str) -> String {
        let Some(debugger) = self.debugger.as_ref() else {
            return function.to_string();
        };

        return match debugger.program_addr(&self.programs[debugger.program], pc) {
            Some(addr) => self.address_name(debugger.program, addr),
            None if function.is_empty() => "??".to_string(),
            None => function.to_string(),
        };
    }

    /// The status of the debugger for the title bar
    pub(crate) fn debug_status(&self) -> Option<String> {
        let debugger = self.debugger.as_ref()?;

        let state = match &debugger.state {
            DebugState::Starting => "starting".to_string(),
            DebugState::Running => format!("{} running", crate::render::spinner()),
            DebugState::Stopped => match debugger.snapshot.as_ref() {
                Some(snapshot) => {
                    let frame = snapshot.frames.get(snapshot.frame);
                    let place = frame.map_or(String::new(), |f| format!(" in {}", self.frame_name(f.pc, &f.function)));
                    format!("stopped{} ({})", place, snapshot.reason)
                }
                None => "stopped".to_string(),
            },
            DebugState::Exited(Some(code)) => format!("exited ({})", code),
            DebugState::Exited(None) => "killed".to_string(),
            DebugState::Ended => "ended".to_string(),
        };

        return Some(format!("{}: {}", debugger.kind.name(), state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(format_value(Shape::Int { bytes: 4, signed: true }, &(-5i32).to_le_bytes(), None), "-5");
        assert_eq!(format_value(Shape::Int { bytes: 4, signed: false }, &0xfffffffbu32.to_le_bytes(), None), "4294967291 (0xfffffffb)");
        assert_eq!(format_value(Shape::Int { bytes: 1, signed: true }, b"A", None), "65 'A'");
        assert_eq!(format_value(Shape::Float { bytes: 8 }, &1.5f64.to_le_bytes(), None), "1.5");
        assert_eq!(format_value(Shape::Pointer { text: true }, &0x4000u64.to_le_bytes(), Some(b"hi\n\0rest")), "0x4000 \"hi\\n\"");
        assert_eq!(format_value(Shape::Pointer { text: false }, &[0; 8], None), "NULL");
        assert_eq!(format_value(Shape::Bytes(3), &[1, 2, 255], None), "01 02 ff");
        assert_eq!(format_value(Shape::Text(8), b"hello\0\x01\x02", None), "\"hello\"");
    }

    #[test]
    fn lines_of_a_terminal() {
        let text = b"\x1b[1;32mok\x1b[0m\r\nprogress 10%\rprogress 100%\r\n\x1b]0;title\x07name: ";
        assert_eq!(terminal_lines(text, 10), ["ok", "progress 100%", "name: "]);
        assert_eq!(terminal_lines(b"a\nb\nc\n", 2), ["b", "c"]);
    }
}
