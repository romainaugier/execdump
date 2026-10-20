/*
 * A debugging session: a backend on a thread of its own, driven by requests, its stops sent back as events. The
 * interface never waits for the program: a request that runs it returns once it stops, an interrupt (a SIGINT to
 * the debugger) stops it early.
 *
 * The program starts stopped at its first instruction: Started gives the load bias, the interface then sends its
 * breakpoints (at the addresses of the process) and runs it.
 *
 * Stepping by lines of C is Until: temporary breakpoints at the addresses of the lines and the return addresses,
 * the program continues until it reaches one of them. A line address is only a stop in the frame the step started
 * in (a recursive call reaches the same lines deeper in the stack): the stack pointer there, minus its offset from
 * the entry of the function at that address, is the stack pointer at the entry of the frame.
 */

use crate::{backend, Backend, Frame, Kind, Resume, Stop, StopReason};

use anyhow::{anyhow, Result};

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;

/// Frames of the call stack read at each stop
const MAX_FRAMES: usize = 64;
/// Bytes of the stack read at each stop, from the stack pointer (the slots of the variables of the frame)
const STACK_WINDOW: usize = 4096;

pub struct Config {
    pub kind: Kind,
    pub debugger: PathBuf,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// File (or terminal) the output of the program goes to
    pub output: PathBuf,
    /// Terminal the program reads its input from, empty without one
    pub input: Option<PathBuf>,
    /// Entry point of the binary (its address in the file), to find where it was loaded
    pub link_entry: u64,
    /// Registers read at every stop, the stack pointer among them
    pub registers: Vec<String>,
    pub stack_pointer: String,
}

/// How the program runs
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Run {
    Continue,
    StepInstruction,
    NextInstruction,
    Finish,
    Until(Until),
}

/// Continues until one of the addresses is reached (or a breakpoint, or a signal)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Until {
    /// Addresses of lines, with the offset of the stack pointer from the entry of their function there when known
    pub stops: Vec<(u64, Option<i64>)>,
    /// Stack pointer at the entry of the frame the lines must be reached in
    pub entry_sp: Option<u64>,
    /// Return addresses: stops in any frame
    pub returns: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The breakpoints of the user (addresses of the process): the ones missing are added, the others removed
    Breakpoints(Vec<u64>),
    Run(Run),
    Read { addr: u64, len: usize },
    SelectFrame(usize),
    Kill,
}

/// The state of the program at a stop
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub reason: String,
    /// Frame the registers and the stack are read in (0: the innermost)
    pub frame: usize,
    pub frames: Vec<Frame>,
    pub registers: Vec<(String, u128)>,
    pub pc: u64,
    pub sp: u64,
    /// Bytes from the stack pointer
    pub stack: Vec<u8>,
}

impl Snapshot {
    pub fn register(&self, name: &str) -> Option<u128> {
        return self.registers.iter().find(|(n, _)| n == name).map(|(_, v)| *v);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The program is loaded and stopped at its first instruction
    Started { bias: u64, kind: Kind },
    Running,
    Stopped(Snapshot),
    /// The program exited (None: killed by a signal)
    Exited(Option<i32>),
    Memory { addr: u64, bytes: Vec<u8> },
    Error(String),
    /// The debugger is gone
    Ended,
}

pub struct Session {
    requests: Sender<Request>,
    events: Receiver<Event>,
    pid: Arc<AtomicU32>,
    pub kind: Kind,
}

impl Session {
    pub fn start(config: Config) -> Session {
        let (requests, receiver) = channel();
        let (sender, events) = channel();
        let pid = Arc::new(AtomicU32::new(0));
        let kind = config.kind;
        let shared_pid = pid.clone();

        let spawned = std::thread::Builder::new().name("debugger".to_string()).spawn(move || {
            let mut worker = match Worker::launch(&config, &sender, &shared_pid) {
                Ok(worker) => worker,
                Err(error) => {
                    let _ = sender.send(Event::Error(format!("{:#}", error)));
                    let _ = sender.send(Event::Ended);
                    return;
                }
            };

            worker.serve(receiver);
            worker.backend.kill();
            let _ = worker.events.send(Event::Ended);
        });

        if let Err(error) = spawned {
            let (sender, events) = channel();
            let _ = sender.send(Event::Error(error.to_string()));
            let _ = sender.send(Event::Ended);
            return Session { requests, events, pid, kind };
        }

        return Session { requests, events, pid, kind };
    }

    pub fn send(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    /// The next event, without waiting
    pub fn poll(&self) -> Option<Event> {
        return match self.events.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        };
    }

    /// Stops the running program: the request running it returns with a stop by a signal
    pub fn interrupt(&self) {
        let pid = self.pid.load(Ordering::Relaxed);

        #[cfg(unix)]
        if pid != 0 {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGINT);
            }
        }

        #[cfg(not(unix))]
        let _ = pid;
    }

    /// Kills the program and the debugger
    pub fn stop(&self) {
        self.interrupt();
        self.send(Request::Kill);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Worker {
    backend: Box<dyn Backend>,
    events: Sender<Event>,
    registers: Vec<String>,
    stack_pointer: String,
    /// Breakpoints of the user: address -> id of the debugger
    breakpoints: BTreeMap<u64, u32>,
    exited: bool,
}

impl Worker {
    fn launch(config: &Config, events: &Sender<Event>, pid: &AtomicU32) -> Result<Worker> {
        let mut backend = backend(config.kind, &config.debugger)?;
        pid.store(backend.pid(), Ordering::Relaxed);

        let stop = backend.launch(&config.program, &config.args, &config.output, config.input.as_deref())?;

        if let StopReason::Exited(code) = stop.reason {
            return Err(anyhow!("the program exited before its first instruction (code {:?})", code));
        }

        let bias = backend.load_bias(config.link_entry)?;
        let _ = events.send(Event::Started { bias, kind: config.kind });

        return Ok(Worker { backend, events: events.clone(), registers: config.registers.clone(), stack_pointer: config.stack_pointer.clone(), breakpoints: BTreeMap::new(), exited: false });
    }

    fn serve(&mut self, requests: Receiver<Request>) {
        while let Ok(request) = requests.recv() {
            let result = match request {
                Request::Kill => return,
                Request::Breakpoints(addrs) => self.set_breakpoints(&addrs),
                Request::Run(_) | Request::SelectFrame(_) if self.exited => Err(anyhow!("the program is not running")),
                Request::Run(run) => self.run(run),
                Request::Read { addr, len } => self.backend.read_memory(addr, len).map(|bytes| {
                    let _ = self.events.send(Event::Memory { addr, bytes });
                }),
                Request::SelectFrame(index) => self.backend.select_frame(index).and_then(|_| self.snapshot("frame selected".to_string(), index)),
            };

            if let Err(error) = result {
                let _ = self.events.send(Event::Error(format!("{:#}", error)));
            }
        }
    }

    fn set_breakpoints(&mut self, addrs: &[u64]) -> Result<()> {
        let wanted: HashSet<u64> = addrs.iter().copied().collect();
        let gone: Vec<(u64, u32)> = self.breakpoints.iter().filter(|(a, _)| !wanted.contains(a)).map(|(&a, &id)| (a, id)).collect();

        for (addr, id) in gone {
            self.backend.delete_breakpoint(id)?;
            self.breakpoints.remove(&addr);
        }

        for &addr in addrs {
            if !self.breakpoints.contains_key(&addr) {
                let id = self.backend.insert_breakpoint(addr)?;
                self.breakpoints.insert(addr, id);
            }
        }

        return Ok(());
    }

    fn run(&mut self, run: Run) -> Result<()> {
        let _ = self.events.send(Event::Running);

        let stop = match run {
            Run::Continue => self.backend.resume(Resume::Continue)?,
            Run::StepInstruction => self.backend.resume(Resume::StepInstruction)?,
            Run::NextInstruction => self.backend.resume(Resume::NextInstruction)?,
            Run::Finish => self.backend.resume(Resume::Finish)?,
            Run::Until(until) => self.until(&until)?,
        };

        if let StopReason::Exited(code) = stop.reason {
            self.exited = true;
            let _ = self.events.send(Event::Exited(code));
            return Ok(());
        }

        return self.snapshot(stop.reason.describe(), 0);
    }

    fn until(&mut self, until: &Until) -> Result<Stop> {
        let mut temporary: Vec<(u64, u32)> = Vec::new();

        for addr in until.stops.iter().map(|(a, _)| *a).chain(until.returns.iter().copied()) {
            if !self.breakpoints.contains_key(&addr) && !temporary.iter().any(|(a, _)| *a == addr) {
                temporary.push((addr, self.backend.insert_breakpoint(addr)?));
            }
        }

        let stop = self.continue_until(until);

        for (_, id) in temporary {
            let _ = self.backend.delete_breakpoint(id);
        }

        return stop;
    }

    fn continue_until(&mut self, until: &Until) -> Result<Stop> {
        loop {
            let stop = self.backend.resume(Resume::Continue)?;

            let (Some(pc), StopReason::Breakpoint) = (stop.pc, &stop.reason) else {
                return Ok(stop);
            };

            if self.breakpoints.contains_key(&pc) {
                return Ok(stop);
            }

            // The temporary breakpoints are the end of a step
            if until.returns.contains(&pc) {
                return Ok(Stop { pc: Some(pc), reason: StopReason::Step });
            }

            let Some(&(_, offset)) = until.stops.iter().find(|(a, _)| *a == pc) else {
                return Ok(stop);
            };

            let (Some(entry_sp), Some(offset)) = (until.entry_sp, offset) else {
                return Ok(Stop { pc: Some(pc), reason: StopReason::Step });
            };

            let sp = self.backend.registers(&[self.stack_pointer.as_str()])?.first().copied().flatten();

            // In the frame of the step, not in a recursive call
            if sp.is_none_or(|sp| (sp as u64).wrapping_sub(offset as u64) == entry_sp) {
                return Ok(Stop { pc: Some(pc), reason: StopReason::Step });
            }
        }
    }

    fn snapshot(&mut self, reason: String, frame: usize) -> Result<()> {
        let mut frames = self.backend.backtrace(MAX_FRAMES).unwrap_or_default();
        let names: Vec<&str> = self.registers.iter().map(String::as_str).collect();
        let values = self.backend.registers(&names)?;
        let registers: Vec<(String, u128)> = self.registers.iter().zip(values).filter_map(|(n, v)| Some((n.clone(), v?))).collect();

        let sp = registers.iter().find(|(n, _)| *n == self.stack_pointer).map_or(0, |(_, v)| *v as u64);
        let pc = frames.get(frame).map_or(0, |f| f.pc);

        if frames.is_empty() {
            frames.push(Frame { pc, function: String::new() });
        }

        // The stack from the stack pointer: less of it near its top
        let stack = [STACK_WINDOW, STACK_WINDOW / 8, 64].iter().find_map(|&len| self.backend.read_memory(sp, len).ok()).unwrap_or_default();

        let _ = self.events.send(Event::Stopped(Snapshot { reason, frame, frames, registers, pc, sp, stack }));
        return Ok(());
    }
}
