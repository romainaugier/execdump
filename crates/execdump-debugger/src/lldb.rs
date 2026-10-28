// SPDX-License-Identifier: Apache-2.0
/*
 * lldb through its command line. lldb reads its commands from a pipe, echoes each one after its prompt, and prints
 * the prompt only when it reads the next line: each command is followed by one lldb does not know, a sync, whose
 * error ends the output of the command (errors and output share one pipe, their order is kept).
 *
 * While the program runs, lldb gives the lines it reads to the program: a command that runs it is written alone, its
 * stop (or the exit of the program) is waited for, then syncs are sent until one of them is answered. The syncs are
 * numbered, a late answer to an earlier one is not taken for the one waited for.
 *
 * The stops and the frames are printed with formats of their own (thread-stop-format, frame-format). A SIGINT to
 * lldb interrupts the program.
 */

use crate::pipe::Pipe;
use crate::{hex, Backend, Frame, Resume, Stop, StopReason};

use anyhow::{bail, Context, Result};

use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT: &str = "<execdump-lldb>";
/// Commands lldb does not know (numbered)
const SYNC: &str = "execdump-sync-";
/// Time a sync is waited for after a stop, before another one is sent
const RESYNC: Duration = Duration::from_millis(500);
const STOP: &str = "@@STOP pc=";
const FRAME: &str = "@@FRAME ";

pub struct Lldb {
    pipe: Pipe,
    syncs: u64,
}

/// A word of the command line of lldb
fn quote(text: &str) -> String {
    return format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
}

impl Lldb {
    pub fn start(path: &Path) -> Result<Lldb> {
        let pipe = Pipe::spawn(path, &["--no-lldbinit", "--no-use-colors"])?;
        let mut lldb = Lldb { pipe, syncs: 0 };

        lldb.command(&format!("settings set prompt {}", PROMPT))?;

        for setting in [
            "auto-confirm true",
            "use-color false",
            "stop-disassembly-display never",
            "stop-line-count-before 0",
            "stop-line-count-after 0",
            "thread-stop-format \"@@STOP pc=${frame.pc} reason=${thread.stop-reason}\\n\"",
            "frame-format \"@@FRAME ${frame.index} ${frame.pc} ${function.name}\\n\"",
        ] {
            lldb.command(&format!("settings set {}", setting))?;
        }

        return Ok(lldb);
    }

    /// Output of a command, without its prompt and its echo; an error when it prints one
    fn command(&mut self, command: &str) -> Result<String> {
        return self.command_with_timeout(command, Some(TIMEOUT));
    }

    fn command_with_timeout(&mut self, command: &str, timeout: Option<Duration>) -> Result<String> {
        self.pipe.write_line(command)?;
        let text = self.sync(timeout)?;

        // [prompt]command\n output [prompt]
        let text = text.trim_end_matches(PROMPT);
        let output = match text.split_once('\n') {
            Some((echo, rest)) if echo.ends_with(command.trim()) => rest,
            _ => text,
        };

        if let Some(error) = output.lines().filter(|l| !l.contains(SYNC)).find_map(|l| l.trim().strip_prefix("error: ")) {
            bail!("{}", error);
        }

        return Ok(output.to_string());
    }

    /// Sends a sync and returns the output before it (up to its prompt and echo)
    fn sync(&mut self, timeout: Option<Duration>) -> Result<String> {
        self.syncs += 1;
        let name = format!("{}{}", SYNC, self.syncs);
        self.pipe.write_line(&name)?;

        let text = self.pipe.read_until(format!("'{}' is not a valid command", name).as_bytes(), timeout)?;
        self.pipe.read_line(Some(TIMEOUT))?;

        let end = text.rfind(&name).unwrap_or(text.len());
        return Ok(text[..end].to_string());
    }

    /// A command that runs the program, as long as it takes
    fn run(&mut self, command: &str) -> Result<Stop> {
        self.pipe.write_line(command)?;

        let stop = loop {
            let line = self.pipe.read_line(None)?;

            if line.contains(" exited with status = ") || line.contains(STOP) {
                break stop(&line).with_context(|| format!("cannot read the stop: {}", line.trim()))?;
            }

            if let Some(error) = line.trim().strip_prefix("error: ") {
                bail!("{}", error);
            }
        };

        // The rest of the stop (its frames), until lldb reads commands again
        for _ in 0..20 {
            match self.sync(Some(RESYNC)) {
                Ok(_) => return Ok(stop),
                Err(error) if error.to_string().contains("did not answer") => continue,
                Err(error) => return Err(error),
            }
        }

        bail!("lldb does not read its commands after the stop");
    }
}

/// The stop a line (or the output of a command) gives: the exit of the program, or the stop format
fn stop(output: &str) -> Option<Stop> {
    if let Some(line) = output.lines().find(|l| l.contains(" exited with status = ")) {
        let status = line.split(" exited with status = ").nth(1)?.split_whitespace().next()?.parse::<i32>().ok();
        return Some(Stop { pc: None, reason: StopReason::Exited(status.filter(|&s| s >= 0)) });
    }

    let line = output.lines().find(|l| l.contains(STOP))?;
    let rest = &line[line.find(STOP)? + STOP.len()..];
    let (pc, reason) = rest.split_once(" reason=").unwrap_or((rest, ""));
    let reason = reason.trim();

    let reason = if reason.starts_with("breakpoint") {
        StopReason::Breakpoint
    } else if let Some(signal) = reason.strip_prefix("signal ") {
        StopReason::Signal(signal.to_string())
    } else if reason.is_empty() || reason.contains("step") || reason == "trace" {
        StopReason::Step
    } else {
        StopReason::Other(reason.to_string())
    };

    return Some(Stop { pc: hex(pc), reason });
}

/// Value of a register: a number, or the bytes of a vector register ({0x00 0x01 ...}, the low one first)
fn register_value(text: &str) -> Option<u128> {
    let text = text.trim();

    if let Some(bytes) = text.strip_prefix('{').and_then(|t| t.split('}').next()) {
        let bytes: Vec<u8> = bytes.split_whitespace().filter_map(|b| hex(b).map(|v| v as u8)).collect();
        return Some(bytes.iter().take(16).enumerate().fold(0u128, |value, (i, &b)| value | (b as u128) << (8 * i)));
    }

    let number = text.split_whitespace().next()?;
    return u128::from_str_radix(number.trim_start_matches("0x"), 16).ok();
}

impl Backend for Lldb {
    fn launch(&mut self, program: &Path, args: &[String], output: &Path, input: Option<&Path>) -> Result<Stop> {
        self.command(&format!("target create {}", quote(&program.to_string_lossy())))?;

        let output = quote(&output.to_string_lossy());
        let empty = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let input = input.map_or(empty.to_string(), |i| quote(&i.to_string_lossy()));
        let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
        let separator = if args.is_empty() { "" } else { " -- " };

        return self.run(&format!("process launch --stop-at-entry -o {} -e {} -i {}{}{}", output, output, input, separator, args.join(" ")));
    }

    fn load_bias(&mut self, _link_entry: u64) -> Result<u64> {
        // The offset of the executable (the first module) from the addresses of its file
        let output = self.command("image list -o")?;
        let first = output.lines().find(|l| l.trim_start().starts_with('['));
        return Ok(first.and_then(|l| l.split(']').nth(1)).and_then(|l| l.split_whitespace().next()).and_then(hex).unwrap_or(0));
    }

    fn program_pid(&mut self) -> Option<u32> {
        // Process 1234 stopped
        let output = self.command("process status").ok()?;
        return output.lines().find_map(|l| l.trim().strip_prefix("Process ")).and_then(|l| l.split_whitespace().next()).and_then(|p| p.parse().ok());
    }

    fn insert_breakpoint(&mut self, addr: u64) -> Result<u32> {
        let output = self.command(&format!("breakpoint set -a {:#x}", addr))?;
        let id = output.lines().find_map(|l| l.trim().strip_prefix("Breakpoint ")).and_then(|l| l.split(':').next()).and_then(|n| n.trim().parse().ok());
        return id.with_context(|| format!("no breakpoint: {}", output.trim()));
    }

    fn delete_breakpoint(&mut self, id: u32) -> Result<()> {
        self.command(&format!("breakpoint delete {}", id))?;
        return Ok(());
    }

    fn resume(&mut self, how: Resume) -> Result<Stop> {
        let command = match how {
            Resume::Continue => "process continue",
            Resume::StepInstruction => "thread step-inst",
            Resume::NextInstruction => "thread step-inst-over",
            Resume::Finish => "thread step-out",
        };

        return self.run(command);
    }

    fn registers(&mut self, names: &[&str]) -> Result<Vec<Option<u128>>> {
        let alias = |name: &str| -> String {
            return match name {
                "eflags" if !names.contains(&"eip") => "rflags".to_string(),
                other => other.to_string(),
            };
        };

        let wanted: Vec<String> = names.iter().map(|n| alias(n)).collect();
        let mut values: Vec<(String, Option<u128>)> = Vec::new();

        // A register lldb does not know fails the whole command: they are read one by one then
        let outputs = match self.command(&format!("register read {}", wanted.join(" "))) {
            Ok(output) => vec![output],
            Err(_) => wanted.iter().filter_map(|n| self.command(&format!("register read {}", n)).ok()).collect(),
        };

        for line in outputs.iter().flat_map(|o| o.lines()) {
            if let Some((name, value)) = line.split_once(" = ") {
                values.push((name.trim().to_string(), register_value(value)));
            }
        }

        return Ok(wanted.iter().map(|n| values.iter().find(|(name, _)| name == n).and_then(|(_, v)| *v)).collect());
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let output = self.command(&format!("memory read --force -s 1 -f x -c {} {:#x}", len, addr))?;

        let bytes: Vec<u8> = output
            .lines()
            .filter_map(|l| l.split_once(": "))
            .flat_map(|(_, values)| values.split_whitespace().filter_map(|b| hex(b).map(|v| v as u8)).collect::<Vec<_>>())
            .collect();

        if bytes.is_empty() {
            bail!("cannot read the memory at {:#x}", addr);
        }

        return Ok(bytes);
    }

    fn backtrace(&mut self, max: usize) -> Result<Vec<Frame>> {
        let output = self.command(&format!("thread backtrace -c {}", max))?;

        return Ok(output
            .lines()
            .filter_map(|l| l.find(FRAME).map(|i| &l[i + FRAME.len()..]))
            .filter_map(|l| {
                let mut words = l.splitn(3, ' ');
                let _index = words.next()?;
                let pc = hex(words.next()?)?;
                Some(Frame { pc, function: words.next().unwrap_or_default().trim().to_string() })
            })
            .collect());
    }

    fn select_frame(&mut self, index: usize) -> Result<()> {
        self.command(&format!("frame select {}", index))?;
        return Ok(());
    }

    /// The program runs under lldb-server: it is killed before lldb exits (it would keep running otherwise)
    fn kill(&mut self) {
        let _ = self.command("process kill");
        let _ = self.pipe.write_line("quit");
        self.pipe.finish(TIMEOUT / 10);
    }

    fn pid(&self) -> u32 {
        return self.pipe.pid();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_and_values() {
        let output = "Process 578 resuming\nProcess 578 stopped\n* @@STOP pc=0x00005555555551b6 reason=breakpoint 1.1\n    @@FRAME 0 0x00005555555551b6 greet\n";
        assert_eq!(stop(output), Some(Stop { pc: Some(0x5555555551b6), reason: StopReason::Breakpoint }));
        assert_eq!(stop("Process 578 stopped\n* @@STOP pc=0x7ffff7fe4540 reason=signal SIGSTOP\n").unwrap().reason, StopReason::Signal("SIGSTOP".to_string()));
        assert_eq!(stop("@@STOP pc=0x10 reason=instruction step over\n").unwrap().reason, StopReason::Step);
        assert_eq!(stop("Process 578 exited with status = 3 (0x00000003)\n"), Some(Stop { pc: None, reason: StopReason::Exited(Some(3)) }));

        assert_eq!(register_value("0x00007ffff7fe4540  ld-linux-x86-64.so.2`_start"), Some(0x7ffff7fe4540));
        assert_eq!(register_value("{0x00 0x00 0xff 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01}"), Some(0x01000000000000000000000000ff0000));
    }
}
