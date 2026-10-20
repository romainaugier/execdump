/*
 * gdb through GDB/MI: each command has a token its result record repeats (^done, ^running, ^error), the stops
 * of the program are *stopped records. gdb runs synchronously: after ^running it reads nothing until the program
 * stops (a SIGINT to gdb interrupts it).
 */

use crate::mi::{self, quote, Record, Value};
use crate::pipe::Pipe;
use crate::{hex, shell_quote, Backend, Frame, Resume, Stop, StopReason};

use anyhow::{bail, Context, Result};

use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Gdb {
    pipe: Pipe,
    token: u64,
    /// Names of the registers by number
    register_names: Vec<String>,
}

impl Gdb {
    pub fn start(path: &Path) -> Result<Gdb> {
        let pipe = Pipe::spawn(path, &["--interpreter=mi3", "-q", "-nx"])?;
        let mut gdb = Gdb { pipe, token: 0, register_names: Vec::new() };

        for setting in ["confirm off", "pagination off", "width 0", "height 0", "print thread-events off", "print inferior-events off", "disassemble-next-line off", "startup-with-shell on"] {
            gdb.command(&format!("-gdb-set {}", setting))?;
        }

        return Ok(gdb);
    }

    /// Runs a command: its result record and the records before it (console output, notifications, stops)
    fn command(&mut self, command: &str) -> Result<(Record, Vec<Record>)> {
        self.token += 1;
        let token = self.token;
        self.pipe.write_line(&format!("{}{}", token, command))?;

        let mut others = Vec::new();

        loop {
            let line = self.pipe.read_line(Some(TIMEOUT))?;

            let Some(record) = mi::parse(&line) else {
                continue;
            };

            if record.kind == '^' && record.token == Some(token) {
                if record.class == "error" {
                    bail!("{}", record.str("msg").unwrap_or("gdb error"));
                }

                return Ok((record, others));
            }

            others.push(record);
        }
    }

    /// Text gdb prints for a command of its command line
    fn console(&mut self, command: &str) -> Result<String> {
        let (_, others) = self.command(&format!("-interpreter-exec console {}", quote(command)))?;
        return Ok(others.iter().filter(|r| r.kind == '~').map(|r| r.class.as_str()).collect());
    }

    /// A command that runs the program: waits for its stop (as long as it takes)
    /// A command that runs the program: waits for its stop (as long as it takes). The program may not start after
    /// ^running: a breakpoint that cannot be inserted is an error of the same command then, the program stays where
    /// it was.
    fn run(&mut self, command: &str) -> Result<Stop> {
        let (_, others) = self.command(command)?;
        let token = self.token;

        if let Some(stopped) = others.iter().find(|r| r.kind == '*' && r.class == "stopped") {
            return Ok(stop(stopped));
        }

        loop {
            let line = self.pipe.read_line(None)?;

            let Some(record) = mi::parse(&line) else {
                continue;
            };

            match (record.kind, record.class.as_str()) {
                ('*', "stopped") => return Ok(stop(&record)),
                ('^', "error") if record.token == Some(token) => bail!("{}", record.str("msg").unwrap_or("gdb error")),
                _ => {}
            }
        }
    }

    fn register_number(&mut self, name: &str) -> Result<Option<usize>> {
        if self.register_names.is_empty() {
            let (record, _) = self.command("-data-list-register-names")?;
            self.register_names = record.get("register-names").map_or(Vec::new(), |names| names.items().iter().map(|n| n.str().unwrap_or_default().to_string()).collect());
        }

        let aliases: &[&str] = match name {
            "rflags" => &["eflags"],
            "eflags" => &["eflags", "rflags"],
            "cpsr" => &["cpsr", "pstate"],
            _ => &[],
        };

        let found = std::iter::once(name).chain(aliases.iter().copied()).find_map(|n| self.register_names.iter().position(|r| r == n));
        return Ok(found);
    }
}

/// The stop of a *stopped record
fn stop(record: &Record) -> Stop {
    let pc = record.get("frame").and_then(|f| f.get("addr")).and_then(Value::str).and_then(hex);

    let reason = match record.str("reason") {
        Some("breakpoint-hit") => StopReason::Breakpoint,
        Some("end-stepping-range" | "function-finished" | "location-reached") | None => StopReason::Step,
        Some("signal-received") => StopReason::Signal(record.str("signal-name").unwrap_or("?").to_string()),
        Some("exited-normally") => StopReason::Exited(Some(0)),
        // The exit code is in octal
        Some("exited") => StopReason::Exited(record.str("exit-code").and_then(|c| i32::from_str_radix(c, 8).ok())),
        Some("exited-signalled") => StopReason::Exited(None),
        Some(other) => StopReason::Other(other.to_string()),
    };

    return Stop { pc: if matches!(reason, StopReason::Exited(_)) { None } else { pc }, reason };
}

/// Value of a register as gdb prints it in hexadecimal: a number, or a union of the views of a vector register
fn register_value(text: &str) -> Option<u128> {
    let number = |t: &str| -> Option<u128> {
        let digits: String = t.trim_start_matches("0x").chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        u128::from_str_radix(&digits, 16).ok()
    };

    if text.starts_with("0x") {
        return number(text);
    }

    // xmm: {..., uint128 = 0x...}, aarch64 v: {..., q = {u = {0x...}, s = {...}}}
    for marker in ["uint128 = ", "q = {u = {", "u = {", "u = "] {
        if let Some(position) = text.find(marker) {
            return number(&text[position + marker.len()..]);
        }
    }

    return None;
}

impl Backend for Gdb {
    fn launch(&mut self, program: &Path, args: &[String], output: &Path) -> Result<Stop> {
        self.command(&format!("-file-exec-and-symbols {}", quote(&program.to_string_lossy())))?;

        let mut words: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();

        if cfg!(unix) {
            let output = shell_quote(&output.to_string_lossy());
            words.extend([format!(">{}", output), "2>&1".to_string(), "</dev/null".to_string()]);
        }

        self.console(&format!("set args {}", words.join(" ")))?;

        return self.run(&format!("-interpreter-exec console {}", quote("starti")));
    }

    fn load_bias(&mut self, link_entry: u64) -> Result<u64> {
        // The entry point of the process in its auxiliary vector (Linux, BSDs)
        let auxv = self.console("info auxv").unwrap_or_default();
        let entry = auxv.lines().find(|l| l.contains("AT_ENTRY")).and_then(|l| l.split_whitespace().last()).and_then(hex);

        return Ok(entry.map_or(0, |e| e.wrapping_sub(link_entry)));
    }

    fn insert_breakpoint(&mut self, addr: u64) -> Result<u32> {
        let (record, _) = self.command(&format!("-break-insert *{:#x}", addr))?;
        return record.get("bkpt").and_then(|b| b.get("number")).and_then(Value::str).and_then(|n| n.parse().ok()).context("no breakpoint number");
    }

    fn delete_breakpoint(&mut self, id: u32) -> Result<()> {
        self.command(&format!("-break-delete {}", id))?;
        return Ok(());
    }

    fn resume(&mut self, how: Resume) -> Result<Stop> {
        let command = match how {
            Resume::Continue => "-exec-continue",
            Resume::StepInstruction => "-exec-step-instruction",
            Resume::NextInstruction => "-exec-next-instruction",
            Resume::Finish => "-exec-finish",
        };

        return self.run(command);
    }

    fn registers(&mut self, names: &[&str]) -> Result<Vec<Option<u128>>> {
        let numbers: Vec<Option<usize>> = names.iter().map(|n| self.register_number(n)).collect::<Result<_>>()?;
        let known: Vec<String> = numbers.iter().flatten().map(|n| n.to_string()).collect();

        if known.is_empty() {
            return Ok(vec![None; names.len()]);
        }

        let (record, _) = self.command(&format!("-data-list-register-values --skip-unavailable x {}", known.join(" ")))?;
        let values: Vec<(usize, Option<u128>)> = record
            .get("register-values")
            .map_or(&[][..], |v| v.items())
            .iter()
            .filter_map(|v| Some((v.get("number")?.str()?.parse().ok()?, v.get("value").and_then(Value::str).and_then(register_value))))
            .collect();

        return Ok(numbers.iter().map(|n| n.and_then(|n| values.iter().find(|(number, _)| *number == n).and_then(|(_, v)| *v))).collect());
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let (record, _) = self.command(&format!("-data-read-memory-bytes {:#x} {}", addr, len))?;
        let mut bytes = Vec::new();

        // The blocks that can be read, the first one from the address
        for block in record.get("memory").map_or(&[][..], |m| m.items()) {
            let begin = block.get("begin").and_then(Value::str).and_then(hex);

            if begin != Some(addr + bytes.len() as u64) {
                break;
            }

            let contents = block.get("contents").and_then(Value::str).unwrap_or_default();
            bytes.extend((0..contents.len() / 2).filter_map(|i| u8::from_str_radix(&contents[2 * i..2 * i + 2], 16).ok()));
        }

        if bytes.is_empty() {
            bail!("cannot read the memory at {:#x}", addr);
        }

        return Ok(bytes);
    }

    fn backtrace(&mut self, max: usize) -> Result<Vec<Frame>> {
        let (record, _) = self.command(&format!("-stack-list-frames 0 {}", max.saturating_sub(1)))?;

        return Ok(record
            .get("stack")
            .map_or(&[][..], |s| s.items())
            .iter()
            .filter_map(|f| f.get("frame"))
            .filter_map(|f| Some(Frame { pc: f.get("addr").and_then(Value::str).and_then(hex)?, function: f.get("func").and_then(Value::str).unwrap_or_default().to_string() }))
            .collect());
    }

    fn select_frame(&mut self, index: usize) -> Result<()> {
        self.command(&format!("-stack-select-frame {}", index))?;
        return Ok(());
    }

    /// gdb kills the program when it exits
    fn kill(&mut self) {
        let _ = self.pipe.write_line("-gdb-exit");
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
    fn values_and_stops() {
        assert_eq!(register_value("0x5555555551b6"), Some(0x5555555551b6));
        assert_eq!(register_value("{v8_bfloat16 = {0x0, 0x0}, v4_int32 = {0xff0000, 0x0}, uint128 = 0xff0000}"), Some(0xff0000));
        assert_eq!(register_value("{d = {f = {0x0, 0x0}}, q = {u = {0x3ff0000000000000}, s = {0x3ff0000000000000}}}"), Some(0x3ff0000000000000));
        assert_eq!(register_value("<unavailable>"), None);

        let record = mi::parse(r#"*stopped,reason="exited",exit-code="012""#).unwrap();
        assert_eq!(stop(&record), Stop { pc: None, reason: StopReason::Exited(Some(10)) });

        let record = mi::parse(r#"*stopped,frame={addr="0x000055555555520b",func="main",args=[]},thread-id="1""#).unwrap();
        assert_eq!(stop(&record), Stop { pc: Some(0x55555555520b), reason: StopReason::Step });
    }
}
