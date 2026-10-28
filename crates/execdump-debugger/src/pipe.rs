// SPDX-License-Identifier: Apache-2.0
/*
 * A debugger process: commands written to its input, its output and errors read from one pipe by a thread (so
 * that their order is kept), until a pattern (a prompt, the end of a line)
 *
 * With EXECDUMP_DEBUGGER_LOG=<file>, what is written to the debugger and what it answers is appended to the file
 */

use anyhow::{anyhow, bail, Context, Result};

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub struct Pipe {
    child: Child,
    input: ChildStdin,
    output: Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    name: String,
    log: Option<std::fs::File>,
}

impl Pipe {
    pub fn spawn(path: &Path, args: &[&str]) -> Result<Pipe> {
        let (reader, writer) = std::io::pipe()?;
        let mut command = Command::new(path);

        command.args(args).stdin(Stdio::piped()).stdout(writer.try_clone()?).stderr(writer).env("TERM", "dumb");

        // A session of its own: the keys of the terminal (Ctrl-C) are the interface's, not the debugger's
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;

            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let mut child = command.spawn().with_context(|| format!("cannot start {}", path.display()))?;
        drop(command);

        let input = child.stdin.take().context("no input to the debugger")?;
        let (sender, output) = channel();

        std::thread::Builder::new().name("debugger-output".to_string()).spawn(move || {
            let mut reader = reader;
            let mut chunk = [0u8; 8192];

            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sender.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        })?;

        let name = path.file_name().map_or("debugger".to_string(), |n| n.to_string_lossy().to_string());
        let log = std::env::var_os("EXECDUMP_DEBUGGER_LOG").and_then(|path| std::fs::OpenOptions::new().create(true).append(true).open(path).ok());

        return Ok(Pipe { child, input, output, buffer: Vec::new(), name, log });
    }

    pub fn pid(&self) -> u32 {
        return self.child.id();
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        if let Some(log) = self.log.as_mut() {
            let _ = writeln!(log, ">> {}", line);
        }

        self.input.write_all(line.as_bytes())?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        return Ok(());
    }

    /// The output up to a pattern (which is consumed), waiting at most for a timeout (forever without one)
    pub fn read_until(&mut self, pattern: &[u8], timeout: Option<Duration>) -> Result<String> {
        let deadline = timeout.map(|t| Instant::now() + t);

        loop {
            if let Some(position) = find(&self.buffer, pattern) {
                let text = String::from_utf8_lossy(&self.buffer[..position]).to_string();
                self.buffer.drain(..position + pattern.len());
                return Ok(text);
            }

            let chunk = match deadline {
                Some(deadline) => match self.output.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(chunk) => chunk,
                    Err(RecvTimeoutError::Timeout) => bail!("{} did not answer in time", self.name),
                    Err(RecvTimeoutError::Disconnected) => return Err(self.exited()),
                },
                None => self.output.recv().map_err(|_| self.exited())?,
            };

            if let Some(log) = self.log.as_mut() {
                let _ = log.write_all(&chunk);
            }

            self.buffer.extend(chunk);
        }
    }

    pub fn read_line(&mut self, timeout: Option<Duration>) -> Result<String> {
        return self.read_until(b"\n", timeout);
    }

    fn exited(&mut self) -> anyhow::Error {
        let status = self.child.try_wait().ok().flatten().map_or(String::new(), |s| format!(" ({})", s));
        let rest = String::from_utf8_lossy(&self.buffer).trim().to_string();
        let rest = if rest.is_empty() { String::new() } else { format!(": {}", rest) };
        return anyhow!("{} exited{}{}", self.name, status, rest);
    }

    /// Waits for the debugger to exit by itself for a while, then kills it
    pub fn finish(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        self.kill();
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.kill();
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    return haystack.windows(needle.len()).position(|w| w == needle);
}
