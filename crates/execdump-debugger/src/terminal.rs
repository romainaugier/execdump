/*
 * The terminal of the program: a pseudo-terminal its input, output and errors go to. On a terminal the C library
 * flushes the output at each line (to a file it keeps it until its buffer is full or the program exits), so the
 * interface shows it as it is written. A thread reads the master side, what is written to it is the input of the
 * program (echoed, as a terminal does).
 */

use anyhow::{bail, Context, Result};

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

pub struct Terminal {
    master: File,
    /// The slave side stays open: the reads of the master fail once no process has it
    _slave: File,
    /// Path of the slave side, the program opens it
    pub path: PathBuf,
    output: Receiver<Vec<u8>>,
}

impl Terminal {
    pub fn open() -> Result<Terminal> {
        let (mut master, mut slave) = (-1, -1);

        // SAFETY: openpty writes two descriptors, the name, termios and window size are not asked for
        let status = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };

        if status != 0 {
            bail!("cannot open a pseudo-terminal: {}", std::io::Error::last_os_error());
        }

        // SAFETY: both descriptors were just opened and are owned here
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let path = std::fs::read_link(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&slave))).or_else(|_| slave_name(&master))?;

        let mut reader = master.try_clone()?;
        let (sender, output) = channel();

        std::thread::Builder::new().name("program-output".to_string()).spawn(move || {
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

        return Ok(Terminal { master, _slave: slave, path, output });
    }

    /// What the program wrote since the last call
    pub fn read(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        while let Ok(chunk) = self.output.try_recv() {
            bytes.extend(chunk);
        }

        return bytes;
    }

    /// Input of the program
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.master.write_all(bytes).context("cannot write to the terminal of the program")?;
        return Ok(());
    }
}

/// Name of the slave side of a master (macOS and the BSDs have no /proc)
fn slave_name(master: &File) -> Result<PathBuf> {
    // SAFETY: ptsname returns a static buffer read before any other call
    let name = unsafe { libc::ptsname(std::os::fd::AsRawFd::as_raw_fd(master)) };

    if name.is_null() {
        bail!("no name for the pseudo-terminal");
    }

    // SAFETY: a NUL terminated string from libc
    let name = unsafe { std::ffi::CStr::from_ptr(name) };
    return Ok(PathBuf::from(name.to_string_lossy().to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    #[test]
    fn output_and_input() {
        let mut terminal = Terminal::open().unwrap();
        let mut program = std::process::Command::new("sh")
            .args(["-c", "echo first; read line; echo got $line"])
            .stdin(File::options().read(true).write(true).open(&terminal.path).unwrap())
            .stdout(File::options().write(true).open(&terminal.path).unwrap())
            .spawn()
            .unwrap();

        let mut text = String::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        while !text.contains("first") && Instant::now() < deadline {
            text.push_str(&String::from_utf8_lossy(&terminal.read()));
            std::thread::sleep(Duration::from_millis(10));
        }

        terminal.write(b"typed\n").unwrap();
        program.wait().unwrap();

        while !text.contains("got typed") && Instant::now() < deadline {
            text.push_str(&String::from_utf8_lossy(&terminal.read()));
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(text.contains("first\r\n") && text.contains("got typed"), "{:?}", text);
    }
}
