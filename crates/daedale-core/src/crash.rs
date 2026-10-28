// SPDX-License-Identifier: Apache-2.0
/*
 * Panics. A panic inside catch() is an error of what was running (one function of the decompiler), its
 * message is returned and nothing is printed. Any other panic in the TUI is a crash: the terminal is
 * restored (the TUI registers how) before the message and the backtrace are printed, and the process
 * exits.
 *
 * Fatal errors that are not panics (stack overflows abort, invalid memory accesses) cannot run Rust code:
 * on Unix, signal handlers give the terminal back with system calls only, then let the error go on.
 */

use anyhow::{anyhow, Result};

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Mutex, Once};

thread_local! {
    static CATCHING: Cell<usize> = const { Cell::new(0) };
    static LAST: RefCell<Option<String>> = const { RefCell::new(None) };
}

type Restore = Box<dyn Fn() + Send>;

static RESTORE: Mutex<Option<Restore>> = Mutex::new(None);
static INSTALL: Once = Once::new();

/// Installs the panic hook (once per process)
pub fn install() {
    INSTALL.call_once(|| {
        let default = panic::take_hook();

        panic::set_hook(Box::new(move |info| {
            let location = info.location().map_or(String::new(), |l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()));
            let message = format!("panicked{}: {}", location, payload_message(info.payload()));

            if CATCHING.with(|c| c.get()) > 0 {
                LAST.with(|last| *last.borrow_mut() = Some(message));
                return;
            }

            let restore = RESTORE.lock().map(|mut r| r.take()).unwrap_or(None);

            let Some(restore) = restore else {
                default(info);
                return;
            };

            restore();
            default(info);
            eprintln!("\ndaedale crashed, please report this error with the binary it happened on");

            // The main thread unwinds and exits on its own, the others would leave it running without a terminal
            if std::thread::current().name() != Some("main") {
                std::process::exit(101);
            }
        }));
    });
}

/// How to give the terminal back before a crash is printed (None when the terminal is given back). Called
/// before the terminal is changed: the fatal signal handlers put back its current settings.
pub fn on_crash(restore: Option<Restore>) {
    #[cfg(unix)]
    signals::terminal(restore.is_some());

    if let Ok(mut current) = RESTORE.lock() {
        *current = restore;
    }
}

#[cfg(unix)]
mod signals {
    use std::mem::MaybeUninit;
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SIGNALS: [libc::c_int; 3] = [libc::SIGABRT, libc::SIGSEGV, libc::SIGBUS];
    const LEAVE_SCREEN: &[u8] = b"\x1b[?1049l\x1b[?25h";

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static INSTALL: Once = Once::new();
    static mut TERMIOS: MaybeUninit<libc::termios> = MaybeUninit::uninit();
    static mut PREVIOUS: [MaybeUninit<libc::sigaction>; 3] = [const { MaybeUninit::uninit() }; 3];

    pub fn terminal(active: bool) {
        if active {
            // The settings before the raw mode
            unsafe {
                if libc::tcgetattr(libc::STDIN_FILENO, (&raw mut TERMIOS).cast()) != 0 {
                    return;
                }
            }

            INSTALL.call_once(install);
        }

        ACTIVE.store(active, Ordering::SeqCst);
    }

    fn install() {
        for (index, &signal) in SIGNALS.iter().enumerate() {
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = handler as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, (&raw mut PREVIOUS[index]).cast());
            }
        }
    }

    fn write(fd: libc::c_int, bytes: &[u8]) {
        unsafe {
            libc::write(fd, bytes.as_ptr().cast(), bytes.len());
        }
    }

    extern "C" fn handler(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
        if ACTIVE.swap(false, Ordering::SeqCst) {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, (&raw const TERMIOS).cast());
            }

            write(libc::STDOUT_FILENO, LEAVE_SCREEN);
            write(libc::STDERR_FILENO, b"\ndaedale crashed, please report this error with the binary it happened on\n");
        }

        // The error goes on: Rust's handler (stack overflow message) or the default action
        let Some(index) = SIGNALS.iter().position(|&s| s == signal) else {
            return;
        };

        unsafe {
            let previous = (*(&raw const PREVIOUS[index])).assume_init_ref();

            if previous.sa_sigaction == libc::SIG_DFL || previous.sa_sigaction == libc::SIG_IGN {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigaction(signal, &action, std::ptr::null_mut());

                // An abort raises its signal again, a fault happens again when the handler returns
                return;
            }

            if previous.sa_flags & libc::SA_SIGINFO != 0 {
                let previous: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) = std::mem::transmute(previous.sa_sigaction);
                previous(signal, info, context);
            } else {
                let previous: extern "C" fn(libc::c_int) = std::mem::transmute(previous.sa_sigaction);
                previous(signal);
            }
        }
    }
}

/// Stack of the threads running the analysis and the decompiler, which recurse on big functions (the
/// default is 2 MB, only the pages used are allocated)
pub const STACK_SIZE: usize = 512 << 20;

pub fn thread(name: &str) -> std::thread::Builder {
    return std::thread::Builder::new().name(name.to_string()).stack_size(STACK_SIZE);
}

/// Runs f, a panic inside it is returned as an error
pub fn catch<T>(f: impl FnOnce() -> T) -> Result<T> {
    install();
    CATCHING.with(|c| c.set(c.get() + 1));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    CATCHING.with(|c| c.set(c.get() - 1));

    return result.map_err(|payload| anyhow!(LAST.with(|last| last.borrow_mut().take()).unwrap_or_else(|| format!("panicked: {}", payload_message(&*payload)))));
}

fn payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        return text.to_string();
    }

    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }

    return "unknown error".to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caught_panics() {
        assert_eq!(catch(|| 2 + 2).unwrap(), 4);

        let error = catch(|| -> u32 { panic!("broken {}", 42) }).unwrap_err().to_string();
        assert!(error.contains("crash.rs") && error.ends_with("broken 42"), "{}", error);

        let nested = catch(|| catch(|| -> u32 { panic!("inner") }).unwrap_err());
        assert!(nested.unwrap().to_string().ends_with("inner"));
    }
}
