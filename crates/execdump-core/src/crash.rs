/*
 * Panics. A panic inside catch() is an error of what was running (one function of the decompiler), its
 * message is returned and nothing is printed. Any other panic is a crash: the terminal is restored
 * (the TUI registers how) before the message and the backtrace are printed, and the process exits.
 */

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

            if let Some(restore) = restore {
                restore();
            }

            default(info);
            eprintln!("\nexecdump crashed, please report this error with the binary it happened on");

            // The main thread unwinds and exits on its own, the others would leave it running without a terminal
            if std::thread::current().name() != Some("main") {
                std::process::exit(101);
            }
        }));
    });
}

/// How to give the terminal back before a crash is printed (None when the terminal is given back)
pub fn on_crash(restore: Option<Restore>) {
    if let Ok(mut current) = RESTORE.lock() {
        *current = restore;
    }
}

/// Runs f, a panic inside it is returned as an error
pub fn catch<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    install();
    CATCHING.with(|c| c.set(c.get() + 1));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    CATCHING.with(|c| c.set(c.get() - 1));

    return result.map_err(|payload| LAST.with(|last| last.borrow_mut().take()).unwrap_or_else(|| format!("panicked: {}", payload_message(&*payload))));
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
        assert_eq!(catch(|| 2 + 2), Ok(4));

        let error = catch(|| -> u32 { panic!("broken {}", 42) }).unwrap_err();
        assert!(error.contains("crash.rs") && error.ends_with("broken 42"), "{}", error);

        let nested = catch(|| catch(|| -> u32 { panic!("inner") }).unwrap_err());
        assert!(nested.unwrap().ends_with("inner"));
    }
}
