// SPDX-License-Identifier: Apache-2.0
/*
 * Clipboard: what is copied goes to the clipboard of the terminal (OSC 52: kitty, WezTerm, iTerm2, foot, xterm,
 * tmux with set-clipboard, through ssh) and to the one of the system, which the terminals without OSC 52 (GNOME
 * Terminal and the other VTE ones, Konsole) paste from.
 *
 * The clipboard of the system is the one of X11 (the Wayland sessions of GNOME and KDE run XWayland and share it),
 * macOS or Windows: the process owns what it copied while it runs. Without one (Wayland only, no display), the tools
 * of the system do it: wl-copy, xclip, xsel.
 */

use anyhow::{anyhow, bail, Result};

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

/// Tools copying their input to the clipboard: when they apply (an environment variable), the command
const TOOLS: &[(&str, &str, &[&str])] = &[
    ("WAYLAND_DISPLAY", "wl-copy", &[]),
    ("DISPLAY", "xclip", &["-selection", "clipboard"]),
    ("DISPLAY", "xsel", &["--clipboard", "--input"]),
];

/// Characters of a copied text shown in the messages
const PREVIEW: usize = 60;

#[derive(Default)]
pub(crate) struct Clipboard {
    system: Option<arboard::Clipboard>,
    /// Why the clipboard of the system could not be opened, it is not tried again
    unavailable: Option<String>,
}

impl Clipboard {
    /// Copies text to the clipboards, an error when the one of the system was not reached (the one of the terminal
    /// may still have it)
    pub fn copy(&mut self, text: &str) -> Result<()> {
        let mut stdout = std::io::stdout();

        if stdout.is_terminal() {
            let _ = write!(stdout, "\x1b]52;c;{}\x07", crate::literal::base64(text.as_bytes()));
            let _ = stdout.flush();
        }

        let system = match self.system() {
            Some(clipboard) => clipboard.set_text(text).map_err(|e| anyhow!("{}", e)),
            None => Err(anyhow!("{}", self.unavailable.clone().unwrap_or_default())),
        };

        return system.or_else(|error| tool(text).map_err(|tool_error| anyhow!("{}, {}", error, tool_error)));
    }

    fn system(&mut self) -> Option<&mut arboard::Clipboard> {
        // The clipboard of X11 needs a display (connecting without one waits for a timeout)
        if cfg!(all(unix, not(target_os = "macos"))) && std::env::var_os("DISPLAY").is_none_or(|d| d.is_empty()) && self.unavailable.is_none() {
            self.unavailable = Some("no X11 display".to_string());
        }

        if self.system.is_none() && self.unavailable.is_none() {
            match arboard::Clipboard::new() {
                Ok(clipboard) => self.system = Some(clipboard),
                Err(error) => self.unavailable = Some(error.to_string()),
            }
        }

        return self.system.as_mut();
    }
}

/// The first tool of the session that copies the text
fn tool(text: &str) -> Result<()> {
    let mut tried = Vec::new();

    for (_, program, args) in TOOLS.iter().filter(|(v, ..)| std::env::var_os(v).is_some_and(|value| !value.is_empty())) {
        let child = Command::new(program).args(*args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();

        let Ok(mut child) = child else {
            tried.push(*program);
            continue;
        };

        // The tools fork to keep the selection: the first process ends once it read the text
        let written = child.stdin.take().map(|mut input| input.write_all(text.as_bytes()));

        if matches!(written, Some(Ok(()))) && child.wait().is_ok_and(|s| s.success()) {
            return Ok(());
        }

        tried.push(*program);
    }

    if tried.is_empty() {
        bail!("no Wayland display for wl-copy");
    }

    bail!("{} failed or not installed", tried.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With a display (xvfb-run cargo test), the text is in the clipboard of the system for the other clients
    #[test]
    fn system_clipboard() {
        if std::env::var_os("DISPLAY").is_none() {
            eprintln!("no display, skipped");
            return;
        }

        let mut clipboard = Clipboard::default();
        clipboard.copy("int main(int argc)\n{").unwrap();

        let mut other = arboard::Clipboard::new().unwrap();
        assert_eq!(other.get_text().unwrap(), "int main(int argc)\n{");
    }

    #[test]
    fn previews() {
        assert_eq!(preview("hello"), "hello");
        assert_eq!(preview("int main(int argc)\n{\n"), "int main(int argc)…");
        assert_eq!(preview(&"x".repeat(80)), format!("{}…", "x".repeat(60)));
    }
}

/// The start of a copied text, for a message
pub(crate) fn preview(text: &str) -> String {
    let first = text.lines().next().unwrap_or_default();
    let short: String = first.chars().take(PREVIEW).collect();
    let more = short.len() < first.len() || text.trim_end().contains('\n');

    return if more { format!("{}…", short) } else { short };
}
