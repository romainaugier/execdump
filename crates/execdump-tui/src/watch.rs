// SPDX-License-Identifier: Apache-2.0
/*
 * Watches of the debugger: expressions whose value the debug view shows at each stop (:watch), and blocks of memory
 * it shows in hexadecimal (:memory). What changed since the stop before is highlighted.
 *
 * An expression is a name, a number, or a name plus or minus a number, with * to read the pointer at its address and
 * & for the address of a variable: a variable of the function of the selected frame, a register, a function or a
 * global of the program (its address in the process), a number (an address in the process). For a block of memory
 * the expression is its address: the value of a variable or of a register, the address of a global.
 *
 * :value shows the forms of the value of an expression (see value), Enter copies one.
 *
 * The memory is read from /proc/<pid>/mem of the program (Linux), which does not need the program to be stopped: the
 * blocks of memory and the values read from memory change while it runs. Without it the debugger reads the memory
 * at the stops.
 */

use super::*;

use crate::debug::DebugState;

use anyhow::{bail, Context};
use execdump_decompiler::storage::Shape;

use std::time::{Duration, Instant};

pub(crate) const DEFAULT_MEMORY: usize = 64;
pub(crate) const MAX_MEMORY: usize = 4096;
/// Bytes on a line of a block of memory
pub(crate) const MEMORY_COLUMNS: usize = 16;
/// Time between two reads of the memory while the program runs
const LIVE_PERIOD: Duration = Duration::from_millis(100);

/// What a watch shows
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Seen {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug)]
pub(crate) struct Watch {
    pub expr: String,
    /// Bytes of memory shown from the address of the expression (:memory)
    pub length: Option<usize>,
    /// The memory it reads at the last stop: its address and size (a word for a value), read again while the program
    /// runs
    pub read: Option<(u64, usize)>,
    pub seen: Option<Seen>,
    /// What it showed at the last stop (the changes while the program runs are the ones since), and at the stop before
    /// (the changes of the last stop)
    pub stop: Option<Seen>,
    pub before: Option<Seen>,
    pub error: Option<String>,
}

impl Watch {
    pub fn new(expr: &str, length: Option<usize>) -> Self {
        return Watch { expr: expr.trim().to_string(), length, read: None, seen: None, stop: None, before: None, error: None };
    }

    /// What the changes are against: the last stop while the program runs, else the stop before
    fn reference(&self, running: bool) -> Option<&Seen> {
        return if running { self.stop.as_ref() } else { self.before.as_ref() };
    }
}

/// An expression: [*][&]name[+-offset]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Parsed {
    deref: bool,
    address_of: bool,
    name: String,
    offset: i64,
}

fn number(text: &str) -> Option<u64> {
    let text = text.trim();

    return match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    };
}

fn parse(expr: &str) -> Result<Parsed> {
    let text = expr.trim();
    let (deref, text) = text.strip_prefix('*').map_or((false, text), |t| (true, t.trim()));
    let (address_of, text) = text.strip_prefix('&').map_or((false, text), |t| (true, t.trim()));

    // The offset after the last + or - (not the first character)
    let (name, offset) = match text.char_indices().skip(1).filter(|(_, c)| *c == '+' || *c == '-').last() {
        Some((at, sign)) => {
            let value = number(&text[at + 1..]).with_context(|| format!("{} is not a number", text[at + 1..].trim()))? as i64;
            (text[..at].trim(), if sign == '-' { -value } else { value })
        }
        None => (text, 0),
    };

    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "_.$:".contains(c)) {
        bail!("not an expression: {} (a name or a number, plus or minus a number, with * or &)", expr);
    }

    return Ok(Parsed { deref, address_of, name: name.to_string(), offset });
}

/// What a name is at a stop
enum Term {
    /// A variable of the frame: its value (in a register, a constant) or its address in the stack, its formatted
    /// value
    Variable { place: Option<std::result::Result<u128, u64>>, text: Option<String>, shape: Shape },
    Register(u128),
    /// A function or a global, at its address in the process
    Symbol { addr: u64, function: bool },
    Number(u64),
}

fn word(bytes: &[u8]) -> u64 {
    return bytes.iter().take(8).rev().fold(0u64, |v, &b| v << 8 | b as u64);
}

fn hex_value(value: u64) -> String {
    return if value < 10 { value.to_string() } else { format!("{:#x} ({})", value, value as i64) };
}

impl App {
    /*
     * Commands
     */

    pub(crate) fn add_watch(&mut self, expr: &str, length: Option<usize>) {
        if let Err(error) = parse(expr) {
            return self.error(format!("{:#}", error));
        }

        let length = length.map(|l| l.clamp(1, MAX_MEMORY));
        self.watches.push(Watch::new(expr, length));
        self.evaluate_watches(false);
        self.info(format!("Watching {}{}", expr.trim(), length.map_or(String::new(), |l| format!(" ({} bytes)", l))));
    }

    /// Removes a watch: by its number (from 1), all of them, or the one under the cursor of the debug view
    pub(crate) fn remove_watch(&mut self, which: Option<&str>) {
        let index = match which {
            Some("all") => {
                self.watches.clear();
                return;
            }
            Some(n) => match n.parse::<usize>() {
                Ok(n) if n >= 1 && n <= self.watches.len() => n - 1,
                _ => match self.watches.iter().position(|w| w.expr == n) {
                    Some(index) => index,
                    None => return self.error(format!("No watch {}", n)),
                },
            },
            None => match self.watch_under_cursor() {
                Some(index) => index,
                None => return self.error("No watch under the cursor: :unwatch <n>".to_string()),
            },
        };

        let watch = self.watches.remove(index);
        self.info(format!("No more watching {}", watch.expr));
    }

    /*
     * Evaluation
     */

    /// The memory of the program: from its process while it runs (Linux), else what the debugger read (the reads
    /// missing are asked for)
    fn read_memory(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let debugger = self.debugger.as_mut()?;

        if let Some(bytes) = debugger.read_process(addr, len) {
            return Some(bytes);
        }

        if let Some(bytes) = debugger.bytes(addr, len) {
            return Some(bytes.to_vec());
        }

        debugger.request_read(addr, len);
        return None;
    }

    fn term(&mut self, name: &str) -> Option<Term> {
        let debugger = self.debugger.as_ref()?;
        let program = debugger.program;
        let bias = debugger.bias;

        if let Some((_, _, shape, place)) = self.variable_places().into_iter().find(|(n, ..)| n == name) {
            let text = self.variables().into_iter().find(|v| v.name == name).and_then(|v| v.value);
            return Some(Term::Variable { place, text, shape });
        }

        let debugger = self.debugger.as_ref()?;

        if let Some(value) = debugger.snapshot.as_ref().and_then(|s| s.register(name)) {
            return Some(Term::Register(value));
        }

        // A function, a global the function of the frame uses, a symbol of the binary
        let function = self.frame_function().map(|(f, _)| f);
        let project = self.projects[program].as_mut()?;

        if let Some(addr) = project.resolve(name) {
            return Some(Term::Symbol { addr: addr + bias, function: true });
        }

        if let Some(addr) = function.and_then(|f| project.global(f, name)) {
            return Some(Term::Symbol { addr: addr + bias, function: false });
        }

        if let Some(symbol) = self.programs[program].symbols.values().find(|s| s.name == name) {
            let function = self.analyses[program].as_ref().is_some_and(|a| a.functions.contains_key(&symbol.addr));
            return Some(Term::Symbol { addr: symbol.addr + bias, function });
        }

        return number(name).map(Term::Number);
    }

    /// Address an expression designates: the value of a variable, a register or a number, the address of a symbol (&: of a
    /// variable in memory), plus the offset, then the pointer read there with *
    fn watch_address(&mut self, parsed: &Parsed, pointer_size: usize) -> Result<Option<u64>> {
        let term = self.term(&parsed.name).with_context(|| format!("{} is not a variable, a register, a symbol or a number here", parsed.name))?;

        let base = match (term, parsed.address_of) {
            (Term::Variable { place: Some(Err(addr)), .. }, true) => Some(addr),
            (Term::Symbol { addr, .. }, _) => Some(addr),
            (_, true) => bail!("{} has no address (a register or a constant)", parsed.name),
            (Term::Variable { place: Some(Ok(value)), .. }, false) => Some(value as u64),
            (Term::Variable { place: Some(Err(addr)), .. }, false) => self.read_memory(addr, pointer_size).map(|b| word(&b)),
            (Term::Variable { place: None, .. }, false) => bail!("{} is not anywhere at this address", parsed.name),
            (Term::Register(value), false) => Some(value as u64),
            (Term::Number(value), false) => Some(value),
        };

        let Some(base) = base.map(|b| b.wrapping_add_signed(parsed.offset)) else {
            return Ok(None);
        };

        if !parsed.deref {
            return Ok(Some(base));
        }

        return Ok(self.read_memory(base, pointer_size).map(|b| word(&b)));
    }

    /// What a watch shows now, and the memory it reads
    fn evaluate(&mut self, watch: &Watch, pointer_size: usize) -> Result<(Option<Seen>, Option<(u64, usize)>)> {
        let parsed = parse(&watch.expr)?;

        if let Some(length) = watch.length {
            let Some(addr) = self.watch_address(&parsed, pointer_size)? else {
                return Ok((None, None));
            };

            return Ok((self.read_memory(addr, length).map(Seen::Bytes), Some((addr, length))));
        }

        // A value: the one of the variable, the register, the global, or the word read at the address
        let plain = !parsed.deref && !parsed.address_of && parsed.offset == 0;

        if plain {
            match self.term(&parsed.name) {
                Some(Term::Variable { text, .. }) => return Ok((text.map(Seen::Text), None)),
                Some(Term::Register(value)) => return Ok((Some(Seen::Text(hex_value(value as u64))), None)),
                Some(Term::Symbol { addr, function: false }) => {
                    let read = self.read_memory(addr, pointer_size);
                    return Ok((read.map(|b| Seen::Text(hex_value(word(&b)))), Some((addr, pointer_size))));
                }
                _ => {}
            }
        }

        if parsed.deref {
            let address = Parsed { deref: false, ..parsed.clone() };
            let Some(addr) = self.watch_address(&address, pointer_size)? else {
                return Ok((None, None));
            };

            let read = self.read_memory(addr, pointer_size);
            return Ok((read.map(|b| Seen::Text(hex_value(word(&b)))), Some((addr, pointer_size))));
        }

        let addr = self.watch_address(&parsed, pointer_size)?;
        return Ok((addr.map(|a| Seen::Text(format!("{:#x}", a))), None));
    }

    /// The watches at a stop (what they showed is the one of the stop before), or again with what was read since
    pub(crate) fn evaluate_watches(&mut self, stopped: bool) {
        let Some(debugger) = self.debugger.as_ref().filter(|d| d.state == DebugState::Stopped && d.snapshot.is_some()) else {
            return;
        };

        let pointer_size = self.programs[debugger.program].pointer_size.max(4) as usize;

        for index in 0..self.watches.len() {
            let watch = self.watches[index].clone();
            let result = self.evaluate(&watch, pointer_size);
            let watch = &mut self.watches[index];

            if stopped {
                watch.before = watch.stop.take();
                watch.seen = None;
            }

            match result {
                Ok((seen, read)) => {
                    watch.seen = seen.or(watch.seen.take());
                    watch.stop = watch.seen.clone();
                    watch.read = read;
                    watch.error = None;
                }
                Err(error) => {
                    watch.seen = None;
                    watch.read = None;
                    watch.error = Some(format!("{:#}", error));
                }
            }
        }

        if let Some(debugger) = self.debugger.as_mut() {
            debugger.last_live = Some(Instant::now());
        }
    }

    /// While the program runs, the memory the watches read changes (read from its process)
    pub(crate) fn watch_live(&mut self) {
        let Some(debugger) = self.debugger.as_mut().filter(|d| d.state == DebugState::Running && d.can_read_process()) else {
            return;
        };

        if debugger.last_live.is_some_and(|t| t.elapsed() < LIVE_PERIOD) {
            return;
        }

        debugger.last_live = Some(Instant::now());

        for watch in self.watches.iter_mut() {
            let Some((addr, len)) = watch.read else {
                continue;
            };

            let Some(bytes) = debugger.read_process(addr, len) else {
                continue;
            };

            watch.seen = Some(match watch.length {
                Some(_) => Seen::Bytes(bytes),
                None => Seen::Text(hex_value(word(&bytes))),
            });
        }
    }

    /*
     * Values (:value)
     */

    /// The bytes of the value of an expression (of the block of memory of a length at its address) and how the debug
    /// view shows it, None while the memory is read
    fn value_bytes(&mut self, expr: &str, length: Option<usize>) -> Result<Option<(Vec<u8>, Option<String>)>> {
        let Some(debugger) = self.debugger.as_ref() else {
            bail!("No program under the debugger");
        };

        let program = &self.programs[debugger.program];
        let (pointer_size, big_endian) = (program.pointer_size.max(4) as usize, program.big_endian);
        let parsed = parse(expr)?;

        // A number in the byte order of the program
        let number = move |value: u128, size: usize| -> Vec<u8> {
            return match big_endian {
                true => value.to_be_bytes()[16 - size..].to_vec(),
                false => value.to_le_bytes()[..size].to_vec(),
            };
        };

        if let Some(length) = length {
            let Some(addr) = self.watch_address(&parsed, pointer_size)? else {
                return Ok(None);
            };

            return Ok(self.read_memory(addr, length).map(|bytes| (bytes, None)));
        }

        if !parsed.deref && !parsed.address_of && parsed.offset == 0 {
            match self.term(&parsed.name) {
                Some(Term::Variable { place, text, shape }) => {
                    let size = shape.size(pointer_size as u8).clamp(1, 256);

                    let bytes = match place {
                        Some(Ok(value)) => Some(number(value, size.min(16))),
                        Some(Err(addr)) => self.read_memory(addr, size),
                        None => bail!("{} is not anywhere at this address", parsed.name),
                    };

                    return Ok(bytes.map(|bytes| (bytes, text)));
                }
                Some(Term::Register(value)) if value >> 64 != 0 => return Ok(Some((number(value, 16), Some(format!("{:#x}", value))))),
                Some(Term::Register(value)) => return Ok(Some((number(value, pointer_size), Some(hex_value(value as u64))))),
                Some(Term::Symbol { addr, function: false }) => return Ok(self.read_memory(addr, pointer_size).map(|bytes| (bytes, None))),
                _ => {}
            }
        }

        if parsed.deref {
            let address = Parsed { deref: false, ..parsed.clone() };

            let Some(addr) = self.watch_address(&address, pointer_size)? else {
                return Ok(None);
            };

            return Ok(self.read_memory(addr, pointer_size).map(|bytes| (bytes, None)));
        }

        let addr = self.watch_address(&parsed, pointer_size)?;
        return Ok(addr.map(|a| (number(a as u128, pointer_size), Some(format!("{:#x}", a)))));
    }

    /// What a value points to: a function of the program or a symbol, the bytes there
    fn pointee(&self, bytes: &[u8]) -> Option<crate::value::Pointee> {
        let debugger = self.debugger.as_ref()?;
        let program = &self.programs[debugger.program];
        let pointer_size = program.pointer_size.max(4) as usize;

        if bytes.len() < pointer_size || bytes.len() > 16 {
            return None;
        }

        let addr = crate::value::unsigned(&bytes[..pointer_size], program.big_endian) as u64;

        if addr == 0 {
            return None;
        }

        let name = match debugger.program_addr(program, addr) {
            Some(local) => Some(self.address_name(debugger.program, local)).filter(|name| *name != format!("{:#x}", local)),
            None => program.symbols.get(&addr.wrapping_sub(debugger.bias)).map(|s| s.name.clone()),
        };

        return Some(crate::value::Pointee { name, bytes: debugger.bytes_from(addr) });
    }

    /// The expression of the value under the cursor: the watch (a block of memory and its length) or the variable of
    /// the line of the debug view, the word of the code
    fn value_under_cursor(&mut self) -> Option<(String, Option<usize>)> {
        use crate::views::debug::Row;

        let row = match self.view() {
            View::Debug(view) => Some(view.row()),
            _ => None,
        };

        return match row {
            Some(Row::Watch(index)) => self.watches.get(index).map(|w| (w.expr.clone(), w.length)),
            Some(Row::Variable(index)) => self.variables().get(index).map(|v| (v.name.clone(), None)),
            Some(_) => None,
            None => self.word_under_cursor().map(|word| (word, None)),
        };
    }

    /// :value: the forms of the value of an expression in a popup (Enter copies one), or one form copied. Without an
    /// expression: the value under the cursor
    pub(crate) fn value_command(&mut self, expr: Option<String>, form: Option<String>) {
        if let Some(form) = form.as_deref().filter(|f| !crate::value::FORMS.contains(f)) {
            return self.error(format!("No form {}: {}", form, crate::value::FORMS.join(", ")));
        }

        let (expr, length) = match expr {
            Some(expr) => (expr, None),
            None => match self.value_under_cursor() {
                Some(found) => found,
                None => return self.error("No value under the cursor: :value <expression> [form]".to_string()),
            },
        };

        self.pending_value = None;
        self.show_value(expr, length, form);
    }

    fn show_value(&mut self, expr: String, length: Option<usize>, form: Option<String>) {
        let (bytes, shown) = match self.value_bytes(&expr, length) {
            Ok(Some(found)) => found,
            Ok(None) => {
                self.info(format!("Reading the memory of {}...", expr));
                self.pending_value = Some((expr, length, form));
                return;
            }
            Err(error) => return self.error(format!("{:#}", error)),
        };

        let Some(program) = self.debugger.as_ref().map(|d| &self.programs[d.program]) else {
            return;
        };

        let (pointer_size, big_endian) = (program.pointer_size.max(4) as usize, program.big_endian);
        let pointee = self.pointee(&bytes);
        let forms = crate::value::forms(&bytes, big_endian, pointer_size, shown, pointee);

        let Some(form) = form else {
            let items = forms.into_iter().map(|(label, text)| (format!("{:<8}{}", label, text), Target::Copy(text))).collect();
            self.popup = Some(Popup { title: format!("Value of {} (Enter copies)", expr), items, cursor: 0 });
            return;
        };

        match forms.into_iter().find(|(label, _)| *label == form) {
            Some((_, text)) => {
                self.copy(&text);
            }
            None => self.error(format!("{} has no {} form", expr, form)),
        }
    }

    /// Memory the debugger read: the value :value waits for, dropped when the program stopped again
    pub(crate) fn value_read(&mut self, stopped: bool) {
        let Some((expr, length, form)) = self.pending_value.take() else {
            return;
        };

        if !stopped {
            self.show_value(expr, length, form);
        }
    }

    /*
     * Debug view
     */

    /// Index of the watch of the line under the cursor of the debug view
    fn watch_under_cursor(&self) -> Option<usize> {
        return match self.view() {
            View::Debug(view) => view.watch_row(),
            _ => None,
        };
    }

    pub(crate) fn watch_lines(&self, theme: &Theme) -> Vec<(Line<'static>, crate::views::debug::Row)> {
        use crate::views::debug::Row;

        if self.watches.is_empty() {
            return Vec::new();
        }

        let running = self.debugger.as_ref().is_some_and(|d| d.state == DebugState::Running);
        let title = if running && self.debugger.as_ref().is_some_and(|d| d.can_read_process()) { "Watches (live)" } else { "Watches" };
        let mut lines = vec![(Line::from(Span::styled(title, Style::default().fg(theme.title).add_modifier(Modifier::BOLD))), Row::Text)];
        let changed = Style::default().fg(theme.warning).add_modifier(Modifier::BOLD);

        for (index, watch) in self.watches.iter().enumerate() {
            let row = Row::Watch(index);
            let label = Span::styled(format!("  {:>2} {} ", index + 1, watch.expr), Style::default().fg(theme.asm_register));

            if let Some(error) = watch.error.as_ref() {
                lines.push((Line::from(vec![label, Span::styled(format!("  {}", error), Style::default().fg(theme.dim))]), row));
                continue;
            }

            match (&watch.seen, watch.length) {
                (Some(Seen::Bytes(bytes)), Some(length)) => {
                    let addr = watch.read.map_or(0, |(a, _)| a);
                    let header = Span::styled(format!("@ {:#x} ({} bytes)", addr, length), Style::default().fg(theme.dim));
                    lines.push((Line::from(vec![label, header]), row));

                    let before = match watch.reference(running) {
                        Some(Seen::Bytes(before)) => Some(before.as_slice()),
                        _ => None,
                    };

                    for (line, chunk) in bytes.chunks(MEMORY_COLUMNS).enumerate() {
                        let start = line * MEMORY_COLUMNS;
                        let differs = |i: usize| before.is_some_and(|b| b.get(start + i).is_some_and(|&old| old != chunk[i]));
                        let mut spans = vec![Span::styled(format!("     {:016x}  ", addr + start as u64), Style::default().fg(theme.asm_address))];

                        for (i, byte) in chunk.iter().enumerate() {
                            let style = if differs(i) { changed } else { Style::default().fg(theme.hex_data) };
                            spans.push(Span::styled(format!("{:02x}", byte), style));
                            spans.push(Span::raw(if i == 7 { "  " } else { " " }));
                        }

                        let missing = MEMORY_COLUMNS - chunk.len();
                        spans.push(Span::raw(" ".repeat(missing * 3 + usize::from(chunk.len() <= 7))));
                        spans.push(Span::raw(" "));

                        for (i, &byte) in chunk.iter().enumerate() {
                            let c = if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' };
                            let style = if differs(i) { changed } else { Style::default().fg(theme.hex_ascii) };
                            spans.push(Span::styled(c.to_string(), style));
                        }

                        lines.push((Line::from(spans), row));
                    }
                }
                (Some(Seen::Text(text)), _) => {
                    let style = if watch.reference(running).is_some_and(|b| *b != Seen::Text(text.clone())) { changed } else { Style::default().fg(theme.value) };
                    lines.push((Line::from(vec![label, Span::raw("= "), Span::styled(text.clone(), style)]), row));
                }
                _ => {
                    let state = if self.debugger.as_ref().is_some_and(|d| d.state == DebugState::Stopped) { "reading..." } else { "?" };
                    lines.push((Line::from(vec![label, Span::styled(format!("= {}", state), Style::default().fg(theme.dim))]), row));
                }
            }
        }

        return lines;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expressions() {
        assert_eq!(parse("v1").unwrap(), Parsed { deref: false, address_of: false, name: "v1".to_string(), offset: 0 });
        assert_eq!(parse("*rsp+0x10").unwrap(), Parsed { deref: true, address_of: false, name: "rsp".to_string(), offset: 16 });
        assert_eq!(parse("&buffer - 8").unwrap(), Parsed { deref: false, address_of: true, name: "buffer".to_string(), offset: -8 });
        assert_eq!(parse("0x4010a0").unwrap().name, "0x4010a0");
        assert!(parse("a[1]").is_err() && parse("x + y").is_err());
        assert_eq!(hex_value(5), "5");
        assert_eq!(hex_value(0x1234), "0x1234 (4660)");
        assert_eq!(word(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);
    }
}
