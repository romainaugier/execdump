/*
 * Popups: a list of places to go to (the calls of a block, the cross references to a function, the
 * callers of the root of a call graph), Enter opens one
 */

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct Popup {
    pub title: String,
    pub items: Vec<(String, Target)>,
    pub cursor: usize,
}

impl App {
    pub(crate) fn calls_popup(&mut self, program: usize, block_addr: u64, function_addr: u64) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let Some(function) = analysis.functions.get(&function_addr) else {
            return;
        };

        let Some(block) = function.blocks.get(&block_addr) else {
            return;
        };

        let mut items = Vec::new();

        for call in function.calls.iter().filter(|c| c.addr >= block.start && c.addr < block.end) {
            if let CallTarget::Function(target) = call.target {
                let label = format!("{:#x}  {}{}", call.addr, analysis.call_target_name(&call.target), if call.tail { " (tail)" } else { "" });
                items.push((label, Target::Function(program, target)));
            }
        }

        // Code references (callbacks, function pointers)
        for insn in block.insns.iter() {
            for r in [insn.imm_ref, insn.mem_ref].into_iter().flatten() {
                if let Some(target) = analysis.functions.get(&r) {
                    if !items.iter().any(|(_, t)| *t == Target::Function(program, r)) {
                        items.push((format!("{:#x}  &{}", insn.addr, target.name), Target::Function(program, r)));
                    }
                }
            }
        }

        self.show_popup("Go to".to_string(), items);
    }

    pub(crate) fn xrefs_popup(&mut self, program: usize, function_addr: u64) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let name = analysis.functions.get(&function_addr).map_or(String::new(), |f| f.name.clone());
        let mut items = Vec::new();

        for (&caller_addr, caller) in analysis.functions.iter() {
            for call in caller.calls.iter().filter(|c| c.target == CallTarget::Function(function_addr)) {
                items.push((format!("{:#x}  {} ({})", call.addr, caller.name, if call.tail { "jump" } else { "call" }), Target::Address(program, call.addr)));
            }

            for &(insn, target) in caller.refs.iter() {
                if target == function_addr && caller_addr != function_addr {
                    items.push((format!("{:#x}  {} (reference)", insn, caller.name), Target::Address(program, insn)));
                }
            }
        }

        self.show_popup(format!("Cross references to {}", name), items);
    }

    /// The forms of the string literal under the cursor of the C code, Enter copies one
    pub(crate) fn string_forms(&mut self) {
        let App { workspace, projects, .. } = self;

        let found = match workspace.view_mut() {
            View::Source(view) => projects[view.program].as_mut().map(|project| (view.cursor_line(project), view.col)),
            _ => None,
        };

        let Some(bytes) = found.and_then(|(line, col)| crate::literal::literal_at(&line, col)) else {
            return self.info("No string literal on the line".to_string());
        };

        let items = crate::literal::forms(&bytes).into_iter().map(|(label, text)| (format!("{:<8}{}", label, text), Target::Copy(text))).collect();
        self.popup = Some(Popup { title: "String (Enter copies)".to_string(), items, cursor: 0 });
    }

    /// Copies text to the clipboard of the terminal (OSC 52, most terminals and tmux with set-clipboard)
    pub(crate) fn copy(&mut self, text: &str) {
        use std::io::{IsTerminal, Write};

        let mut stdout = std::io::stdout();

        if stdout.is_terminal() {
            let _ = write!(stdout, "\x1b]52;c;{}\x07", crate::literal::base64(text.as_bytes()));
            let _ = stdout.flush();
        }

        self.info(format!("Copied {}", text));
    }

    pub(crate) fn show_popup(&mut self, title: String, items: Vec<(String, Target)>) {
        match items.len() {
            0 => self.info(format!("{}: nothing found", title)),
            1 => self.open_target(items[0].1.clone()),
            _ => self.popup = Some(Popup { title, items, cursor: 0 }),
        }
    }

    /// Keys of an open popup
    pub(crate) fn popup_key(&mut self, key: KeyEvent) {
        let Some(mut popup) = self.popup.take() else {
            return;
        };

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {}
            KeyCode::Char('j') | KeyCode::Down => {
                popup.cursor = (popup.cursor + 1).min(popup.items.len() - 1);
                self.popup = Some(popup);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                popup.cursor = popup.cursor.saturating_sub(1);
                self.popup = Some(popup);
            }
            KeyCode::Char('g') => {
                popup.cursor = 0;
                self.popup = Some(popup);
            }
            KeyCode::Char('G') => {
                popup.cursor = popup.items.len() - 1;
                self.popup = Some(popup);
            }
            KeyCode::Enter | KeyCode::Char('l') => self.open_target(popup.items[popup.cursor].1.clone()),
            _ => self.popup = Some(popup),
        }
    }
}

pub(crate) fn render_popup(f: &mut Frame, theme: &Theme, popup: &Popup) {
    let width = popup.items.iter().map(|(l, _)| l.len()).max().unwrap_or(10).max(popup.title.len()) as u16 + 6;
    let area = centered_rect(width, popup.items.len() as u16 + 2, f.area());

    let items: Vec<ListItem> = popup.items.iter().map(|(label, _)| ListItem::new(label.clone())).collect();
    let mut state = ListState::default();
    state.select(Some(popup.cursor));

    let list = List::new(items)
        .block(Block::default().title(format!(" {} ", popup.title)).borders(Borders::ALL).border_style(Style::default().fg(theme.node_selected)).style(theme.base()))
        .highlight_style(Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg))
        .highlight_symbol("> ");

    f.render_widget(Clear, area);
    f.render_stateful_widget(list, area, &mut state);
}
