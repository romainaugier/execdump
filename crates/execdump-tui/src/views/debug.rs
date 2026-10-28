// SPDX-License-Identifier: Apache-2.0
/*
 * Debug view: the state of the program under the debugger. The variables of the function of the selected frame and
 * their values (Enter shows the forms of a value, as :value), the call stack (Enter selects a frame: the code and the
 * variables follow it), the registers, the breakpoints (Enter shows the code of one) and the last lines of the output
 * of the program.
 */

use crate::commands::{Command, Motion};
use crate::debug::DebugState;
use crate::theme::Theme;
use crate::views::follow_cursor;
use crate::App;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// Lines of output of the program shown
const OUTPUT_SHOWN: usize = 12;
/// Registers on a line
const REGISTER_COLUMNS: usize = 3;

/// What a line of the view is, for Enter
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Row {
    Text,
    Frame(usize),
    /// Program and address of a breakpoint
    Breakpoint(usize, u64),
    /// A line of a watch
    Watch(usize),
    /// A variable of the frame
    Variable(usize),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DebugView {
    pub cursor: usize,
    scroll: usize,
    height: usize,
    rows: Vec<Row>,
}

impl DebugView {
    pub fn row(&self) -> Row {
        return self.rows.get(self.cursor).copied().unwrap_or(Row::Text);
    }

    /// The watch of the line under the cursor
    pub fn watch_row(&self) -> Option<usize> {
        return match self.row() {
            Row::Watch(index) => Some(index),
            _ => None,
        };
    }
}

fn title(theme: &Theme, text: &str) -> (Line<'static>, Row) {
    return (Line::from(Span::styled(text.to_string(), Style::default().fg(theme.title).add_modifier(Modifier::BOLD))), Row::Text);
}

fn dim(theme: &Theme, text: String) -> (Line<'static>, Row) {
    return (Line::from(Span::styled(text, Style::default().fg(theme.dim))), Row::Text);
}

impl App {
    /// Lines of the debug view
    pub(crate) fn debug_lines(&mut self, theme: &Theme) -> Vec<(Line<'static>, Row)> {
        let mut lines = Vec::new();

        let Some(status) = self.debug_status() else {
            lines.push(dim(theme, "No program under the debugger: :debug [arguments] (or F5) runs it".to_string()));
            lines.push(dim(theme, "F9 / gb / :break toggle a breakpoint at the cursor, F7 step, F8 step over, F4 finish, F6 interrupt".to_string()));
            lines.push(dim(theme, "w / :watch <expression> watches a value, m / :memory <address> [bytes] a block of memory, dd / :unwatch removes one".to_string()));
            lines.push(dim(theme, "Enter / y / :value [expression] [form] shows a value as integers, floats, a pointer, a string and bytes (Enter copies one)".to_string()));
            lines.extend(self.watch_lines(theme));
            lines.extend(self.breakpoint_lines(theme));
            return lines;
        };

        lines.push((Line::from(Span::styled(status, Style::default().fg(theme.fg).add_modifier(Modifier::BOLD))), Row::Text));
        lines.extend(self.watch_lines(theme));

        let stopped = self.debugger.as_ref().is_some_and(|d| d.state == DebugState::Stopped && d.snapshot.is_some());

        if stopped {
            lines.push(title(theme, "Variables"));
            let variables = self.variables();

            if variables.is_empty() {
                lines.push(dim(theme, "  none known here (not code of the program, or not decompiled yet)".to_string()));
            }

            let width = variables.iter().map(|v| v.name.chars().count()).max().unwrap_or(0);

            for (index, variable) in variables.into_iter().enumerate() {
                let (value, color) = match variable.value {
                    Some(value) => (value, theme.value),
                    None => ("?".to_string(), theme.dim),
                };

                lines.push((
                    Line::from(vec![
                        Span::styled(format!("  {:<width$} = ", variable.name, width = width), Style::default().fg(theme.asm_register)),
                        Span::styled(value, Style::default().fg(color)),
                        Span::styled(format!("  {}", variable.location), Style::default().fg(theme.dim)),
                    ]),
                    Row::Variable(index),
                ));
            }

            lines.push(title(theme, "Call stack"));
            lines.extend(self.frame_lines(theme));

            lines.push(title(theme, "Registers"));
            lines.extend(self.register_lines(theme));
        }

        lines.extend(self.breakpoint_lines(theme));

        let output: Vec<String> = self.debugger.as_ref().map_or(Vec::new(), |d| d.output_tail.iter().rev().take(OUTPUT_SHOWN).rev().cloned().collect());

        if !output.is_empty() {
            lines.push(title(theme, "Output"));
            lines.extend(output.into_iter().map(|l| (Line::from(Span::styled(format!("  {}", l), Style::default().fg(theme.fg))), Row::Text)));
        }

        if let Some(error) = self.debugger.as_ref().and_then(|d| d.last_error.clone()) {
            lines.push((Line::from(Span::styled(format!("Last error: {}", error), Style::default().fg(theme.warning))), Row::Text));
        }

        return lines;
    }

    fn frame_lines(&self, theme: &Theme) -> Vec<(Line<'static>, Row)> {
        let Some(snapshot) = self.debugger.as_ref().and_then(|d| d.snapshot.as_ref()) else {
            return Vec::new();
        };

        return snapshot
            .frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                let selected = index == snapshot.frame;
                let marker = if selected { "▶" } else { " " };

                let module = self.frame_module(frame.pc).map_or(String::new(), |m| format!("  {}", m));

                let line = Line::from(vec![
                    Span::styled(format!(" {}#{:<2} ", marker, index), Style::default().fg(if selected { theme.title } else { theme.dim })),
                    Span::styled(format!("{:#014x} ", frame.pc), Style::default().fg(theme.asm_address)),
                    Span::styled(self.frame_name(frame.pc, &frame.function), Style::default().fg(theme.asm_label)),
                    Span::styled(module, Style::default().fg(theme.dim)),
                ]);

                (line, Row::Frame(index))
            })
            .collect();
    }

    fn register_lines(&self, theme: &Theme) -> Vec<(Line<'static>, Row)> {
        let Some(debugger) = self.debugger.as_ref() else {
            return Vec::new();
        };

        let Some(snapshot) = debugger.snapshot.as_ref() else {
            return Vec::new();
        };

        let digits = self.programs[debugger.program].pointer_size.max(4) as usize * 2;
        let values: Vec<(String, u128)> = debugger.shown_registers.iter().filter_map(|n| Some((n.clone(), snapshot.register(n)?))).collect();

        return values
            .chunks(REGISTER_COLUMNS)
            .map(|row| {
                let mut spans = vec![Span::raw("  ")];

                for (name, value) in row {
                    spans.push(Span::styled(format!("{:>6} ", name), Style::default().fg(theme.asm_register)));
                    spans.push(Span::styled(format!("{:0digits$x}  ", value, digits = digits), Style::default().fg(theme.value)));
                }

                (Line::from(spans), Row::Text)
            })
            .collect();
    }

    fn breakpoint_lines(&self, theme: &Theme) -> Vec<(Line<'static>, Row)> {
        if self.breakpoints.is_empty() {
            return Vec::new();
        }

        let mut lines = vec![title(theme, "Breakpoints")];

        for &(program, addr) in self.breakpoints.iter() {
            let line = Line::from(vec![
                Span::styled("  ● ", Style::default().fg(theme.warning)),
                Span::styled(self.address_name(program, addr), Style::default().fg(theme.asm_label)),
                Span::styled(format!("  {:#x}", addr), Style::default().fg(theme.dim)),
            ]);

            lines.push((line, Row::Breakpoint(program, addr)));
        }

        return lines;
    }

    /// Commands of the debug view: moves, Enter on a frame or a breakpoint
    pub(crate) fn debug_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let repeat = count.unwrap_or(1).max(1);

        let crate::views::View::Debug(view) = self.workspace.view_mut() else {
            return false;
        };

        let last = view.rows.len().saturating_sub(1);
        let page = (view.height / 2).max(1);

        match command {
            Command::Move(motion) => {
                view.cursor = match motion {
                    Motion::Down | Motion::JumpDown => (view.cursor + repeat).min(last),
                    Motion::Up | Motion::JumpUp => view.cursor.saturating_sub(repeat),
                    Motion::PageDown => (view.cursor + page).min(last),
                    Motion::PageUp => view.cursor.saturating_sub(page),
                    Motion::First => 0,
                    Motion::Last => last,
                    // The next (previous) frame or breakpoint
                    Motion::Next => (view.cursor + 1..=last).find(|&i| view.rows[i] != Row::Text).unwrap_or(view.cursor),
                    Motion::Previous => (0..view.cursor).rev().find(|&i| view.rows[i] != Row::Text).unwrap_or(view.cursor),
                    _ => return false,
                };

                return true;
            }
            Command::Open(_) => {
                match view.row() {
                    Row::Frame(index) => self.select_frame(index),
                    Row::Breakpoint(program, addr) => self.open_code(program, addr),
                    Row::Watch(_) | Row::Variable(_) => self.value_command(None, None),
                    Row::Text => {}
                }

                return true;
            }
            _ => return false,
        }
    }
}

pub(crate) fn render(view: &mut DebugView, f: &mut Frame, theme: &Theme, area: Rect, content: Vec<(Line<'static>, Row)>) {
    view.height = area.height as usize;
    view.rows = content.iter().map(|(_, row)| *row).collect();
    view.cursor = view.cursor.min(view.rows.len().saturating_sub(1));
    follow_cursor(view.cursor, &mut view.scroll, view.height);

    let lines: Vec<Line> = content
        .into_iter()
        .enumerate()
        .skip(view.scroll)
        .take(view.height)
        .map(|(index, (line, _))| if index == view.cursor { line.style(Style::default().bg(theme.cursor_bg)) } else { line })
        .collect();

    f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
}
