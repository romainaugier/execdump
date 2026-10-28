// SPDX-License-Identifier: Apache-2.0
/*
 * Welcome view, before anything is opened
 */

use crate::commands::{Command, Motion};
use crate::theme::Theme;
use crate::{App, Focus};

use daedale_core::program::{Language, Program};

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use std::sync::Arc;

impl App {
    pub(crate) fn welcome_command(&mut self, command: &Command) -> bool {
        if *command == Command::Move(Motion::Left) {
            self.focus = Focus::Explorer;
            return true;
        }

        return false;
    }
}

pub(crate) fn render(f: &mut Frame, theme: &Theme, area: Rect, analysis_errors: &[Option<String>], programs: &[Arc<Program>]) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled("Welcome to daedale", theme.title_style())),
        Line::from(""),
        Line::from("Pick something in the explorer (j/k, Enter), or type : and an address or a function name."),
        Line::from("Analysis/Entry point opens the control flow graph of the entry point,"),
        Line::from("Modules/ hold the C code of the program, decompiled in the background."),
        Line::from(""),
        Line::from("Ctrl-w v splits the screen, gt goes to the next tab. Press ? at any time for the key bindings."),
    ];

    for program in programs.iter().filter(|p| p.language == Language::DotNet) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("{}: a .NET assembly, its code is CIL bytecode (the machine code is the stub that starts the runtime), not decompiled yet", program.name), Style::default().fg(theme.warning))));
    }

    if let Some(error) = analysis_errors.iter().flatten().next() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("Analysis failed: {}", error), Style::default().fg(theme.warning))));
    }

    f.render_widget(Paragraph::new(Text::from(lines)).centered().style(theme.base()), area);
}
