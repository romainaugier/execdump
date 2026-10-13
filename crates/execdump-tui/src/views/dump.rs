/*
 * Dump view: the headers and tables of the parsers
 */

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use execdump_core::dump::Dump;

use crate::commands::{Command, Motion};
use crate::theme::Theme;
use crate::views::View;
use crate::App;

use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

#[derive(Clone, Debug)]
pub struct DumpView {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    pub scroll: usize,
    pub height: usize,
}

impl DumpView {
    pub fn new(theme: &Theme, dump: &Dump) -> Self {
        return Self { title: dump.label().to_string(), lines: lines_from_dump(theme, dump, 0, 4), scroll: 0, height: 1 };
    }

    pub fn max_scroll(&self) -> usize {
        return self.lines.len().saturating_sub(self.height);
    }

    pub fn search(&mut self, pattern: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.lines.len();

        for i in 1..=count {
            let index = (self.scroll + i) % count;
            let text: String = self.lines[index].spans.iter().map(|s| s.content.to_lowercase()).collect();

            if text.contains(&pattern) {
                self.scroll = index.min(self.max_scroll());
                return true;
            }
        }

        return false;
    }

    pub fn render(&mut self, height: usize) -> Vec<Line<'static>> {
        self.height = height;
        self.scroll = self.scroll.min(self.max_scroll());

        return self.lines.iter().skip(self.scroll).take(height).cloned().collect();
    }
}

fn lines_from_dump(theme: &Theme, dump: &Dump, indent: usize, indent_size: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(format!("{:>width$}{}", "", dump.label(), width = indent * indent_size), theme.title_style())));

    let align = dump.fields_align();
    let fields_indent = (indent + 1) * indent_size;

    for field in dump.iter_fields() {
        if field.key.is_empty() {
            lines.push(Line::from(Span::styled(format!("{:>width$}{}", "", field.value, width = fields_indent), Style::default().fg(theme.value))));
        } else {
            let mut spans = vec![
                Span::styled(format!("{:>width$}{:<align$}: ", "", field.key, width = fields_indent, align = align), Style::default().fg(theme.key)),
                Span::styled(field.value.clone(), Style::default().fg(theme.value)),
            ];

            if let Some(comment) = field.comment {
                spans.push(Span::styled(format!("  {}", comment), Style::default().fg(theme.dim).add_modifier(Modifier::ITALIC)));
            }

            lines.push(Line::from(spans));
        }
    }

    for child in dump.iter_children() {
        lines.extend(lines_from_dump(theme, child, indent + 1, indent_size));
    }

    return lines;
}

/*
 * Commands
 */

impl App {
    pub(crate) fn dump_command(&mut self, command: &Command) -> bool {
        let View::Dump(view) = self.view_mut() else {
            return false;
        };

        let page = (view.height / 2).max(1);

        match command {
            Command::Move(Motion::PageDown) => view.scroll = (view.scroll + page).min(view.max_scroll()),
            Command::Move(Motion::PageUp) => view.scroll = view.scroll.saturating_sub(page),
            Command::Move(Motion::Down) => view.scroll = (view.scroll + 1).min(view.max_scroll()),
            Command::Move(Motion::Up) => view.scroll = view.scroll.saturating_sub(1),
            Command::Move(Motion::First) => view.scroll = 0,
            Command::Move(Motion::Last) => view.scroll = view.max_scroll(),
            _ => return false,
        }

        return true;
    }
}

pub(crate) fn render(view: &mut DumpView, f: &mut Frame, theme: &Theme, area: Rect) {
    let lines = view.render(area.height as usize);
    f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
}
