/*
 * Hex view of a region or a section
 */

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::commands::{Command, Motion};
use crate::theme::Theme;
use crate::views::View;
use crate::App;

use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct HexView {
    pub title: String,
    pub base: u64,
    /// Shared between the copies of the view (splits, jumplists)
    pub data: Arc<[u8]>,
    /// First displayed row
    pub scroll: usize,
    pub height: usize,
}

const HEX_ROW: usize = 16;

impl HexView {
    pub fn new(title: String, base: u64, data: impl Into<Arc<[u8]>>) -> Self {
        return Self { title, base, data: data.into(), scroll: 0, height: 1 };
    }

    pub fn rows(&self) -> usize {
        return self.data.len().div_ceil(HEX_ROW);
    }

    pub fn max_scroll(&self) -> usize {
        return self.rows().saturating_sub(self.height);
    }

    pub fn goto(&mut self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.data.len() as u64 {
            return false;
        }

        self.scroll = ((addr - self.base) as usize / HEX_ROW).saturating_sub(2);
        return true;
    }

    pub fn render(&mut self, theme: &Theme, height: usize) -> Vec<Line<'static>> {
        self.height = height;
        self.scroll = self.scroll.min(self.max_scroll());

        let addr_width = format!("{:x}", self.base + self.data.len() as u64).len().max(8);
        let mut lines = Vec::new();

        for row in self.scroll..(self.scroll + height).min(self.rows()) {
            let offset = row * HEX_ROW;
            let chunk = &self.data[offset..(offset + HEX_ROW).min(self.data.len())];

            let mut spans = vec![Span::styled(format!("{:0width$x}  ", self.base + offset as u64, width = addr_width), Style::default().fg(theme.hex_offset))];

            for (i, byte) in chunk.iter().enumerate() {
                let color = if *byte == 0 { theme.dim } else { theme.hex_data };
                spans.push(Span::styled(format!("{:02x} ", byte), Style::default().fg(color)));

                if i == 7 {
                    spans.push(Span::raw(" "));
                }
            }

            for i in chunk.len()..HEX_ROW {
                spans.push(Span::raw("   "));

                if i == 7 {
                    spans.push(Span::raw(" "));
                }
            }

            spans.push(Span::styled("│", Style::default().fg(theme.border)));

            let ascii: String = chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
            spans.push(Span::styled(ascii, Style::default().fg(theme.hex_ascii)));
            spans.push(Span::styled("│", Style::default().fg(theme.border)));

            lines.push(Line::from(spans));
        }

        return lines;
    }
}


/*
 * Commands
 */

impl App {
    pub(crate) fn hex_command(&mut self, command: &Command) -> bool {
        let View::Hex(view) = self.view_mut() else {
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

pub(crate) fn render(view: &mut HexView, f: &mut Frame, theme: &Theme, area: Rect) {
    let lines = view.render(theme, area.height as usize);
    f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_goto() {
        let mut hex = HexView::new("data".to_string(), 0x1000, vec![0; 0x1000]);
        hex.height = 10;

        assert!(hex.goto(0x1800));
        assert_eq!(hex.scroll, 0x80 - 2);
        assert!(!hex.goto(0x3000));
    }
}
