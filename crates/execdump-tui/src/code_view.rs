/*
 * Decompiled C code of a function, with syntax highlighting and the address of each line
 */

use crate::theme::Theme;
use crate::views::follow_cursor;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

const KEYWORDS: &[&str] = &["if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return", "goto", "sizeof"];

const TYPES: &[&str] = &["void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "bool", "struct", "union", "enum", "const", "undefined"];

#[derive(Clone, Debug, PartialEq)]
pub enum CodeState {
    Loading,
    Ready,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct CodeView {
    pub program: usize,
    pub function: u64,
    pub title: String,
    pub lines: Vec<String>,
    pub addrs: Vec<Option<u64>>,
    pub state: CodeState,
    /// Improved by the LLM
    pub improved: bool,
    pub cursor: usize,
    pub scroll: usize,
    pub height: usize,
}

fn is_type(word: &str) -> bool {
    return TYPES.contains(&word) || (word.ends_with("_t") && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
}

impl CodeView {
    pub fn loading(program: usize, function: u64, name: &str) -> Self {
        return CodeView {
            program,
            function,
            title: format!("{} @ {:#x} (C)", name, function),
            lines: Vec::new(),
            addrs: Vec::new(),
            state: CodeState::Loading,
            improved: false,
            cursor: 0,
            scroll: 0,
            height: 1,
        };
    }

    pub fn set_code(&mut self, text: &str, addrs: Vec<Option<u64>>) {
        self.lines = text.lines().map(|l| l.to_string()).collect();
        self.addrs = addrs;
        self.state = CodeState::Ready;
        self.cursor = self.cursor.min(self.lines.len().saturating_sub(1));
    }

    /// Address of the line under the cursor, or of the closest line above with one
    pub fn cursor_addr(&self) -> Option<u64> {
        let end = (self.cursor + 1).min(self.addrs.len());
        return self.addrs[..end].iter().rev().flatten().next().copied().or(Some(self.function));
    }

    /// Moves the cursor to the first line of an address
    pub fn goto(&mut self, addr: u64) -> bool {
        // The closest address at or before the one requested
        let best = self.addrs.iter().enumerate().filter_map(|(i, a)| a.filter(|&a| a <= addr).map(|a| (i, a))).max_by_key(|(i, a)| (*a, usize::MAX - i));

        if let Some((index, _)) = best {
            self.cursor = index;
            self.scroll = index.saturating_sub(self.height / 3);
            return true;
        }

        return false;
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let max = self.lines.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max.max(0)) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    pub fn search(&mut self, pattern: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.lines.len();

        for i in 1..=count {
            let index = (self.cursor + i) % count;

            if self.lines[index].to_lowercase().contains(&pattern) {
                self.cursor = index;
                self.scroll = index.saturating_sub(self.height / 3);
                return true;
            }
        }

        return false;
    }

    /// Identifier under the cursor that is followed by a call (the function the line calls)
    pub fn called_names(&self) -> Vec<String> {
        let Some(line) = self.lines.get(self.cursor) else {
            return Vec::new();
        };

        let mut names = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
                let start = i;

                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }

                let word: String = chars[start..i].iter().collect();

                if chars.get(i) == Some(&'(') && !KEYWORDS.contains(&word.as_str()) {
                    names.push(word);
                }
            } else {
                i += 1;
            }
        }

        return names;
    }

    fn highlight(theme: &Theme, line: &str) -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        let style = |color| Style::default().fg(color);

        while i < chars.len() {
            let c = chars[i];
            let start = i;

            let color = if line[line.char_indices().nth(i).map_or(0, |(b, _)| b)..].starts_with("//") {
                i = chars.len();
                theme.comment
            } else if c == '"' || c == '\'' {
                i += 1;

                while i < chars.len() && chars[i] != c {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }

                i = (i + 1).min(chars.len());
                theme.hex_ascii
            } else if c.is_ascii_digit() {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric()) {
                    i += 1;
                }

                theme.asm_immediate
            } else if c.is_ascii_alphabetic() || c == '_' {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }

                let word: String = chars[start..i].iter().collect();

                if KEYWORDS.contains(&word.as_str()) {
                    theme.asm_call
                } else if is_type(&word) {
                    theme.asm_instruction
                } else if chars.get(i) == Some(&'(') {
                    theme.asm_label
                } else if chars.get(start.wrapping_sub(1)) != Some(&'.') && word.ends_with(':') {
                    theme.asm_jump
                } else {
                    theme.asm_register
                }
            } else {
                i += 1;
                theme.fg
            };

            spans.push(Span::styled(chars[start..i].iter().collect::<String>(), style(color)));
        }

        return spans;
    }

    pub fn render(&mut self, theme: &Theme, height: usize) -> Vec<Line<'static>> {
        self.height = height;

        match &self.state {
            CodeState::Loading => return vec![Line::from(Span::styled("Decompiling...", Style::default().fg(theme.dim)))],
            CodeState::Failed(error) => return vec![Line::from(Span::styled(format!("Decompilation failed: {}", error), Style::default().fg(theme.warning)))],
            CodeState::Ready => {}
        }

        follow_cursor(self.cursor, &mut self.scroll, height);

        let mut lines = Vec::new();

        for (index, text) in self.lines.iter().enumerate().skip(self.scroll).take(height) {
            let addr = match self.addrs.get(index).copied().flatten() {
                Some(addr) => format!("{:>10x}  ", addr),
                None => " ".repeat(12),
            };

            let mut spans = vec![Span::styled(addr, Style::default().fg(theme.asm_address))];
            spans.extend(Self::highlight(theme, text));

            let mut line = Line::from(spans);

            if index == self.cursor {
                line = line.style(Style::default().bg(theme.cursor_bg).add_modifier(Modifier::BOLD));
            }

            lines.push(line);
        }

        return lines;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_addresses() {
        let mut view = CodeView::loading(0, 0x1000, "f");
        view.set_code("int f(int a1)\n{\n    return g(a1) + 1;\n}\n", vec![Some(0x1000), None, Some(0x1004), None]);
        view.height = 10;

        assert!(view.goto(0x1006));
        assert_eq!(view.cursor, 2);
        assert_eq!(view.called_names(), ["g"]);

        view.move_cursor(1);
        assert_eq!(view.cursor_addr(), Some(0x1004));

        let theme = Theme::codedark();
        let text: String = CodeView::highlight(&theme, "    if (x == \"a\") { return 0x10; } // done").iter().map(|s| s.content.to_string()).collect();
        assert_eq!(text, "    if (x == \"a\") { return 0x10; } // done");
    }
}
