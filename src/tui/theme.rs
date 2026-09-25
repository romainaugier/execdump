use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

use serde::{Deserialize, Serialize};

use crate::aarch64::is_aarch64_register;
use crate::analysis::function::EdgeKind;
use crate::x86_64::is_x86_64_register;

#[derive(Clone, Debug)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub highlight_bg: Color,
    pub highlight_fg: Color,
    pub cursor_bg: Color,
    pub border: Color,
    pub title: Color,
    pub key: Color,
    pub value: Color,
    pub hex_offset: Color,
    pub hex_data: Color,
    pub hex_ascii: Color,
    pub comment: Color,
    pub dim: Color,
    pub warning: Color,

    /// Disassembly syntax highlighting
    pub asm_address: Color,
    pub asm_instruction: Color,
    pub asm_register: Color,
    pub asm_immediate: Color,
    pub asm_label: Color,
    pub asm_separator: Color,
    pub asm_call: Color,
    pub asm_jump: Color,
    pub asm_ret: Color,

    /// Graph
    pub node_border: Color,
    pub node_selected: Color,
    pub node_import: Color,
    pub edge_true: Color,
    pub edge_false: Color,
    pub edge_jump: Color,
    pub edge_fallthrough: Color,
    pub edge_switch: Color,
    pub edge_call: Color,
    pub edge_reference: Color,

    /// Memory permissions
    pub perm_exec: Color,
    pub perm_write: Color,
    pub perm_read: Color,
}

impl Theme {
    pub fn codedark() -> Self {
        return Theme {
            bg: Color::Rgb(30, 30, 30),
            fg: Color::Rgb(212, 212, 212),
            highlight_bg: Color::Rgb(38, 79, 120),
            highlight_fg: Color::Rgb(255, 255, 255),
            cursor_bg: Color::Rgb(50, 50, 60),
            border: Color::Rgb(84, 84, 84),
            title: Color::Rgb(86, 156, 214),
            key: Color::Rgb(156, 220, 254),
            value: Color::Rgb(206, 145, 120),
            hex_offset: Color::Rgb(128, 128, 128),
            hex_data: Color::Rgb(181, 206, 168),
            hex_ascii: Color::Rgb(206, 145, 120),
            comment: Color::Rgb(106, 153, 85),
            dim: Color::Rgb(110, 110, 110),
            warning: Color::Rgb(220, 180, 90),
            asm_address: Color::Rgb(128, 128, 128),
            asm_instruction: Color::Rgb(86, 156, 214),
            asm_register: Color::Rgb(156, 220, 254),
            asm_immediate: Color::Rgb(181, 206, 168),
            asm_label: Color::Rgb(220, 220, 170),
            asm_separator: Color::Rgb(180, 180, 180),
            asm_call: Color::Rgb(197, 134, 192),
            asm_jump: Color::Rgb(220, 220, 170),
            asm_ret: Color::Rgb(244, 71, 71),
            node_border: Color::Rgb(110, 110, 110),
            node_selected: Color::Rgb(255, 200, 60),
            node_import: Color::Rgb(90, 90, 90),
            edge_true: Color::Rgb(78, 201, 78),
            edge_false: Color::Rgb(224, 82, 82),
            edge_jump: Color::Rgb(86, 156, 214),
            edge_fallthrough: Color::Rgb(150, 150, 150),
            edge_switch: Color::Rgb(197, 134, 192),
            edge_call: Color::Rgb(86, 156, 214),
            edge_reference: Color::Rgb(120, 120, 120),
            perm_exec: Color::Rgb(224, 82, 82),
            perm_write: Color::Rgb(86, 156, 214),
            perm_read: Color::Rgb(78, 201, 78),
        };
    }

    pub fn base(&self) -> Style {
        return Style::default().fg(self.fg).bg(self.bg);
    }

    pub fn title_style(&self) -> Style {
        return Style::default().fg(self.title).add_modifier(Modifier::BOLD);
    }

    pub fn edge_color(&self, kind: EdgeKind) -> Color {
        match kind {
            EdgeKind::True => self.edge_true,
            EdgeKind::False => self.edge_false,
            EdgeKind::Jump => self.edge_jump,
            EdgeKind::Fallthrough => self.edge_fallthrough,
            EdgeKind::Switch => self.edge_switch,
        }
    }

    pub fn mnemonic_style(&self, mnemonic: &str) -> Style {
        let base = mnemonic.rsplit(' ').next().unwrap_or(mnemonic);

        let color = if base.starts_with("call") || base == "bl" || base.starts_with("blr") {
            self.asm_call
        } else if base.starts_with("ret") || base == "hlt" || base == "ud2" || base == "int3" || base == "brk" {
            self.asm_ret
        } else if base.starts_with('j') || base == "b" || base.starts_with("b.") || base.starts_with("cb") || base.starts_with("tb") || base == "br" || base.starts_with("loop") {
            self.asm_jump
        } else {
            self.asm_instruction
        };

        return Style::default().fg(color);
    }

    /// Splits instruction operands into highlighted spans
    pub fn operand_spans(&self, operands: &str) -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        let chars: Vec<char> = operands.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];
            let start = i;

            if c.is_ascii_alphabetic() || c == '_' || c == '.' || c == '$' {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '.' | '$' | ':' | '<' | '>' | '~' | '@')) {
                    i += 1;
                }

                let word: String = chars[start..i].iter().collect();

                let style = if is_x86_64_register(&word) || is_aarch64_register(&word) || word.starts_with("xmm") || word.starts_with("ymm") {
                    Style::default().fg(self.asm_register)
                } else if matches!(word.as_str(), "byte" | "word" | "dword" | "qword" | "xmmword" | "ymmword" | "zmmword" | "tbyte" | "ptr" |
                                                   "lsl" | "lsr" | "asr" | "ror" | "uxtw" | "sxtw" | "uxtb" | "sxtb" | "uxth" | "sxth" | "sxtx" | "uxtx") {
                    Style::default().fg(self.asm_separator)
                } else {
                    Style::default().fg(self.asm_label)
                };

                spans.push(Span::styled(word, style));
            } else if c.is_ascii_digit() || c == '#' || (c == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
                i += 1;

                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '-') {
                    i += 1;
                }

                spans.push(Span::styled(chars[start..i].iter().collect::<String>(), Style::default().fg(self.asm_immediate)));
            } else {
                while i < chars.len() && !(chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '.' | '$' | '#')) {
                    i += 1;
                }

                spans.push(Span::styled(chars[start..i].iter().collect::<String>(), Style::default().fg(self.asm_separator)));
            }
        }

        return spans;
    }
}

/// Key bindings configuration, loaded from ~/.execdumprc (TOML)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct KeyBindings {
    pub quit: char,
    pub down: char,
    pub up: char,
    pub left: char,
    pub right: char,
    pub page_down: char,
    pub page_up: char,
    pub start: char,
    pub end: char,
    pub next_node: char,
    pub prev_node: char,
    pub follow_true: char,
    pub follow_false: char,
    pub center: char,
    pub toggle_view: char,
    pub toggle_explorer: char,
    pub xrefs: char,
    pub call_graph: char,
}

impl Default for KeyBindings {
    fn default() -> Self {
        return KeyBindings {
            quit: 'q',
            down: 'j',
            up: 'k',
            left: 'h',
            right: 'l',
            page_down: 'd',
            page_up: 'u',
            start: 'g',
            end: 'G',
            next_node: 'n',
            prev_node: 'p',
            follow_true: 't',
            follow_false: 'f',
            center: 'c',
            toggle_view: ' ',
            toggle_explorer: 'e',
            xrefs: 'x',
            call_graph: 'C',
        };
    }
}

impl KeyBindings {
    pub fn load() -> Self {
        if let Some(home) = dirs::home_dir() {
            if let Ok(contents) = std::fs::read_to_string(home.join(".execdumprc")) {
                if let Ok(bindings) = toml::from_str(&contents) {
                    return bindings;
                }
            }
        }

        return KeyBindings::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_highlighting() {
        let theme = Theme::codedark();
        let spans = theme.operand_spans("qword ptr [rip + 0x2fe2], rax");
        let text: String = spans.iter().map(|s| s.content.to_string()).collect();

        assert_eq!(text, "qword ptr [rip + 0x2fe2], rax");
        assert!(spans.iter().any(|s| s.content == "rip" && s.style.fg == Some(theme.asm_register)));
        assert!(spans.iter().any(|s| s.content == "0x2fe2" && s.style.fg == Some(theme.asm_immediate)));

        let spans = theme.operand_spans("x0, [sp, #0x10]");
        assert!(spans.iter().any(|s| s.content == "#0x10" && s.style.fg == Some(theme.asm_immediate)));
        assert!(spans.iter().any(|s| s.content == "sp" && s.style.fg == Some(theme.asm_register)));
    }

    #[test]
    fn partial_config() {
        let bindings: KeyBindings = toml::from_str("quit = 'Q'").unwrap();
        assert_eq!(bindings.quit, 'Q');
        assert_eq!(bindings.next_node, 'n');
    }
}
