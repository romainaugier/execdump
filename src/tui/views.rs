/*
 * Text based views: header dumps, hex, linear disassembly and tables
 */

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::analysis::insn::{Decoder, Flow, InsnText, Instruction};
use crate::analysis::Analysis;
use crate::dump::Dump;
use crate::program::Program;
use crate::tui::graph_view::insn_spans;
use crate::tui::theme::Theme;

/// Where a table row or an instruction leads to
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Control flow graph of the function at this address
    Function(usize, u64),
    /// Any address (opens the function, the code or the data containing it)
    Address(usize, u64),
}

/// Keeps a cursor visible in a scrolled list
pub fn follow_cursor(cursor: usize, scroll: &mut usize, height: usize) {
    let height = height.max(1);

    if cursor < *scroll {
        *scroll = cursor;
    } else if cursor >= *scroll + height {
        *scroll = cursor + 1 - height;
    }
}

/*
 * Dump view (headers, tables from the parsers)
 */

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
 * Hex view
 */

#[derive(Clone, Debug)]
pub struct HexView {
    pub title: String,
    pub base: u64,
    pub data: Vec<u8>,
    /// First displayed row
    pub scroll: usize,
    pub height: usize,
}

const HEX_ROW: usize = 16;

impl HexView {
    pub fn new(title: String, base: u64, data: Vec<u8>) -> Self {
        return Self { title, base, data, scroll: 0, height: 1 };
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
 * Linear disassembly view
 */

#[derive(Clone, Debug)]
pub enum DisasmLine {
    Blank,
    Label(String, u64),
    Insn(InsnText),
}

impl DisasmLine {
    pub fn addr(&self) -> Option<u64> {
        match self {
            DisasmLine::Insn(insn) => Some(insn.addr),
            DisasmLine::Label(_, addr) => Some(*addr),
            DisasmLine::Blank => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DisasmView {
    pub program: usize,
    pub title: String,
    pub lines: Vec<DisasmLine>,
    pub cursor: usize,
    pub scroll: usize,
    pub height: usize,
    /// Function shown, when the view only shows one function
    pub function: Option<u64>,
    /// Region shown, when the view shows a whole region
    pub region: Option<String>,
    addr_width: usize,
}

impl DisasmView {
    /// Linear disassembly of a whole region
    pub fn region(program_index: usize, program: &Program, analysis: Option<&Analysis>, decoder: &Decoder, region_name: &str) -> Option<Self> {
        let region = program.regions.iter().find(|r| r.name == region_name)?;
        let insns = decoder.text_all(&region.data, region.vaddr);

        let mut lines = Vec::with_capacity(insns.len());

        for insn in insns {
            if let Some(function) = analysis.and_then(|a| a.functions.get(&insn.addr)) {
                lines.push(DisasmLine::Blank);
                lines.push(DisasmLine::Label(function.name.clone(), insn.addr));
            }

            lines.push(DisasmLine::Insn(insn));
        }

        return Some(Self {
            program: program_index,
            title: format!("{} ({:#x} - {:#x})", region.name, region.vaddr, region.end()),
            addr_width: format!("{:x}", region.end()).len(),
            lines,
            cursor: 0,
            scroll: 0,
            height: 1,
            function: None,
            region: Some(region.name.clone()),
        });
    }

    /// Linear disassembly of a function, block by block
    pub fn function(program_index: usize, program: &Program, analysis: &Analysis, decoder: &Decoder, addr: u64) -> Option<Self> {
        let function = analysis.functions.get(&addr)?;
        let mut lines = vec![DisasmLine::Label(function.name.clone(), function.addr)];

        for block in function.blocks.values() {
            if block.start != function.addr {
                lines.push(DisasmLine::Blank);
                lines.push(DisasmLine::Label(format!("{:#x}", block.start), block.start));
            }

            for insn in block.insns.iter() {
                if let Some(text) = program.bytes_from(insn.addr).and_then(|b| decoder.text(b, insn.addr)) {
                    lines.push(DisasmLine::Insn(text));
                }
            }
        }

        return Some(Self {
            program: program_index,
            title: format!("{} @ {:#x} (linear)", function.name, function.addr),
            addr_width: format!("{:x}", function.end()).len(),
            lines,
            cursor: 0,
            scroll: 0,
            height: 1,
            function: Some(addr),
            region: None,
        });
    }

    pub fn cursor_addr(&self) -> Option<u64> {
        return self.lines.get(self.cursor).and_then(|l| l.addr());
    }

    pub fn goto(&mut self, addr: u64) -> bool {
        let index = self.lines.iter().position(|l| matches!(l, DisasmLine::Insn(i) if addr >= i.addr && addr < i.addr + i.size as u64))
            .or_else(|| self.lines.iter().position(|l| l.addr() == Some(addr)));

        if let Some(index) = index {
            self.cursor = index;
            self.scroll = index.saturating_sub(self.height / 3);
            return true;
        }

        return false;
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let max = self.lines.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    /// Moves to the next (or previous) label
    pub fn jump_label(&mut self, forward: bool) {
        let found = if forward {
            self.lines.iter().enumerate().skip(self.cursor + 1).find(|(_, l)| matches!(l, DisasmLine::Label(..))).map(|(i, _)| i)
        } else {
            self.lines.iter().enumerate().take(self.cursor).rev().find(|(_, l)| matches!(l, DisasmLine::Label(..))).map(|(i, _)| i)
        };

        if let Some(index) = found {
            self.cursor = index;
            self.scroll = index.saturating_sub(1);
        }
    }

    pub fn search(&mut self, pattern: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.lines.len();

        for i in 1..=count {
            let index = (self.cursor + i) % count;

            let text = match &self.lines[index] {
                DisasmLine::Insn(insn) => format!("{:x} {} {}", insn.addr, insn.mnemonic, insn.operands),
                DisasmLine::Label(name, _) => name.clone(),
                DisasmLine::Blank => continue,
            };

            if text.to_lowercase().contains(&pattern) {
                self.cursor = index;
                self.scroll = index.saturating_sub(self.height / 3);
                return true;
            }
        }

        return false;
    }

    /// Instruction under the cursor, as recovered by the analysis
    pub fn cursor_insn(&self, analysis: &Analysis) -> Option<Instruction> {
        let addr = match self.lines.get(self.cursor)? {
            DisasmLine::Insn(insn) => insn.addr,
            _ => return None,
        };

        return find_insn(analysis, addr);
    }

    pub fn render(&mut self, theme: &Theme, program: &Program, analysis: Option<&Analysis>, decoder: &Decoder, height: usize) -> Vec<Line<'static>> {
        self.height = height;
        follow_cursor(self.cursor, &mut self.scroll, height);

        let mut lines = Vec::new();

        for (index, line) in self.lines.iter().enumerate().skip(self.scroll).take(height) {
            let mut rendered = match line {
                DisasmLine::Blank => Line::from(""),
                DisasmLine::Label(name, addr) => Line::from(vec![
                    Span::styled(format!("{:0width$x}  ", addr, width = self.addr_width), Style::default().fg(theme.asm_address)),
                    Span::styled(format!("{}:", name), Style::default().fg(theme.asm_label).add_modifier(Modifier::BOLD)),
                ]),
                DisasmLine::Insn(text) => {
                    let insn = analysis.and_then(|a| find_insn(a, text.addr));

                    match (insn, analysis) {
                        (Some(insn), Some(analysis)) => {
                            let (mut spans, _) = insn_spans(theme, program, analysis, decoder, &insn, self.addr_width);
                            spans.insert(1, Span::raw("    "));
                            Line::from(spans)
                        }
                        _ => {
                            let mut spans = vec![
                                Span::styled(format!("{:0width$x}      ", text.addr, width = self.addr_width), Style::default().fg(theme.asm_address)),
                                Span::styled(format!("{:<6} ", text.mnemonic), if insn.is_none() && analysis.is_some() { Style::default().fg(theme.dim) } else { theme.mnemonic_style(&text.mnemonic) }),
                            ];

                            spans.extend(theme.operand_spans(&text.operands));
                            Line::from(spans)
                        }
                    }
                }
            };

            if index == self.cursor {
                rendered = rendered.style(Style::default().bg(theme.cursor_bg));
            }

            lines.push(rendered);
        }

        return lines;
    }
}

/// Instruction at an address, from the recovered functions
pub fn find_insn(analysis: &Analysis, addr: u64) -> Option<Instruction> {
    let function = analysis.function_containing(addr)?;
    let block = function.block_containing(addr)?;

    return block.insns.iter().find(|i| i.addr == addr).copied();
}

/// Address an instruction leads to (branch target, then referenced address)
pub fn insn_target(insn: &Instruction) -> Option<u64> {
    match insn.flow {
        Flow::Jump(t) | Flow::CondJump(t) | Flow::Call(t) => Some(t),
        _ => insn.imm_ref.or(insn.mem_ref),
    }
}

/*
 * Table view (functions, strings, imports, memory map)
 */

#[derive(Clone, Debug)]
pub struct TableRow {
    pub cells: Vec<String>,
    pub target: Target,
    pub style: Option<Style>,
}

#[derive(Clone, Debug)]
pub struct TableView {
    pub title: String,
    pub headers: Vec<String>,
    pub rows: Vec<TableRow>,
    pub filtered: Vec<usize>,
    pub filter: String,
    pub cursor: usize,
    pub scroll: usize,
    pub height: usize,
    /// Optional line drawn above the table (memory map bar)
    pub banner: Option<Line<'static>>,
}

impl TableView {
    pub fn new(title: String, headers: Vec<&str>, rows: Vec<TableRow>) -> Self {
        let filtered = (0..rows.len()).collect();

        return Self {
            title,
            headers: headers.into_iter().map(|h| h.to_string()).collect(),
            rows,
            filtered,
            filter: String::new(),
            cursor: 0,
            scroll: 0,
            height: 1,
            banner: None,
        };
    }

    pub fn set_filter(&mut self, filter: &str) {
        self.filter = filter.to_string();
        let pattern = filter.to_lowercase();

        self.filtered = (0..self.rows.len())
            .filter(|&i| pattern.is_empty() || self.rows[i].cells.iter().any(|c| c.to_lowercase().contains(&pattern)))
            .collect();

        self.cursor = 0;
        self.scroll = 0;
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let max = self.filtered.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    pub fn selected(&self) -> Option<&TableRow> {
        return self.filtered.get(self.cursor).map(|&i| &self.rows[i]);
    }

    pub fn render(&mut self, theme: &Theme, height: usize, width: usize) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        if let Some(banner) = &self.banner {
            lines.push(banner.clone());
            lines.push(Line::from(""));
        }

        // Column widths from the visible rows, the last column takes the remaining space
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();

        for &i in self.filtered.iter().take(2000) {
            for (c, cell) in self.rows[i].cells.iter().enumerate() {
                if c < widths.len() {
                    widths[c] = widths[c].max(cell.chars().count().min(64));
                }
            }
        }

        let format_row = |cells: &[String]| -> String {
            let mut text = String::new();

            for (c, cell) in cells.iter().enumerate() {
                if c + 1 == cells.len() {
                    text.push_str(cell);
                } else {
                    let cell: String = cell.chars().take(widths[c]).collect();
                    text.push_str(&format!("{:<width$}  ", cell, width = widths[c]));
                }
            }

            return text.chars().take(width).collect();
        };

        lines.push(Line::from(Span::styled(format_row(&self.headers), theme.title_style())));

        let rows_height = height.saturating_sub(lines.len()).max(1);
        self.height = rows_height;
        follow_cursor(self.cursor, &mut self.scroll, rows_height);

        for (pos, &i) in self.filtered.iter().enumerate().skip(self.scroll).take(rows_height) {
            let row = &self.rows[i];
            let mut style = row.style.unwrap_or(Style::default().fg(theme.fg));

            if pos == self.cursor {
                style = style.bg(theme.highlight_bg).fg(theme.highlight_fg);
            }

            lines.push(Line::from(Span::styled(format_row(&row.cells), style)));
        }

        if self.filtered.is_empty() {
            lines.push(Line::from(Span::styled("No entries", Style::default().fg(theme.dim))));
        }

        return lines;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_filter_and_cursor() {
        let rows = vec![
            TableRow { cells: vec!["0x1000".to_string(), "main".to_string()], target: Target::Function(0, 0x1000), style: None },
            TableRow { cells: vec!["0x2000".to_string(), "helper".to_string()], target: Target::Function(0, 0x2000), style: None },
        ];

        let mut table = TableView::new("Functions".to_string(), vec!["Address", "Name"], rows);
        table.set_filter("help");

        assert_eq!(table.filtered, vec![1]);
        assert_eq!(table.selected().unwrap().target, Target::Function(0, 0x2000));

        table.set_filter("");
        table.move_cursor(10);
        assert_eq!(table.cursor, 1);
    }

    #[test]
    fn hex_goto() {
        let mut hex = HexView::new("data".to_string(), 0x1000, vec![0; 0x1000]);
        hex.height = 10;

        assert!(hex.goto(0x1800));
        assert_eq!(hex.scroll, 0x80 - 2);
        assert!(!hex.goto(0x3000));
    }
}
