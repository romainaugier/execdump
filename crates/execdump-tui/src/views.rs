/*
 * Text based views: header dumps, hex, linear disassembly and tables
 */

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use execdump_decompiler::analysis::insn::{Decoder, Flow, InsnText, Instruction};
use execdump_decompiler::analysis::Analysis;
use execdump_core::dump::Dump;
use execdump_core::program::Program;
use crate::graph_view::insn_spans;
use crate::theme::Theme;

use std::rc::Rc;
use std::sync::Arc;

/// Where a table row or an instruction leads to
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Control flow graph of the function at this address
    Function(usize, u64),
    /// Any address (opens the function, the code or the data containing it)
    Address(usize, u64),
    /// Call graph rooted at a function, selecting another function in it
    CallGraph { program: usize, root: u64, depth: usize, imports: bool, select: u64 },
    /// C code of a module
    Module(usize, String),
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
 * Linear disassembly view
 *
 * A region can hold millions of instructions: the view keeps their offsets only (8 bytes per line),
 * their text is decoded when they are shown or searched.
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisasmLine {
    Blank,
    /// Index of the label
    Label(u32),
    /// Offset of the instruction from the base address, and its size
    Insn(u32, u8),
    /// Bytes that do not decode
    Data(u32, u8),
}

#[derive(Clone, Debug)]
pub struct DisasmView {
    pub program: usize,
    pub title: String,
    base: u64,
    lines: Rc<Vec<DisasmLine>>,
    labels: Rc<Vec<(String, u64)>>,
    /// Lines of the instructions, in address order
    insns: Rc<Vec<u32>>,
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
        let mut lines = Vec::with_capacity(region.data.len() / 4);
        let mut labels = Vec::new();

        decoder.sweep(&region.data, region.vaddr, |addr, size, valid| {
            let offset = (addr - region.vaddr) as u32;

            if let Some(function) = analysis.and_then(|a| a.functions.get(&addr)) {
                lines.push(DisasmLine::Blank);
                lines.push(DisasmLine::Label(labels.len() as u32));
                labels.push((function.name.clone(), addr));
            }

            lines.push(if valid { DisasmLine::Insn(offset, size) } else { DisasmLine::Data(offset, size) });
        });

        lines.shrink_to_fit();
        let insns = instruction_lines(&lines);

        return Some(Self {
            program: program_index,
            title: format!("{} ({:#x} - {:#x})", region.name, region.vaddr, region.end()),
            base: region.vaddr,
            addr_width: format!("{:x}", region.end()).len(),
            lines: Rc::new(lines),
            labels: Rc::new(labels),
            insns: Rc::new(insns),
            cursor: 0,
            scroll: 0,
            height: 1,
            function: None,
            region: Some(region.name.clone()),
        });
    }

    /// Linear disassembly of a function, block by block
    pub fn function(program_index: usize, _program: &Program, analysis: &Analysis, _decoder: &Decoder, addr: u64) -> Option<Self> {
        let function = analysis.functions.get(&addr)?;
        let base = function.blocks.keys().next().copied().unwrap_or(addr).min(addr);
        let mut labels = vec![(function.name.clone(), function.addr)];
        let mut lines = vec![DisasmLine::Label(0)];

        for block in function.blocks.values() {
            if block.start != function.addr {
                lines.push(DisasmLine::Blank);
                lines.push(DisasmLine::Label(labels.len() as u32));
                labels.push((format!("{:#x}", block.start), block.start));
            }

            for insn in block.insns.iter() {
                lines.push(DisasmLine::Insn((insn.addr - base) as u32, insn.size));
            }
        }

        let insns = instruction_lines(&lines);

        return Some(Self {
            program: program_index,
            title: format!("{} @ {:#x} (linear)", function.name, function.addr),
            base,
            addr_width: format!("{:x}", function.end()).len(),
            lines: Rc::new(lines),
            labels: Rc::new(labels),
            insns: Rc::new(insns),
            cursor: 0,
            scroll: 0,
            height: 1,
            function: Some(addr),
            region: None,
        });
    }

    fn line_addr(&self, line: DisasmLine) -> Option<u64> {
        return match line {
            DisasmLine::Insn(offset, _) | DisasmLine::Data(offset, _) => Some(self.base + offset as u64),
            DisasmLine::Label(index) => Some(self.labels[index as usize].1),
            DisasmLine::Blank => None,
        };
    }

    pub fn cursor_addr(&self) -> Option<u64> {
        return self.lines.get(self.cursor).and_then(|&l| self.line_addr(l));
    }

    /// Moves the cursor to the instruction containing an address (the lines are in address order)
    pub fn goto(&mut self, addr: u64) -> bool {
        let Some(offset) = addr.checked_sub(self.base).and_then(|o| u32::try_from(o).ok()) else {
            return false;
        };

        let range = |line: u32| match self.lines[line as usize] {
            DisasmLine::Insn(o, size) | DisasmLine::Data(o, size) => (o as u64, o as u64 + size as u64),
            _ => (0, 0),
        };

        // First instruction ending after the address
        let position = self.insns.partition_point(|&line| range(line).1 <= offset as u64);
        let found = self.insns.get(position).copied().filter(|&line| range(line).0 <= offset as u64).map(|line| line as usize);

        // A label at the address (the start of a function in a function view)
        let index = found.or_else(|| self.lines.iter().position(|&l| self.line_addr(l) == Some(addr)));

        if let Some(index) = index {
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

    /// Text of an instruction line
    fn text(&self, program: &Program, decoder: &Decoder, line: DisasmLine) -> Option<InsnText> {
        let addr = self.line_addr(line)?;

        return match line {
            DisasmLine::Insn(..) => program.bytes_from(addr).and_then(|b| decoder.text(b, addr)),
            DisasmLine::Data(_, size) => {
                let bytes = program.read(addr, size as usize).unwrap_or_default();
                let mnemonic = if size == 4 { ".word" } else { ".byte" };
                Some(InsnText { addr, size: size as usize, mnemonic: mnemonic.to_string(), operands: bytes.iter().rev().map(|b| format!("{:02x}", b)).collect() })
            }
            _ => None,
        };
    }

    pub fn search(&mut self, pattern: &str, program: &Program, decoder: &Decoder) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.lines.len();

        for i in 1..=count {
            let index = (self.cursor + i) % count;

            let text = match self.lines[index] {
                DisasmLine::Label(label) => self.labels[label as usize].0.clone(),
                DisasmLine::Blank => continue,
                line => match self.text(program, decoder, line) {
                    Some(insn) => format!("{:x} {} {}", insn.addr, insn.mnemonic, insn.operands),
                    None => continue,
                },
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
            &DisasmLine::Insn(offset, _) => self.base + offset as u64,
            _ => return None,
        };

        return find_insn(analysis, addr);
    }

    pub fn render(&mut self, theme: &Theme, program: &Program, analysis: Option<&Analysis>, decoder: &Decoder, height: usize) -> Vec<Line<'static>> {
        self.height = height;
        follow_cursor(self.cursor, &mut self.scroll, height);

        let mut lines = Vec::new();

        for (index, &line) in self.lines.iter().enumerate().skip(self.scroll).take(height) {
            let mut rendered = match line {
                DisasmLine::Blank => Line::from(""),
                DisasmLine::Label(label) => {
                    let (name, addr) = &self.labels[label as usize];

                    Line::from(vec![
                        Span::styled(format!("{:0width$x}  ", addr, width = self.addr_width), Style::default().fg(theme.asm_address)),
                        Span::styled(format!("{}:", name), Style::default().fg(theme.asm_label).add_modifier(Modifier::BOLD)),
                    ])
                }
                DisasmLine::Insn(..) | DisasmLine::Data(..) => {
                    let addr = self.line_addr(line).unwrap_or(0);
                    let insn = if matches!(line, DisasmLine::Insn(..)) { analysis.and_then(|a| find_insn(a, addr)) } else { None };

                    match (insn, analysis) {
                        (Some(insn), Some(analysis)) => {
                            let (mut spans, _) = insn_spans(theme, program, analysis, decoder, &insn, self.addr_width);
                            spans.insert(1, Span::raw("    "));
                            Line::from(spans)
                        }
                        _ => match self.text(program, decoder, line) {
                            Some(text) => {
                                let mut spans = vec![
                                    Span::styled(format!("{:0width$x}      ", text.addr, width = self.addr_width), Style::default().fg(theme.asm_address)),
                                    Span::styled(format!("{:<6} ", text.mnemonic), if analysis.is_some() { Style::default().fg(theme.dim) } else { theme.mnemonic_style(&text.mnemonic) }),
                                ];

                                spans.extend(theme.operand_spans(&text.operands));
                                Line::from(spans)
                            }
                            None => Line::from(Span::styled(format!("{:0width$x}      ???", addr, width = self.addr_width), Style::default().fg(theme.dim))),
                        },
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

/// Lines holding instructions (or undecodable bytes)
fn instruction_lines(lines: &[DisasmLine]) -> Vec<u32> {
    return lines.iter().enumerate().filter(|(_, l)| matches!(l, DisasmLine::Insn(..) | DisasmLine::Data(..))).map(|(i, _)| i as u32).collect();
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
    fn region_disassembly() {
        use execdump_core::elf::parse_elf;
        use execdump_core::exec::Exec;
        use execdump_core::program::programs_from_exec;
        use execdump_decompiler::analysis::analyze;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let program = programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();
        let decoder = Decoder::new(program.architecture()).unwrap();
        let theme = Theme::codedark();

        let mut view = DisasmView::region(0, &program, Some(&analysis), &decoder, ".text").unwrap();
        view.height = 10;

        let main = analysis.function_by_name("main").unwrap();
        let second = main.blocks[&main.addr].insns[1];
        assert!(view.goto(second.addr + 1));
        assert_eq!(view.cursor_addr(), Some(second.addr));
        assert!(view.cursor_insn(&analysis).is_some());

        assert!(view.search("classify", &program, &decoder));
        let lines = view.render(&theme, &program, Some(&analysis), &decoder, 10);
        assert_eq!(lines.len(), 10);

        let mut function = DisasmView::function(0, &program, &analysis, &decoder, main.addr).unwrap();
        assert!(function.goto(main.addr));
        assert_eq!(function.cursor_addr(), Some(main.addr));
        assert!(!function.goto(0x10));
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
