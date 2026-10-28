// SPDX-License-Identifier: Apache-2.0
/*
 * Linear disassembly view
 *
 * A region can hold millions of instructions: the view decodes a window of it around the cursor (from
 * an instruction start known by the analysis), and decodes another one when the cursor leaves it. The
 * lines keep offsets only, their text is decoded when they are shown or searched.
 */

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use execdump_decompiler::analysis::insn::{Decoder, Flow, InsnText, Instruction};
use execdump_decompiler::analysis::Analysis;
use execdump_core::program::Program;

use super::follow_cursor;
use super::graph::insn_spans;
use crate::commands::{Command, Motion};
use crate::debug::Marks;
use crate::theme::Theme;
use crate::views::View;
use crate::{App, OpenMode, VERTICAL_STEP};

use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use std::rc::Rc;
use std::sync::Arc;

/// Bytes decoded on each side of the cursor
const WINDOW_HALF: u64 = 32 << 10;
/// Moves larger than this go to the start or the end of the region
const FAR: isize = 1 << 40;

#[derive(Clone, Debug)]
struct Window {
    program: Arc<Program>,
    analysis: Option<Arc<Analysis>>,
    /// The region, and the part of it decoded
    start: u64,
    end: u64,
    from: u64,
    to: u64,
}

impl Window {
    /// Instruction start at or before an address (from the analysis), where decoding is aligned
    fn anchor(&self, addr: u64) -> u64 {
        let addr = addr.clamp(self.start, self.end.saturating_sub(1).max(self.start));

        let known = self.analysis.as_ref().and_then(|analysis| {
            analysis.functions.range(..=addr).rev().take(64).flat_map(|(_, f)| f.blocks.range(..=addr).next_back().map(|(_, b)| b)).find_map(|block| {
                if addr < block.end {
                    let index = block.insns.partition_point(|i| i.addr <= addr);
                    return block.insns.get(index.checked_sub(1)?).map(|i| i.addr);
                }

                // Past the block: its end is the start of what follows
                Some(block.end).filter(|&end| addr - end < WINDOW_HALF)
            })
        });

        return known.filter(|&a| a >= self.start).unwrap_or(addr);
    }
}

struct Decoded {
    lines: Vec<DisasmLine>,
    labels: Vec<(String, u64)>,
    from: u64,
    to: u64,
}

/// Lines of a part of a region, from an aligned address to another
fn decode_range(program: &Program, analysis: Option<&Analysis>, decoder: &Decoder, base: u64, from: u64, to: u64) -> Decoded {
    let mut lines = Vec::new();
    let mut labels = Vec::new();
    let mut end = from;

    if let Some(bytes) = program.read(from, (to - from) as usize) {
        decoder.sweep(bytes, from, |addr, size, valid| {
            let offset = (addr - base) as u32;

            if let Some(function) = analysis.and_then(|a| a.functions.get(&addr)) {
                lines.push(DisasmLine::Blank);
                lines.push(DisasmLine::Label(labels.len() as u32));
                labels.push((function.name.clone(), addr));
            }

            lines.push(if valid { DisasmLine::Insn(offset, size) } else { DisasmLine::Data(offset, size) });
            end = addr + size as u64;
        });
    }

    return Decoded { lines, labels, from, to: end.max(from) };
}

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
    /// Part of the region decoded (region views)
    window: Option<Window>,
}

impl DisasmView {
    /// Linear disassembly of a whole region, decoded around its start
    pub fn region(program_index: usize, program: Arc<Program>, analysis: Option<Arc<Analysis>>, decoder: &Decoder, region_name: &str) -> Option<Self> {
        let region = program.regions.iter().find(|r| r.name == region_name)?;
        let (start, end) = (region.vaddr, region.vaddr + region.data.len() as u64);
        let title = format!("{} ({:#x} - {:#x})", region.name, region.vaddr, region.end());
        let addr_width = format!("{:x}", region.end()).len();
        let name = region.name.clone();

        let mut view = Self {
            program: program_index,
            title,
            base: start,
            addr_width,
            lines: Rc::new(Vec::new()),
            labels: Rc::new(Vec::new()),
            insns: Rc::new(Vec::new()),
            cursor: 0,
            scroll: 0,
            height: 1,
            function: None,
            region: Some(name),
            window: Some(Window { program, analysis, start, end, from: start, to: start }),
        };

        view.decode_window(decoder, start);
        return Some(view);
    }

    /// Decodes the part of the region around an address, the cursor goes to it
    fn decode_window(&mut self, decoder: &Decoder, center: u64) {
        let Some(window) = self.window.as_mut() else {
            return;
        };

        let from = window.anchor(center.saturating_sub(WINDOW_HALF));
        let to = center.saturating_add(WINDOW_HALF).min(window.end);
        let decoded = decode_range(&window.program, window.analysis.as_deref(), decoder, self.base, from, to.max(from));

        window.from = decoded.from;
        window.to = decoded.to;
        self.insns = Rc::new(instruction_lines(&decoded.lines));
        self.lines = Rc::new(decoded.lines);
        self.labels = Rc::new(decoded.labels);
        self.cursor = 0;
        self.goto_decoded(center);
    }

    /// The decoder of a region view (its window is decoded again when the cursor leaves it)
    fn decoder(&self) -> Option<Decoder> {
        return self.window.as_ref().and_then(|w| Decoder::new(w.program.architecture()).ok());
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
            window: None,
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
        let outside = self.window.as_ref().map(|w| (w.start..w.end).contains(&addr) && !(w.from..w.to).contains(&addr));

        match outside {
            Some(true) => match self.decoder() {
                Some(decoder) => {
                    self.decode_window(&decoder, addr);
                    return true;
                }
                None => return false,
            },
            _ => return self.goto_decoded(addr),
        }
    }

    fn goto_decoded(&mut self, addr: u64) -> bool {
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
        if let Some(window) = self.window.as_ref() {
            let (start, end) = (window.start, window.end);

            // The start or the end of the region
            if delta.abs() >= FAR {
                if let Some(decoder) = self.decoder() {
                    self.decode_window(&decoder, if delta < 0 { start } else { end.saturating_sub(1) });
                    self.cursor = if delta < 0 { 0 } else { self.lines.len().saturating_sub(1) };
                    self.scroll = self.cursor.saturating_sub(self.height.saturating_sub(1));
                }

                return;
            }

            // The window follows the cursor, the cursor stays on the same row of the screen
            let target = self.cursor as isize + delta;
            let margin = self.height.max(1) as isize;
            let (from, to) = (window.from, window.to);
            let leaves = (target < margin && from > start) || (target >= self.lines.len() as isize - margin && to < end);

            if leaves {
                let row = self.cursor.saturating_sub(self.scroll);
                let edge = self.line_addr_near(target.clamp(0, self.lines.len().saturating_sub(1) as isize) as usize);

                if let (Some(edge), Some(decoder)) = (edge, self.decoder()) {
                    let rest = target - target.clamp(0, self.lines.len().saturating_sub(1) as isize);
                    self.decode_window(&decoder, edge);
                    let max = self.lines.len().saturating_sub(1) as isize;
                    self.cursor = (self.cursor as isize + rest).clamp(0, max.max(0)) as usize;
                    self.scroll = self.cursor.saturating_sub(row);
                    follow_cursor(self.cursor, &mut self.scroll, self.height);
                    return;
                }
            }
        }

        let max = self.lines.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max.max(0)) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    /// Address of a line, or of the closest line with one
    fn line_addr_near(&self, index: usize) -> Option<u64> {
        return self.lines[index..].iter().chain(self.lines[..index].iter().rev()).find_map(|&l| self.line_addr(l));
    }

    /// Moves to the next (or previous) label
    pub fn jump_label(&mut self, forward: bool) {
        // Region views: the next function of the analysis, which may be outside of the window
        if let Some(window) = self.window.as_ref() {
            let (Some(analysis), Some(addr)) = (window.analysis.as_ref(), self.cursor_addr()) else {
                return;
            };

            let next = if forward { analysis.functions.range(addr + 1..window.end).next() } else { analysis.functions.range(window.start..addr).next_back() };

            if let Some((&next, _)) = next {
                self.goto(next);

                // On the label of the function, not its first instruction
                if self.cursor > 0 && matches!(self.lines.get(self.cursor - 1), Some(DisasmLine::Label(..))) {
                    self.cursor -= 1;
                }

                self.scroll = self.cursor.saturating_sub(1);
            }

            return;
        }

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

    /// Text of a line for the search
    fn search_text(&self, program: &Program, decoder: &Decoder, line: DisasmLine, labels: &[(String, u64)]) -> Option<String> {
        return match line {
            DisasmLine::Label(label) => Some(labels[label as usize].0.clone()),
            DisasmLine::Blank => None,
            line => self.text(program, decoder, line).map(|insn| format!("{:x} {} {}", insn.addr, insn.mnemonic, insn.operands)),
        };
    }

    /// Next (or previous) line containing a pattern, from the cursor and wrapping
    pub fn search(&mut self, pattern: &str, program: &Program, decoder: &Decoder, forward: bool) -> bool {
        let pattern = pattern.to_lowercase();

        if self.window.is_some() {
            return if forward { self.search_region(&pattern, program, decoder) } else { self.search_region_back(&pattern, program, decoder) };
        }

        let count = self.lines.len();

        for i in 1..=count {
            let index = if forward { (self.cursor + i) % count } else { (self.cursor + count * 2 - i) % count };

            let Some(text) = self.search_text(program, decoder, self.lines[index], &self.labels) else {
                continue;
            };

            if text.to_lowercase().contains(&pattern) {
                self.cursor = index;
                self.scroll = index.saturating_sub(self.height / 3);
                return true;
            }
        }

        return false;
    }

    /// Address of a line of a decoded range (labels are at their function)
    fn decoded_addr(&self, decoded: &Decoded, line: DisasmLine) -> Option<u64> {
        return match line {
            DisasmLine::Label(label) => Some(decoded.labels[label as usize].1),
            DisasmLine::Blank => None,
            line => self.line_addr(line),
        };
    }

    /// Searches the whole region backwards from the cursor, window after window (wrapping at its start)
    fn search_region_back(&mut self, pattern: &str, program: &Program, decoder: &Decoder) -> bool {
        let Some(window) = self.window.clone() else {
            return false;
        };

        let analysis = window.analysis.as_deref();
        let start = self.cursor_addr().unwrap_or(window.start);
        let mut to = start;
        let mut wrapped = false;

        loop {
            let from = to.saturating_sub(2 * WINDOW_HALF).max(window.start);
            let decoded = decode_range(&window.program, analysis, decoder, self.base, window.anchor(from), to);
            let mut found = None;

            for &line in decoded.lines.iter() {
                let Some(addr) = self.decoded_addr(&decoded, line) else {
                    continue;
                };

                let before = if wrapped { addr > start && addr < to } else { addr < to };

                if before && self.search_text(program, decoder, line, &decoded.labels).is_some_and(|t| t.to_lowercase().contains(pattern)) {
                    found = Some(addr);
                }
            }

            if let Some(addr) = found {
                self.goto(addr);
                return true;
            }

            to = from;

            if to <= window.start {
                if wrapped {
                    return false;
                }

                wrapped = true;
                to = window.end;
            }

            if wrapped && to <= start {
                return false;
            }
        }
    }

    /// Searches the whole region from the cursor, window after window (wrapping at its end)
    fn search_region(&mut self, pattern: &str, program: &Program, decoder: &Decoder) -> bool {
        let Some(window) = self.window.clone() else {
            return false;
        };

        let analysis = window.analysis.as_deref();
        let matches = |text: &str| text.to_lowercase().contains(pattern);
        let start = self.cursor_addr().unwrap_or(window.start);
        let mut from = start;
        let mut wrapped = false;

        loop {
            let to = from.saturating_add(2 * WINDOW_HALF).min(window.end);
            let decoded = decode_range(&window.program, analysis, decoder, self.base, window.anchor(from), to);

            for line in decoded.lines.iter() {
                let addr = match *line {
                    DisasmLine::Label(label) => {
                        let (name, addr) = &decoded.labels[label as usize];

                        if *addr > start || wrapped {
                            if matches(name) {
                                self.goto(*addr);
                                return true;
                            }
                        }

                        continue;
                    }
                    DisasmLine::Blank => continue,
                    line => self.line_addr(line).unwrap_or(0),
                };

                if (addr <= start && !wrapped) || (wrapped && addr > start) {
                    continue;
                }

                if let Some(insn) = self.text(program, decoder, *line) {
                    if matches(&format!("{:x} {} {}", insn.addr, insn.mnemonic, insn.operands)) {
                        self.goto(addr);
                        return true;
                    }
                }
            }

            from = decoded.to.max(to);

            if from >= window.end {
                if wrapped {
                    return false;
                }

                wrapped = true;
                from = window.start;
            }

            if wrapped && from > start {
                return false;
            }
        }
    }

    /// Instruction under the cursor, as recovered by the analysis
    pub fn cursor_insn(&self, analysis: &Analysis) -> Option<Instruction> {
        let addr = match self.lines.get(self.cursor)? {
            &DisasmLine::Insn(offset, _) => self.base + offset as u64,
            _ => return None,
        };

        return find_insn(analysis, addr);
    }

    pub fn render(&mut self, theme: &Theme, program: &Program, analysis: Option<&Analysis>, decoder: &Decoder, height: usize, marks: &Marks) -> Vec<Line<'static>> {
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

            // The instruction the program is stopped at, the breakpoints
            let addr = matches!(line, DisasmLine::Insn(..)).then(|| self.line_addr(line)).flatten();
            let stopped = addr.is_some() && addr == marks.pc;

            if !marks.is_empty() {
                let breakpoint = addr.is_some_and(|a| marks.breakpoint(a));

                let (mark, color) = match (stopped, breakpoint) {
                    (true, true) => ("◉ ", theme.breakpoint),
                    (true, false) => ("▶ ", theme.node_selected),
                    (false, true) => ("● ", theme.breakpoint),
                    (false, false) => ("  ", theme.dim),
                };

                rendered.spans.insert(0, Span::styled(mark, Style::default().fg(color)));
            }

            if index == self.cursor {
                rendered = rendered.style(Style::default().bg(theme.cursor_bg));
            } else if stopped {
                rendered = rendered.style(Style::default().bg(theme.stopped_bg));
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
 * Commands
 */

impl App {
    pub(crate) fn region_disasm(&self, program: usize, region: &str) -> Option<DisasmView> {
        let decoder = self.decoders[program].as_ref()?;
        return DisasmView::region(program, self.programs[program].clone(), self.analyses[program].clone(), decoder, region);
    }

    pub(crate) fn disasm_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let repeat = count.unwrap_or(1).max(1) as isize;

        let View::Disasm(view) = self.view_mut() else {
            return false;
        };

        let page = (view.height / 2).max(1) as isize;

        match command {
            Command::Move(motion) => match motion {
                Motion::PageDown => view.move_cursor(page),
                Motion::PageUp => view.move_cursor(-page),
                Motion::Down => view.move_cursor(repeat),
                Motion::Up => view.move_cursor(-repeat),
                Motion::JumpDown => view.move_cursor(VERTICAL_STEP as isize),
                Motion::JumpUp => view.move_cursor(-VERTICAL_STEP as isize),
                Motion::First => view.move_cursor(isize::MIN / 2),
                Motion::Last => view.move_cursor(isize::MAX / 2),
                Motion::Next => view.jump_label(true),
                Motion::Previous => view.jump_label(false),
                _ => return false,
            },
            Command::Open(OpenMode::Replace) => self.follow_instruction(),
            Command::ToggleView => self.toggle_graph_linear(),
            _ => return false,
        }

        return true;
    }

    /// Instruction under the cursor of a linear disassembly: its target opens
    pub(crate) fn follow_instruction(&mut self) {
        let View::Disasm(view) = self.view() else {
            return;
        };

        let program = view.program;

        let Some(analysis) = self.analyses[program].clone() else {
            return;
        };

        let Some(insn) = view.cursor_insn(&analysis) else {
            return;
        };

        let Some(target) = insn_target(&insn) else {
            return;
        };

        let same_function = analysis.function_containing(insn.addr).map_or(false, |f| f.contains(target) && f.addr != target);

        if same_function {
            if let View::Disasm(view) = self.view_mut() {
                view.goto(target);
            }
        } else if analysis.functions.contains_key(&target) {
            self.open_function(program, target, None);
        } else {
            self.goto_address(program, target);
        }
    }
}

pub(crate) fn render(view: &mut DisasmView, f: &mut Frame, theme: &Theme, area: Rect, programs: &[Arc<Program>], analyses: &[Option<Arc<Analysis>>], decoders: &[Option<Decoder>], marks: &Marks) {
    if let Some(decoder) = decoders[view.program].as_ref() {
        let lines = view.render(theme, &programs[view.program], analyses[view.program].as_deref(), decoder, area.height as usize, marks);
        f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_disassembly() {
        use execdump_core::elf::parse_elf;
        use execdump_core::exec::Exec;
        use execdump_core::program::programs_from_exec;
        use execdump_decompiler::analysis::analyze;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let program = Arc::new(programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0));
        let analysis = Arc::new(analyze(&program, None).unwrap());
        let decoder = Decoder::new(program.architecture()).unwrap();
        let theme = Theme::codedark();

        let mut view = DisasmView::region(0, program.clone(), Some(analysis.clone()), &decoder, ".text").unwrap();
        view.height = 10;

        let main = analysis.function_by_name("main").unwrap();
        let second = main.blocks[&main.addr].insns[1];
        assert!(view.goto(second.addr + 1));
        assert_eq!(view.cursor_addr(), Some(second.addr));
        assert!(view.cursor_insn(&analysis).is_some());

        assert!(view.search("classify", &program, &decoder, true));
        let lines = view.render(&theme, &program, Some(&analysis), &decoder, 10, &Marks::default());
        assert_eq!(lines.len(), 10);

        let mut function = DisasmView::function(0, &program, &analysis, &decoder, main.addr).unwrap();
        assert!(function.goto(main.addr));
        assert_eq!(function.cursor_addr(), Some(main.addr));
        assert!(!function.goto(0x10));
    }

    #[test]
    fn large_region_windows() {
        use execdump_core::disasm::Architecture;
        use execdump_core::program::{Perms, Region};

        // 4 MB of nops, a ret near the end
        let mut code = vec![0x90u8; 4 << 20];
        let ret = code.len() - 100;
        code[ret] = 0xc3;

        let mut program = Program::default();
        program.arch = Some(Architecture::X86_64);
        program.pointer_size = 8;
        program.regions.push(Region { name: ".text".to_string(), vaddr: 0x100000, size: code.len() as u64, data: code, perms: Perms { read: true, write: false, exec: true } });

        let program = Arc::new(program);
        let decoder = Decoder::new(program.architecture()).unwrap();
        let mut view = DisasmView::region(0, program.clone(), None, &decoder, ".text").unwrap();
        view.height = 20;

        // Only a window is decoded
        assert!(view.lines.len() < (1 << 17));

        // Line by line across the end of the window, one instruction (byte) per line
        let first = view.cursor_addr().unwrap();
        let count = view.lines.len() as isize + 1000;
        view.move_cursor(count);
        assert_eq!(view.cursor_addr(), Some(first + count as u64));

        view.move_cursor(FAR);
        assert_eq!(view.cursor_addr(), Some(0x100000 + (4 << 20) - 1));

        assert!(view.goto(0x100000 + (2 << 20)));
        assert_eq!(view.cursor_addr(), Some(0x100000 + (2 << 20)));

        assert!(view.search("ret", &program, &decoder, true));
        assert_eq!(view.cursor_addr(), Some(0x100000 + ret as u64));

        view.move_cursor(-FAR);
        assert_eq!(view.cursor_addr(), Some(0x100000));

        // Backwards from the start: wraps to the end of the region
        assert!(view.search("ret", &program, &decoder, false));
        assert_eq!(view.cursor_addr(), Some(0x100000 + ret as u64));
    }
}
