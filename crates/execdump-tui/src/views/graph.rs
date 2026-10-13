/*
 * Graph view: control flow graph of a function or call graph, rendered with the layered layout
 */

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use execdump_decompiler::analysis::function::{CallTarget, EdgeKind};
use execdump_decompiler::analysis::insn::{Decoder, Instruction};
use execdump_decompiler::analysis::Analysis;
use crate::layout::{layout, GraphInput, Layout};
use super::source::highlight_with;
use execdump_core::program::Program;
use execdump_project::{Priority, Project};
use crate::theme::Theme;
use crate::commands::{Command, Motion};
use crate::views::disasm::DisasmView;
use crate::views::{Target, View};
use crate::{App, OpenMode, HORIZONTAL_STEP, VERTICAL_STEP};

use ratatui::Frame;

use std::collections::{HashMap, VecDeque};

/// Maximum width of a line inside a node
const MAX_LINE_WIDTH: usize = 96;
/// Maximum number of nodes in a call graph
const MAX_CALL_GRAPH_NODES: usize = 400;
/// Maximum number of lines of code shown in a node
const MAX_NODE_LINES: usize = 40;

const UP: u8 = 1;
const DOWN: u8 = 2;
const LEFT: u8 = 4;
const RIGHT: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Block,
    Function,
    Import,
}

/// What the nodes show: the summary of a function, the disassembly or the C code
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    Summary,
    Disasm,
    Source,
}

#[derive(Clone, Debug)]
pub struct GraphNode {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    /// Plain text of the node, for searching
    pub text: String,
    pub addr: u64,
    pub kind: NodeKind,
    pub detail: Detail,
    /// Lines the node was built with (disassembly of a block, summary of a function)
    original: Vec<Line<'static>>,
    /// Waiting for the C code of its function
    pending: bool,
}

impl GraphNode {
    fn new(title: String, lines: Vec<Line<'static>>, text: String, addr: u64, kind: NodeKind) -> Self {
        let detail = if kind == NodeKind::Block { Detail::Disasm } else { Detail::Summary };
        return GraphNode { title, original: lines.clone(), lines, text, addr, kind, detail, pending: false };
    }
}

impl GraphNode {
    fn size(&self) -> (i32, i32) {
        let content = self.lines.iter().map(|l| l.width()).max().unwrap_or(0);
        let title = self.title.chars().count() + 4;

        return (content.max(title) as i32 + 4, self.lines.len() as i32 + 2);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphEdgeKind {
    Flow(EdgeKind),
    Call,
    TailCall,
    Reference,
}

#[derive(Clone, Copy, Debug)]
pub struct GraphEdge {
    pub from: usize,
    pub to: usize,
    pub kind: GraphEdgeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphKind {
    Cfg { function: u64 },
    CallGraph { root: u64, depth: usize, imports: bool },
}

#[derive(Clone, Debug)]
pub struct GraphView {
    pub program: usize,
    pub kind: GraphKind,
    pub title: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub layout: Layout,
    pub selected: usize,
    pub scroll_x: i32,
    pub scroll_y: i32,
    viewport: (i32, i32),
    pending_focus: bool,
    theme: Theme,
}

fn truncate_spans(spans: Vec<Span<'static>>, max_width: usize) -> Vec<Span<'static>> {
    let mut res = Vec::new();
    let mut width = 0;

    for span in spans {
        let len = span.content.chars().count();

        if width + len <= max_width {
            width += len;
            res.push(span);
            continue;
        }

        let keep = max_width.saturating_sub(width + 1);
        let content: String = span.content.chars().take(keep).collect();
        res.push(Span::styled(format!("{}…", content), span.style));
        break;
    }

    return res;
}

/// Styled text of an instruction: address, mnemonic, operands and comment
pub fn insn_spans(theme: &Theme, program: &Program, analysis: &Analysis, decoder: &Decoder, insn: &Instruction, addr_width: usize) -> (Vec<Span<'static>>, String) {
    let (mnemonic, operands, comment) = analysis.insn_text(program, decoder, insn);

    let mut spans = vec![
        Span::styled(format!("{:0width$x}", insn.addr, width = addr_width), Style::default().fg(theme.asm_address)),
        Span::raw("  "),
        Span::styled(format!("{:<6}", mnemonic), theme.mnemonic_style(&mnemonic)),
        Span::raw(" "),
    ];

    spans.extend(theme.operand_spans(&operands));

    let mut text = format!("{:x} {} {}", insn.addr, mnemonic, operands);

    if let Some(comment) = comment {
        text.push_str(&format!(" ; {}", comment));
        spans.push(Span::styled(format!("  ; {}", comment), Style::default().fg(theme.comment)));
    }

    return (truncate_spans(spans, MAX_LINE_WIDTH), text);
}

impl GraphView {
    fn new(program: usize, kind: GraphKind, title: String, nodes: Vec<GraphNode>, edges: Vec<GraphEdge>, root: usize, theme: &Theme) -> Self {
        let input = GraphInput {
            sizes: nodes.iter().map(|n| n.size()).collect(),
            edges: edges.iter().map(|e| (e.from, e.to)).collect(),
            roots: vec![root],
        };

        let layout = layout(&input);

        return Self {
            program,
            kind,
            title,
            nodes,
            edges,
            layout,
            selected: root,
            scroll_x: 0,
            scroll_y: 0,
            viewport: (0, 0),
            pending_focus: true,
            theme: theme.clone(),
        };
    }

    /// Control flow graph of a function
    pub fn cfg(program_index: usize, program: &Program, analysis: &Analysis, decoder: &Decoder, theme: &Theme, addr: u64) -> Option<Self> {
        let function = analysis.functions.get(&addr)?;

        let addr_width = format!("{:x}", function.end()).len();
        let mut index: HashMap<u64, usize> = HashMap::new();
        let mut nodes = Vec::new();

        for block in function.blocks.values() {
            index.insert(block.start, nodes.len());

            let mut lines = Vec::new();
            let mut text = String::new();

            for insn in block.insns.iter() {
                let (spans, plain) = insn_spans(theme, program, analysis, decoder, insn, addr_width);
                lines.push(Line::from(spans));
                text.push_str(&plain);
                text.push('\n');
            }

            let title = if block.start == function.addr { format!("{} ({:#x})", function.name, block.start) } else { format!("{:#x}", block.start) };

            nodes.push(GraphNode::new(title, lines, text, block.start, NodeKind::Block));
        }

        let mut edges = Vec::new();

        for block in function.blocks.values() {
            for edge in block.succs.iter() {
                if let Some(&to) = index.get(&edge.to) {
                    edges.push(GraphEdge { from: index[&block.start], to, kind: GraphEdgeKind::Flow(edge.kind) });
                }
            }
        }

        let root = index.get(&function.addr).copied().unwrap_or(0);
        let title = format!("{} @ {:#x}  ({} blocks, {} instructions)", function.name, function.addr, function.blocks.len(), function.num_insns());

        return Some(Self::new(program_index, GraphKind::Cfg { function: addr }, title, nodes, edges, root, theme));
    }

    /// Call graph starting from a function, up to a depth
    pub fn call_graph(program_index: usize, analysis: &Analysis, theme: &Theme, root: u64, depth: usize, imports: bool) -> Option<Self> {
        let root_function = analysis.functions.get(&root)?;

        let mut nodes: Vec<GraphNode> = Vec::new();
        let mut edges: Vec<GraphEdge> = Vec::new();
        let mut functions: HashMap<u64, usize> = HashMap::new();
        let mut import_nodes: HashMap<String, usize> = HashMap::new();
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        let mut truncated = false;

        let function_node = |addr: u64| -> GraphNode {
            let function = &analysis.functions[&addr];

            let mut lines = vec![Line::from(Span::styled(format!("{:#x}", addr), Style::default().fg(theme.asm_address)))];

            lines.push(Line::from(Span::styled(
                format!("{} block{}, {} insns", function.blocks.len(), if function.blocks.len() == 1 { "" } else { "s" }, function.num_insns()),
                Style::default().fg(theme.dim),
            )));

            if function.noreturn {
                lines.push(Line::from(Span::styled("noreturn", Style::default().fg(theme.warning))));
            }

            let title: String = function.name.chars().take(MAX_LINE_WIDTH).collect();

            GraphNode::new(title, lines, function.name.clone(), addr, NodeKind::Function)
        };

        functions.insert(root, 0);
        nodes.push(function_node(root));
        queue.push_back((root, 0));

        while let Some((addr, level)) = queue.pop_front() {
            let from = functions[&addr];
            let function = &analysis.functions[&addr];

            if level >= depth {
                continue;
            }

            let mut targets: Vec<(CallTarget, GraphEdgeKind)> = analysis.callees(function)
                .into_iter()
                .map(|(target, tail)| (target, if tail { GraphEdgeKind::TailCall } else { GraphEdgeKind::Call }))
                .collect();

            // Functions referenced by address (callbacks, main passed to __libc_start_main...)
            for &(_, target) in function.refs.iter() {
                if target != addr && analysis.functions.contains_key(&target) {
                    let call_target = CallTarget::Function(target);

                    if !targets.iter().any(|(t, _)| *t == call_target) {
                        targets.push((call_target, GraphEdgeKind::Reference));
                    }
                }
            }

            for (target, kind) in targets {
                if nodes.len() >= MAX_CALL_GRAPH_NODES {
                    truncated = true;
                    break;
                }

                let to = match &target {
                    CallTarget::Function(target) => {
                        if !analysis.functions.contains_key(target) {
                            continue;
                        }

                        if !imports && analysis.functions[target].thunk.is_some() {
                            continue;
                        }

                        match functions.get(target) {
                            Some(&index) => index,
                            None => {
                                let index = nodes.len();
                                functions.insert(*target, index);
                                nodes.push(function_node(*target));
                                queue.push_back((*target, level + 1));
                                index
                            }
                        }
                    }
                    CallTarget::Import(name) => {
                        if !imports {
                            continue;
                        }

                        match import_nodes.get(name) {
                            Some(&index) => index,
                            None => {
                                let index = nodes.len();
                                let display = analysis.call_target_name(&target);
                                import_nodes.insert(name.clone(), index);
                                nodes.push(GraphNode::new(
                                    display.chars().take(MAX_LINE_WIDTH).collect(),
                                    vec![Line::from(Span::styled("import", Style::default().fg(theme.dim)))],
                                    display,
                                    0,
                                    NodeKind::Import,
                                ));
                                index
                            }
                        }
                    }
                    CallTarget::Indirect => continue,
                };

                edges.push(GraphEdge { from, to, kind });
            }
        }

        let title = format!(
            "Call graph from {} (depth {}, {} functions{}){}",
            root_function.name,
            depth,
            nodes.len(),
            if imports { ", imports shown" } else { "" },
            if truncated { " [truncated]" } else { "" },
        );

        return Some(Self::new(program_index, GraphKind::CallGraph { root, depth, imports }, title, nodes, edges, 0, theme));
    }

    /*
     * Content of the nodes
     */

    /// Detail after the one of the selected node: disassembly and C code for the blocks, summary,
    /// disassembly and C code for the functions
    pub fn next_detail(&self, _all: bool) -> Detail {
        let node = self.selected_node();

        return match (node.kind, node.detail) {
            (NodeKind::Block, Detail::Source) => Detail::Disasm,
            (NodeKind::Block, _) => Detail::Source,
            (_, Detail::Summary) => Detail::Disasm,
            (_, Detail::Disasm) => Detail::Source,
            (_, Detail::Source) => Detail::Summary,
        };
    }

    /// Changes what the selected node (or every node) shows, the graph is laid out again
    #[allow(clippy::too_many_arguments)]
    pub fn set_detail(&mut self, detail: Detail, all: bool, program: &Program, analysis: &Analysis, decoder: &Decoder, project: &mut Project, theme: &Theme) {
        let indices: Vec<usize> = if all { (0..self.nodes.len()).collect() } else { vec![self.selected] };

        for index in indices {
            if self.nodes[index].kind == NodeKind::Import {
                continue;
            }

            self.nodes[index].detail = detail;
            self.fill(index, Some((program, analysis, decoder)), project, theme);
        }

        self.relayout();
    }

    /// The C code of some functions changed: the nodes showing it follow
    pub fn changed(&mut self, project: &mut Project, addrs: &[u64]) {
        let function = |node: &GraphNode, kind: GraphKind| match kind {
            GraphKind::Cfg { function } => function,
            GraphKind::CallGraph { .. } => node.addr,
        };

        let theme = self.theme.clone();
        let indices: Vec<usize> = (0..self.nodes.len()).filter(|&i| self.nodes[i].detail == Detail::Source && addrs.contains(&function(&self.nodes[i], self.kind))).collect();

        if indices.is_empty() {
            return;
        }

        for index in indices {
            self.fill(index, None, project, &theme);
        }

        self.relayout();
    }

    /// The functions whose C code is shown are decompiled first
    pub fn prioritize(&self, project: &Project) {
        let pending: Vec<u64> = self.nodes.iter().filter(|n| n.pending).map(|n| match self.kind {
            GraphKind::Cfg { function } => function,
            GraphKind::CallGraph { .. } => n.addr,
        }).collect();

        if !pending.is_empty() {
            project.prioritize(&pending, Priority::Visible);
        }
    }

    fn fill(&mut self, index: usize, code: Option<(&Program, &Analysis, &Decoder)>, project: &mut Project, theme: &Theme) {
        let kind = self.kind;
        let node = &mut self.nodes[index];
        node.pending = false;

        let lines = match node.detail {
            Detail::Summary => node.original.clone(),
            Detail::Disasm if node.kind == NodeKind::Block => node.original.clone(),
            Detail::Disasm => match code {
                Some((program, analysis, decoder)) => function_disasm(theme, program, analysis, decoder, node.addr),
                None => node.lines.clone(),
            },
            Detail::Source => {
                let function = match kind {
                    GraphKind::Cfg { function } => function,
                    GraphKind::CallGraph { .. } => node.addr,
                };

                let import = project.analysis.functions.get(&function).and_then(|f| f.thunk.clone());

                match project.shown(function) {
                    _ if import.is_some() => {
                        let text = format!("// {} is imported, Enter opens it in its library", import.unwrap_or_default());
                        vec![Line::from(Span::styled(text, Style::default().fg(theme.comment)))]
                    }
                    Some((rendered, _)) => {
                        let range = match kind {
                            GraphKind::Cfg { .. } => project.analysis.functions.get(&function).and_then(|f| f.blocks.get(&node.addr)).map(|b| (b.start, b.end)),
                            GraphKind::CallGraph { .. } => None,
                        };

                        source_lines(theme, &rendered.text, &rendered.lines, range, function)
                    }
                    None => {
                        node.pending = true;
                        vec![Line::from(Span::styled("decompiling...", Style::default().fg(theme.dim)))]
                    }
                }
            }
        };

        node.lines = if lines.is_empty() { vec![Line::from(Span::styled("(no C code for this block)", Style::default().fg(theme.dim)))] } else { lines };
    }

    /// Lays the graph out again with the new node sizes, keeping the selection in view
    fn relayout(&mut self) {
        let input = GraphInput {
            sizes: self.nodes.iter().map(|n| n.size()).collect(),
            edges: self.edges.iter().map(|e| (e.from, e.to)).collect(),
            roots: vec![self.layout.order.first().copied().unwrap_or(0)],
        };

        self.layout = layout(&input);
        self.clamp_scroll();
        self.ensure_visible();
    }

    pub fn selected_node(&self) -> &GraphNode {
        return &self.nodes[self.selected];
    }

    /*
     * Navigation
     */

    pub fn scroll(&mut self, dx: i32, dy: i32) {
        self.scroll_x += dx;
        self.scroll_y += dy;
        self.clamp_scroll();
    }

    fn clamp_scroll(&mut self) {
        let (w, h) = self.viewport;

        self.scroll_x = self.scroll_x.clamp(-w / 2, (self.layout.width - w / 2).max(-w / 2));
        self.scroll_y = self.scroll_y.clamp(-h / 2, (self.layout.height - h / 2).max(-h / 2));
    }

    pub fn page_height(&self) -> i32 {
        return (self.viewport.1 / 2).max(1);
    }

    pub fn select(&mut self, node: usize) {
        if node < self.nodes.len() {
            self.selected = node;
            self.ensure_visible();
        }
    }

    fn order_position(&self) -> usize {
        return self.layout.order.iter().position(|&n| n == self.selected).unwrap_or(0);
    }

    pub fn select_next(&mut self) {
        let pos = self.order_position();

        if pos + 1 < self.layout.order.len() {
            self.select(self.layout.order[pos + 1]);
        }
    }

    pub fn select_previous(&mut self) {
        let pos = self.order_position();

        if pos > 0 {
            self.select(self.layout.order[pos - 1]);
        }
    }

    pub fn select_first(&mut self) {
        if let Some(&first) = self.layout.order.first() {
            self.select(first);
        }
    }

    pub fn select_last(&mut self) {
        if let Some(&last) = self.layout.order.last() {
            self.select(last);
        }
    }

    /// Selects the successor of the selected block through a true (or false) edge
    pub fn follow(&mut self, kind: EdgeKind) -> bool {
        let target = self.edges.iter().find(|e| e.from == self.selected && e.kind == GraphEdgeKind::Flow(kind)).map(|e| e.to);

        if let Some(target) = target {
            self.select(target);
            return true;
        }

        return false;
    }

    /// Selects the only successor of the selected node, if there is only one
    pub fn follow_single(&mut self) -> bool {
        let successors: Vec<usize> = self.edges.iter().filter(|e| e.from == self.selected).map(|e| e.to).collect();

        if successors.len() == 1 {
            self.select(successors[0]);
            return true;
        }

        return false;
    }

    pub fn select_addr(&mut self, addr: u64) -> bool {
        let node = self.nodes.iter().position(|n| n.addr == addr)
            .or_else(|| self.nodes.iter().position(|n| n.kind == NodeKind::Block && n.text.lines().any(|l| l.starts_with(&format!("{:x} ", addr)))));

        if let Some(node) = node {
            self.select(node);
            return true;
        }

        return false;
    }

    /// Selects the next node (in reading order) whose text contains the pattern
    /// Next (or previous) node, in the reading order, whose text contains a pattern
    pub fn search(&mut self, pattern: &str, forward: bool) -> bool {
        let pattern = pattern.to_lowercase();
        let pos = self.order_position();
        let count = self.layout.order.len();

        for i in 1..=count {
            let index = if forward { (pos + i) % count } else { (pos + count * 2 - i) % count };
            let node = self.layout.order[index];

            if self.nodes[node].text.to_lowercase().contains(&pattern) || self.nodes[node].title.to_lowercase().contains(&pattern) {
                self.select(node);
                return true;
            }
        }

        return false;
    }

    pub fn center(&mut self) {
        let node = self.layout.nodes[self.selected];
        let (w, h) = self.viewport;

        self.scroll_x = node.center_x() - w / 2;

        if node.h > h - 2 {
            self.scroll_y = node.y - 1;
        } else {
            self.scroll_y = node.center_y() - h / 2;
        }

        self.clamp_scroll();
    }

    fn ensure_visible(&mut self) {
        let (w, h) = self.viewport;

        if w == 0 || h == 0 {
            self.pending_focus = true;
            return;
        }

        let node = self.layout.nodes[self.selected];

        let visible = node.x >= self.scroll_x && node.x + node.w <= self.scroll_x + w &&
                      node.y >= self.scroll_y && node.y + node.h.min(h - 1) <= self.scroll_y + h;

        if !visible {
            self.center();
        }
    }

    /*
     * Rendering
     */

    fn edge_style(&self, theme: &Theme, kind: GraphEdgeKind) -> (Color, bool, Option<char>) {
        match kind {
            GraphEdgeKind::Flow(EdgeKind::True) => (theme.edge_true, false, Some('t')),
            GraphEdgeKind::Flow(EdgeKind::False) => (theme.edge_false, false, Some('f')),
            GraphEdgeKind::Flow(kind) => (theme.edge_color(kind), false, None),
            GraphEdgeKind::Call => (theme.edge_call, false, None),
            GraphEdgeKind::TailCall => (theme.edge_switch, true, None),
            GraphEdgeKind::Reference => (theme.edge_reference, true, None),
        }
    }

    pub fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        self.viewport = (area.width as i32, area.height as i32);

        if self.pending_focus && area.width > 0 {
            self.pending_focus = false;

            let node = self.layout.nodes[self.selected];
            self.scroll_x = node.center_x() - self.viewport.0 / 2;
            self.scroll_y = node.y - 1;
            self.clamp_scroll();
        }

        buf.set_style(area, theme.base());

        let (w, h) = (area.width as i32, area.height as i32);
        let to_screen = |x: i32, y: i32| -> Option<(u16, u16)> {
            let (sx, sy) = (x - self.scroll_x, y - self.scroll_y);

            if sx >= 0 && sy >= 0 && sx < w && sy < h {
                return Some((area.x + sx as u16, area.y + sy as u16));
            }

            return None;
        };

        // Edges: accumulate the line directions of each cell, then pick the box drawing character
        let mut grid: Vec<(u8, Color, bool, bool)> = vec![(0, theme.fg, false, false); (w.max(0) * h.max(0)) as usize];

        let mut order: Vec<usize> = (0..self.edges.len()).collect();
        let selected = self.selected;
        order.sort_by_key(|&i| self.edges[i].from == selected || self.edges[i].to == selected);

        for &i in order.iter() {
            let edge = &self.edges[i];
            let (color, dashed, _) = self.edge_style(theme, edge.kind);
            let bold = edge.from == selected || edge.to == selected;
            let points = &self.layout.edges[i].points;

            for pair in points.windows(2) {
                let ((x1, y1), (x2, y2)) = (pair[0], pair[1]);

                if y1 == y2 {
                    let (lo, hi) = (x1.min(x2), x1.max(x2));

                    for x in lo..=hi {
                        let bits = if x > lo { LEFT } else { 0 } | if x < hi { RIGHT } else { 0 };

                        if let Some(cell) = cell_index(x - self.scroll_x, y1 - self.scroll_y, w, h) {
                            grid[cell] = (grid[cell].0 | bits, color, dashed, bold);
                        }
                    }
                } else {
                    let (lo, hi) = (y1.min(y2), y1.max(y2));

                    for y in lo..=hi {
                        let bits = if y > lo { UP } else { 0 } | if y < hi { DOWN } else { 0 };

                        if let Some(cell) = cell_index(x1 - self.scroll_x, y - self.scroll_y, w, h) {
                            grid[cell] = (grid[cell].0 | bits, color, dashed, bold);
                        }
                    }
                }
            }

            // The first point connects to the node above
            if let Some(&(x, y)) = points.first() {
                if let Some(cell) = cell_index(x - self.scroll_x, y - self.scroll_y, w, h) {
                    grid[cell].0 |= UP;
                }
            }
        }

        for (i, &(bits, color, dashed, bold)) in grid.iter().enumerate() {
            if bits == 0 {
                continue;
            }

            let (x, y) = (area.x + (i as i32 % w) as u16, area.y + (i as i32 / w) as u16);
            let mut style = Style::default().fg(color).bg(theme.bg);

            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }

            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(box_char(bits, dashed)).set_style(style);
            }
        }

        // Nodes
        for (i, node) in self.nodes.iter().enumerate() {
            let rect = self.layout.nodes[i];

            if rect.x + rect.w < self.scroll_x || rect.x > self.scroll_x + w || rect.y + rect.h < self.scroll_y || rect.y > self.scroll_y + h {
                continue;
            }

            let is_selected = i == self.selected;

            let border_style = if is_selected {
                Style::default().fg(theme.node_selected).bg(theme.bg).add_modifier(Modifier::BOLD)
            } else if node.kind == NodeKind::Import {
                Style::default().fg(theme.node_import).bg(theme.bg)
            } else {
                Style::default().fg(theme.node_border).bg(theme.bg)
            };

            let (tl, tr, bl, br) = match (is_selected, node.kind) {
                (true, _) => ('╔', '╗', '╚', '╝'),
                (false, NodeKind::Import) => ('╭', '╮', '╰', '╯'),
                _ => ('┌', '┐', '└', '┘'),
            };

            let (hz, vt) = if is_selected { ('═', '║') } else { ('─', '│') };

            for dy in 0..rect.h {
                for dx in 0..rect.w {
                    let Some(pos) = to_screen(rect.x + dx, rect.y + dy) else {
                        continue;
                    };

                    let top = dy == 0;
                    let bottom = dy == rect.h - 1;
                    let left = dx == 0;
                    let right = dx == rect.w - 1;

                    let ch = match (top, bottom, left, right) {
                        (true, _, true, _) => tl,
                        (true, _, _, true) => tr,
                        (_, true, true, _) => bl,
                        (_, true, _, true) => br,
                        (true, _, _, _) | (_, true, _, _) => hz,
                        (_, _, true, _) | (_, _, _, true) => vt,
                        _ => ' ',
                    };

                    if let Some(cell) = buf.cell_mut(pos) {
                        cell.set_char(ch).set_style(if ch == ' ' { theme.base() } else { border_style });
                    }
                }
            }

            // Title in the top border
            let title_style = if is_selected {
                Style::default().fg(theme.node_selected).bg(theme.bg).add_modifier(Modifier::BOLD)
            } else if node.kind == NodeKind::Import {
                Style::default().fg(theme.dim).bg(theme.bg)
            } else {
                Style::default().fg(theme.asm_label).bg(theme.bg).add_modifier(Modifier::BOLD)
            };

            let title = format!(" {} ", node.title);
            self.put_str(buf, area, rect.x + 2, rect.y, &title, title_style, rect.w - 4);

            // Content
            for (row, line) in node.lines.iter().enumerate() {
                let mut x = rect.x + 2;
                let y = rect.y + 1 + row as i32;

                for span in line.spans.iter() {
                    let style = span.style.bg(theme.bg);
                    let written = self.put_str(buf, area, x, y, &span.content, style, rect.x + rect.w - 2 - x);
                    x += written;
                }
            }
        }

        // Edge endpoints: port on the source border, label below it, arrow above the target
        for &i in order.iter() {
            let edge = &self.edges[i];
            let (color, _, label) = self.edge_style(theme, edge.kind);
            let bold = edge.from == selected || edge.to == selected;
            let points = &self.layout.edges[i].points;

            let mut style = Style::default().fg(color).bg(theme.bg);

            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }

            let (Some(&first), Some(&last)) = (points.first(), points.last()) else {
                continue;
            };

            let source_border = if edge.from == selected { '╦' } else { '┬' };

            if let Some(pos) = to_screen(first.0, first.1 - 1) {
                if let Some(cell) = buf.cell_mut(pos) {
                    let border_style = if edge.from == selected { Style::default().fg(theme.node_selected).bg(theme.bg).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.node_border).bg(theme.bg) };
                    cell.set_char(source_border).set_style(border_style);
                }
            }

            if let Some(label) = label {
                if let Some(pos) = to_screen(first.0, first.1) {
                    if let Some(cell) = buf.cell_mut(pos) {
                        cell.set_char(label).set_style(style);
                    }
                }
            }

            if let Some(pos) = to_screen(last.0, last.1) {
                if let Some(cell) = buf.cell_mut(pos) {
                    cell.set_char('▼').set_style(style);
                }
            }
        }
    }

    /// Writes a string clipped to the viewport, returns the number of columns used
    fn put_str(&self, buf: &mut Buffer, area: Rect, x: i32, y: i32, text: &str, style: Style, max_width: i32) -> i32 {
        let mut written = 0;

        for (i, ch) in text.chars().enumerate() {
            if i as i32 >= max_width {
                break;
            }

            let (sx, sy) = (x + i as i32 - self.scroll_x, y - self.scroll_y);

            if sx >= 0 && sy >= 0 && sx < area.width as i32 && sy < area.height as i32 {
                if let Some(cell) = buf.cell_mut((area.x + sx as u16, area.y + sy as u16)) {
                    cell.set_char(ch).set_style(style);
                }
            }

            written += 1;
        }

        return written;
    }
}

/// Linear disassembly of a function, block by block, capped
fn function_disasm(theme: &Theme, program: &Program, analysis: &Analysis, decoder: &Decoder, addr: u64) -> Vec<Line<'static>> {
    let Some(function) = analysis.functions.get(&addr) else {
        return Vec::new();
    };

    let addr_width = format!("{:x}", function.end()).len();
    let insns: Vec<&Instruction> = function.blocks.values().flat_map(|b| b.insns.iter()).collect();
    let mut lines: Vec<Line<'static>> = insns.iter().take(MAX_NODE_LINES).map(|insn| Line::from(insn_spans(theme, program, analysis, decoder, insn, addr_width).0)).collect();

    if insns.len() > MAX_NODE_LINES {
        lines.push(Line::from(Span::styled(format!("... {} more instructions", insns.len() - MAX_NODE_LINES), Style::default().fg(theme.dim))));
    }

    return lines;
}

/// C code of a function (or of the block of an address range: the lines of its statements), capped
fn source_lines(theme: &Theme, text: &str, addrs: &[Option<u64>], range: Option<(u64, u64)>, function: u64) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut current = function;
    let mut total = 0;

    let mut comment = false;

    for (index, line) in text.lines().enumerate() {
        // Lines without an address belong with the statement above them
        if let Some(addr) = addrs.get(index).copied().flatten() {
            current = addr;
        }

        // Every line is highlighted to follow the block comments
        let line: String = line.chars().take(MAX_LINE_WIDTH).collect();
        let spans = highlight_with(theme, &line, &mut comment);

        if range.is_some_and(|(start, end)| current < start || current >= end) {
            continue;
        }

        total += 1;

        if lines.len() < MAX_NODE_LINES {
            lines.push(Line::from(spans));
        }
    }

    if total > MAX_NODE_LINES {
        lines.push(Line::from(Span::styled(format!("... {} more lines", total - MAX_NODE_LINES), Style::default().fg(theme.dim))));
    }

    return lines;
}

fn cell_index(x: i32, y: i32, w: i32, h: i32) -> Option<usize> {
    if x >= 0 && y >= 0 && x < w && y < h {
        return Some((y * w + x) as usize);
    }

    return None;
}

fn box_char(bits: u8, dashed: bool) -> char {
    match bits {
        b if b == UP | DOWN || b == UP || b == DOWN => if dashed { '┆' } else { '│' },
        b if b == LEFT | RIGHT || b == LEFT || b == RIGHT => if dashed { '┄' } else { '─' },
        b if b == DOWN | RIGHT => '┌',
        b if b == DOWN | LEFT => '┐',
        b if b == UP | RIGHT => '└',
        b if b == UP | LEFT => '┘',
        b if b == UP | DOWN | RIGHT => '├',
        b if b == UP | DOWN | LEFT => '┤',
        b if b == LEFT | RIGHT | DOWN => '┬',
        b if b == LEFT | RIGHT | UP => '┴',
        _ => '┼',
    }
}

/*
 * Commands
 */

impl App {
    pub(crate) fn cfg_view(&mut self, program: usize, addr: u64) -> Option<GraphView> {
        let analysis = self.analysis(program)?;
        let decoder = self.decoders[program].as_ref()?;

        return GraphView::cfg(program, &self.programs[program], &analysis, decoder, &self.theme, addr);
    }

    pub(crate) fn open_function(&mut self, program: usize, addr: u64, select: Option<u64>) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let Some(function) = analysis.function_containing(addr) else {
            self.error(format!("No function at {:#x}", addr));
            return;
        };

        // Imported functions are opened in their library (their stub otherwise)
        if let Some(import) = function.thunk.clone() {
            if self.follow_import(&import, false) {
                return;
            }
        }

        if let Some(mut view) = self.cfg_view(program, function.addr) {
            if let Some(select) = select.or(if addr != function.addr { Some(addr) } else { None }) {
                view.select_addr(select);
            }

            self.open(View::Graph(view));
        }
    }

    pub(crate) fn open_call_graph(&mut self, program: usize, root: Option<u64>, depth: usize, imports: bool) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let program_ref = &self.programs[program];

        let root = root
            .or(program_ref.entry.filter(|e| analysis.functions.contains_key(e)))
            .or(analysis.function_by_name("main").map(|f| f.addr))
            .or(analysis.functions.keys().next().copied());

        let Some(root) = root else {
            self.error("No function found".to_string());
            return;
        };

        if let Some(view) = GraphView::call_graph(program, &analysis, &self.theme, root, depth, imports) {
            self.open(View::Graph(view));
        }
    }

    /// Opens a call graph and selects a function in it
    pub(crate) fn open_call_graph_at(&mut self, program: usize, root: u64, depth: usize, imports: bool, select: u64) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        if let Some(mut view) = GraphView::call_graph(program, &analysis, &self.theme, root, depth, imports) {
            if let Some(index) = view.nodes.iter().position(|n| n.kind == NodeKind::Function && n.addr == select) {
                view.select(index);
            }

            self.open(View::Graph(view));
        }
    }

    /// Commands of the graphs (control flow graphs and call graphs)
    pub(crate) fn graph_command(&mut self, command: &Command, _count: Option<usize>) -> bool {
        let View::Graph(view) = self.view_mut() else {
            return false;
        };

        let page = view.page_height();

        match command {
            Command::Move(motion) => match motion {
                Motion::PageDown => view.scroll(0, page),
                Motion::PageUp => view.scroll(0, -page),
                Motion::Left => view.scroll(-1, 0),
                Motion::Down => view.scroll(0, 1),
                Motion::Up => view.scroll(0, -1),
                Motion::Right => view.scroll(1, 0),
                Motion::JumpLeft => view.scroll(-HORIZONTAL_STEP, 0),
                Motion::JumpDown => view.scroll(0, VERTICAL_STEP),
                Motion::JumpUp => view.scroll(0, -VERTICAL_STEP),
                Motion::JumpRight => view.scroll(HORIZONTAL_STEP, 0),
                Motion::Next => view.select_next(),
                Motion::Previous => view.select_previous(),
                Motion::First => view.select_first(),
                Motion::Last => view.select_last(),
                _ => return false,
            },
            Command::Center => view.center(),
            Command::Follow(branch) => {
                let kind = if *branch { EdgeKind::True } else { EdgeKind::False };

                if !view.follow(kind) && !view.follow_single() {
                    self.message = Some((format!("No {} branch from this node", if *branch { "true" } else { "false" }), false));
                }
            }
            Command::Detail { all } => self.graph_detail(*all),
            Command::ToggleView => self.toggle_graph_linear(),
            Command::DepthBy(_) | Command::ToggleImports | Command::Reroot => self.call_graph_option(command),
            Command::Depth(depth) => {
                if let GraphKind::CallGraph { root, imports, .. } = view.kind {
                    let program = view.program;
                    self.open_call_graph(program, Some(root), *depth, imports);
                }
            }
            Command::CallGraphUp => self.call_graph_up(),
            Command::Open(OpenMode::Replace) => {
                let program = view.program;
                let node = view.selected_node().clone();

                match view.kind {
                    GraphKind::Cfg { function } => self.calls_popup(program, node.addr, function),
                    GraphKind::CallGraph { .. } => {
                        if node.kind == NodeKind::Function {
                            self.open_function(program, node.addr, None);
                        } else {
                            self.follow_import(&node.title, false);
                        }
                    }
                }
            }
            _ => return false,
        }

        return true;
    }

    /// Shows the C code or the disassembly in the nodes of a graph (the selected one, or all)
    pub(crate) fn graph_detail(&mut self, all: bool) {
        let App { workspace, projects, analyses, decoders, programs, theme, .. } = self;

        let View::Graph(view) = workspace.view_mut() else {
            return;
        };

        let program = view.program;
        let (Some(project), Some(analysis), Some(decoder)) = (projects[program].as_mut(), analyses[program].as_ref(), decoders[program].as_ref()) else {
            return;
        };

        let detail = view.next_detail(all);
        view.set_detail(detail, all, &programs[program], analysis, decoder, project, theme);
        let name = match detail {
            Detail::Summary => "summaries",
            Detail::Disasm => "disassembly",
            Detail::Source => "C code",
        };

        self.info(format!("Graph nodes: {}{}", name, if all { "" } else { " (selected node, V for all)" }));
    }

    /// Changes the depth, the imports or the root of a call graph: the view is replaced, a new root is
    /// a new view
    fn call_graph_option(&mut self, command: &Command) {
        let View::Graph(view) = self.view() else {
            return;
        };

        let GraphKind::CallGraph { root, depth, imports } = view.kind else {
            return;
        };

        let program = view.program;
        let selected = view.selected_node().clone();

        let (root, depth, imports) = match command {
            Command::DepthBy(delta) => (root, (depth as i64 + *delta as i64).max(1) as usize, imports),
            Command::ToggleImports => (root, depth, !imports),
            Command::Reroot if selected.kind == NodeKind::Function => (selected.addr, depth, imports),
            _ => return,
        };

        let Some(analysis) = self.analysis(program) else {
            return;
        };

        if let Some(mut new_view) = GraphView::call_graph(program, &analysis, &self.theme, root, depth, imports) {
            // Keep the selection on the same function when possible
            if let Some(index) = new_view.nodes.iter().position(|n| n.kind == selected.kind && n.addr == selected.addr && n.title == selected.title) {
                new_view.select(index);
            }

            if *command == Command::Reroot {
                self.open(View::Graph(new_view));
            } else {
                *self.view_mut() = View::Graph(new_view);
            }
        }
    }

    /// Re-roots the call graph at a caller of its root (popup when there are several)
    pub(crate) fn call_graph_up(&mut self) {
        let View::Graph(view) = self.view() else {
            self.error("Not in a call graph".to_string());
            return;
        };

        let GraphKind::CallGraph { root, depth, imports } = view.kind else {
            self.error("Not in a call graph".to_string());
            return;
        };

        let program = view.program;

        let Some(analysis) = self.analysis(program) else {
            return;
        };

        // Same edges as the call graph: calls, tail calls and references by address
        let mut items: Vec<(String, Target)> = Vec::new();

        for (&caller_addr, caller) in analysis.functions.iter() {
            if caller_addr == root {
                continue;
            }

            let kind = if caller.calls.iter().any(|c| c.target == CallTarget::Function(root)) {
                "call"
            } else if caller.refs.iter().any(|&(_, target)| target == root) {
                "reference"
            } else {
                continue;
            };

            items.push((
                format!("{:#x}  {} ({})", caller_addr, caller.name, kind),
                Target::CallGraph { program, root: caller_addr, depth, imports, select: root },
            ));
        }

        let name = analysis.functions.get(&root).map_or(String::new(), |f| f.name.clone());
        self.show_popup(format!("Callers of {}", name), items);
    }

    pub(crate) fn toggle_graph_linear(&mut self) {
        match self.view() {
            View::Graph(view) => {
                let GraphKind::Cfg { function } = view.kind else {
                    return;
                };

                let program = view.program;
                let block = view.selected_node().addr;

                let Some(analysis) = self.analysis(program) else {
                    return;
                };

                let Some(decoder) = self.decoders[program].as_ref() else {
                    return;
                };

                if let Some(mut linear) = DisasmView::function(program, &self.programs[program], &analysis, decoder, function) {
                    linear.height = 20;
                    linear.goto(block);
                    *self.view_mut() = View::Disasm(linear);
                }
            }
            View::Disasm(view) => {
                let program = view.program;
                let function_view = view.function.is_some();

                let Some(addr) = view.cursor_addr() else {
                    return;
                };

                let Some(analysis) = self.analysis(program) else {
                    return;
                };

                let Some(function) = analysis.function_containing(addr).map(|f| f.addr) else {
                    self.error(format!("No function at {:#x}", addr));
                    return;
                };

                if let Some(mut graph) = self.cfg_view(program, function) {
                    graph.select_addr(addr);

                    // A function linear view is the same "place" as its graph, a region view is not
                    if function_view {
                        *self.view_mut() = View::Graph(graph);
                    } else {
                        self.open(View::Graph(graph));
                    }
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn render(view: &mut GraphView, f: &mut Frame, theme: &Theme, area: Rect, projects: &mut [Option<Project>]) {
    if let Some(project) = projects[view.program].as_mut() {
        view.prioritize(project);
    }

    view.render(area, f.buffer_mut(), theme);
}


#[cfg(test)]
mod tests {
    use super::*;
    use execdump_decompiler::analysis::analyze;
    use execdump_core::elf::parse_elf;
    use execdump_core::exec::Exec;
    use execdump_core::program::programs_from_exec;

    use std::path::PathBuf;

    fn buffer_text(buf: &Buffer) -> String {
        let mut text = String::new();

        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).map_or(" ", |c| c.symbol()));
            }

            text.push('\n');
        }

        return text;
    }

    #[test]
    fn render_cfg_and_navigate() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let program = programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();
        let decoder = Decoder::new(program.architecture()).unwrap();
        let theme = Theme::codedark();

        let main = analysis.function_by_name("main").unwrap().addr;
        let mut view = GraphView::cfg(0, &program, &analysis, &decoder, &theme, main).unwrap();

        let area = Rect::new(0, 0, 120, 40);
        let mut buf = Buffer::empty(area);
        view.render(area, &mut buf, &theme);

        let text = buffer_text(&buf);
        assert!(text.contains("main"), "{}", text);
        assert!(text.contains("╔"), "{}", text);

        view.select_last();
        view.select_first();
        assert_eq!(view.selected, view.layout.order[0]);

        let mut view = GraphView::call_graph(0, &analysis, &theme, program.entry.unwrap(), 3, true).unwrap();
        view.render(area, &mut buf, &theme);

        assert!(view.nodes.iter().any(|n| n.title == "classify"), "{:?}", view.nodes.iter().map(|n| n.title.clone()).collect::<Vec<_>>());
    }
}
