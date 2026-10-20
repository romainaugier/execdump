/*
 * Views of the content: one module per kind of view, with the commands it handles and how it is drawn.
 * The commands a view does not handle go to the splits and the application (see commands).
 */

pub(crate) mod debug;
pub(crate) mod disasm;
pub(crate) mod dump;
pub(crate) mod graph;
pub(crate) mod hex;
pub(crate) mod review;
pub(crate) mod source;
pub(crate) mod table;
pub(crate) mod welcome;

use crate::commands::Command;
use crate::debug::Marks;
use crate::{App, DEFAULT_CALL_GRAPH_DEPTH};

use debug::DebugView;
use disasm::DisasmView;
use dump::DumpView;
use graph::{GraphKind, GraphView, NodeKind};
use hex::HexView;
use review::ReviewView;
use source::SourceView;
use table::TableView;

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::theme::Theme;

#[derive(Clone, Debug)]
pub(crate) enum View {
    Welcome,
    Dump(DumpView),
    Hex(HexView),
    Disasm(DisasmView),
    Graph(GraphView),
    Table(TableView),
    Source(SourceView),
    Review(ReviewView),
    Debug(DebugView),
}

impl View {
    pub fn title(&self) -> String {
        match self {
            View::Welcome => "Welcome".to_string(),
            View::Dump(v) => v.title.clone(),
            View::Hex(v) => v.title.clone(),
            View::Disasm(v) => v.title.clone(),
            View::Graph(v) => v.title.clone(),
            View::Source(v) => v.title(),
            View::Review(v) => v.title(),
            View::Debug(_) => "Debugger".to_string(),
            View::Table(v) => if v.filter.is_empty() { v.title.clone() } else { format!("{} [/{}] ({} matches)", v.title, v.filter, v.filtered.len()) },
        }
    }

    /// Short title, for the tab bar
    pub fn tab_title(&self) -> String {
        let title = match self {
            View::Source(v) => v.module.clone(),
            View::Graph(v) => v.title.split("  (").next().unwrap_or(&v.title).to_string(),
            _ => self.title(),
        };

        return title.chars().take(28).collect();
    }

    pub fn program(&self) -> Option<usize> {
        match self {
            View::Disasm(v) => Some(v.program),
            View::Graph(v) => Some(v.program),
            View::Source(v) => Some(v.program),
            View::Review(v) => Some(v.program),
            _ => None,
        }
    }
}

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
    /// Text copied to the clipboard of the terminal
    Copy(String),
    /// A frame of the call stack of the program under the debugger
    Frame(usize),
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


impl App {
    /// Commands of the view of the focused split, then the ones every view shares
    pub(crate) fn view_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let handled = match self.view() {
            View::Welcome => self.welcome_command(command),
            View::Dump(_) => self.dump_command(command),
            View::Hex(_) => self.hex_command(command),
            View::Disasm(_) => self.disasm_command(command, count),
            View::Graph(_) => self.graph_command(command, count),
            View::Table(_) => self.table_command(command, count),
            View::Source(_) => self.source_command(command, count),
            View::Review(_) => self.review_command(command, count),
            View::Debug(_) => self.debug_command(command, count),
        };

        if handled {
            return true;
        }

        match command {
            Command::Xrefs => self.xrefs_current(),
            Command::FunctionCallGraph => self.call_graph_current(),
            Command::ToggleCode => self.decompile_current(),
            _ => return false,
        }

        return true;
    }

    /// Draws the view of the active tab of a split
    pub(crate) fn render_view(&mut self, f: &mut Frame, theme: &Theme, group: crate::workspace::GroupId, area: Rect) {
        let (is_debug, program) = {
            let group = self.workspace.group(group);
            let view = &group.tabs[group.active].view;
            (matches!(view, View::Debug(_)), view.program())
        };

        // The content of the debug view and the marks of the debugger are made before the view is borrowed
        let debug_lines = if is_debug { self.debug_lines(theme) } else { Vec::new() };
        let marks = program.map_or_else(Marks::default, |p| App::marks(&self.debugger, &self.breakpoints, &self.programs, p));

        let App { workspace, projects, analyses, programs, decoders, analysis_errors, .. } = self;
        let group = workspace.group_mut(group);
        let active = group.active;

        match &mut group.tabs[active].view {
            View::Welcome => welcome::render(f, theme, area, analysis_errors, programs),
            View::Dump(view) => dump::render(view, f, theme, area),
            View::Hex(view) => hex::render(view, f, theme, area),
            View::Disasm(view) => disasm::render(view, f, theme, area, programs, analyses, decoders, &marks),
            View::Graph(view) => graph::render(view, f, theme, area, projects),
            View::Source(view) => source::render(view, f, theme, area, projects, &marks),
            View::Review(view) => review::render(view, f, theme, area, projects),
            View::Table(view) => table::render(view, f, theme, area),
            View::Debug(view) => debug::render(view, f, theme, area, debug_lines),
        }
    }

    /// Opens the most relevant view for an address: function graph, code or data
    pub(crate) fn goto_address(&mut self, program: usize, addr: u64) {
        let program_ref = self.programs[program].clone();

        if let Some(analysis) = &self.analyses[program] {
            if analysis.function_containing(addr).is_some() {
                self.open_function(program, addr, None);
                return;
            }
        }

        let Some(region) = program_ref.region_at(addr) else {
            self.error(format!("Address {:#x} is not mapped", addr));
            return;
        };

        if region.perms.exec && !region.data.is_empty() {
            if let Some(mut view) = self.region_disasm(program, &region.name) {
                view.goto(addr);
                self.open(View::Disasm(view));
            }
        } else {
            let mut view = HexView::new(format!("{} ({:#x})", region.name, region.vaddr), region.vaddr, region.data.clone());
            view.height = 20;
            view.goto(addr);
            self.open(View::Hex(view));
        }
    }

    pub(crate) fn open_target(&mut self, target: Target) {
        match target {
            Target::Function(program, addr) => self.open_function(program, addr, None),
            Target::Address(program, addr) => self.goto_address(program, addr),
            Target::CallGraph { program, root, depth, imports, select } => self.open_call_graph_at(program, root, depth, imports, select),
            Target::Module(program, module) => self.open_module(program, &module),
            Target::Copy(text) => {
                self.copy(&text);
            }
            Target::Frame(index) => self.select_frame(index),
        }
    }

    /// Resolves an address, a function name or a symbol
    pub(crate) fn resolve_address(&self, program: usize, text: &str) -> Option<u64> {
        let hex = text.trim_start_matches("0x").trim_start_matches("0X");

        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) && (text.starts_with("0x") || hex.len() >= 4) {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return Some(addr);
            }
        }

        if let Some(addr) = self.projects[program].as_ref().and_then(|p| p.resolve(text)) {
            return Some(addr);
        }

        if let Some(analysis) = &self.analyses[program] {
            if let Some(function) = analysis.function_by_name(text) {
                return Some(function.addr);
            }
        }

        if let Some(symbol) = self.programs[program].symbols.values().find(|s| s.name == text || s.demangled == text) {
            return Some(symbol.addr);
        }

        // The names of the C code for the functions and the globals without symbol
        return ["sub_", "g_", "s_"].iter().find_map(|prefix| text.strip_prefix(prefix).and_then(|hex| u64::from_str_radix(hex, 16).ok()));
    }

    /// Function shown by the current view (graph, linear disassembly or C code)
    pub(crate) fn current_function(&mut self) -> Option<(usize, u64)> {
        let App { workspace, projects, analyses, .. } = self;

        match workspace.view_mut() {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { function } => Some((view.program, function)),
                GraphKind::CallGraph { .. } => {
                    let node = view.selected_node();
                    if node.kind == NodeKind::Function { Some((view.program, node.addr)) } else { None }
                }
            },
            View::Disasm(view) => {
                let addr = view.cursor_addr()?;
                let analysis = analyses[view.program].as_ref()?;
                analysis.function_containing(addr).map(|f| (view.program, f.addr))
            }
            View::Source(view) => view.function().map(|f| (view.program, f)),
            View::Review(view) => {
                let id = view.proposal()?;
                let project = projects[view.program].as_ref()?;
                project.proposals.iter().find(|p| p.id == id).and_then(|p| p.functions.keys().next()).map(|&f| (view.program, f))
            }
            _ => None,
        }
    }

    /// C code of the function shown by the current view, back to the graph from the C code
    pub(crate) fn decompile_current(&mut self) {
        let target = match self.view() {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { .. } => Some((view.program, view.selected_node().addr)),
                GraphKind::CallGraph { .. } => self.current_function(),
            },
            View::Disasm(view) => view.cursor_addr().map(|a| (view.program, a)),
            View::Source(_) => {
                let App { workspace, projects, .. } = self;

                let target = match workspace.view() {
                    View::Source(view) => projects[view.program].as_mut().and_then(|p| view.cursor_addr(p)).map(|a| (view.program, a)),
                    _ => None,
                };

                if let Some((program, addr)) = target {
                    self.open_function(program, addr, Some(addr));
                }

                return;
            }
            _ => None,
        };

        if let Some((program, addr)) = target {
            self.open_code(program, addr);
        }
    }

    pub(crate) fn xrefs_current(&mut self) {
        if let Some((program, function)) = self.current_function() {
            self.xrefs_popup(program, function);
        }
    }

    pub(crate) fn call_graph_current(&mut self) {
        if let Some((program, function)) = self.current_function() {
            self.open_call_graph(program, Some(function), DEFAULT_CALL_GRAPH_DEPTH, false);
        }
    }

    /// Address under the cursor of a view
    pub(crate) fn view_addr(view: &View, projects: &mut [Option<execdump_project::Project>]) -> Option<(usize, u64)> {
        return match view {
            View::Source(source) => projects[source.program].as_mut().and_then(|p| source.cursor_addr(p)).map(|a| (source.program, a)),
            View::Disasm(disasm) => disasm.cursor_addr().map(|a| (disasm.program, a)),
            View::Graph(graph) if graph.selected_node().kind != NodeKind::Import => Some((graph.program, graph.selected_node().addr)),
            _ => None,
        };
    }

}
