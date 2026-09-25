/*
 * Terminal user interface
 *
 * The executable is parsed once, the Programs are built once and analyzed in a background thread.
 * Views (graphs, disassembly, tables, dumps) are stacked in a jumplist (Ctrl-o / Ctrl-i like in vim).
 */

mod graph_view;
mod theme;
mod views;

use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

use crate::analysis::function::{CallTarget, EdgeKind};
use crate::analysis::insn::Decoder;
use crate::analysis::{analyze, Analysis};
use crate::dump::Dump;
use crate::exec::Exec;
use crate::program::{programs_from_exec, Program};

use graph_view::{GraphKind, GraphView, NodeKind};
use theme::{KeyBindings, Theme};
use views::{insn_target, DisasmView, DumpView, HexView, TableRow, TableView, Target};

use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_CALL_GRAPH_DEPTH: usize = 2;
const HORIZONTAL_STEP: i32 = 10;
const VERTICAL_STEP: i32 = 5;

/*
 * Explorer
 */

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExplorerItem {
    Group(String),
    EntryPoint(usize),
    CallGraph(usize),
    Functions(usize),
    Strings(usize),
    Imports(usize),
    MemoryMap(usize),
    PEDosHeader,
    PENtHeader,
    PEOptionalHeader,
    PEImportTable,
    PEExportTable,
    PEExceptionTable,
    PEDebugDirectory,
    ELFHeader,
    ELFProgramHeaders,
    ELFSymbols,
    ELFDynamic,
    ELFRelocations,
    ELFImports,
    ELFNotes,
    MachOFatHeader,
    MachOHeader(usize),
    MachOLoadCommands(usize),
    MachOSymbols(usize),
    MachOImports(usize),
    /// Section of a program (program index, section name)
    Section(usize, String),
}

impl ExplorerItem {
    fn display_name(&self, app: &App) -> String {
        let suffix = |program: &usize| -> String {
            if app.programs.len() > 1 { format!(" ({})", app.programs[*program].name) } else { String::new() }
        };

        match self {
            ExplorerItem::Group(name) => format!("{}/", name),
            ExplorerItem::EntryPoint(p) => format!("  Entry point{}", suffix(p)),
            ExplorerItem::CallGraph(p) => format!("  Call graph{}", suffix(p)),
            ExplorerItem::Functions(p) => {
                let count = app.analyses[*p].as_ref().map_or(String::new(), |a| format!(" ({})", a.functions.len()));
                format!("  Functions{}{}", count, suffix(p))
            }
            ExplorerItem::Strings(p) => {
                let count = app.analyses[*p].as_ref().map_or(String::new(), |a| format!(" ({})", a.strings.len()));
                format!("  Strings{}{}", count, suffix(p))
            }
            ExplorerItem::Imports(p) => format!("  Imports{}", suffix(p)),
            ExplorerItem::MemoryMap(p) => format!("  Memory map{}", suffix(p)),
            ExplorerItem::PEDosHeader => "  DOS Header".to_string(),
            ExplorerItem::PENtHeader => "  NT Header".to_string(),
            ExplorerItem::PEOptionalHeader => "  Optional Header".to_string(),
            ExplorerItem::PEImportTable => "  Import Table".to_string(),
            ExplorerItem::PEExportTable => "  Export Table".to_string(),
            ExplorerItem::PEExceptionTable => "  Exception Table".to_string(),
            ExplorerItem::PEDebugDirectory => "  Debug Directory".to_string(),
            ExplorerItem::ELFHeader => "  Header".to_string(),
            ExplorerItem::ELFProgramHeaders => "  Program Headers".to_string(),
            ExplorerItem::ELFSymbols => "  Symbols".to_string(),
            ExplorerItem::ELFDynamic => "  Dynamic".to_string(),
            ExplorerItem::ELFRelocations => "  Relocations".to_string(),
            ExplorerItem::ELFImports => "  Imports".to_string(),
            ExplorerItem::ELFNotes => "  Notes".to_string(),
            ExplorerItem::MachOFatHeader => "  Fat Header".to_string(),
            ExplorerItem::MachOHeader(p) => format!("  Header{}", suffix(p)),
            ExplorerItem::MachOLoadCommands(p) => format!("  Load Commands{}", suffix(p)),
            ExplorerItem::MachOSymbols(p) => format!("  Symbols{}", suffix(p)),
            ExplorerItem::MachOImports(p) => format!("  Imports{}", suffix(p)),
            ExplorerItem::Section(p, name) => format!("  {}{}", name, suffix(p)),
        }
    }
}

fn explorer_items(exec: &Exec, programs: &[Arc<Program>]) -> Vec<ExplorerItem> {
    let mut items = vec![ExplorerItem::Group("Analysis".to_string())];

    for p in 0..programs.len() {
        items.push(ExplorerItem::EntryPoint(p));
        items.push(ExplorerItem::CallGraph(p));
        items.push(ExplorerItem::Functions(p));
        items.push(ExplorerItem::Strings(p));
        items.push(ExplorerItem::Imports(p));
        items.push(ExplorerItem::MemoryMap(p));
    }

    items.push(ExplorerItem::Group("Headers".to_string()));

    match exec {
        Exec::PE(_) => {
            items.push(ExplorerItem::PEDosHeader);
            items.push(ExplorerItem::PENtHeader);
            items.push(ExplorerItem::PEOptionalHeader);
        }
        Exec::ELF(_) => {
            items.push(ExplorerItem::ELFHeader);
            items.push(ExplorerItem::ELFProgramHeaders);
        }
        Exec::MachO(macho) => {
            if macho.fat_header.is_some() {
                items.push(ExplorerItem::MachOFatHeader);
            }

            for p in 0..macho.binaries.len() {
                items.push(ExplorerItem::MachOHeader(p));
                items.push(ExplorerItem::MachOLoadCommands(p));
            }
        }
    }

    items.push(ExplorerItem::Group("Sections".to_string()));

    match exec {
        Exec::PE(pe) => {
            let mut sections: Vec<&crate::pe::Section> = pe.sections.values().collect();
            sections.sort_by_key(|s| s.header.virtual_address);
            items.extend(sections.iter().map(|s| ExplorerItem::Section(0, s.header.name.clone())));
        }
        Exec::ELF(elf) => {
            let mut sections: Vec<&crate::elf::ELFSection> = elf.sections.values().filter(|s| !s.name.is_empty()).collect();
            sections.sort_by_key(|s| s.offset());
            items.extend(sections.iter().map(|s| ExplorerItem::Section(0, s.name.clone())));
        }
        Exec::MachO(macho) => {
            for (p, binary) in macho.binaries.iter().enumerate() {
                let mut sections: Vec<&crate::macho::MachOSection> = binary.sections.values().collect();
                sections.sort_by_key(|s| s.header.addr);
                items.extend(sections.iter().map(|s| ExplorerItem::Section(p, s.header.full_name())));
            }
        }
    }

    match exec {
        Exec::PE(_) => {
            items.push(ExplorerItem::Group("Data Directories".to_string()));
            items.push(ExplorerItem::PEImportTable);
            items.push(ExplorerItem::PEExportTable);
            items.push(ExplorerItem::PEExceptionTable);
            items.push(ExplorerItem::PEDebugDirectory);
        }
        Exec::ELF(_) => {
            items.push(ExplorerItem::Group("Tables".to_string()));
            items.push(ExplorerItem::ELFSymbols);
            items.push(ExplorerItem::ELFDynamic);
            items.push(ExplorerItem::ELFRelocations);
            items.push(ExplorerItem::ELFImports);
            items.push(ExplorerItem::ELFNotes);
        }
        Exec::MachO(macho) => {
            items.push(ExplorerItem::Group("Tables".to_string()));

            for p in 0..macho.binaries.len() {
                items.push(ExplorerItem::MachOSymbols(p));
                items.push(ExplorerItem::MachOImports(p));
            }
        }
    }

    return items;
}

/*
 * Application state
 */

#[derive(Clone, Debug)]
enum View {
    Welcome,
    Dump(DumpView),
    Hex(HexView),
    Disasm(DisasmView),
    Graph(GraphView),
    Table(TableView),
}

impl View {
    fn title(&self) -> String {
        match self {
            View::Welcome => "Welcome".to_string(),
            View::Dump(v) => v.title.clone(),
            View::Hex(v) => v.title.clone(),
            View::Disasm(v) => v.title.clone(),
            View::Graph(v) => v.title.clone(),
            View::Table(v) => if v.filter.is_empty() { v.title.clone() } else { format!("{} [/{}] ({} matches)", v.title, v.filter, v.filtered.len()) },
        }
    }

    fn program(&self) -> Option<usize> {
        match self {
            View::Disasm(v) => Some(v.program),
            View::Graph(v) => Some(v.program),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Explorer,
    Content,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputKind {
    Command,
    Search,
}

#[derive(Clone, Debug)]
struct Popup {
    title: String,
    items: Vec<(String, Target)>,
    cursor: usize,
}

struct App {
    exec: Exec,
    exec_path: PathBuf,
    theme: Theme,
    keys: KeyBindings,

    programs: Vec<Arc<Program>>,
    analyses: Vec<Option<Arc<Analysis>>>,
    analysis_errors: Vec<Option<String>>,
    progress: Vec<Arc<AtomicUsize>>,
    receiver: Receiver<(usize, Result<Analysis, String>)>,
    decoders: Vec<Option<Decoder>>,

    explorer_items: Vec<ExplorerItem>,
    explorer_state: ListState,
    explorer_visible: bool,
    focus: Focus,

    view: View,
    back: Vec<View>,
    forward: Vec<View>,

    input: Option<(InputKind, String)>,
    last_search: String,
    message: Option<(String, bool)>,
    popup: Option<Popup>,
    help: bool,
    should_quit: bool,
}

impl App {
    fn new(exec: Exec, exec_path: PathBuf) -> Self {
        let programs: Vec<Arc<Program>> = programs_from_exec(&exec).into_iter().map(Arc::new).collect();
        let (sender, receiver) = channel();
        let mut progress = Vec::new();

        for (i, program) in programs.iter().enumerate() {
            let counter = Arc::new(AtomicUsize::new(0));
            progress.push(counter.clone());

            let program = program.clone();
            let sender = sender.clone();

            std::thread::spawn(move || {
                let result = analyze(&program, Some(&counter)).map_err(|e| e.to_string());
                let _ = sender.send((i, result));
            });
        }

        let explorer_items = explorer_items(&exec, &programs);
        let mut explorer_state = ListState::default();
        explorer_state.select(Some(1));

        return App {
            decoders: programs.iter().map(|p| Decoder::new(p.architecture()).ok()).collect(),
            analyses: vec![None; programs.len()],
            analysis_errors: vec![None; programs.len()],
            programs,
            progress,
            receiver,
            exec,
            exec_path,
            theme: Theme::codedark(),
            keys: KeyBindings::load(),
            explorer_items,
            explorer_state,
            explorer_visible: true,
            focus: Focus::Explorer,
            view: View::Welcome,
            back: Vec::new(),
            forward: Vec::new(),
            input: None,
            last_search: String::new(),
            message: None,
            popup: None,
            help: false,
            should_quit: false,
        };
    }

    fn poll_analysis(&mut self) {
        while let Ok((index, result)) = self.receiver.try_recv() {
            match result {
                Ok(analysis) => {
                    self.analyses[index] = Some(Arc::new(analysis));

                    // Refresh the region disassembly so it gets the function labels and annotations
                    if let View::Disasm(view) = &self.view {
                        if view.program == index && view.region.is_some() {
                            let (region, addr) = (view.region.clone().unwrap(), view.cursor_addr());

                            if let Some(mut refreshed) = self.region_disasm(index, &region) {
                                if let Some(addr) = addr {
                                    refreshed.goto(addr);
                                }

                                self.view = View::Disasm(refreshed);
                            }
                        }
                    }
                }
                Err(error) => self.analysis_errors[index] = Some(error),
            }
        }
    }

    fn analysis(&mut self, program: usize) -> Option<Arc<Analysis>> {
        if let Some(analysis) = &self.analyses[program] {
            return Some(analysis.clone());
        }

        if let Some(error) = &self.analysis_errors[program] {
            self.error(format!("Analysis failed: {}", error));
        } else {
            self.error(format!("Analysis in progress ({} functions so far), try again in a moment", self.progress[program].load(Ordering::Relaxed)));
        }

        return None;
    }

    fn current_program(&self) -> usize {
        return self.view.program().unwrap_or(0);
    }

    fn info(&mut self, message: String) {
        self.message = Some((message, false));
    }

    fn error(&mut self, message: String) {
        self.message = Some((message, true));
    }

    /*
     * Jumplist
     */

    fn open(&mut self, view: View) {
        let previous = std::mem::replace(&mut self.view, view);

        if !matches!(previous, View::Welcome) {
            self.back.push(previous);
        }

        self.forward.clear();
        self.focus = Focus::Content;
    }

    fn go_back(&mut self) {
        if let Some(view) = self.back.pop() {
            let current = std::mem::replace(&mut self.view, view);
            self.forward.push(current);
        } else {
            self.info("Already at the oldest view".to_string());
        }
    }

    fn go_forward(&mut self) {
        if let Some(view) = self.forward.pop() {
            let current = std::mem::replace(&mut self.view, view);
            self.back.push(current);
        } else {
            self.info("Already at the newest view".to_string());
        }
    }

    /*
     * View builders
     */

    fn cfg_view(&mut self, program: usize, addr: u64) -> Option<GraphView> {
        let analysis = self.analysis(program)?;
        let decoder = self.decoders[program].as_ref()?;

        return GraphView::cfg(program, &self.programs[program], &analysis, decoder, &self.theme, addr);
    }

    fn open_function(&mut self, program: usize, addr: u64, select: Option<u64>) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let Some(function) = analysis.function_containing(addr) else {
            self.error(format!("No function at {:#x}", addr));
            return;
        };

        if let Some(mut view) = self.cfg_view(program, function.addr) {
            if let Some(select) = select.or(if addr != function.addr { Some(addr) } else { None }) {
                view.select_addr(select);
            }

            self.open(View::Graph(view));
        }
    }

    fn open_call_graph(&mut self, program: usize, root: Option<u64>, depth: usize, imports: bool) {
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

    fn region_disasm(&self, program: usize, region: &str) -> Option<DisasmView> {
        let decoder = self.decoders[program].as_ref()?;
        return DisasmView::region(program, &self.programs[program], self.analyses[program].as_deref(), decoder, region);
    }

    /// Opens the most relevant view for an address: function graph, code or data
    fn goto_address(&mut self, program: usize, addr: u64) {
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

    fn open_target(&mut self, target: Target) {
        match target {
            Target::Function(program, addr) => self.open_function(program, addr, None),
            Target::Address(program, addr) => self.goto_address(program, addr),
        }
    }

    fn functions_table(&mut self, program: usize) -> Option<TableView> {
        let analysis = self.analysis(program)?;

        let rows = analysis.functions.values().map(|f| {
            let mut flags = Vec::new();

            if f.thunk.is_some() {
                flags.push("thunk");
            }

            if f.noreturn {
                flags.push("noreturn");
            }

            if f.unresolved_jumps > 0 {
                flags.push("indirect");
            }

            TableRow {
                cells: vec![
                    format!("{:#x}", f.addr),
                    format!("{}", f.size()),
                    format!("{}", f.blocks.len()),
                    format!("{}", analysis.callers.get(&f.addr).map_or(0, |c| c.len())),
                    f.source.name().to_string(),
                    flags.join(","),
                    f.name.clone(),
                ],
                target: Target::Function(program, f.addr),
                style: if f.thunk.is_some() { Some(Style::default().fg(self.theme.dim)) } else { None },
            }
        }).collect();

        return Some(TableView::new(
            format!("Functions ({})", analysis.functions.len()),
            vec!["Address", "Size", "Blocks", "Xrefs", "Source", "Flags", "Name"],
            rows,
        ));
    }

    fn strings_table(&mut self, program: usize) -> Option<TableView> {
        let analysis = self.analysis(program)?;
        let program_ref = self.programs[program].clone();

        // Code referencing each string
        let mut xrefs: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

        for function in analysis.functions.values() {
            for &(_, target) in function.refs.iter() {
                if analysis.strings.contains_key(&target) {
                    *xrefs.entry(target).or_default() += 1;
                }
            }
        }

        let rows = analysis.strings.iter().map(|(&addr, string)| TableRow {
            cells: vec![
                format!("{:#x}", addr),
                program_ref.region_at(addr).map_or(String::new(), |r| r.name.clone()),
                format!("{}", xrefs.get(&addr).copied().unwrap_or(0)),
                crate::analysis::strings::escape(string, 200),
            ],
            target: Target::Address(program, addr),
            style: None,
        }).collect();

        return Some(TableView::new(format!("Strings ({})", analysis.strings.len()), vec!["Address", "Section", "Xrefs", "String"], rows));
    }

    fn imports_table(&mut self, program: usize) -> TableView {
        let program_ref = self.programs[program].clone();
        let analysis = self.analyses[program].clone();

        let mut rows: Vec<TableRow> = Vec::new();

        // Thunks (PLT entries, stubs) first: they are what the code calls
        if let Some(analysis) = &analysis {
            for function in analysis.functions.values().filter(|f| f.thunk.is_some()) {
                rows.push(TableRow {
                    cells: vec![format!("{:#x}", function.addr), "thunk".to_string(), function.name.clone()],
                    target: Target::Function(program, function.addr),
                    style: None,
                });
            }
        }

        let mut slots: Vec<(&u64, &String)> = program_ref.import_slots.iter().collect();
        slots.sort();

        for (&addr, name) in slots {
            rows.push(TableRow {
                cells: vec![format!("{:#x}", addr), "pointer".to_string(), crate::demangle::demangle(name).unwrap_or(name.clone())],
                target: Target::Address(program, addr),
                style: Some(Style::default().fg(self.theme.dim)),
            });
        }

        return TableView::new(format!("Imports ({})", rows.len()), vec!["Address", "Kind", "Name"], rows);
    }

    fn memory_map(&self, program: usize) -> TableView {
        let program_ref = &self.programs[program];

        let rows = program_ref.regions.iter().map(|r| {
            let color = if r.perms.exec { self.theme.perm_exec } else if r.perms.write { self.theme.perm_write } else { self.theme.perm_read };

            TableRow {
                cells: vec![
                    format!("{:#x}", r.vaddr),
                    format!("{:#x}", r.end()),
                    format!("{:#x}", r.size),
                    r.perms.as_string(),
                    if r.data.is_empty() { "bss".to_string() } else { String::new() },
                    r.name.clone(),
                ],
                target: Target::Address(program, r.vaddr),
                style: Some(Style::default().fg(color)),
            }
        }).collect();

        let mut table = TableView::new(format!("Memory map ({})", program_ref.name), vec!["Start", "End", "Size", "Perms", "Kind", "Name"], rows);

        // Proportional bar of the address space: one character per region slice, colored by permissions
        let (start, end) = (
            program_ref.regions.iter().map(|r| r.vaddr).min().unwrap_or(0),
            program_ref.regions.iter().map(|r| r.end()).max().unwrap_or(0),
        );

        if end > start {
            const BAR_WIDTH: u64 = 64;
            let mut spans = Vec::new();

            for i in 0..BAR_WIDTH {
                let addr = start + (end - start) * i / BAR_WIDTH;
                let region = program_ref.region_at(addr);

                let (ch, color) = match region {
                    Some(r) if r.perms.exec => ('█', self.theme.perm_exec),
                    Some(r) if r.perms.write => ('█', self.theme.perm_write),
                    Some(_) => ('█', self.theme.perm_read),
                    None => ('░', self.theme.dim),
                };

                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }

            spans.push(Span::styled(format!("  {:#x} - {:#x}   ", start, end), Style::default().fg(self.theme.dim)));
            spans.push(Span::styled("■ x ", Style::default().fg(self.theme.perm_exec)));
            spans.push(Span::styled("■ w ", Style::default().fg(self.theme.perm_write)));
            spans.push(Span::styled("■ r", Style::default().fg(self.theme.perm_read)));

            table.banner = Some(Line::from(spans));
        }

        return table;
    }

    fn section_view(&mut self, program: usize, name: &str) -> Option<View> {
        let program_ref = self.programs[program].clone();

        if let Some(region) = program_ref.regions.iter().find(|r| r.name == name) {
            if region.perms.exec && !region.data.is_empty() {
                return self.region_disasm(program, name).map(View::Disasm);
            }

            return Some(View::Hex(HexView::new(format!("{} ({:#x})", region.name, region.vaddr), region.vaddr, region.data.clone())));
        }

        // Sections not loaded in memory (symbol tables, debug information...), shown from the file
        let data = match &self.exec {
            Exec::ELF(elf) => elf.sections.get(name).map(|s| (s.header.virtual_address(), s.data.clone())),
            Exec::PE(pe) => pe.sections.get(name).map(|s| (s.header.virtual_address as u64, s.data.clone())),
            Exec::MachO(macho) => macho.binaries.get(program).and_then(|b| b.sections.get(name)).map(|s| (s.header.addr, s.data.clone())),
        };

        return data.map(|(base, data)| View::Hex(HexView::new(name.to_string(), base, data)));
    }

    fn dump_view(&self, dump: Dump) -> View {
        return View::Dump(DumpView::new(&self.theme, &dump));
    }

    fn activate_explorer_item(&mut self) {
        let Some(item) = self.explorer_state.selected().and_then(|i| self.explorer_items.get(i)).cloned() else {
            return;
        };

        let view = match &item {
            ExplorerItem::Group(_) => return,
            ExplorerItem::EntryPoint(p) => {
                match self.programs[*p].entry {
                    Some(entry) => self.open_function(*p, entry, None),
                    None => self.error("No entry point".to_string()),
                }

                return;
            }
            ExplorerItem::CallGraph(p) => {
                self.open_call_graph(*p, None, DEFAULT_CALL_GRAPH_DEPTH, false);
                return;
            }
            ExplorerItem::Functions(p) => self.functions_table(*p).map(View::Table),
            ExplorerItem::Strings(p) => self.strings_table(*p).map(View::Table),
            ExplorerItem::Imports(p) => Some(View::Table(self.imports_table(*p))),
            ExplorerItem::MemoryMap(p) => Some(View::Table(self.memory_map(*p))),
            ExplorerItem::Section(p, name) => self.section_view(*p, name),
            _ => {
                let dump = match (&self.exec, &item) {
                    (Exec::PE(pe), ExplorerItem::PEDosHeader) => pe.get_dos_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PENtHeader) => pe.get_nt_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PEOptionalHeader) => pe.get_optional_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PEImportTable) => pe.hint_name_table.as_ref().map_or(Dump::new("No import table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEExportTable) => pe.export_data.as_ref().map_or(Dump::new("No export table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEExceptionTable) => pe.exception_table.as_ref().map_or(Dump::new("No exception table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEDebugDirectory) => pe.debug_directory.as_ref().map_or(Dump::new("No debug directory found"), |t| t.dump()),
                    (Exec::ELF(elf), ExplorerItem::ELFHeader) => elf.get_elf_header().dump(),
                    (Exec::ELF(elf), ExplorerItem::ELFProgramHeaders) => elf.dump_program_headers(),
                    (Exec::ELF(elf), ExplorerItem::ELFSymbols) => {
                        let mut dump = Dump::new("Symbols");
                        elf.symbol_tables.iter().for_each(|t| dump.push_child(t.dump()));
                        dump
                    }
                    (Exec::ELF(elf), ExplorerItem::ELFDynamic) => elf.dynamic.as_ref().map_or(Dump::new("No dynamic section found"), |d| d.dump()),
                    (Exec::ELF(elf), ExplorerItem::ELFRelocations) => {
                        let mut dump = Dump::new("Relocations");
                        elf.relocation_tables.iter().for_each(|t| dump.push_child(t.dump()));
                        dump
                    }
                    (Exec::ELF(elf), ExplorerItem::ELFImports) => elf.dump_imports(),
                    (Exec::ELF(elf), ExplorerItem::ELFNotes) => elf.dump_notes(),
                    (Exec::MachO(macho), ExplorerItem::MachOFatHeader) => macho.fat_header.as_ref().map_or(Dump::new("No fat header found"), |h| h.dump()),
                    (Exec::MachO(macho), ExplorerItem::MachOHeader(p)) => macho.binaries[*p].header.dump(),
                    (Exec::MachO(macho), ExplorerItem::MachOLoadCommands(p)) => macho.binaries[*p].dump_load_commands(),
                    (Exec::MachO(macho), ExplorerItem::MachOSymbols(p)) => macho.binaries[*p].dump_symbols(),
                    (Exec::MachO(macho), ExplorerItem::MachOImports(p)) => macho.binaries[*p].dump_dylibs(),
                    _ => return,
                };

                Some(self.dump_view(dump))
            }
        };

        if let Some(view) = view {
            self.open(view);
        }
    }

    /*
     * Popups (call targets, cross references)
     */

    fn calls_popup(&mut self, program: usize, block_addr: u64, function_addr: u64) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let Some(function) = analysis.functions.get(&function_addr) else {
            return;
        };

        let Some(block) = function.blocks.get(&block_addr) else {
            return;
        };

        let mut items = Vec::new();

        for call in function.calls.iter().filter(|c| c.addr >= block.start && c.addr < block.end) {
            if let CallTarget::Function(target) = call.target {
                let label = format!("{:#x}  {}{}", call.addr, analysis.call_target_name(&call.target), if call.tail { " (tail)" } else { "" });
                items.push((label, Target::Function(program, target)));
            }
        }

        // Code references (callbacks, function pointers)
        for insn in block.insns.iter() {
            for r in [insn.imm_ref, insn.mem_ref].into_iter().flatten() {
                if let Some(target) = analysis.functions.get(&r) {
                    if !items.iter().any(|(_, t)| *t == Target::Function(program, r)) {
                        items.push((format!("{:#x}  &{}", insn.addr, target.name), Target::Function(program, r)));
                    }
                }
            }
        }

        self.show_popup("Go to".to_string(), items);
    }

    fn xrefs_popup(&mut self, program: usize, function_addr: u64) {
        let Some(analysis) = self.analysis(program) else {
            return;
        };

        let name = analysis.functions.get(&function_addr).map_or(String::new(), |f| f.name.clone());
        let mut items = Vec::new();

        for (&caller_addr, caller) in analysis.functions.iter() {
            for call in caller.calls.iter().filter(|c| c.target == CallTarget::Function(function_addr)) {
                items.push((format!("{:#x}  {} ({})", call.addr, caller.name, if call.tail { "jump" } else { "call" }), Target::Address(program, call.addr)));
            }

            for &(insn, target) in caller.refs.iter() {
                if target == function_addr && caller_addr != function_addr {
                    items.push((format!("{:#x}  {} (reference)", insn, caller.name), Target::Address(program, insn)));
                }
            }
        }

        self.show_popup(format!("Cross references to {}", name), items);
    }

    fn show_popup(&mut self, title: String, items: Vec<(String, Target)>) {
        match items.len() {
            0 => self.info(format!("{}: nothing found", title)),
            1 => self.open_target(items[0].1.clone()),
            _ => self.popup = Some(Popup { title, items, cursor: 0 }),
        }
    }

    /*
     * Commands
     */

    fn run_command(&mut self, command: &str) {
        let command = command.trim();
        let mut parts = command.split_whitespace();
        let name = parts.next().unwrap_or("");
        let argument = parts.next();
        let program = self.current_program();

        match name {
            "" => {}
            "q" | "quit" | "q!" => self.should_quit = true,
            "cg" | "callgraph" => {
                let root = argument.and_then(|a| self.resolve_address(program, a));
                self.open_call_graph(program, root, DEFAULT_CALL_GRAPH_DEPTH, false);
            }
            "functions" | "fn" => {
                if let Some(table) = self.functions_table(program) {
                    self.open(View::Table(table));
                }
            }
            "strings" => {
                if let Some(table) = self.strings_table(program) {
                    self.open(View::Table(table));
                }
            }
            "imports" => {
                let table = self.imports_table(program);
                self.open(View::Table(table));
            }
            "sections" | "memmap" | "maps" => {
                let table = self.memory_map(program);
                self.open(View::Table(table));
            }
            "entry" => {
                if let Some(entry) = self.programs[program].entry {
                    self.open_function(program, entry, None);
                }
            }
            "depth" => {
                let depth = argument.and_then(|a| a.parse::<usize>().ok());

                match (&self.view, depth) {
                    (View::Graph(view), Some(depth)) => {
                        if let GraphKind::CallGraph { root, imports, .. } = view.kind {
                            self.open_call_graph(view.program, Some(root), depth, imports);
                        }
                    }
                    _ => self.error("Usage in a call graph: depth <n>".to_string()),
                }
            }
            "help" | "h" => self.help = true,
            _ => match self.resolve_address(program, command) {
                Some(addr) => self.goto_address(program, addr),
                None => self.error(format!("Unknown command, address or function: {}", command)),
            },
        }
    }

    /// Resolves an address, a function name or a symbol
    fn resolve_address(&self, program: usize, text: &str) -> Option<u64> {
        let hex = text.trim_start_matches("0x").trim_start_matches("0X");

        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) && (text.starts_with("0x") || hex.len() >= 4) {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return Some(addr);
            }
        }

        if let Some(analysis) = &self.analyses[program] {
            if let Some(function) = analysis.function_by_name(text) {
                return Some(function.addr);
            }
        }

        return self.programs[program].symbols.values().find(|s| s.name == text || s.demangled == text).map(|s| s.addr);
    }

    fn run_search(&mut self, pattern: &str) {
        let pattern = if pattern.is_empty() { self.last_search.clone() } else { pattern.to_string() };
        self.last_search = pattern.clone();

        let found = match &mut self.view {
            View::Table(view) => {
                view.set_filter(&pattern);
                true
            }
            View::Graph(view) => view.search(&pattern),
            View::Disasm(view) => view.search(&pattern),
            View::Dump(view) => view.search(&pattern),
            _ => false,
        };

        if !found {
            self.error(format!("Pattern not found: {}", pattern));
        }
    }

    /*
     * Keys
     */

    fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        if let Some((kind, mut text)) = self.input.take() {
            match key.code {
                KeyCode::Esc => {
                    if kind == InputKind::Search {
                        if let View::Table(view) = &mut self.view {
                            view.set_filter("");
                        }
                    }
                }
                KeyCode::Enter => match kind {
                    InputKind::Command => self.run_command(&text),
                    InputKind::Search => self.run_search(&text),
                },
                KeyCode::Backspace => {
                    if text.pop().is_some() {
                        self.input = Some((kind, text.clone()));
                    }

                    if kind == InputKind::Search {
                        if let View::Table(view) = &mut self.view {
                            view.set_filter(&text);
                        }
                    }
                }
                KeyCode::Char(c) => {
                    text.push(c);

                    // Tables are filtered while typing
                    if kind == InputKind::Search {
                        if let View::Table(view) = &mut self.view {
                            view.set_filter(&text);
                        }
                    }

                    self.input = Some((kind, text));
                }
                _ => self.input = Some((kind, text)),
            }

            return;
        }

        if let Some(mut popup) = self.popup.take() {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {}
                KeyCode::Char('j') | KeyCode::Down => {
                    popup.cursor = (popup.cursor + 1).min(popup.items.len() - 1);
                    self.popup = Some(popup);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    popup.cursor = popup.cursor.saturating_sub(1);
                    self.popup = Some(popup);
                }
                KeyCode::Char('g') => {
                    popup.cursor = 0;
                    self.popup = Some(popup);
                }
                KeyCode::Char('G') => {
                    popup.cursor = popup.items.len() - 1;
                    self.popup = Some(popup);
                }
                KeyCode::Enter | KeyCode::Char('l') => self.open_target(popup.items[popup.cursor].1.clone()),
                _ => self.popup = Some(popup),
            }

            return;
        }

        if self.help {
            self.help = false;
            return;
        }

        self.message = None;

        match key.code {
            KeyCode::Char(c) if c == self.keys.quit && !ctrl => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('c') if ctrl => {
                self.should_quit = true;
                return;
            }
            KeyCode::Tab => {
                self.focus = if self.focus == Focus::Explorer { Focus::Content } else { Focus::Explorer };

                if self.focus == Focus::Explorer {
                    self.explorer_visible = true;
                }

                return;
            }
            KeyCode::Char(':') => {
                self.input = Some((InputKind::Command, String::new()));
                return;
            }
            KeyCode::Char('/') => {
                self.input = Some((InputKind::Search, String::new()));
                return;
            }
            KeyCode::Char('?') => {
                self.help = true;
                return;
            }
            KeyCode::Char('o') if ctrl => {
                self.go_back();
                return;
            }
            KeyCode::Char('i') if ctrl => {
                self.go_forward();
                return;
            }
            KeyCode::Char('r') if ctrl => {
                self.go_forward();
                return;
            }
            KeyCode::Backspace => {
                self.go_back();
                return;
            }
            KeyCode::Char(c) if c == self.keys.toggle_explorer && !ctrl => {
                self.explorer_visible = !self.explorer_visible;

                if !self.explorer_visible {
                    self.focus = Focus::Content;
                }

                return;
            }
            _ => {}
        }

        match self.focus {
            Focus::Explorer => self.handle_explorer_key(key),
            Focus::Content => self.handle_content_key(key),
        }
    }

    fn handle_explorer_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let count = self.explorer_items.len();
        let selected = self.explorer_state.selected().unwrap_or(0);

        let select = |state: &mut ListState, index: usize| state.select(Some(index.min(count.saturating_sub(1))));

        match key.code {
            KeyCode::Char(c) if c == self.keys.down && !ctrl => select(&mut self.explorer_state, selected + 1),
            KeyCode::Down => select(&mut self.explorer_state, selected + 1),
            KeyCode::Char(c) if c == self.keys.up && !ctrl => select(&mut self.explorer_state, selected.saturating_sub(1)),
            KeyCode::Up => select(&mut self.explorer_state, selected.saturating_sub(1)),
            KeyCode::Char(c) if c == self.keys.page_down => select(&mut self.explorer_state, selected + 10),
            KeyCode::Char(c) if c == self.keys.page_up => select(&mut self.explorer_state, selected.saturating_sub(10)),
            KeyCode::Char(c) if c == self.keys.start => select(&mut self.explorer_state, 0),
            KeyCode::Char(c) if c == self.keys.end => select(&mut self.explorer_state, count),
            KeyCode::Enter => self.activate_explorer_item(),
            KeyCode::Char(c) if c == self.keys.right => self.activate_explorer_item(),
            _ => {}
        }
    }

    fn handle_content_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let keys = self.keys.clone();

        let code = match key.code {
            KeyCode::Down => KeyCode::Char(keys.down),
            KeyCode::Up => KeyCode::Char(keys.up),
            KeyCode::Left => KeyCode::Char(keys.left),
            KeyCode::Right => KeyCode::Char(keys.right),
            KeyCode::PageDown => {
                return self.handle_content_key(KeyEvent::new(KeyCode::Char(keys.page_down), KeyModifiers::CONTROL));
            }
            KeyCode::PageUp => {
                return self.handle_content_key(KeyEvent::new(KeyCode::Char(keys.page_up), KeyModifiers::CONTROL));
            }
            KeyCode::Home => KeyCode::Char(keys.start),
            KeyCode::End => KeyCode::Char(keys.end),
            code => code,
        };

        let KeyCode::Char(c) = code else {
            if code == KeyCode::Enter {
                self.content_enter();
            } else if code == KeyCode::Esc {
                if let View::Table(view) = &mut self.view {
                    view.set_filter("");
                }
            }

            return;
        };

        // Half page moves: Ctrl-d / Ctrl-u, or the plain keys (as in the previous versions)
        let half_page_down = c == keys.page_down;
        let half_page_up = c == keys.page_up;

        match &mut self.view {
            View::Graph(view) => {
                let page = view.page_height();

                match c {
                    _ if half_page_down => view.scroll(0, page),
                    _ if half_page_up => view.scroll(0, -page),
                    _ if ctrl => {}
                    _ if c == keys.left => view.scroll(-1, 0),
                    _ if c == keys.down => view.scroll(0, 1),
                    _ if c == keys.up => view.scroll(0, -1),
                    _ if c == keys.right => view.scroll(1, 0),
                    _ if c == keys.left.to_ascii_uppercase() => view.scroll(-HORIZONTAL_STEP, 0),
                    _ if c == keys.down.to_ascii_uppercase() => view.scroll(0, VERTICAL_STEP),
                    _ if c == keys.up.to_ascii_uppercase() => view.scroll(0, -VERTICAL_STEP),
                    _ if c == keys.right.to_ascii_uppercase() => view.scroll(HORIZONTAL_STEP, 0),
                    _ if c == keys.next_node => view.select_next(),
                    _ if c == keys.prev_node => view.select_previous(),
                    _ if c == keys.start => view.select_first(),
                    _ if c == keys.end => view.select_last(),
                    _ if c == keys.center => view.center(),
                    _ if c == keys.follow_true => {
                        if !view.follow(EdgeKind::True) && !view.follow_single() {
                            self.message = Some(("No true branch from this node".to_string(), false));
                        }
                    }
                    _ if c == keys.follow_false => {
                        if !view.follow(EdgeKind::False) && !view.follow_single() {
                            self.message = Some(("No false branch from this node".to_string(), false));
                        }
                    }
                    _ if c == keys.toggle_view => self.toggle_graph_linear(),
                    _ if c == keys.xrefs => self.xrefs_current(),
                    _ if c == keys.call_graph => self.call_graph_current(),
                    '+' | '=' | '-' | 'i' | 'r' => self.call_graph_option(c),
                    _ => {}
                }
            }
            View::Disasm(view) => {
                let page = (view.height / 2).max(1) as isize;

                match c {
                    _ if half_page_down => view.move_cursor(page),
                    _ if half_page_up => view.move_cursor(-page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.move_cursor(1),
                    _ if c == keys.up => view.move_cursor(-1),
                    _ if c == keys.down.to_ascii_uppercase() => view.move_cursor(VERTICAL_STEP as isize),
                    _ if c == keys.up.to_ascii_uppercase() => view.move_cursor(-VERTICAL_STEP as isize),
                    _ if c == keys.start => view.move_cursor(isize::MIN / 2),
                    _ if c == keys.end => view.move_cursor(isize::MAX / 2),
                    _ if c == keys.next_node => view.jump_label(true),
                    _ if c == keys.prev_node => view.jump_label(false),
                    _ if c == keys.right => self.content_enter(),
                    _ if c == keys.toggle_view => self.toggle_graph_linear(),
                    _ if c == keys.xrefs => self.xrefs_current(),
                    _ if c == keys.call_graph => self.call_graph_current(),
                    _ => {}
                }
            }
            View::Table(view) => {
                let page = (view.height / 2).max(1) as isize;

                match c {
                    _ if half_page_down => view.move_cursor(page),
                    _ if half_page_up => view.move_cursor(-page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.move_cursor(1),
                    _ if c == keys.up => view.move_cursor(-1),
                    _ if c == keys.start => view.move_cursor(isize::MIN / 2),
                    _ if c == keys.end => view.move_cursor(isize::MAX / 2),
                    _ if c == keys.right => self.content_enter(),
                    _ => {}
                }
            }
            View::Hex(view) => {
                let page = (view.height / 2).max(1);

                match c {
                    _ if half_page_down => view.scroll = (view.scroll + page).min(view.max_scroll()),
                    _ if half_page_up => view.scroll = view.scroll.saturating_sub(page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.scroll = (view.scroll + 1).min(view.max_scroll()),
                    _ if c == keys.up => view.scroll = view.scroll.saturating_sub(1),
                    _ if c == keys.start => view.scroll = 0,
                    _ if c == keys.end => view.scroll = view.max_scroll(),
                    _ => {}
                }
            }
            View::Dump(view) => {
                let page = (view.height / 2).max(1);

                match c {
                    _ if half_page_down => view.scroll = (view.scroll + page).min(view.max_scroll()),
                    _ if half_page_up => view.scroll = view.scroll.saturating_sub(page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.scroll = (view.scroll + 1).min(view.max_scroll()),
                    _ if c == keys.up => view.scroll = view.scroll.saturating_sub(1),
                    _ if c == keys.start => view.scroll = 0,
                    _ if c == keys.end => view.scroll = view.max_scroll(),
                    _ => {}
                }
            }
            View::Welcome => {
                if c == keys.left {
                    self.focus = Focus::Explorer;
                }
            }
        }
    }

    /// Function shown by the current view (graph or linear disassembly)
    fn current_function(&self) -> Option<(usize, u64)> {
        match &self.view {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { function } => Some((view.program, function)),
                GraphKind::CallGraph { .. } => {
                    let node = view.selected_node();
                    if node.kind == NodeKind::Function { Some((view.program, node.addr)) } else { None }
                }
            },
            View::Disasm(view) => {
                let addr = view.cursor_addr()?;
                let analysis = self.analyses[view.program].as_ref()?;
                analysis.function_containing(addr).map(|f| (view.program, f.addr))
            }
            _ => None,
        }
    }

    fn xrefs_current(&mut self) {
        if let Some((program, function)) = self.current_function() {
            self.xrefs_popup(program, function);
        }
    }

    fn call_graph_current(&mut self) {
        if let Some((program, function)) = self.current_function() {
            self.open_call_graph(program, Some(function), DEFAULT_CALL_GRAPH_DEPTH, false);
        }
    }

    fn call_graph_option(&mut self, c: char) {
        let View::Graph(view) = &self.view else {
            return;
        };

        let GraphKind::CallGraph { root, depth, imports } = view.kind else {
            return;
        };

        let program = view.program;
        let selected = view.selected_node().clone();

        let (root, depth, imports) = match c {
            '+' | '=' => (root, depth + 1, imports),
            '-' => (root, depth.saturating_sub(1).max(1), imports),
            'i' => (root, depth, !imports),
            'r' if selected.kind == NodeKind::Function => (selected.addr, depth, imports),
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

            // Changing options replaces the view, re-rooting pushes a new one
            if c == 'r' {
                self.open(View::Graph(new_view));
            } else {
                self.view = View::Graph(new_view);
            }
        }
    }

    fn toggle_graph_linear(&mut self) {
        match &self.view {
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
                    self.view = View::Disasm(linear);
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
                        self.view = View::Graph(graph);
                    } else {
                        self.open(View::Graph(graph));
                    }
                }
            }
            _ => {}
        }
    }

    fn content_enter(&mut self) {
        match &self.view {
            View::Table(view) => {
                if let Some(row) = view.selected() {
                    let target = row.target.clone();
                    self.open_target(target);
                }
            }
            View::Graph(view) => {
                let program = view.program;
                let node = view.selected_node().clone();

                match view.kind {
                    GraphKind::Cfg { function } => self.calls_popup(program, node.addr, function),
                    GraphKind::CallGraph { .. } => {
                        if node.kind == NodeKind::Function {
                            self.open_function(program, node.addr, None);
                        } else {
                            self.info(format!("{} is imported, its code is not in this binary", node.title));
                        }
                    }
                }
            }
            View::Disasm(view) => {
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
                    if let View::Disasm(view) = &mut self.view {
                        view.goto(target);
                    }
                } else if analysis.functions.contains_key(&target) {
                    self.open_function(program, target, None);
                } else {
                    self.goto_address(program, target);
                }
            }
            _ => {}
        }
    }

    /*
     * Rendering
     */

    fn status_text(&self) -> String {
        let total = self.programs.len();
        let done = self.analyses.iter().filter(|a| a.is_some()).count();

        if done == total {
            let functions: usize = self.analyses.iter().flatten().map(|a| a.functions.len()).sum();
            return format!("{} functions", functions);
        }

        let found: usize = self.progress.iter().map(|p| p.load(Ordering::Relaxed)).sum();
        let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let frame = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis()) / 100) as usize % spinner.len();

        return format!("{} analyzing... {} functions", spinner[frame], found);
    }

    fn hints(&self) -> &'static str {
        if self.focus == Focus::Explorer {
            return "j/k move  Enter open  Tab content  e hide  : command  ? help  q quit";
        }

        match &self.view {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { .. } => "hjkl scroll  n/p node  g/G first/last  t/f branch  Enter calls  Space linear  x xrefs  C callgraph  ^o back  ? help",
                GraphKind::CallGraph { .. } => "hjkl scroll  n/p node  Enter open  +/- depth  i imports  r re-root  x xrefs  ^o back  ? help",
            },
            View::Disasm(_) => "j/k move  n/p function  Enter follow  Space graph  x xrefs  / search  ^o back  ? help",
            View::Table(_) => "j/k move  Enter open  / filter  Esc clear  ^o back  ? help",
            _ => "j/k scroll  ^d/^u page  g/G top/bottom  / search  ^o back  ? help",
        }
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));

    return Rect::new(area.x + (area.width - width) / 2, area.y + (area.height - height) / 2, width, height);
}

const HELP: &[(&str, &str)] = &[
    ("Global", ""),
    ("Tab", "switch between the explorer and the content"),
    ("e", "show/hide the explorer"),
    (":", "command line (address, function name, callgraph, functions, strings, imports, sections, entry, depth <n>, q)"),
    ("/", "search (filters tables, finds nodes/lines)"),
    ("Ctrl-o / Backspace", "go back to the previous view"),
    ("Ctrl-i / Ctrl-r", "go forward"),
    ("q", "quit"),
    ("Graph", ""),
    ("h j k l", "scroll by one cell (H J K L by more)"),
    ("Ctrl-d / Ctrl-u", "scroll by half a page"),
    ("n / p", "next / previous node"),
    ("g / G", "first / last node"),
    ("t / f", "follow the true / false branch"),
    ("c", "center on the selected node"),
    ("Enter", "go to a called function (graph) / open the function (call graph)"),
    ("Space", "switch between graph and linear disassembly"),
    ("x", "cross references to the function"),
    ("C", "call graph from the function"),
    ("+ / - / i / r", "call graph depth / imports / re-root at the selection"),
    ("Linear disassembly", ""),
    ("j / k", "move the cursor"),
    ("n / p", "next / previous function or block"),
    ("Enter / l", "follow the jump, call or reference"),
];

fn ui(f: &mut Frame, app: &mut App) {
    let theme = app.theme.clone();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0), Constraint::Length(1)])
        .split(f.area());

    // Title bar
    let program_names: Vec<String> = app.programs.iter().map(|p| p.name.clone()).collect();

    let title = Line::from(vec![
        Span::styled(" execdump ", Style::default().fg(theme.bg).bg(theme.title).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", app.exec_path.display()), Style::default().fg(theme.fg)),
        Span::styled(format!(" {} ", program_names.join(", ")), Style::default().fg(theme.dim)),
        Span::styled(format!(" {}", app.status_text()), Style::default().fg(theme.comment)),
    ]);

    f.render_widget(Paragraph::new(title).style(theme.base()), chunks[0]);

    // Main area
    let content_area = if app.explorer_visible {
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(32.min(chunks[1].width / 3)), Constraint::Min(0)])
            .split(chunks[1]);

        let names: Vec<String> = app.explorer_items.iter().map(|item| item.display_name(app)).collect();

        let items: Vec<ListItem> = app.explorer_items.iter().zip(names).map(|(item, name)| {
            let style = if matches!(item, ExplorerItem::Group(_)) { theme.title_style() } else { Style::default().fg(theme.fg) };
            ListItem::new(name).style(style)
        }).collect();

        let active = app.focus == Focus::Explorer;

        let explorer = List::new(items)
            .block(
                Block::default()
                    .title(" Explorer ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if active { theme.highlight_bg } else { theme.border }))
                    .style(theme.base()),
            )
            .highlight_style(if active { Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg) } else { Style::default().fg(theme.fg).bg(theme.cursor_bg) })
            .highlight_symbol("> ");

        f.render_stateful_widget(explorer, main_chunks[0], &mut app.explorer_state);

        main_chunks[1]
    } else {
        chunks[1]
    };

    let active = app.focus == Focus::Content;

    let block = Block::default()
        .title(Span::styled(format!(" {} ", app.view.title()), theme.title_style()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if active { theme.highlight_bg } else { theme.border }))
        .style(theme.base());

    let inner = block.inner(content_area);
    f.render_widget(block, content_area);

    let height = inner.height as usize;
    let program = app.current_program();
    let analysis = app.analyses.get(program).cloned().flatten();

    match &mut app.view {
        View::Welcome => {
            let mut lines = vec![
                Line::from(""),
                Line::from(Span::styled("Welcome to execdump", theme.title_style())),
                Line::from(""),
                Line::from("Pick something in the explorer (j/k, Enter), or type : and an address or a function name."),
                Line::from("Analysis/Entry point opens the control flow graph of the entry point,"),
                Line::from("Analysis/Call graph shows which functions are called from it."),
                Line::from(""),
                Line::from("Press ? at any time for the key bindings."),
            ];

            if let Some(error) = app.analysis_errors.iter().flatten().next() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(format!("Analysis failed: {}", error), Style::default().fg(theme.warning))));
            }

            f.render_widget(Paragraph::new(Text::from(lines)).centered().style(theme.base()), inner);
        }
        View::Dump(view) => {
            let lines = view.render(height);
            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
        View::Hex(view) => {
            let lines = view.render(&theme, height);
            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
        View::Disasm(view) => {
            if let Some(decoder) = app.decoders[view.program].as_ref() {
                let lines = view.render(&theme, &app.programs[view.program], analysis.as_deref(), decoder, height);
                f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
            }
        }
        View::Graph(view) => view.render(inner, f.buffer_mut(), &theme),
        View::Table(view) => {
            let lines = view.render(&theme, height, inner.width as usize);
            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
    }

    // Status / command line
    let status = match (&app.input, &app.message) {
        (Some((kind, text)), _) => Line::from(vec![
            Span::styled(if *kind == InputKind::Command { ":" } else { "/" }, Style::default().fg(theme.title)),
            Span::styled(text.clone(), Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.fg)),
        ]),
        (None, Some((message, error))) => Line::from(Span::styled(message.clone(), Style::default().fg(if *error { theme.warning } else { theme.fg }))),
        (None, None) => Line::from(Span::styled(app.hints(), Style::default().fg(theme.dim))),
    };

    f.render_widget(Paragraph::new(status).style(theme.base()), chunks[2]);

    // Popups
    if let Some(popup) = &app.popup {
        let width = popup.items.iter().map(|(l, _)| l.len()).max().unwrap_or(10).max(popup.title.len()) as u16 + 6;
        let area = centered_rect(width, popup.items.len() as u16 + 2, f.area());

        let items: Vec<ListItem> = popup.items.iter().map(|(label, _)| ListItem::new(label.clone())).collect();
        let mut state = ListState::default();
        state.select(Some(popup.cursor));

        let list = List::new(items)
            .block(Block::default().title(format!(" {} ", popup.title)).borders(Borders::ALL).border_style(Style::default().fg(theme.node_selected)).style(theme.base()))
            .highlight_style(Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg))
            .highlight_symbol("> ");

        f.render_widget(Clear, area);
        f.render_stateful_widget(list, area, &mut state);
    }

    if app.help {
        let lines: Vec<Line> = HELP.iter().map(|(key, description)| {
            if description.is_empty() {
                Line::from(Span::styled(key.to_string(), theme.title_style()))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {:<20}", key), Style::default().fg(theme.key)),
                    Span::styled(description.to_string(), Style::default().fg(theme.fg)),
                ])
            }
        }).collect();

        let area = centered_rect(110, lines.len() as u16 + 2, f.area());

        f.render_widget(Clear, area);
        f.render_widget(
            Paragraph::new(Text::from(lines)).block(Block::default().title(" Keys (any key to close) ").borders(Borders::ALL).style(theme.base())),
            area,
        );
    }
}

pub fn main(exec_path: &PathBuf, exec: Exec) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(exec, exec_path.clone());

    let result: Result<(), Box<dyn Error>> = (|| {
        loop {
            app.poll_analysis();

            terminal.draw(|f| ui(f, &mut app))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.handle_key(key);
                    }
                }
            }

            if app.should_quit {
                return Ok(());
            }
        }
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    return result;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::parse_elf;
    use ratatui::backend::TestBackend;

    fn key(c: char) -> KeyEvent {
        return KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
    }

    fn wait_analysis(app: &mut App) {
        for _ in 0..500 {
            app.poll_analysis();

            if app.analyses.iter().all(|a| a.is_some()) {
                return;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("Analysis did not finish");
    }

    #[test]
    fn navigate_views() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/elf_x86_64_analysis");
        let mut app = App::new(Exec::ELF(parse_elf(&path).unwrap()), path);
        wait_analysis(&mut app);

        let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();

        // Entry point graph
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.view, View::Graph(_)));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        // Command line: go to main
        for c in ":main".chars() {
            app.handle_key(key(c));
        }

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let View::Graph(view) = &app.view else { panic!("Expected a graph") };
        assert!(view.title.starts_with("main"));

        for c in "njklhpgGtfc".chars() {
            app.handle_key(key(c));
            terminal.draw(|f| ui(f, &mut app)).unwrap();
        }

        // Linear view and back
        app.handle_key(key(' '));
        assert!(matches!(app.view, View::Disasm(_)));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        app.handle_key(key(' '));
        assert!(matches!(app.view, View::Graph(_)));

        // Call graph from main, then back to the entry point graph
        app.handle_key(key('C'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        let View::Graph(view) = &app.view else { panic!("Expected a graph") };
        assert!(matches!(view.kind, GraphKind::CallGraph { .. }));
        app.handle_key(key('i'));
        app.handle_key(key('+'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        let View::Graph(view) = &app.view else { panic!("Expected a graph") };
        assert!(matches!(view.kind, GraphKind::Cfg { .. }));

        // Tables
        app.run_command("functions");
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        app.run_search("main");
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.view, View::Graph(_)));

        for command in ["strings", "imports", "sections", ".text"] {
            app.run_command(command);
            terminal.draw(|f| ui(f, &mut app)).unwrap();
        }

        // Every explorer item can be opened and rendered
        for i in 0..app.explorer_items.len() {
            app.explorer_state.select(Some(i));
            app.activate_explorer_item();
            terminal.draw(|f| ui(f, &mut app)).unwrap();
        }

        app.handle_key(key('?'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        app.handle_key(key('q'));
        assert!(!app.should_quit);
        app.handle_key(key('q'));
        assert!(app.should_quit);
    }
}
