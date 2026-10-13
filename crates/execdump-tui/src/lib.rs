/*
 * Terminal user interface
 *
 * The executable is parsed once, the Programs are built once and analyzed in a background thread,
 * then each program gets a project: its functions are decompiled in the background, organized in
 * modules, annotated, edited and saved (see execdump-project).
 *
 * The content area is a workspace of splits, each one a group of tabs, each tab a view with its own
 * jumplist (Ctrl-o / Ctrl-i like in vim). Ctrl-w moves between the splits, gt/gT between the tabs.
 */

mod graph_view;
mod layout;
mod review_view;
mod source_view;
mod theme;
mod views;
mod workspace;

pub use theme::KeyBindings;

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

use execdump_decompiler::analysis::function::{CallTarget, EdgeKind};
use execdump_decompiler::analysis::insn::Decoder;
use execdump_decompiler::analysis::{analyze, Analysis};
use execdump_decompiler::llm::LlmConfig;
use execdump_core::crash;
use execdump_core::dump::Dump;
use execdump_core::exec::Exec;
use execdump_core::program::{programs_from_exec, Program};
use execdump_project::{default_workers, Project};

use graph_view::{Detail, GraphKind, GraphView, NodeKind};
use review_view::ReviewView;
use source_view::{InsertWhere, SourceView};
use theme::Theme;
use views::{insn_target, DisasmView, DumpView, HexView, TableRow, TableView, Target};
use workspace::{Dir, Workspace};

use serde::{Deserialize, Serialize};

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
    Proposals(usize),
    /// Module of a program (program index, module path)
    Module(usize, String),
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
            ExplorerItem::Proposals(p) => {
                let count = app.projects[*p].as_ref().map_or(0, |project| project.proposals.iter().filter(|p| !p.functions.is_empty()).count());
                format!("  LLM proposals ({}){}", count, suffix(p))
            }
            ExplorerItem::Module(p, name) => {
                let count = app.projects[*p].as_ref().map_or(0, |project| project.modules.functions(name).len());
                format!("  {} ({}){}", name, count, suffix(p))
            }
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

fn explorer_items(exec: &Exec, programs: &[Arc<Program>], projects: &[Option<Project>]) -> Vec<ExplorerItem> {
    let mut items = vec![ExplorerItem::Group("Analysis".to_string())];

    for p in 0..programs.len() {
        items.push(ExplorerItem::EntryPoint(p));
        items.push(ExplorerItem::CallGraph(p));
        items.push(ExplorerItem::Functions(p));
        items.push(ExplorerItem::Strings(p));
        items.push(ExplorerItem::Imports(p));
        items.push(ExplorerItem::MemoryMap(p));
        items.push(ExplorerItem::Proposals(p));
    }

    for (p, project) in projects.iter().enumerate() {
        let Some(project) = project else {
            continue;
        };

        let title = if programs.len() > 1 { format!("Modules ({})", programs[p].name) } else { "Modules".to_string() };
        items.push(ExplorerItem::Group(title));
        items.extend(project.modules.names().map(|m| ExplorerItem::Module(p, m.clone())));
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
            let mut sections: Vec<&execdump_core::pe::Section> = pe.sections.values().collect();
            sections.sort_by_key(|s| s.header.virtual_address);
            items.extend(sections.iter().map(|s| ExplorerItem::Section(0, s.header.name.clone())));
        }
        Exec::ELF(elf) => {
            let mut sections: Vec<&execdump_core::elf::ELFSection> = elf.sections.values().filter(|s| !s.name.is_empty()).collect();
            sections.sort_by_key(|s| s.offset());
            items.extend(sections.iter().map(|s| ExplorerItem::Section(0, s.name.clone())));
        }
        Exec::MachO(macho) => {
            for (p, binary) in macho.binaries.iter().enumerate() {
                let mut sections: Vec<&execdump_core::macho::MachOSection> = binary.sections.values().collect();
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
 * Views
 */

#[derive(Clone, Debug)]
enum View {
    Welcome,
    Dump(DumpView),
    Hex(HexView),
    Disasm(DisasmView),
    Graph(GraphView),
    Table(TableView),
    Source(SourceView),
    Review(ReviewView),
}

impl View {
    fn title(&self) -> String {
        match self {
            View::Welcome => "Welcome".to_string(),
            View::Dump(v) => v.title.clone(),
            View::Hex(v) => v.title.clone(),
            View::Disasm(v) => v.title.clone(),
            View::Graph(v) => v.title.clone(),
            View::Source(v) => v.title(),
            View::Review(v) => v.title(),
            View::Table(v) => if v.filter.is_empty() { v.title.clone() } else { format!("{} [/{}] ({} matches)", v.title, v.filter, v.filtered.len()) },
        }
    }

    /// Short title, for the tab bar
    fn tab_title(&self) -> String {
        let title = match self {
            View::Source(v) => v.module.clone(),
            View::Graph(v) => v.title.split("  (").next().unwrap_or(&v.title).to_string(),
            _ => self.title(),
        };

        return title.chars().take(28).collect();
    }

    fn program(&self) -> Option<usize> {
        match self {
            View::Disasm(v) => Some(v.program),
            View::Graph(v) => Some(v.program),
            View::Source(v) => Some(v.program),
            View::Review(v) => Some(v.program),
            _ => None,
        }
    }
}

/// What a tab shows, saved in the sessions (addresses in hexadecimal: TOML integers are signed)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Resource {
    Welcome,
    Cfg { program: usize, function: String, select: String },
    CallGraph { program: usize, root: String, depth: usize, imports: bool, select: String },
    Linear { program: usize, function: String, addr: String },
    Region { program: usize, region: String, addr: String },
    Address { program: usize, addr: String },
    Source { program: usize, module: String, addr: String },
    Table { program: usize, table: String },
    Review { program: usize },
}

fn hex(addr: u64) -> String {
    return format!("{:#x}", addr);
}

fn parse_hex(text: &str) -> u64 {
    return u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap_or(0);
}

#[derive(Serialize, Deserialize)]
struct Session {
    layout: workspace::Layout<Resource>,
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

/// Where the next view opens
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenMode {
    /// In the current tab (pushed on its jumplist)
    Replace,
    Tab,
    Split(Dir),
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
    /// Analysis of each program and its project, both made in the background
    receiver: Receiver<(usize, Result<(Arc<Analysis>, Project), String>)>,
    decoders: Vec<Option<Decoder>>,

    /// Project of each program, opened when its analysis is done
    projects: Vec<Option<Project>>,
    project_location: Option<PathBuf>,
    /// Session to restore once every project is open
    session_pending: bool,
    pending_export: Option<(usize, PathBuf)>,

    explorer_items: Vec<ExplorerItem>,
    explorer_state: ListState,
    explorer_visible: bool,
    explorer_version: u64,
    /// First explorer item shown
    explorer_offset: usize,
    focus: Focus,

    workspace: Workspace<View>,
    open_mode: OpenMode,
    /// Address the linked splits were last synchronized on
    synced: Option<(usize, u64)>,

    input: Option<(InputKind, String)>,
    last_search: String,
    message: Option<(String, bool)>,
    popup: Option<Popup>,
    help: bool,
    should_quit: bool,
    /// First key of a key sequence (g, d, c, ], [, Ctrl-w) and the count typed before it
    pending_key: Option<char>,
    count: Option<usize>,
    /// A key sequence is replaying a key
    in_sequence: bool,

    llm: LlmConfig,
}

impl App {
    fn new(exec: Exec, exec_path: PathBuf, keys: KeyBindings, project_location: Option<PathBuf>, workers: usize) -> Self {
        let programs: Vec<Arc<Program>> = programs_from_exec(&exec).into_iter().map(Arc::new).collect();
        let (sender, receiver) = channel();
        let mut progress = Vec::new();
        let count = programs.len();

        for (i, program) in programs.iter().enumerate() {
            let counter = Arc::new(AtomicUsize::new(0));
            progress.push(counter.clone());

            let (program, sender, path, location) = (program.clone(), sender.clone(), exec_path.clone(), project_location.clone());

            std::thread::spawn(move || {
                let result = crash::catch(|| {
                    analyze(&program, Some(&counter)).map_err(|e| e.to_string()).map(|analysis| {
                        let analysis = Arc::new(analysis);
                        let project = Project::open(i, count, program, analysis.clone(), &path, location, workers);
                        (analysis, project)
                    })
                });
                let result = result.unwrap_or_else(|error| Err(format!("analysis failed: {}", error)));

                let _ = sender.send((i, result));
            });
        }

        let projects: Vec<Option<Project>> = programs.iter().map(|_| None).collect();
        let explorer_items = explorer_items(&exec, &programs, &projects);
        let mut explorer_state = ListState::default();
        explorer_state.select(Some(1));

        return App {
            decoders: programs.iter().map(|p| Decoder::new(p.architecture()).ok()).collect(),
            analyses: vec![None; programs.len()],
            analysis_errors: vec![None; programs.len()],
            programs,
            progress,
            receiver,
            projects,
            project_location,
            session_pending: true,
            pending_export: None,
            exec,
            exec_path,
            theme: Theme::codedark(),
            keys,
            explorer_items,
            explorer_state,
            explorer_visible: true,
            explorer_version: 0,
            explorer_offset: 0,
            focus: Focus::Explorer,
            workspace: Workspace::new(View::Welcome),
            open_mode: OpenMode::Replace,
            synced: None,
            input: None,
            last_search: String::new(),
            message: None,
            popup: None,
            help: false,
            should_quit: false,
            pending_key: None,
            count: None,
            in_sequence: false,
            llm: LlmConfig::default(),
        };
    }

    fn view(&self) -> &View {
        return self.workspace.view();
    }

    fn view_mut(&mut self) -> &mut View {
        return self.workspace.view_mut();
    }

    fn poll_analysis(&mut self) {
        while let Ok((index, result)) = self.receiver.try_recv() {
            match result {
                Ok((analysis, project)) => {
                    self.analyses[index] = Some(analysis);
                    self.projects[index] = Some(project);
                    self.explorer_version = u64::MAX;

                    // Refresh the region disassemblies so they get the function labels and annotations
                    let refreshed: Vec<(usize, String, Option<u64>)> = self.workspace.views_mut()
                        .filter_map(|v| match v {
                            View::Disasm(view) if view.program == index && view.region.is_some() => Some((view.program, view.region.clone().unwrap(), view.cursor_addr())),
                            _ => None,
                        })
                        .collect();

                    for (program, region, addr) in refreshed {
                        if let Some(mut fresh) = self.region_disasm(program, &region) {
                            if let Some(addr) = addr {
                                fresh.goto(addr);
                            }

                            for view in self.workspace.views_mut() {
                                if matches!(view, View::Disasm(v) if v.program == program && v.region.as_deref() == Some(region.as_str())) {
                                    *view = View::Disasm(fresh.clone());
                                }
                            }
                        }
                    }
                }
                Err(error) => self.analysis_errors[index] = Some(error),
            }
        }

        if self.session_pending && self.projects.iter().all(|p| p.is_some()) {
            self.session_pending = false;
            self.restore_session();
        }
    }

    /// Work done in the background by the projects: decompiled functions, LLM answers, messages
    fn poll_projects(&mut self) {
        let App { projects, workspace, message, explorer_version, .. } = self;
        let mut versions = 0u64;

        for (index, project) in projects.iter_mut().enumerate() {
            let Some(project) = project.as_mut() else {
                continue;
            };

            let changed = project.poll();

            for view in workspace.views_mut() {
                match view {
                    View::Source(source) if source.program == index && !changed.is_empty() => source.changed(project, &changed),
                    View::Graph(graph) if graph.program == index && !changed.is_empty() => graph.changed(project, &changed),
                    _ => {}
                }
            }

            if let Some((text, error)) = project.messages.pop() {
                *message = Some((text, error));
                project.messages.clear();
            }

            versions = versions.wrapping_add(project.version).wrapping_add(project.modules.len() as u64);
        }

        if *explorer_version != versions {
            *explorer_version = versions;
            let selected = self.explorer_state.selected().and_then(|i| self.explorer_items.get(i)).cloned();
            self.explorer_items = explorer_items(&self.exec, &self.programs, &self.projects);

            if let Some(index) = selected.and_then(|s| self.explorer_items.iter().position(|i| *i == s)) {
                self.explorer_state.select(Some(index));
            }
        }

        if let Some((program, dir)) = self.pending_export.clone() {
            if self.projects[program].as_ref().is_some_and(|p| p.is_idle()) {
                self.pending_export = None;
                self.export(program, dir);
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

    fn project(&mut self, program: usize) -> Option<&mut Project> {
        if self.projects[program].is_none() {
            self.analysis(program);
        }

        return self.projects[program].as_mut();
    }

    fn current_program(&self) -> usize {
        return self.view().program().unwrap_or(0);
    }

    fn info(&mut self, message: String) {
        self.message = Some((message, false));
    }

    fn error(&mut self, message: String) {
        self.message = Some((message, true));
    }

    fn report(&mut self, result: Result<(), String>) {
        if let Err(error) = result {
            self.error(error);
        }
    }

    /*
     * Jumplist and tabs
     */

    fn open(&mut self, view: View) {
        match std::mem::replace(&mut self.open_mode, OpenMode::Replace) {
            OpenMode::Replace => {
                let tab = self.workspace.tab_mut();
                let previous = std::mem::replace(&mut tab.view, view);

                if !matches!(previous, View::Welcome) {
                    tab.back.push(previous);
                }

                tab.forward.clear();
            }
            OpenMode::Tab => self.workspace.new_tab(view),
            OpenMode::Split(dir) => {
                self.workspace.split(dir, view);
            }
        }

        self.focus = Focus::Content;
    }

    fn go_back(&mut self) {
        let tab = self.workspace.tab_mut();

        if let Some(view) = tab.back.pop() {
            let current = std::mem::replace(&mut tab.view, view);
            tab.forward.push(current);
        } else {
            self.info("Already at the oldest view".to_string());
        }
    }

    fn go_forward(&mut self) {
        let tab = self.workspace.tab_mut();

        if let Some(view) = tab.forward.pop() {
            let current = std::mem::replace(&mut tab.view, view);
            tab.back.push(current);
        } else {
            self.info("Already at the newest view".to_string());
        }
    }

    /// Opens the next view in a split, or in the current tab when there is no target
    fn split(&mut self, dir: Dir, target: Option<&str>) {
        match target {
            Some(target) => {
                let program = self.current_program();

                match self.resolve_address(program, target) {
                    Some(addr) => {
                        self.open_mode = OpenMode::Split(dir);
                        self.goto_address(program, addr);
                        self.open_mode = OpenMode::Replace;
                    }
                    None => self.error(format!("Unknown address or function: {}", target)),
                }
            }
            None => {
                let view = self.view().clone();
                self.workspace.split(dir, view);
            }
        }

        self.focus = Focus::Content;
    }

    fn close_tab(&mut self, force: bool) {
        if !self.workspace.close_tab() {
            self.quit(force);
        }
    }

    fn quit(&mut self, force: bool) {
        let dirty = self.projects.iter().flatten().any(|p| p.is_dirty());

        if dirty && !force {
            self.error("Unsaved changes: :w to save them, :qa! to quit without saving".to_string());
            return;
        }

        self.save_session();
        self.should_quit = true;
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

    /// Opens a call graph and selects a function in it
    fn open_call_graph_at(&mut self, program: usize, root: u64, depth: usize, imports: bool, select: u64) {
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

    fn region_disasm(&self, program: usize, region: &str) -> Option<DisasmView> {
        let decoder = self.decoders[program].as_ref()?;
        return DisasmView::region(program, self.programs[program].clone(), self.analyses[program].clone(), decoder, region);
    }

    /// Source view of the module of a function, on the line of an address
    fn source_view(&mut self, program: usize, addr: u64) -> Option<SourceView> {
        let project = self.project(program)?;
        let function = project.analysis.function_containing(addr).map(|f| f.addr);

        let Some(module) = function.and_then(|f| project.module_of(f)).map(|m| m.to_string()) else {
            let thunk = function.and_then(|f| project.analysis.functions.get(&f)).is_some_and(|f| f.thunk.is_some());
            self.error(if thunk { "Imported function: its code is not in this binary".to_string() } else { format!("No function at {:#x}", addr) });
            return None;
        };

        let mut view = SourceView::new(program, &module, project);
        view.height = 20;
        view.goto(project, addr);

        return Some(view);
    }

    /// Opens the C code of the module of a function, on the line of an address
    fn open_code(&mut self, program: usize, addr: u64) {
        if let Some(view) = self.source_view(program, addr) {
            self.open(View::Source(view));
        }
    }

    fn open_module(&mut self, program: usize, module: &str) {
        let Some(project) = self.project(program) else {
            return;
        };

        if !project.modules.contains(module) {
            self.error(format!("No module {}", module));
            return;
        }

        let view = SourceView::new(program, module, project);
        self.open(View::Source(view));
    }

    fn open_review(&mut self, program: usize) {
        if let Some(project) = self.project(program) {
            let view = ReviewView::new(program, project);
            self.open(View::Review(view));
        }
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
            Target::CallGraph { program, root, depth, imports, select } => self.open_call_graph_at(program, root, depth, imports, select),
            Target::Module(program, module) => self.open_module(program, &module),
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

            let project = self.projects[program].as_ref();
            let module = project.and_then(|p| p.module_of(f.addr)).unwrap_or("").to_string();
            let name = project.map_or(f.name.clone(), |p| p.function_name(f.addr));

            TableRow {
                cells: vec![
                    format!("{:#x}", f.addr),
                    format!("{}", f.size()),
                    format!("{}", f.blocks.len()),
                    format!("{}", analysis.callers.get(&f.addr).map_or(0, |c| c.len())),
                    f.source.name().to_string(),
                    flags.join(","),
                    module,
                    name,
                ],
                target: Target::Function(program, f.addr),
                style: if f.thunk.is_some() { Some(Style::default().fg(self.theme.dim)) } else { None },
            }
        }).collect();

        return Some(TableView::new(
            format!("Functions ({})", analysis.functions.len()),
            vec!["Address", "Size", "Blocks", "Xrefs", "Source", "Flags", "Module", "Name"],
            rows,
        ));
    }

    fn modules_table(&mut self, program: usize) -> Option<TableView> {
        let project = self.project(program)?;

        let rows = project.modules.names().map(|name| {
            let functions = project.modules.functions(name);
            let edited = functions.iter().filter(|a| project.work.edits.contains_key(a)).count();

            TableRow {
                cells: vec![format!("{}", functions.len()), format!("{}", edited), name.clone()],
                target: Target::Module(program, name.clone()),
                style: None,
            }
        }).collect();

        return Some(TableView::new(format!("Modules ({})", project.modules.len()), vec!["Functions", "Edited", "Module"], rows));
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
                execdump_decompiler::analysis::strings::escape(string, 200),
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
                cells: vec![format!("{:#x}", addr), "pointer".to_string(), execdump_core::demangle::demangle(name).unwrap_or(name.clone())],
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

    fn table(&mut self, program: usize, name: &str) -> Option<TableView> {
        return match name {
            "functions" => self.functions_table(program),
            "strings" => self.strings_table(program),
            "imports" => Some(self.imports_table(program)),
            "modules" => self.modules_table(program),
            _ => Some(self.memory_map(program)),
        };
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
            ExplorerItem::Group(_) => {
                self.open_mode = OpenMode::Replace;
                return;
            }
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
            ExplorerItem::Proposals(p) => {
                self.open_review(*p);
                return;
            }
            ExplorerItem::Module(p, module) => {
                self.open_module(*p, module);
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

        match view {
            Some(view) => self.open(view),
            None => self.open_mode = OpenMode::Replace,
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
        let (name, rest) = command.split_once(char::is_whitespace).map_or((command, ""), |(n, r)| (n, r.trim()));
        let argument = rest.split_whitespace().next();
        let program = self.current_program();

        match name {
            "" => {}
            "q" | "quit" | "close" | "clo" => self.close_tab(false),
            "q!" | "quit!" => self.close_tab(true),
            "qa" | "qall" | "quitall" => self.quit(false),
            "qa!" | "qall!" | "quitall!" => self.quit(true),
            "w" | "write" => self.save(if rest.is_empty() { None } else { Some(PathBuf::from(rest)) }),
            "wq" | "x" => {
                self.save(None);

                if !self.projects.iter().flatten().any(|p| p.is_dirty()) {
                    self.quit(false);
                }
            }
            "cg" | "callgraph" => {
                let root = argument.and_then(|a| self.resolve_address(program, a));
                self.open_call_graph(program, root, DEFAULT_CALL_GRAPH_DEPTH, false);
            }
            "c" | "decompile" => {
                let addr = match argument {
                    Some(a) => self.resolve_address(program, a),
                    None => self.current_function().map(|(_, f)| f),
                };

                match addr {
                    Some(addr) => self.open_code(program, addr),
                    None => self.error("Usage: c [function or address]".to_string()),
                }
            }
            "src" | "source" | "module" => match argument {
                Some(module) => self.open_module(program, module),
                None => match self.current_function() {
                    Some((program, addr)) => self.open_code(program, addr),
                    None => self.error("Usage: source <module>".to_string()),
                },
            },
            "functions" | "fn" | "strings" | "imports" | "modules" | "mods" => {
                let table = match name {
                    "fn" => "functions",
                    "mods" => "modules",
                    other => other,
                };

                if let Some(table) = self.table(program, table) {
                    self.open(View::Table(table));
                }
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

                match (self.view(), depth) {
                    (View::Graph(view), Some(depth)) => {
                        if let GraphKind::CallGraph { root, imports, .. } = view.kind {
                            let program = view.program;
                            self.open_call_graph(program, Some(root), depth, imports);
                        }
                    }
                    _ => self.error("Usage in a call graph: depth <n>".to_string()),
                }
            }
            "up" | "parent" => self.call_graph_up(),
            "help" | "h" => self.help = true,

            // Windows
            "sp" | "split" | "new" => self.split(Dir::Down, argument),
            "vs" | "vsplit" | "vnew" => self.split(Dir::Right, argument),
            "tabnew" | "tabe" | "tabedit" => match argument {
                Some(target) => match self.resolve_address(program, target) {
                    Some(addr) => {
                        self.open_mode = OpenMode::Tab;
                        self.goto_address(program, addr);
                        self.open_mode = OpenMode::Replace;
                    }
                    None => self.error(format!("Unknown address or function: {}", target)),
                },
                None => {
                    let view = self.view().clone();
                    self.workspace.new_tab(view);
                }
            },
            "tabc" | "tabclose" => self.close_tab(false),
            "tabn" | "tabnext" => self.workspace.cycle_tab(true),
            "tabp" | "tabprevious" | "tabN" => self.workspace.cycle_tab(false),
            "on" | "only" => self.workspace.only(),
            "link" | "unlink" => self.toggle_link(),

            // Project
            "export" => match argument {
                Some(dir) => self.export(program, PathBuf::from(dir)),
                None => self.error("Usage: export <directory>".to_string()),
            },
            "review" | "proposals" => self.open_review(program),
            "llm" => match argument {
                Some("modules") | Some("mods") => {
                    let scope = rest.split_whitespace().nth(1);
                    let module = match scope {
                        Some("all") => None,
                        Some(module) => Some(module.to_string()),
                        None => self.current_module(),
                    };

                    let llm = self.llm.clone();
                    let result = self.project(program).ok_or_else(String::new).and_then(|p| p.llm_modules(module.as_deref(), &llm));
                    match result {
                        Ok(()) => self.info(format!("Asking the LLM to organize {}...", module.as_deref().unwrap_or("the program"))),
                        Err(error) if !error.is_empty() => self.error(error),
                        Err(_) => {}
                    }
                }
                _ => self.improve_code(),
            },
            "accept" | "reject" => {
                let id = argument.and_then(|a| a.parse::<u64>().ok());
                let Some(id) = id else {
                    return self.error(format!("Usage: {} <proposal number>", name));
                };

                let result = self.project(program).ok_or_else(String::new).and_then(|p| if name == "accept" { p.accept(id) } else { p.reject(id) });
                self.report(result.map_err(|e| if e.is_empty() { "No project yet".to_string() } else { e }));
            }
            "mv" | "move" => {
                let module = argument.map(|m| m.to_string());
                let function = rest.split_whitespace().nth(1).map(|f| f.to_string());
                self.move_function(module, function);
            }
            "mkmod" | "newmod" => match argument {
                Some(module) => {
                    let module = module.to_string();
                    let result = self.project(program).ok_or_else(String::new).and_then(|p| p.create_module(&module));
                    self.report(result);
                }
                None => self.error("Usage: mkmod <module path>".to_string()),
            },
            "rmmod" => match argument {
                Some(module) => {
                    let module = module.to_string();
                    let result = self.project(program).ok_or_else(String::new).and_then(|p| p.remove_module(&module));
                    self.report(result);
                }
                None => self.error("Usage: rmmod <module path>".to_string()),
            },
            "renmod" => {
                let mut words = rest.split_whitespace();

                match (words.next(), words.next()) {
                    (Some(old), Some(new)) => {
                        let (old, new) = (old.to_string(), new.to_string());
                        let result = self.project(program).ok_or_else(String::new).and_then(|p| p.rename_module(&old, &new));
                        self.report(result);

                        for view in self.workspace.views_mut() {
                            if let View::Source(source) = view {
                                if source.module == old {
                                    source.module = new.clone();
                                }
                            }
                        }
                    }
                    _ => self.error("Usage: renmod <old module> <new module>".to_string()),
                }
            }
            "rename" | "ren" => {
                let mut words = rest.split_whitespace();

                match (words.next(), words.next()) {
                    (Some(old), Some(new)) => self.rename(old, new),
                    _ => self.error("Usage: rename <name> <new name> (- restores the original name)".to_string()),
                }
            }
            "retype" => match rest.split_once(char::is_whitespace) {
                Some((var, ty)) => self.retype(var, ty.trim()),
                None => self.error("Usage: retype <variable> <C type> (- restores the recovered type)".to_string()),
            },
            "sig" | "signature" | "prototype" => self.signature(rest),
            "summary" => {
                let rest = rest.to_string();
                self.with_function(|project, addr| {
                    project.set_summary(addr, Some(rest.as_str()).filter(|s| !s.is_empty()));
                    Ok(())
                });
            }
            "comment" => {
                let text = rest.to_string();
                self.with_source(|source, project| source.comment(project, &text));
            }
            "revert" => self.with_function(|project, addr| {
                project.revert(addr);
                Ok(())
            }),
            "ours" | "edited" => self.with_source(|source, project| source.resolve(project, true, false)),
            "theirs" | "decompiled" => self.with_source(|source, project| source.resolve(project, false, true)),
            "both" => self.with_source(|source, project| source.resolve(project, true, true)),
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

        if let Some(addr) = self.projects[program].as_ref().and_then(|p| p.resolve(text)) {
            return Some(addr);
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

        let App { workspace, projects, programs, decoders, .. } = self;

        let found = match workspace.view_mut() {
            View::Table(view) => {
                view.set_filter(&pattern);
                true
            }
            View::Graph(view) => view.search(&pattern),
            View::Disasm(view) => decoders[view.program].as_ref().is_some_and(|d| view.search(&pattern, &programs[view.program], d)),
            View::Source(view) => projects[view.program].as_mut().is_some_and(|p| view.search(p, &pattern)),
            View::Dump(view) => view.search(&pattern),
            _ => false,
        };

        if !found {
            self.error(format!("Pattern not found: {}", pattern));
        }
    }

    /*
     * Project actions
     */

    fn save(&mut self, location: Option<PathBuf>) {
        if location.is_some() {
            self.project_location = location.clone();
        }

        let mut messages = Vec::new();

        for project in self.projects.iter_mut().flatten() {
            match project.save(location.clone()) {
                Ok(message) => messages.push(message),
                Err(error) => {
                    self.message = Some((format!("Cannot save: {}", error), true));
                    return;
                }
            }
        }

        self.save_session();

        match messages.first() {
            Some(message) => self.info(message.clone()),
            None => self.error("Nothing to save until the analysis is done".to_string()),
        }
    }

    fn describe(&self, view: &View) -> Resource {
        return match view {
            View::Graph(graph) => match graph.kind {
                GraphKind::Cfg { function } => Resource::Cfg { program: graph.program, function: hex(function), select: hex(graph.selected_node().addr) },
                GraphKind::CallGraph { root, depth, imports } => Resource::CallGraph { program: graph.program, root: hex(root), depth, imports, select: hex(graph.selected_node().addr) },
            },
            View::Disasm(disasm) => match (disasm.function, disasm.region.as_ref()) {
                (Some(function), _) => Resource::Linear { program: disasm.program, function: hex(function), addr: hex(disasm.cursor_addr().unwrap_or(function)) },
                (None, Some(region)) => Resource::Region { program: disasm.program, region: region.clone(), addr: hex(disasm.cursor_addr().unwrap_or(0)) },
                _ => Resource::Welcome,
            },
            View::Hex(hex_view) => Resource::Address { program: self.current_program(), addr: hex(hex_view.base + hex_view.scroll as u64 * 16) },
            View::Source(source) => {
                let addr = source.function().unwrap_or(0);
                Resource::Source { program: source.program, module: source.module.clone(), addr: hex(addr) }
            }
            View::Table(table) => {
                let name = table.title.split_whitespace().next().unwrap_or("").to_lowercase();
                Resource::Table { program: self.current_program(), table: if name == "memory" { "memmap".to_string() } else { name } }
            }
            View::Review(review) => Resource::Review { program: review.program },
            View::Welcome | View::Dump(_) => Resource::Welcome,
        };
    }

    fn reopen(&mut self, resource: &Resource) -> View {
        self.open_mode = OpenMode::Replace;
        let saved = std::mem::replace(&mut self.workspace, Workspace::new(View::Welcome));

        match resource {
            Resource::Welcome => {}
            Resource::Cfg { program, function, select } => self.open_function(*program, parse_hex(function), Some(parse_hex(select))),
            Resource::CallGraph { program, root, depth, imports, select } => self.open_call_graph_at(*program, parse_hex(root), *depth, *imports, parse_hex(select)),
            Resource::Linear { program, function, addr } => {
                let (program, function, addr) = (*program, parse_hex(function), parse_hex(addr));

                if let (Some(analysis), Some(decoder)) = (self.analyses.get(program).cloned().flatten(), self.decoders.get(program).and_then(|d| d.as_ref())) {
                    if let Some(mut view) = DisasmView::function(program, &self.programs[program], &analysis, decoder, function) {
                        view.goto(addr);
                        self.open(View::Disasm(view));
                    }
                }
            }
            Resource::Region { program, region, addr } => {
                if let Some(mut view) = self.region_disasm(*program, region) {
                    view.goto(parse_hex(addr));
                    self.open(View::Disasm(view));
                }
            }
            Resource::Address { program, addr } => self.goto_address(*program, parse_hex(addr)),
            Resource::Source { program, module, addr } => {
                if let Some(project) = self.projects.get_mut(*program).and_then(|p| p.as_mut()) {
                    if project.modules.contains(module) {
                        let mut view = SourceView::new(*program, module, project);
                        view.goto(project, parse_hex(addr));
                        self.open(View::Source(view));
                    }
                }
            }
            Resource::Table { program, table } => {
                if let Some(table) = self.table(*program, table) {
                    self.open(View::Table(table));
                }
            }
            Resource::Review { program } => self.open_review(*program),
        }

        let view = std::mem::replace(&mut self.workspace, saved).view().clone();
        self.message = None;

        return view;
    }

    fn save_session(&mut self) {
        let Some(project) = self.projects.iter().flatten().next() else {
            return;
        };

        // Sessions are kept with the projects that were saved
        if !project.location().exists() {
            return;
        }

        let layout = self.workspace.save(&|view| self.describe(view));

        if let Ok(text) = toml::to_string(&Session { layout }) {
            let _ = project.save_session(&text);
        }
    }

    fn restore_session(&mut self) {
        let Some(text) = self.projects.iter().flatten().next().and_then(|p| p.session()) else {
            return;
        };

        let Ok(session) = toml::from_str::<Session>(&text) else {
            return;
        };

        // Only when nothing was opened while the analysis was running
        if self.workspace.group_count() > 1 || !matches!(self.view(), View::Welcome) {
            return;
        }

        let workspace = Workspace::restore(&session.layout, &mut |r| self.reopen(r));

        if workspace.is_valid() {
            self.workspace = workspace;
            self.focus = Focus::Content;
        }
    }

    fn export(&mut self, program: usize, dir: PathBuf) {
        let Some(project) = self.project(program) else {
            return;
        };

        if !project.is_idle() {
            let (done, total) = project.progress();
            self.pending_export = Some((program, dir.clone()));
            self.info(format!("Exporting to {} once the decompilation is done ({}/{})", dir.display(), done, total));
            return;
        }

        match project.export(&dir) {
            Ok(report) => {
                let conflicts = if report.conflicts.is_empty() { String::new() } else { format!(", {} functions with conflicts", report.conflicts.len()) };
                self.info(format!("Exported {} functions in {} files to {}{}", report.functions, report.files, report.dir.display(), conflicts));
            }
            Err(error) => self.error(format!("Export failed: {}", error)),
        }
    }

    /// Runs an action on the project and the function under the cursor
    fn with_function(&mut self, action: impl FnOnce(&mut Project, u64) -> Result<(), String>) {
        let Some((program, addr)) = self.current_function() else {
            return self.error("No function under the cursor".to_string());
        };

        let result = match self.project(program) {
            Some(project) => action(project, addr),
            None => return,
        };

        self.report(result);
    }

    /// Runs an action on the source view and its project
    fn with_source(&mut self, action: impl FnOnce(&mut SourceView, &mut Project) -> Result<(), String>) {
        let App { workspace, projects, .. } = self;

        let result = match workspace.view_mut() {
            View::Source(source) => match projects[source.program].as_mut() {
                Some(project) => action(source, project),
                None => Ok(()),
            },
            _ => Err("Only in the C code (:source)".to_string()),
        };

        self.report(result);
    }

    fn current_module(&self) -> Option<String> {
        return match self.view() {
            View::Source(source) => Some(source.module.clone()),
            _ => None,
        };
    }

    /// Renames what a name refers to: a variable of the current function, a function or a global
    fn rename(&mut self, old: &str, new: &str) {
        let new = if new == "-" { None } else { Some(new) };
        let Some((program, function)) = self.current_function() else {
            let program = self.current_program();
            let addr = self.projects[program].as_ref().and_then(|p| p.resolve(old));

            let result = match (addr, self.project(program)) {
                (Some(addr), Some(project)) => project.rename_function(addr, new),
                _ => Err(format!("Unknown function: {}", old)),
            };

            return self.report(result);
        };

        let Some(project) = self.project(program) else {
            return;
        };

        let is_var = project.shown(function).is_some_and(|(r, _)| r.meta.vars.iter().any(|(_, shown)| shown == old));

        let result = if is_var {
            match new {
                Some(new) => project.rename_var(function, old, new),
                None => project.original_var(function, old).and_then(|original| project.rename_var(function, old, &original)),
            }
        } else if let Some(addr) = project.resolve(old) {
            project.rename_function(addr, new)
        } else if let Some(addr) = project.global(function, old) {
            project.rename_global(addr, new)
        } else {
            Err(format!("{} is not a variable, a function or a global of {}", old, project.function_name(function)))
        };

        self.report(result);
    }

    fn retype(&mut self, var: &str, ty: &str) {
        let ty = if ty == "-" { None } else { Some(ty) };
        self.with_function(|project, addr| project.retype_var(addr, var, ty));
    }

    fn signature(&mut self, text: &str) {
        let text = if text.is_empty() || text == "-" { None } else { Some(text) };
        self.with_function(|project, addr| project.set_prototype(addr, text));
    }

    fn move_function(&mut self, module: Option<String>, function: Option<String>) {
        let Some(module) = module else {
            return self.error("Usage: mv <module path> [function]".to_string());
        };

        let program = self.current_program();
        let addr = match function {
            Some(name) => self.resolve_address(program, &name),
            None => self.current_function().map(|(_, a)| a),
        };

        let Some(addr) = addr else {
            return self.error("No function to move".to_string());
        };

        let result = self.project(program).ok_or_else(String::new).and_then(|p| {
            p.move_function(addr, &module)?;
            Ok(format!("{} moved to {}", p.function_name(addr), module))
        });

        match result {
            Ok(message) => self.info(message),
            Err(error) if !error.is_empty() => self.error(error),
            Err(_) => {}
        }
    }

    /// Asks the LLM to improve the function under the cursor: the answer is a proposal to review
    fn improve_code(&mut self) {
        let Some((program, function)) = self.current_function() else {
            return self.error("No function under the cursor".to_string());
        };

        if !self.llm.is_enabled() {
            self.error("No [llm] section in ~/.execdumprc (backend, model, api_key_env...)".to_string());
            return;
        }

        let llm = self.llm.clone();

        let result = match self.project(program) {
            Some(project) => project.llm_function(function, &llm),
            None => return,
        };

        match result {
            Ok(()) => self.info("Asking the LLM to improve the code, its proposal will show in :review".to_string()),
            Err(error) => self.error(format!("LLM: {}", error)),
        }
    }

    /*
     * Links between splits
     */

    fn toggle_link(&mut self) {
        if self.workspace.toggle_link() {
            self.synced = None;
            self.info("Linked with the previous split: their cursors follow each other".to_string());
        } else {
            self.info("Unlinked".to_string());
        }
    }

    /// Address under the cursor of a view
    fn view_addr(view: &View, projects: &mut [Option<Project>]) -> Option<(usize, u64)> {
        return match view {
            View::Source(source) => projects[source.program].as_mut().and_then(|p| source.cursor_addr(p)).map(|a| (source.program, a)),
            View::Disasm(disasm) => disasm.cursor_addr().map(|a| (disasm.program, a)),
            View::Graph(graph) if graph.selected_node().kind != NodeKind::Import => Some((graph.program, graph.selected_node().addr)),
            _ => None,
        };
    }

    /// Moves the linked split to the address under the cursor of the focused one
    fn sync_linked(&mut self) {
        let Some(linked) = self.workspace.linked(self.workspace.focused) else {
            return;
        };

        let App { workspace, projects, .. } = self;
        let Some((program, addr)) = Self::view_addr(workspace.view(), projects) else {
            return;
        };

        if self.synced == Some((program, addr)) {
            return;
        }

        self.synced = Some((program, addr));

        let function = self.analyses[program].as_ref().and_then(|a| a.function_containing(addr)).map(|f| f.addr);

        // The linked view follows in place when it can, otherwise it is replaced by the same kind of view
        enum Replace {
            Source,
            Linear(u64),
            Cfg(u64),
        }

        let replace = {
            let App { workspace, projects, .. } = self;
            let group = workspace.group_mut(linked);
            let active = group.active;

            match &mut group.tabs[active].view {
                View::Source(source) if source.program == program => match projects[program].as_mut() {
                    Some(project) => if source.goto(project, addr) { None } else { Some(Replace::Source) },
                    None => None,
                },
                View::Disasm(disasm) if disasm.program == program => {
                    if disasm.goto(addr) { None } else { function.map(Replace::Linear) }
                }
                View::Graph(graph) if graph.program == program => match graph.kind {
                    GraphKind::Cfg { function: shown } if Some(shown) == function => {
                        graph.select_addr(addr);
                        None
                    }
                    GraphKind::Cfg { .. } => function.map(Replace::Cfg),
                    GraphKind::CallGraph { .. } => {
                        if let Some(index) = function.and_then(|f| graph.nodes.iter().position(|n| n.kind == NodeKind::Function && n.addr == f)) {
                            graph.select(index);
                        }

                        None
                    }
                },
                _ => None,
            }
        };

        let view = match replace {
            None => return,
            Some(Replace::Source) => self.source_view(program, addr).map(View::Source),
            Some(Replace::Linear(function)) => match (self.analyses[program].clone(), self.decoders[program].as_ref()) {
                (Some(analysis), Some(decoder)) => DisasmView::function(program, &self.programs[program], &analysis, decoder, function).map(|mut v| {
                    v.goto(addr);
                    View::Disasm(v)
                }),
                _ => None,
            },
            Some(Replace::Cfg(function)) => self.cfg_view(program, function).map(|mut g| {
                g.select_addr(addr);
                View::Graph(g)
            }),
        };

        if let Some(view) = view {
            let group = self.workspace.group_mut(linked);
            let active = group.active;
            group.tabs[active].view = view;
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
                        if let View::Table(view) = self.view_mut() {
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
                        if let View::Table(view) = self.view_mut() {
                            view.set_filter(&text);
                        }
                    }
                }
                KeyCode::Char(c) => {
                    text.push(c);

                    // Tables are filtered while typing
                    if kind == InputKind::Search {
                        if let View::Table(view) = self.view_mut() {
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

        // Insert mode of the C code
        if self.focus == Focus::Content {
            let App { workspace, projects, .. } = self;

            if let View::Source(source) = workspace.view_mut() {
                if source.insert.is_some() {
                    if let Some(project) = projects[source.program].as_mut() {
                        let result = source.insert_key(project, key);
                        self.report(result.map(|_| ()));
                    }

                    return;
                }
            }
        }

        self.message = None;

        // Second key of a sequence
        if let Some(first) = self.pending_key.take() {
            let count = self.count.take();
            self.key_sequence(first, key, count);
            return;
        }

        // Counts (3gt, 10j)
        if let KeyCode::Char(c @ '0'..='9') = key.code {
            if !ctrl && self.focus == Focus::Content && (c != '0' || self.count.is_some()) {
                self.count = Some(self.count.unwrap_or(0).saturating_mul(10).saturating_add(c as usize - '0' as usize));
                return;
            }
        }

        match key.code {
            KeyCode::Char(c) if c == self.keys.quit && !ctrl => {
                self.quit(false);
                return;
            }
            KeyCode::Char('c') if ctrl => {
                self.quit(false);
                return;
            }
            KeyCode::Char('w') if ctrl => {
                self.pending_key = Some('w');
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
            Focus::Content => {
                self.handle_content_key(key);
                self.sync_linked();
            }
        }
    }

    /// Key sequences: Ctrl-w <key> (splits), g <key> (top, tabs, definition), and the editing ones of the C code
    fn key_sequence(&mut self, first: char, key: KeyEvent, count: Option<usize>) {
        let KeyCode::Char(c) = key.code else {
            let dir = match key.code {
                KeyCode::Left => Some(Dir::Left),
                KeyCode::Down => Some(Dir::Down),
                KeyCode::Up => Some(Dir::Up),
                KeyCode::Right => Some(Dir::Right),
                _ => None,
            };

            if let (Some(dir), 'w') = (dir, first) {
                self.focus_dir(dir);
            }

            return;
        };

        let source = matches!(self.view(), View::Source(_));

        match (first, c) {
            ('w', 'h') => self.focus_dir(Dir::Left),
            ('w', 'j') => self.focus_dir(Dir::Down),
            ('w', 'k') => self.focus_dir(Dir::Up),
            ('w', 'l') => self.focus_dir(Dir::Right),
            ('w', 'w') => self.workspace.cycle_group(true),
            ('w', 'W') => self.workspace.cycle_group(false),
            ('w', 'p') => self.workspace.focus_previous(),
            ('w', 's') | ('w', 'S') => self.split(Dir::Down, None),
            ('w', 'v') => self.split(Dir::Right, None),
            ('w', 'q') | ('w', 'c') => {
                let focused = self.workspace.focused;

                if !self.workspace.close_group(focused) {
                    self.quit(false);
                }
            }
            ('w', 'o') => self.workspace.only(),
            ('w', 'H') => self.workspace.move_tab(Dir::Left),
            ('w', 'J') => self.workspace.move_tab(Dir::Down),
            ('w', 'K') => self.workspace.move_tab(Dir::Up),
            ('w', 'L') => self.workspace.move_tab(Dir::Right),
            ('w', '=') => self.workspace.equalize(),
            ('w', '<') => self.workspace.resize(true, -5 * count.unwrap_or(1) as i32),
            ('w', '>') => self.workspace.resize(true, 5 * count.unwrap_or(1) as i32),
            ('w', '-') => self.workspace.resize(false, -5 * count.unwrap_or(1) as i32),
            ('w', '+') => self.workspace.resize(false, 5 * count.unwrap_or(1) as i32),
            ('w', 'b') => self.toggle_link(),
            ('w', 't') => {
                let view = self.view().clone();
                self.workspace.new_tab(view);
            }
            ('g', 't') => match count {
                Some(n) => self.workspace.goto_tab(n),
                None => self.workspace.cycle_tab(true),
            },
            ('g', 'T') => self.workspace.cycle_tab(false),
            ('g', 'd') => self.definition(),
            ('g', 'g') if self.focus == Focus::Content => {
                self.in_sequence = true;
                self.count = count;
                self.handle_content_key(KeyEvent::new(KeyCode::Char(self.keys.start), KeyModifiers::NONE));
                self.in_sequence = false;
            }
            ('g', 'g') => self.explorer_state.select(Some(0)),
            ('d', 'd') if source => self.with_source(|source, project| source.delete_line(project)),
            ('c', 'n') => {
                let word = self.word_under_cursor();
                self.input = Some((InputKind::Command, format!("rename {} ", word.unwrap_or_default())));
            }
            ('c', 't') => {
                let word = self.word_under_cursor();
                self.input = Some((InputKind::Command, format!("retype {} ", word.unwrap_or_default())));
            }
            ('c', 's') => {
                let signature = self.current_signature();
                self.input = Some((InputKind::Command, format!("sig {}", signature.unwrap_or_default())));
            }
            (']', 'f') | (']', ']') if source => self.with_source(|source, _| Ok(source.jump_function(true))),
            ('[', 'f') | ('[', '[') if source => self.with_source(|source, _| Ok(source.jump_function(false))),
            (']', 'c') | ('[', 'c') if source => {
                let forward = first == ']';
                self.with_source(|source, project| if source.jump_conflict(project, forward) { Ok(()) } else { Err("No conflict in this module".to_string()) });
            }
            _ => {}
        }

        if first == 'w' {
            self.focus = Focus::Content;
        }
    }

    fn focus_dir(&mut self, dir: Dir) {
        if !self.workspace.focus_dir(dir) && dir == Dir::Left && self.explorer_visible {
            self.focus = Focus::Explorer;
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
            KeyCode::Char('g') => self.pending_key = Some('g'),
            KeyCode::Char(c) if c == self.keys.start => select(&mut self.explorer_state, 0),
            KeyCode::Char(c) if c == self.keys.end => select(&mut self.explorer_state, count),
            KeyCode::Enter => self.activate_explorer_item(),
            KeyCode::Char(c) if c == self.keys.right => self.activate_explorer_item(),
            KeyCode::Char('t') => {
                self.open_mode = OpenMode::Tab;
                self.activate_explorer_item();
            }
            KeyCode::Char('s') => {
                self.open_mode = OpenMode::Split(Dir::Down);
                self.activate_explorer_item();
            }
            KeyCode::Char('v') => {
                self.open_mode = OpenMode::Split(Dir::Right);
                self.activate_explorer_item();
            }
            _ => {}
        }
    }

    fn handle_content_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let keys = self.keys.clone();
        let count = self.count.take();
        let repeat = count.unwrap_or(1).max(1) as isize;

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
                if let View::Table(view) = self.view_mut() {
                    view.set_filter("");
                }
            }

            return;
        };

        // g starts a sequence (gg, gt, gT, gd)
        if c == 'g' && !ctrl && !self.in_sequence {
            self.pending_key = Some('g');
            self.count = count;
            return;
        }

        // Half page moves: Ctrl-d / Ctrl-u, or the plain keys (as in the previous versions)
        let half_page_down = c == keys.page_down;
        let half_page_up = c == keys.page_up;

        if matches!(self.view(), View::Source(_)) {
            return self.handle_source_key(c, ctrl, repeat, count);
        }

        match self.view_mut() {
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
                    _ if c == keys.detail => self.graph_detail(false),
                    _ if c == keys.detail.to_ascii_uppercase() => self.graph_detail(true),
                    _ if c == keys.toggle_view => self.toggle_graph_linear(),
                    _ if c == keys.xrefs => self.xrefs_current(),
                    _ if c == keys.call_graph => self.call_graph_current(),
                    _ if c == keys.decompile => self.decompile_current(),
                    '+' | '=' | '-' | 'i' | 'r' => self.call_graph_option(c),
                    _ if c == keys.call_graph_up => self.call_graph_up(),
                    _ => {}
                }
            }
            View::Disasm(view) => {
                let page = (view.height / 2).max(1) as isize;

                match c {
                    _ if half_page_down => view.move_cursor(page),
                    _ if half_page_up => view.move_cursor(-page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.move_cursor(repeat),
                    _ if c == keys.up => view.move_cursor(-repeat),
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
                    _ if c == keys.decompile => self.decompile_current(),
                    _ => {}
                }
            }
            View::Review(view) => {
                let page = (view.height / 2).max(1) as isize;

                match c {
                    _ if half_page_down => view.move_cursor(page),
                    _ if half_page_up => view.move_cursor(-page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.move_cursor(repeat),
                    _ if c == keys.up => view.move_cursor(-repeat),
                    _ if c == keys.start => view.move_cursor(isize::MIN / 2),
                    _ if c == keys.end => view.move_cursor(isize::MAX / 2),
                    _ if c == keys.next_node => view.jump(true),
                    _ if c == keys.prev_node => view.jump(false),
                    'a' | 'r' => {
                        let (program, proposal) = (view.program, view.proposal());

                        if let Some(id) = proposal {
                            let result = self.project(program).ok_or_else(String::new).and_then(|p| if c == 'a' { p.accept(id) } else { p.reject(id) });

                            match result {
                                Ok(()) => self.info(format!("Proposal {} {}", id, if c == 'a' { "accepted, :w to save it" } else { "rejected" })),
                                Err(error) => self.error(error),
                            }
                        }
                    }
                    _ => {}
                }
            }
            View::Table(view) => {
                let page = (view.height / 2).max(1) as isize;

                match c {
                    _ if half_page_down => view.move_cursor(page),
                    _ if half_page_up => view.move_cursor(-page),
                    _ if ctrl => {}
                    _ if c == keys.down => view.move_cursor(repeat),
                    _ if c == keys.up => view.move_cursor(-repeat),
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
            View::Source(_) => {}
        }
    }

    /// Keys of the C code (normal mode)
    fn handle_source_key(&mut self, c: char, ctrl: bool, repeat: isize, count: Option<usize>) {
        let keys = self.keys.clone();
        let App { workspace, projects, .. } = self;

        let View::Source(view) = workspace.view_mut() else {
            return;
        };

        let Some(project) = projects[view.program].as_mut() else {
            return;
        };

        let page = (view.height / 2).max(1) as isize;
        let mut result: Result<(), String> = Ok(());

        match c {
            _ if ctrl && c == keys.page_down => view.move_lines(project, page),
            _ if ctrl && c == keys.page_up => view.move_lines(project, -page),
            _ if ctrl => {}
            _ if c == keys.down => view.move_lines(project, repeat),
            _ if c == keys.up => view.move_lines(project, -repeat),
            _ if c == keys.left => view.move_col(project, -repeat),
            _ if c == keys.right => view.move_col(project, repeat),
            _ if c == keys.down.to_ascii_uppercase() => view.move_lines(project, VERTICAL_STEP as isize),
            _ if c == keys.up.to_ascii_uppercase() => view.move_lines(project, -VERTICAL_STEP as isize),
            _ if c == keys.start => view.first_line(),
            _ if c == keys.end => match count {
                Some(n) => {
                    view.first_line();
                    view.move_lines(project, n as isize - 1);
                }
                None => view.last_line(),
            },
            _ if c == keys.next_node => view.jump_function(true),
            _ if c == keys.prev_node => view.jump_function(false),
            'w' => (0..repeat).for_each(|_| view.word_move(project, true)),
            'b' => (0..repeat).for_each(|_| view.word_move(project, false)),
            '0' => view.line_start(project, false),
            '^' => view.line_start(project, true),
            '$' => view.line_end(project),
            'i' => result = view.start_insert(project, InsertWhere::Cursor),
            'a' => result = view.start_insert(project, InsertWhere::After),
            'A' => result = view.start_insert(project, InsertWhere::LineEnd),
            'I' => result = view.start_insert(project, InsertWhere::LineStart),
            'o' => result = view.start_insert(project, InsertWhere::Below),
            'O' => result = view.start_insert(project, InsertWhere::Above),
            'u' => result = view.undo(project, false),
            'U' => result = view.undo(project, true),
            'd' | 'c' | ']' | '[' => {
                self.pending_key = Some(c);
                return;
            }
            ';' => {
                self.input = Some((InputKind::Command, "comment ".to_string()));
                return;
            }
            'M' => {
                self.input = Some((InputKind::Command, "mv ".to_string()));
                return;
            }
            _ if c == keys.toggle_view || c == keys.decompile => return self.decompile_current(),
            _ if c == keys.xrefs => return self.xrefs_current(),
            _ if c == keys.call_graph => return self.call_graph_current(),
            _ if c == keys.improve => return self.improve_code(),
            _ => {}
        }

        self.report(result);
    }

    /// Identifier under the cursor of the C code
    fn word_under_cursor(&mut self) -> Option<String> {
        let App { workspace, projects, .. } = self;

        return match workspace.view_mut() {
            View::Source(view) => projects[view.program].as_mut().and_then(|p| view.word(p)),
            _ => None,
        };
    }

    fn current_signature(&mut self) -> Option<String> {
        let (program, addr) = self.current_function()?;
        let project = self.projects[program].as_mut()?;

        return project.shown(addr).map(|(r, _)| r.meta.signature.clone());
    }

    /// Goes to what the identifier under the cursor refers to: a function or a global
    fn definition(&mut self) {
        let Some(word) = self.word_under_cursor() else {
            return self.info("No name under the cursor".to_string());
        };

        let Some((program, function)) = self.current_function() else {
            return;
        };

        let Some(project) = self.projects[program].as_mut() else {
            return;
        };

        if let Some(addr) = project.resolve(&word).or_else(|| word.strip_prefix("sub_").and_then(|a| u64::from_str_radix(a, 16).ok())).filter(|a| project.analysis.functions.contains_key(a)) {
            let thunk = project.analysis.functions[&addr].thunk.is_some();

            if thunk {
                return self.info(format!("{} is imported, its code is not in this binary", word));
            }

            // Same module: the cursor moves, otherwise the module of the function opens
            if let View::Source(view) = self.workspace.view_mut() {
                if view.goto(project, addr) {
                    return;
                }
            }

            return self.open_code(program, addr);
        }

        if let Some(addr) = project.global(function, &word) {
            return self.goto_address(program, addr);
        }

        self.info(format!("{} is not a function or a global", word));
    }

    /// Function shown by the current view (graph, linear disassembly or C code)
    fn current_function(&mut self) -> Option<(usize, u64)> {
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
            View::Source(view) => {
                let _ = projects;
                view.function().map(|f| (view.program, f))
            }
            View::Review(view) => {
                let id = view.proposal()?;
                let project = projects[view.program].as_ref()?;
                project.proposals.iter().find(|p| p.id == id).and_then(|p| p.functions.keys().next()).map(|&f| (view.program, f))
            }
            _ => None,
        }
    }

    /// C code of the function shown by the current view, back to the graph from the C code
    fn decompile_current(&mut self) {
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

    /// Shows the C code or the disassembly in the nodes of a graph (the selected one, or all)
    fn graph_detail(&mut self, all: bool) {
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

    fn call_graph_option(&mut self, c: char) {
        let View::Graph(view) = self.view() else {
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
                *self.view_mut() = View::Graph(new_view);
            }
        }
    }

    /// Re-roots the call graph at a caller of its root (popup when there are several)
    fn call_graph_up(&mut self) {
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

    fn toggle_graph_linear(&mut self) {
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

    fn content_enter(&mut self) {
        if matches!(self.view(), View::Source(_)) {
            return self.definition();
        }

        match self.view() {
            View::Table(view) => {
                if let Some(row) = view.selected() {
                    let target = row.target.clone();
                    self.open_target(target);
                }
            }
            View::Review(_) => {
                if let Some((program, addr)) = self.current_function() {
                    self.open_code(program, addr);
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
                    if let View::Disasm(view) = self.view_mut() {
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
        let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let frame = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis()) / 100) as usize % spinner.len();

        if done < total {
            let found: usize = self.progress.iter().map(|p| p.load(Ordering::Relaxed)).sum();
            return format!("{} analyzing... {} functions", spinner[frame], found);
        }

        let functions: usize = self.analyses.iter().flatten().map(|a| a.functions.len()).sum();
        let (decompiled, decompilable) = self.projects.iter().flatten().map(|p| p.progress()).fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
        let llm: usize = self.projects.iter().flatten().map(|p| p.llm_running()).sum();
        let dirty = self.projects.iter().flatten().any(|p| p.is_dirty());

        let mut text = format!("{} functions", functions);

        if decompiled < decompilable {
            text.push_str(&format!("  {} decompiled {}/{}", spinner[frame], decompiled, decompilable));
        } else if decompilable > 0 {
            text.push_str("  all decompiled");
        }

        if llm > 0 {
            text.push_str(&format!("  {} LLM", llm));
        }

        if dirty {
            text.push_str("  [+]");
        }

        return text;
    }

    fn hints(&self) -> &'static str {
        if self.focus == Focus::Explorer {
            return "j/k move  Enter open  t tab  s/v split  Tab content  e hide  : command  ? help  q quit";
        }

        match self.view() {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { .. } => "hjkl scroll  n/p node  t/f branch  Enter calls  v/V C/asm in nodes  Space linear  D code  x xrefs  ^w splits  ? help",
                GraphKind::CallGraph { .. } => "hjkl scroll  n/p node  Enter open  v/V C/asm in nodes  +/- depth  i imports  r re-root  U up  ^w splits  ? help",
            },
            View::Disasm(_) => "j/k move  n/p function  Enter follow  Space graph  D code  x xrefs  / search  ^o back  ? help",
            View::Source(view) if view.insert.is_some() => "-- INSERT --  Esc normal mode",
            View::Source(_) => "hjkl move  Enter/gd go to  i/a/o insert  dd  u/U undo/redo  cn rename  ct retype  cs signature  ; comment  M move  L LLM  :w save",
            View::Review(_) => "j/k move  n/p proposal  a accept  r reject  Enter open the code  :w save",
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
    ("e", "show/hide the explorer (t / s / v in it: open in a new tab / split below / split on the right)"),
    (":", "command line (address, function, :help in the README for the whole list)"),
    ("/", "search (filters tables, finds nodes/lines)"),
    ("Ctrl-o / Backspace", "go back to the previous view of the tab"),
    ("Ctrl-i / Ctrl-r", "go forward"),
    ("q / :qa", "quit (:w saves the project, :qa! quits without saving)"),
    ("Splits and tabs", ""),
    ("Ctrl-w s / v", "split below / on the right (:sp, :vs [function])"),
    ("Ctrl-w h j k l", "go to the split on the left / below / above / on the right"),
    ("Ctrl-w w / p", "next split / previous split"),
    ("Ctrl-w H J K L", "move the tab to the split in that direction"),
    ("Ctrl-w q / o", "close the split / close the other splits"),
    ("Ctrl-w = < > - +", "equal sizes / resize"),
    ("Ctrl-w b", "link with the previous split (:link): their cursors follow each other"),
    ("gt / gT / {n}gt", "next / previous / nth tab (:tabnew, :tabclose)"),
    ("Graph", ""),
    ("h j k l", "scroll by one cell (H J K L by more)"),
    ("n / p, gg / G", "next / previous node, first / last node"),
    ("t / f", "follow the true / false branch"),
    ("v / V", "C code, disassembly or summary in the selected node / in every node"),
    ("Enter", "go to a called function (graph) / open the function (call graph)"),
    ("Space / D", "linear disassembly / C code of the function"),
    ("x / C", "cross references / call graph of the function"),
    ("+ / - / i / r / U", "call graph depth / imports / re-root / go up to a caller"),
    ("C code (module)", ""),
    ("h j k l w b 0 $", "move the cursor, n / p or ]f [f: next / previous function"),
    ("Enter / gd", "go to the function or the global under the cursor"),
    ("i a A I o O, Esc", "insert mode, back to normal mode"),
    ("dd, u / U", "delete the line, undo / redo"),
    ("cn / ct / cs", "rename / retype / give a prototype (:rename, :retype, :sig)"),
    ("; / M", "comment above the line / move the function to a module (:mv)"),
    ("]c [c, :ours :theirs :both", "next / previous conflict, keep the edited side, the decompiled one or both"),
    ("L", "ask the LLM to improve the function (:review to accept or reject)"),
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

    // Explorer
    let content_area = if app.explorer_visible {
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(32.min(chunks[1].width / 3)), Constraint::Min(0)])
            .split(chunks[1]);

        // Only the visible items are built (programs can have thousands of modules)
        let visible = main_chunks[0].height.saturating_sub(2).max(1) as usize;
        let selected = app.explorer_state.selected().unwrap_or(0).min(app.explorer_items.len().saturating_sub(1));

        if selected < app.explorer_offset {
            app.explorer_offset = selected;
        } else if selected >= app.explorer_offset + visible {
            app.explorer_offset = selected + 1 - visible;
        }

        let items: Vec<ListItem> = app.explorer_items.iter().skip(app.explorer_offset).take(visible).map(|item| {
            let style = if matches!(item, ExplorerItem::Group(_)) { theme.title_style() } else { Style::default().fg(theme.fg) };
            ListItem::new(item.display_name(app)).style(style)
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

        let mut state = ListState::default();
        state.select(Some(selected - app.explorer_offset));
        f.render_stateful_widget(explorer, main_chunks[0], &mut state);

        main_chunks[1]
    } else {
        chunks[1]
    };

    // Splits
    let groups = app.workspace.layout(content_area);
    let focused = app.workspace.focused;

    for (id, area) in groups {
        render_group(f, app, &theme, id, area, id == focused);
    }

    // Status / command line
    let status = match (&app.input, &app.message) {
        (Some((kind, text)), _) => Line::from(vec![
            Span::styled(if *kind == InputKind::Command { ":" } else { "/" }, Style::default().fg(theme.title)),
            Span::styled(text.clone(), Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.fg)),
        ]),
        (None, Some((message, error))) => Line::from(Span::styled(message.clone(), Style::default().fg(if *error { theme.warning } else { theme.fg }))),
        (None, None) => {
            let pending = match (app.count, app.pending_key) {
                (None, None) => String::new(),
                (count, key) => format!("{}{}  ", count.map_or(String::new(), |c| c.to_string()), key.map_or(String::new(), |k| if k == 'w' { "^w".to_string() } else { k.to_string() })),
            };

            Line::from(Span::styled(format!("{}{}", pending, app.hints()), Style::default().fg(theme.dim)))
        }
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
                    Span::styled(format!("  {:<26}", key), Style::default().fg(theme.key)),
                    Span::styled(description.to_string(), Style::default().fg(theme.fg)),
                ])
            }
        }).collect();

        let area = centered_rect(120, lines.len() as u16 + 2, f.area());

        f.render_widget(Clear, area);
        f.render_widget(
            Paragraph::new(Text::from(lines)).block(Block::default().title(" Keys (any key to close) ").borders(Borders::ALL).style(theme.base())),
            area,
        );
    }
}

/// A split: its border, its tab bar when it has several tabs, and the view of its active tab
fn render_group(f: &mut Frame, app: &mut App, theme: &Theme, id: workspace::GroupId, area: Rect, focused: bool) {
    let active = focused && app.focus == Focus::Content;
    let linked = app.workspace.linked(id).is_some();
    let group = app.workspace.group(id);
    let view = &group.tabs[group.active].view;

    let title = format!(" {}{} ", view.title(), if linked { " [linked]" } else { "" });

    let block = Block::default()
        .title(Span::styled(title, theme.title_style()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if active { theme.highlight_bg } else { theme.border }))
        .style(theme.base());

    let mut inner = block.inner(area);
    f.render_widget(block, area);

    if group.tabs.len() > 1 && inner.height > 1 {
        let mut spans = Vec::new();

        for (index, tab) in group.tabs.iter().enumerate() {
            let style = if index == group.active { Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg) } else { Style::default().fg(theme.dim) };
            spans.push(Span::styled(format!(" {}:{} ", index + 1, tab.view.tab_title()), style));
            spans.push(Span::raw(" "));
        }

        f.render_widget(Paragraph::new(Line::from(spans)).style(theme.base()), Rect::new(inner.x, inner.y, inner.width, 1));
        inner = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    }

    let height = inner.height as usize;
    let App { workspace, projects, analyses, programs, decoders, analysis_errors, .. } = app;
    let group = workspace.group_mut(id);
    let active_tab = group.active;
    let view = &mut group.tabs[active_tab].view;

    match view {
        View::Welcome => {
            let mut lines = vec![
                Line::from(""),
                Line::from(Span::styled("Welcome to execdump", theme.title_style())),
                Line::from(""),
                Line::from("Pick something in the explorer (j/k, Enter), or type : and an address or a function name."),
                Line::from("Analysis/Entry point opens the control flow graph of the entry point,"),
                Line::from("Modules/ hold the C code of the program, decompiled in the background."),
                Line::from(""),
                Line::from("Ctrl-w v splits the screen, gt goes to the next tab. Press ? at any time for the key bindings."),
            ];

            if let Some(error) = analysis_errors.iter().flatten().next() {
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
            let lines = view.render(theme, height);
            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
        View::Disasm(view) => {
            if let Some(decoder) = decoders[view.program].as_ref() {
                let lines = view.render(theme, &programs[view.program], analyses[view.program].as_deref(), decoder, height);
                f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
            }
        }
        View::Graph(view) => {
            if let Some(project) = projects[view.program].as_mut() {
                view.prioritize(project);
            }

            view.render(inner, f.buffer_mut(), theme);
        }
        View::Source(view) => {
            let lines = match projects[view.program].as_mut() {
                Some(project) => view.render(project, theme, height, inner.width as usize),
                None => vec![Line::from("Analysis in progress...")],
            };

            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
        View::Review(view) => {
            let lines = match projects[view.program].as_ref() {
                Some(project) => view.render(project, theme, height),
                None => Vec::new(),
            };

            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
        View::Table(view) => {
            let lines = view.render(theme, height, inner.width as usize);
            f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), inner);
        }
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}

pub fn main(exec_path: &PathBuf, exec: Exec, keys: KeyBindings, llm: LlmConfig, project: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    crash::install();
    crash::on_crash(Some(Box::new(restore_terminal)));
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(exec, exec_path.clone(), keys, project, default_workers());
    app.llm = llm;

    let result: Result<(), Box<dyn Error>> = (|| {
        loop {
            app.poll_analysis();
            app.poll_projects();

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

    crash::on_crash(None);
    restore_terminal();

    return result;
}

#[cfg(test)]
mod tests {
    use super::*;
    use execdump_core::elf::parse_elf;
    use ratatui::backend::TestBackend;

    fn key(c: char) -> KeyEvent {
        return KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
    }

    fn ctrl(c: char) -> KeyEvent {
        return KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
    }

    fn keys(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(key(c));
        }
    }

    fn enter(app: &mut App) {
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    }

    /// App on the analysis fixture, with its project in a temporary directory
    fn app(name: &str) -> (App, PathBuf) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let location = std::env::temp_dir().join(format!("execdump-tui-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&location);

        let mut app = App::new(Exec::ELF(parse_elf(&path).unwrap()), path, KeyBindings::default(), Some(location.clone()), 1);

        for _ in 0..500 {
            app.poll_analysis();
            app.poll_projects();

            if app.projects.iter().all(|p| p.is_some()) {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(app.projects.iter().all(|p| p.is_some()), "Analysis did not finish");
        return (app, location);
    }

    fn wait_decompiled(app: &mut App) {
        for _ in 0..3000 {
            app.poll_projects();

            if app.projects.iter().flatten().all(|p| p.is_idle()) {
                return;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("Decompilation did not finish");
    }

    #[test]
    fn navigate_views() {
        let (mut app, location) = app("navigate");
        let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();

        // Entry point graph
        enter(&mut app);
        assert!(matches!(app.view(), View::Graph(_)));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        // Command line: go to main
        keys(&mut app, ":main");
        enter(&mut app);
        let View::Graph(view) = app.view() else { panic!("Expected a graph") };
        assert!(view.title.starts_with("main"));

        for c in "njklhpggGtfc".chars() {
            app.handle_key(key(c));
            terminal.draw(|f| ui(f, &mut app)).unwrap();
        }

        // Linear view and back
        app.handle_key(key(' '));
        assert!(matches!(app.view(), View::Disasm(_)));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        app.handle_key(key(' '));
        assert!(matches!(app.view(), View::Graph(_)));

        // Call graph from main, then back to the entry point graph
        app.handle_key(key('C'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        let View::Graph(view) = app.view() else { panic!("Expected a graph") };
        assert!(matches!(view.kind, GraphKind::CallGraph { .. }));
        app.handle_key(key('i'));
        app.handle_key(key('+'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        // Up to the parent graph: classify is called from main, which is selected in it
        app.run_command("cg classify");
        app.handle_key(key('U'));
        if let Some(popup) = app.popup.take() {
            app.open_target(popup.items[0].1.clone());
        }
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        let analysis = app.analyses[0].clone().unwrap();
        let classify = analysis.function_by_name("classify").unwrap().addr;
        let View::Graph(view) = app.view() else { panic!("Expected a graph") };
        let GraphKind::CallGraph { root, .. } = view.kind else { panic!("Expected a call graph") };
        assert!(analysis.callers[&classify].contains(&root));
        assert_eq!(view.selected_node().addr, classify);

        for _ in 0..4 {
            app.handle_key(ctrl('o'));
        }

        let View::Graph(view) = app.view() else { panic!("Expected a graph") };
        assert!(matches!(view.kind, GraphKind::Cfg { .. }));

        // Tables
        app.run_command("functions");
        terminal.draw(|f| ui(f, &mut app)).unwrap();
        app.run_search("main");
        enter(&mut app);
        assert!(matches!(app.view(), View::Graph(_)));

        for command in ["strings", "imports", "sections", "modules", ".text", "review"] {
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

        let _ = std::fs::remove_dir_all(&location);
    }

    #[test]
    fn splits_tabs_and_links() {
        let (mut app, location) = app("splits");
        let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
        wait_decompiled(&mut app);

        app.run_command("main");
        app.handle_key(ctrl('w'));
        app.handle_key(key('v'));
        assert_eq!(app.workspace.group_count(), 2);

        // The new split shows the code of main, linked with the graph
        app.run_command("c main");
        assert!(matches!(app.view(), View::Source(_)));
        app.handle_key(ctrl('w'));
        app.handle_key(key('b'));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        // Moving in the code moves the selection of the graph
        keys(&mut app, "jjjjjjjjjj");
        let source_addr = match app.view() {
            View::Source(_) => {
                let App { workspace, projects, .. } = &mut app;
                App::view_addr(workspace.view(), projects).unwrap().1
            }
            _ => panic!("Expected the C code"),
        };

        app.handle_key(ctrl('w'));
        app.handle_key(key('h'));
        let View::Graph(graph) = app.view() else { panic!("Expected the graph") };
        let analysis = app.analyses[0].clone().unwrap();
        let block = analysis.function_containing(source_addr).unwrap().block_containing(source_addr).unwrap().start;
        assert_eq!(graph.selected_node().addr, block);

        // Tabs in the graph split
        app.run_command("tabnew classify");
        assert_eq!(app.workspace.group(app.workspace.focused).tabs.len(), 2);
        keys(&mut app, "gt");
        assert!(matches!(app.view(), View::Graph(g) if g.title.starts_with("main")));
        keys(&mut app, "2gt");
        assert!(matches!(app.view(), View::Graph(g) if g.title.starts_with("classify")));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        // The tab moves to the code split
        app.handle_key(ctrl('w'));
        app.handle_key(key('L'));
        assert_eq!(app.workspace.group(app.workspace.focused).tabs.len(), 2);
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        app.run_command("q");
        app.run_command("only");
        assert_eq!(app.workspace.group_count(), 1);

        // Sessions: saved with the project, restored when it is opened again
        app.run_command("vs main");
        app.run_command("w");
        assert!(location.join("session.toml").exists());

        let mut reopened = App::new(Exec::ELF(parse_elf(&app.exec_path).unwrap()), app.exec_path.clone(), KeyBindings::default(), Some(location.clone()), 1);

        for _ in 0..500 {
            reopened.poll_analysis();

            if reopened.projects.iter().all(|p| p.is_some()) {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(reopened.workspace.group_count(), 2);
        assert!(matches!(reopened.view(), View::Graph(_)) || matches!(reopened.view(), View::Source(_)));

        let _ = std::fs::remove_dir_all(&location);
    }

    #[test]
    fn code_editing_and_annotations() {
        let (mut app, location) = app("editing");
        let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
        wait_decompiled(&mut app);

        app.run_command("c main");
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        let View::Source(view) = app.view() else { panic!("Expected the C code") };
        assert_eq!(view.module, "analysis.c");
        let main = app.projects[0].as_ref().unwrap().resolve("main").unwrap();
        assert_eq!(view.function(), Some(main));

        // A comment above the first line, typed in insert mode
        keys(&mut app, "O");
        keys(&mut app, "// entry of the program");
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        let project = app.projects[0].as_mut().unwrap();
        let (text, shown) = project.shown(main).map(|(r, s)| (r.text.clone(), s)).unwrap();
        assert!(shown.edited);
        assert!(text.starts_with("// entry of the program\nint main("), "{}", text);

        // Undo, redo
        keys(&mut app, "u");
        assert!(!app.projects[0].as_mut().unwrap().shown(main).unwrap().1.edited);
        keys(&mut app, "U");
        assert!(app.projects[0].as_mut().unwrap().shown(main).unwrap().1.edited);

        // Enter on the call of classify moves to it (same module)
        let classify = app.projects[0].as_ref().unwrap().resolve("classify").unwrap();
        app.run_search("classify(");
        enter(&mut app);
        let View::Source(view) = app.view() else { panic!("Expected the C code") };
        assert_eq!(view.function(), Some(classify));

        // Rename classify from its code, and a variable
        keys(&mut app, "cn");
        assert!(app.input.as_ref().is_some_and(|(kind, t)| *kind == InputKind::Command && t.starts_with("rename ")));
        app.input = None;
        app.run_command("rename classify classify_value");
        app.run_command("rename a1 value");
        app.run_command("mv lib/classes.c");
        wait_decompiled(&mut app);
        terminal.draw(|f| ui(f, &mut app)).unwrap();

        let project = app.projects[0].as_mut().unwrap();
        assert!(project.shown(classify).unwrap().0.text.starts_with("int classify_value(int value)"));
        assert_eq!(project.module_of(classify), Some("lib/classes.c"));

        // The edit of main was rebased on the new name of classify
        let main_text = project.shown(main).unwrap().0.text.clone();
        assert!(main_text.contains("classify_value(") && main_text.starts_with("// entry of the program"), "{}", main_text);

        // The view of analysis.c does not hold classify anymore
        let View::Source(view) = app.view() else { panic!("Expected the C code") };
        assert!(!view.functions.contains(&classify));

        app.run_command("export");
        let out = location.join("export");
        app.run_command(&format!("export {}", out.display()));
        assert!(out.join("src/lib/classes.c").exists(), "{:?}", app.message);

        // Unsaved changes keep the application open
        app.handle_key(key('q'));
        assert!(!app.should_quit);
        app.run_command("w");
        app.run_command("qa");
        assert!(app.should_quit);

        let _ = std::fs::remove_dir_all(&location);
    }
}
