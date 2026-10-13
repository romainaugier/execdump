/*
 * Terminal user interface
 *
 * The executable is parsed once, the Programs are built once and analyzed in a background thread,
 * then each program gets a project: its functions are decompiled in the background, organized in
 * modules, annotated, edited and saved (see execdump-project).
 *
 * The content area is a workspace of splits, each one a group of tabs, each tab a view with its own
 * jumplist (Ctrl-o / Ctrl-i like in vim). Ctrl-w moves between the splits, gt/gT between the tabs.
 *
 * Everything the interface does is a command (commands), bound to keys, run on the focus (the explorer
 * or the view of a split, one module per kind of view), then on the splits, then on the application.
 */

mod actions;
mod commands;
mod explorer;
mod layout;
mod libraries;
mod loading;
mod popup;
mod prompt;
mod render;
mod session;
mod splits;
mod theme;
mod views;
mod workspace;

#[cfg(test)]
mod tests;

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

use execdump_decompiler::analysis::function::CallTarget;
use execdump_decompiler::analysis::insn::Decoder;
use execdump_decompiler::analysis::{analyze, Analysis};
use execdump_decompiler::llm::LlmConfig;
use execdump_core::crash;
use execdump_core::dump::Dump;
use execdump_core::elf::parse_elf;
use execdump_core::exec::{guess_exectype, Exec, ExecType};
use execdump_core::libraries::{needed_libraries, Needed};
use execdump_core::macho::parse_macho;
use execdump_core::pe::parse_pe;
use execdump_core::program::{programs_from_exec, Program};
use execdump_project::{default_location, default_workers, Project};

use commands::{default_bindings, Binding, Key};
use explorer::ExplorerItem;
use libraries::{Library, PendingImport};
use loading::{parse_binary, Loaded, Loading, ANALYSIS};
use popup::Popup;
use render::{centered_rect, ui};
use theme::Theme;
use views::disasm::DisasmView;
use views::dump::DumpView;
use views::graph::{GraphKind, NodeKind};
use views::hex::HexView;
use views::source::SourceView;
use views::{Target, View};
use workspace::{Dir, Workspace};

use serde::{Deserialize, Serialize};

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_CALL_GRAPH_DEPTH: usize = 2;
const HORIZONTAL_STEP: i32 = 10;
const VERTICAL_STEP: i32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Focus {
    Explorer,
    Content,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputKind {
    Command,
    Search,
}

/// Where the next view opens
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenMode {
    /// In the current tab (pushed on its jumplist)
    Replace,
    Tab,
    Split(Dir),
}

pub(crate) struct App {
    exec: Exec,
    exec_path: PathBuf,
    theme: Theme,

    programs: Vec<Arc<Program>>,
    analyses: Vec<Option<Arc<Analysis>>>,
    analysis_errors: Vec<Option<String>>,
    loading: Vec<Loading>,
    /// When the decompilation started, and how many functions were done then (for the remaining time)
    decompile_start: Option<(std::time::Instant, usize)>,
    /// Since when the LLM is running
    llm_start: Option<std::time::Instant>,
    /// Analysis of each program and its project, both made in the background
    receiver: Receiver<Loaded>,
    sender: Sender<Loaded>,
    workers: usize,
    /// Programs of the binary, the ones after them are shared libraries
    main_programs: usize,
    libraries: Vec<Library>,
    pending_import: Option<PendingImport>,
    /// Programs of the session being restored (saved program -> program), once its libraries are loaded
    session_programs: Option<std::collections::HashMap<usize, usize>>,
    decoders: Vec<Option<Decoder>>,

    /// Project of each program, opened when its analysis is done
    projects: Vec<Option<Project>>,
    project_location: Option<PathBuf>,
    /// Session to restore once every project is open
    session_pending: bool,
    pending_export: Option<(usize, PathBuf)>,

    explorer_items: Vec<ExplorerItem>,
    /// Depth of each item in the tree
    explorer_depths: Vec<u8>,
    /// Keys of the collapsed nodes
    explorer_collapsed: std::collections::HashSet<String>,
    /// Width that fits the items, and the one given with < and > (instead)
    explorer_fit: u16,
    explorer_width: Option<u16>,
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
    /// Suggestions of the command line, the commands run (Up / Down in the command line)
    completion: Option<prompt::Completion>,
    history: Vec<String>,
    history_index: Option<usize>,
    last_search: String,
    /// The last search is active: n / p go to its matches
    searching: bool,
    message: Option<(String, bool)>,
    popup: Option<Popup>,
    help: bool,
    /// First line of the help shown
    help_scroll: usize,
    should_quit: bool,
    /// Keys of a sequence being typed (g, d, c, ], [, Ctrl-w) and the count typed before it
    pending: Vec<Key>,
    count: Option<usize>,
    bindings: Vec<Binding>,

    llm: LlmConfig,
}

impl App {
    pub(crate) fn new(exec: Exec, exec_path: PathBuf, keys: KeyBindings, project_location: Option<PathBuf>, workers: usize) -> Self {
        let programs: Vec<Arc<Program>> = programs_from_exec(&exec).into_iter().map(Arc::new).collect();
        let (sender, receiver) = channel();
        let count = programs.len();
        let loading = programs.iter().enumerate().map(|(i, program)| Loading::start(i, count, program.clone(), &sender, &exec_path, project_location.clone(), workers)).collect();

        let projects: Vec<Option<Project>> = programs.iter().map(|_| None).collect();
        let libraries: Vec<Library> = needed_libraries(&exec, &exec_path).into_iter().map(Library::new).collect();
        let mut explorer_state = ListState::default();
        explorer_state.select(Some(2));

        return App {
            sender,
            workers,
            main_programs: programs.len(),
            libraries,
            pending_import: None,
            session_programs: None,
            decoders: programs.iter().map(|p| Decoder::new(p.architecture()).ok()).collect(),
            analyses: vec![None; programs.len()],
            analysis_errors: vec![None; programs.len()],
            programs,
            loading,
            decompile_start: None,
            llm_start: None,
            receiver,
            projects,
            project_location,
            session_pending: true,
            pending_export: None,
            exec,
            exec_path,
            theme: Theme::codedark(),
            explorer_items: Vec::new(),
            explorer_depths: Vec::new(),
            explorer_collapsed: (0..count).flat_map(|p| ["headers", "sections", "tables"].map(|g| format!("p{}/{}", p, g))).collect(),
            explorer_fit: 24,
            explorer_width: None,
            explorer_state,
            explorer_visible: true,
            explorer_version: u64::MAX,
            explorer_offset: 0,
            focus: Focus::Explorer,
            workspace: Workspace::new(View::Welcome),
            open_mode: OpenMode::Replace,
            synced: None,
            input: None,
            completion: None,
            history: Vec::new(),
            history_index: None,
            last_search: String::new(),
            searching: false,
            message: None,
            popup: None,
            help: false,
            help_scroll: 0,
            should_quit: false,
            pending: Vec::new(),
            count: None,
            bindings: default_bindings(&keys),
            llm: LlmConfig::default(),
        };
    }

    fn view(&self) -> &View {
        return self.workspace.view();
    }

    fn view_mut(&mut self) -> &mut View {
        return self.workspace.view_mut();
    }

    pub(crate) fn analysis(&mut self, program: usize) -> Option<Arc<Analysis>> {
        if let Some(analysis) = &self.analyses[program] {
            return Some(analysis.clone());
        }

        if let Some(error) = &self.analysis_errors[program] {
            self.error(format!("Analysis failed: {}", error));
        } else {
            self.error(format!("Analysis in progress ({} functions so far), try again in a moment", self.loading[program].functions.load(Ordering::Relaxed)));
        }

        return None;
    }

    pub(crate) fn project(&mut self, program: usize) -> Option<&mut Project> {
        if self.projects[program].is_none() {
            self.analysis(program);
        }

        return self.projects[program].as_mut();
    }

    pub(crate) fn current_program(&self) -> usize {
        return self.view().program().unwrap_or(0);
    }

    pub(crate) fn info(&mut self, message: String) {
        self.message = Some((message, false));
    }

    pub(crate) fn error(&mut self, message: String) {
        self.message = Some((message, true));
    }

    pub(crate) fn report(&mut self, result: Result<(), String>) {
        if let Err(error) = result {
            self.error(error);
        }
    }

    /*
     * Quitting
     */

    pub(crate) fn quit(&mut self, force: bool) {
        let dirty = self.projects.iter().flatten().any(|p| p.is_dirty());

        if dirty && !force {
            self.error("Unsaved changes: :w to save them, :qa! to quit without saving".to_string());
            return;
        }

        self.save_session();
        self.should_quit = true;
    }

    /*
     * Keys
     */

    /// A key: to the command line, the popup, the help or the insert mode when they are open, otherwise
    /// to the bindings (see commands)
    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if self.input.is_some() {
            return self.prompt_key(key);
        }

        if self.popup.is_some() {
            return self.popup_key(key);
        }

        if self.help {
            return self.help_key(key);
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
        self.sequence_key(key);
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

