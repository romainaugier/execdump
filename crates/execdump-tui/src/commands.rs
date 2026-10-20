/*
 * Commands: everything the interface does is a command, run from the command line (:name arguments) or
 * from the keys bound to it.
 *
 * Keys are bound to the text of a command in a context: the global one, the explorer, the content (any
 * view) or a kind of view. The keys typed are matched against the bindings of the contexts of the focus,
 * the most specific first, a sequence waits for its next key while it is the start of a binding (gt,
 * Ctrl-w v, dd), a count typed before it is given to the command (3gt, 10j).
 *
 * A command goes to the focus first (the explorer, or the view of the focused split), then bubbles up to
 * the splits and tabs, then to the application.
 */

use super::*;

use crate::debug::DebugAction;
use crate::views::source::{InsertWhere, Reach};

use anyhow::{anyhow, bail, Context as _, Result};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/*
 * Keys
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub code: KeyCode,
    pub ctrl: bool,
}

impl Key {
    pub fn char(c: char) -> Key {
        return Key { code: KeyCode::Char(c), ctrl: false };
    }

    pub fn from_event(event: KeyEvent) -> Key {
        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);

        // Shifted letters come as uppercase characters, sometimes with the shift modifier
        return Key { code: event.code, ctrl };
    }

    pub fn name(&self) -> String {
        let name = match self.code {
            KeyCode::Char(' ') => "Space".to_string(),
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Enter => "Enter".to_string(),
            KeyCode::Esc => "Esc".to_string(),
            KeyCode::Tab => "Tab".to_string(),
            KeyCode::Backspace => "Backspace".to_string(),
            KeyCode::Up => "Up".to_string(),
            KeyCode::Down => "Down".to_string(),
            KeyCode::Left => "Left".to_string(),
            KeyCode::Right => "Right".to_string(),
            KeyCode::PageUp => "PageUp".to_string(),
            KeyCode::PageDown => "PageDown".to_string(),
            KeyCode::Home => "Home".to_string(),
            KeyCode::End => "End".to_string(),
            KeyCode::F(n) => format!("F{}", n),
            other => format!("{:?}", other),
        };

        return if self.ctrl { format!("Ctrl-{}", name) } else { name };
    }
}

/// Keys of a notation: characters, <C-x>, <Enter>, <Esc>, <Tab>, <BS>, <Space>, <lt>, <Up>, <Down>...
pub(crate) fn parse_keys(text: &str) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut rest = text;

    while let Some(c) = rest.chars().next() {
        let special = rest.strip_prefix('<').and_then(|r| r.split_once('>')).filter(|(name, _)| name.len() > 1);

        let Some((name, after)) = special else {
            keys.push(Key::char(c));
            rest = &rest[c.len_utf8()..];
            continue;
        };

        let (ctrl, name) = match name.strip_prefix("C-") {
            Some(name) => (true, name),
            None => (false, name),
        };

        let code = match name {
            "Enter" | "CR" => KeyCode::Enter,
            "Esc" => KeyCode::Esc,
            "Tab" => KeyCode::Tab,
            "BS" => KeyCode::Backspace,
            "Space" => KeyCode::Char(' '),
            "lt" => KeyCode::Char('<'),
            "Up" => KeyCode::Up,
            "Down" => KeyCode::Down,
            "Left" => KeyCode::Left,
            "Right" => KeyCode::Right,
            "PageUp" => KeyCode::PageUp,
            "PageDown" => KeyCode::PageDown,
            "Home" => KeyCode::Home,
            "End" => KeyCode::End,
            function if function.starts_with('F') && function[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n)) => KeyCode::F(function[1..].parse().unwrap_or(1)),
            single if single.chars().count() == 1 => KeyCode::Char(single.chars().next().unwrap()),
            _ => {
                keys.push(Key::char('<'));
                rest = &rest[1..];
                continue;
            }
        };

        keys.push(Key { code, ctrl });
        rest = after;
    }

    return keys;
}

/// Name of a sequence of keys: gt, dd, Ctrl-w v
pub(crate) fn sequence_name(keys: &[Key]) -> String {
    let mut name = String::new();

    for (index, key) in keys.iter().enumerate() {
        let previous = index.checked_sub(1).map(|i| keys[i]);

        if previous.is_some_and(|p| p.ctrl || !matches!(p.code, KeyCode::Char(_)) || key.ctrl || !matches!(key.code, KeyCode::Char(_))) {
            name.push(' ');
        }

        name.push_str(&key.name());
    }

    return name;
}

/// Notation of a character (configured keys)
fn key_text(c: char) -> String {
    return match c {
        ' ' => "<Space>".to_string(),
        '<' => "<lt>".to_string(),
        c => c.to_string(),
    };
}

/*
 * Commands
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Motion {
    Down,
    Up,
    Left,
    Right,
    /// Several lines or cells at once (J K H L)
    JumpDown,
    JumpUp,
    JumpLeft,
    JumpRight,
    PageDown,
    PageUp,
    First,
    Last,
    /// Next node, label, function or proposal
    Next,
    Previous,
    WordNext,
    WordPrevious,
    LineStart,
    LineFirst,
    LineEnd,
    NextFunction,
    PreviousFunction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Command {
    // Application
    Quit { all: bool, force: bool },
    Write(Option<String>),
    WriteQuit,
    /// Opens the command line with a text ({word}: the identifier under the cursor, {signature}: of the function)
    Prompt(String),
    Search,
    /// Next (or previous) match of the search
    SearchAgain { forward: bool },
    ClearSearch,
    Help,
    Back,
    Forward,
    SwitchFocus,
    ToggleExplorer,
    ExplorerWidth(Option<i32>),

    // Moves and opening, in the explorer and in the views
    Move(Motion),
    Open(OpenMode),
    /// Explorer: closes the node, or goes to its parent
    Close,
    Definition,

    // Views
    Goto(String),
    CallGraph(Option<String>),
    Code(Option<String>),
    Module(Option<String>),
    Table(String),
    Entry,
    Depth(usize),
    DepthBy(i32),
    CallGraphUp,
    ToggleImports,
    Reroot,
    Follow(bool),
    Center,
    Detail { all: bool },
    /// Graph and linear disassembly
    ToggleView,
    /// Code and graph
    ToggleCode,
    Xrefs,
    FunctionCallGraph,
    Review,
    Accept(Option<u64>),
    Reject(Option<u64>),

    // C code and annotations
    Insert(InsertWhere),
    Undo,
    Redo,
    DeleteLine,
    /// Deletes what a motion goes over, then inserts when it changes it (dw, cw, d$...)
    Operator { change: bool, reach: Reach },
    Conflict { forward: bool },
    Rename(String, String),
    Retype(String, String),
    Signature(String),
    Summary(String),
    Comment(String),
    /// The string literal under the cursor in its forms (text, C, bytes, shell, Python)
    StringForms,
    Revert,
    Resolve { edited: bool, decompiled: bool },
    MoveFunction(String, Option<String>),
    MakeModule(String),
    RemoveModule(String),
    RenameModule(String, String),
    Improve,
    Rewrite,
    LlmModules(Option<String>),
    Export(String),
    Library(String),

    // Debugger
    /// Runs the program under the debugger, with its arguments
    Debug(Vec<String>),
    Debugger(DebugAction),
    /// Toggles a breakpoint at a function or an address, at the line under the cursor without one
    Break(Option<String>),
    /// Frame of the call stack the variables and the code are shown for
    SelectFrame(usize),

    // Splits and tabs
    Split { dir: Dir, target: Option<String> },
    TabNew(Option<String>),
    TabClose,
    TabNext,
    TabPrevious,
    Only,
    Link,
    FocusSplit(Dir),
    NextSplit,
    PreviousSplit,
    LastSplit,
    CloseSplit,
    MoveTab(Dir),
    Equalize,
    Resize { width: bool, delta: i32 },
}

/// What the arguments of a command are, for the completion
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Complete {
    Nothing,
    Function,
    Module,
    Library,
    /// A variable of the current function, or a function
    Name,
    Llm,
    Path,
    Proposal,
    Words(&'static [&'static str]),
}

pub(crate) struct Spec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub usage: &'static str,
    pub help: &'static str,
    pub group: &'static str,
    pub complete: Complete,
}

const fn spec(name: &'static str, aliases: &'static [&'static str], usage: &'static str, help: &'static str, group: &'static str, complete: Complete) -> Spec {
    return Spec { name, aliases, usage, help, group, complete };
}

const APP: &str = "Application";
const MOVES: &str = "Moves";
const SPLITS: &str = "Splits and tabs";
const VIEWS: &str = "Views";
const GRAPH: &str = "Graphs";
const CODE: &str = "C code";
const PROJECT: &str = "Project";
const DEBUG: &str = "Debugger";

use Complete as C;

const DIRECTIONS: &[&str] = &["left", "down", "up", "right"];
const REACHES: &[&str] = &["word", "word-end", "word-back", "line-end", "line-start", "line-first", "line", "down", "up", "char", "char-back"];

/// Every command, in the order of the help
pub(crate) const SPECS: &[Spec] = &[
    spec("quit", &["q", "close", "clo"], "", "close the tab (the split with its last tab, execdump with the last split)", APP, C::Nothing),
    spec("quit!", &["q!"], "", "close the tab, even with unsaved changes", APP, C::Nothing),
    spec("qall", &["qa", "quitall"], "", "quit (unsaved changes keep execdump open)", APP, C::Nothing),
    spec("qall!", &["qa!", "quitall!"], "", "quit without saving", APP, C::Nothing),
    spec("write", &["w"], "[directory]", "save the project and the session, in another directory when given", APP, C::Path),
    spec("wq", &["x"], "", "save and quit", APP, C::Nothing),
    spec("prompt", &[], "[text]", "command line", APP, C::Nothing),
    spec("search", &[], "", "search (filters the tables, finds the nodes and the lines)", APP, C::Nothing),
    spec("search-next", &[], "", "next match of the search", APP, C::Nothing),
    spec("search-previous", &[], "", "previous match of the search", APP, C::Nothing),
    spec("clear-search", &["nohlsearch", "noh"], "", "clear the search (the filter of the tables)", APP, C::Nothing),
    spec("help", &["h"], "", "keys and commands", APP, C::Nothing),
    spec("back", &[], "", "previous view of the tab", APP, C::Nothing),
    spec("forward", &[], "", "next view of the tab", APP, C::Nothing),
    spec("switch-focus", &[], "", "switch between the explorer and the content", APP, C::Nothing),
    spec("toggle-explorer", &["explorer"], "", "show or hide the explorer", APP, C::Nothing),
    spec("explorer-width", &[], "[+n|-n]", "widen or narrow the explorer, fit its content without a size", APP, C::Nothing),
    spec("move-down", &[], "", "down (scroll in the graphs)", MOVES, C::Nothing),
    spec("move-up", &[], "", "up", MOVES, C::Nothing),
    spec("move-left", &[], "", "left", MOVES, C::Nothing),
    spec("move-right", &[], "", "right", MOVES, C::Nothing),
    spec("jump-down", &[], "", "down by several lines", MOVES, C::Nothing),
    spec("jump-up", &[], "", "up by several lines", MOVES, C::Nothing),
    spec("jump-left", &[], "", "left by several cells", MOVES, C::Nothing),
    spec("jump-right", &[], "", "right by several cells", MOVES, C::Nothing),
    spec("page-down", &[], "", "half a page down", MOVES, C::Nothing),
    spec("page-up", &[], "", "half a page up", MOVES, C::Nothing),
    spec("first", &[], "", "first line, node or item", MOVES, C::Nothing),
    spec("last", &[], "", "last line, node or item ({n}G: line n of the C code)", MOVES, C::Nothing),
    spec("next", &[], "", "next node, label, function or proposal", MOVES, C::Nothing),
    spec("previous", &[], "", "previous node, label, function or proposal", MOVES, C::Nothing),
    spec("word-next", &[], "", "next word", MOVES, C::Nothing),
    spec("word-previous", &[], "", "previous word", MOVES, C::Nothing),
    spec("line-start", &[], "", "start of the line", MOVES, C::Nothing),
    spec("line-first", &[], "", "first character of the line", MOVES, C::Nothing),
    spec("line-end", &[], "", "end of the line", MOVES, C::Nothing),
    spec("next-function", &[], "", "next function of the module", MOVES, C::Nothing),
    spec("previous-function", &[], "", "previous function of the module", MOVES, C::Nothing),
    spec("open", &[], "[tab|split|vsplit]", "open the item, follow the instruction, go to the called function", MOVES, C::Words(&["tab", "split", "vsplit"])),
    spec("close", &[], "", "close the node of the explorer, or go to its parent", MOVES, C::Nothing),
    spec("definition", &[], "", "go to the function or the global under the cursor", MOVES, C::Nothing),
    spec("callgraph", &["cg"], "[function]", "call graph (of the entry point without a function)", VIEWS, C::Function),
    spec("decompile", &["c"], "[function]", "C code of a function (the current one without a name)", VIEWS, C::Function),
    spec("source", &["src", "module"], "[module]", "C code of a module", VIEWS, C::Module),
    spec("functions", &["fn"], "", "table of the functions", VIEWS, C::Nothing),
    spec("strings", &[], "", "table of the strings", VIEWS, C::Nothing),
    spec("imports", &[], "", "table of the imports", VIEWS, C::Nothing),
    spec("modules", &["mods"], "", "table of the modules", VIEWS, C::Nothing),
    spec("sections", &["memmap", "maps"], "", "memory map", VIEWS, C::Nothing),
    spec("entry", &[], "", "graph of the entry point", VIEWS, C::Nothing),
    spec("review", &["proposals"], "", "review the proposals of the LLM", VIEWS, C::Nothing),
    spec("toggle-view", &[], "", "graph or linear disassembly of the function", VIEWS, C::Nothing),
    spec("toggle-code", &[], "", "C code of the function, back to its graph from the code", VIEWS, C::Nothing),
    spec("xrefs", &[], "", "cross references to the function", VIEWS, C::Nothing),
    spec("function-call-graph", &[], "", "call graph of the function", VIEWS, C::Nothing),
    spec("follow", &[], "<true|false>", "follow the true or the false branch", GRAPH, C::Words(&["true", "false"])),
    spec("center", &[], "", "center the selected node", GRAPH, C::Nothing),
    spec("detail", &[], "[all]", "C code, disassembly or summary in the selected node (in every node)", GRAPH, C::Words(&["all"])),
    spec("depth", &[], "<n|+n|-n>", "depth of the call graph", GRAPH, C::Nothing),
    spec("toggle-imports", &[], "", "imported functions in the call graph", GRAPH, C::Nothing),
    spec("reroot", &[], "", "call graph rooted at the selected function", GRAPH, C::Nothing),
    spec("up", &["parent"], "", "call graph rooted at a caller of its root", GRAPH, C::Nothing),
    spec("accept", &[], "[n]", "accept a proposal (the selected one without a number)", PROJECT, C::Proposal),
    spec("reject", &[], "[n]", "reject a proposal (the selected one without a number)", PROJECT, C::Proposal),
    spec("insert", &[], "[after|end|start|below|above]", "insert mode (Esc: back to normal mode)", CODE, C::Words(&["after", "end", "start", "below", "above"])),
    spec("undo", &[], "", "undo the last change", CODE, C::Nothing),
    spec("redo", &[], "", "redo the last undone change", CODE, C::Nothing),
    spec("delete-line", &[], "", "delete the line", CODE, C::Nothing),
    spec("delete", &[], "<motion>", "delete over a motion: word, word-end, word-back, line-end, line-start, line-first, line, down, up, char, char-back", CODE, C::Words(REACHES)),
    spec("change", &[], "<motion>", "delete over a motion, then insert", CODE, C::Words(REACHES)),
    spec("next-conflict", &[], "", "next conflict", CODE, C::Nothing),
    spec("previous-conflict", &[], "", "previous conflict", CODE, C::Nothing),
    spec("rename", &["ren"], "<name> <new name>", "rename a variable, a function or a global (- restores the original name)", CODE, C::Name),
    spec("retype", &[], "<variable> <C type>", "retype a variable (same size only, - restores it)", CODE, C::Name),
    spec("sig", &["signature", "prototype"], "<prototype>", "prototype of the current function (its callers follow)", CODE, C::Nothing),
    spec("summary", &[], "[text]", "summary of the function, a comment at the top of its code", CODE, C::Nothing),
    spec("comment", &[], "<text>", "comment above the line", CODE, C::Nothing),
    spec("string", &["str"], "", "the string literal under the cursor as text, C, bytes, shell and Python (Enter copies one)", CODE, C::Nothing),
    spec("revert", &[], "", "drop the edits of the current function", CODE, C::Nothing),
    spec("ours", &["edited"], "", "resolve the conflict: keep the edited code", CODE, C::Nothing),
    spec("theirs", &["decompiled"], "", "resolve the conflict: keep the decompiled code", CODE, C::Nothing),
    spec("both", &[], "", "resolve the conflict: keep both", CODE, C::Nothing),
    spec("mv", &["move"], "<module> [function]", "move a function to a module", PROJECT, C::Module),
    spec("mkmod", &["newmod"], "<module>", "create a module (a path such as net/socket.c)", PROJECT, C::Module),
    spec("rmmod", &[], "<module>", "remove a module", PROJECT, C::Module),
    spec("renmod", &[], "<old> <new>", "rename a module", PROJECT, C::Module),
    spec("llm", &[], "[rewrite|modules [module|all]]", "ask the LLM to improve the function, rewrite it, organize the modules", PROJECT, C::Llm),
    spec("rewrite", &[], "", "ask the LLM to rewrite the function as clear C", PROJECT, C::Nothing),
    spec("export", &[], "<directory>", "export the C code as a source tree", PROJECT, C::Path),
    spec("lib", &["library"], "<name or path>", "load a shared library", PROJECT, C::Library),
    spec("debug", &[], "[arguments]", "run the program under the debugger (gdb or lldb): to its first breakpoint, to main without one", DEBUG, C::Nothing),
    spec("continue", &["cont"], "", "continue the program (start it under the debugger when it is not)", DEBUG, C::Nothing),
    spec("step", &["s"], "", "next line of C, into the functions it calls", DEBUG, C::Nothing),
    spec("step-over", &["over", "n"], "", "next line of C of the function, over the calls", DEBUG, C::Nothing),
    spec("finish", &["step-out", "fin"], "", "until the function returns", DEBUG, C::Nothing),
    spec("stepi", &["si"], "", "next instruction, into the calls", DEBUG, C::Nothing),
    spec("nexti", &["ni"], "", "next instruction, over the calls", DEBUG, C::Nothing),
    spec("interrupt", &["pause"], "", "stop the running program", DEBUG, C::Nothing),
    spec("kill", &["stop-debug"], "", "kill the program and the debugger", DEBUG, C::Nothing),
    spec("break", &["b", "br"], "[function or address]", "toggle a breakpoint (at the line or the instruction under the cursor without an argument)", DEBUG, C::Function),
    spec("frame", &[], "<n>", "frame of the call stack the code and the variables are shown for", DEBUG, C::Nothing),
    spec("split", &["sp", "new"], "[function]", "split below (on a function)", SPLITS, C::Function),
    spec("vsplit", &["vs", "vnew"], "[function]", "split on the right (on a function)", SPLITS, C::Function),
    spec("tabnew", &["tabe", "tabedit"], "[function]", "new tab (on a function)", SPLITS, C::Function),
    spec("tabclose", &["tabc"], "", "close the tab", SPLITS, C::Nothing),
    spec("tabnext", &["tabn"], "", "next tab ({n}gt: tab n)", SPLITS, C::Nothing),
    spec("tabprevious", &["tabp", "tabN"], "", "previous tab", SPLITS, C::Nothing),
    spec("only", &["on"], "", "close the other splits", SPLITS, C::Nothing),
    spec("link", &["unlink"], "", "link with the previous split: their cursors follow each other", SPLITS, C::Nothing),
    spec("focus-split", &[], "<left|down|up|right>", "go to the split in a direction", SPLITS, C::Words(DIRECTIONS)),
    spec("next-split", &[], "", "next split", SPLITS, C::Nothing),
    spec("previous-split", &[], "", "previous split", SPLITS, C::Nothing),
    spec("last-split", &[], "", "split focused before", SPLITS, C::Nothing),
    spec("close-split", &[], "", "close the split", SPLITS, C::Nothing),
    spec("move-tab", &[], "<left|down|up|right>", "move the tab to the split in a direction", SPLITS, C::Words(DIRECTIONS)),
    spec("equalize", &[], "", "equal sizes", SPLITS, C::Nothing),
    spec("resize-width", &[], "<+n|-n>", "wider or narrower split", SPLITS, C::Nothing),
    spec("resize-height", &[], "<+n|-n>", "taller or shorter split", SPLITS, C::Nothing),
];

/// Spec of a command name or alias
pub(crate) fn find_spec(name: &str) -> Option<&'static Spec> {
    return SPECS.iter().find(|s| s.name == name).or_else(|| SPECS.iter().find(|s| s.aliases.contains(&name)));
}

fn direction(text: Option<&str>) -> Result<Dir> {
    return match text {
        Some("left" | "h") => Ok(Dir::Left),
        Some("down" | "j") => Ok(Dir::Down),
        Some("up" | "k") => Ok(Dir::Up),
        Some("right" | "l") => Ok(Dir::Right),
        _ => Err(anyhow!("a direction: left, down, up or right")),
    };
}

fn signed(text: Option<&str>) -> Option<i32> {
    return text.and_then(|t| t.trim_start_matches('+').parse().ok());
}

/// Command of a command line: a command and its arguments, or an address or a function to go to
pub(crate) fn parse(text: &str) -> Result<Command> {
    let text = text.trim_start();
    let (name, rest) = text.split_once(char::is_whitespace).map_or((text.trim_end(), ""), |(n, r)| (n, r));

    // The text of the command line keeps its spaces
    if name == "prompt" {
        return Ok(Command::Prompt(rest.to_string()));
    }

    let rest = rest.trim();
    let mut words = rest.split_whitespace();
    let (first, second) = (words.next(), words.next());
    let first_owned = first.map(|w| w.to_string());
    let usage = |spec: &Spec| anyhow!("Usage: {} {}", spec.name, spec.usage);

    if name.is_empty() {
        bail!("empty command line");
    }

    let Some(spec) = find_spec(name) else {
        return Ok(Command::Goto(text.trim().to_string()));
    };

    return Ok(match spec.name {
        "quit" => Command::Quit { all: false, force: false },
        "quit!" => Command::Quit { all: false, force: true },
        "qall" => Command::Quit { all: true, force: false },
        "qall!" => Command::Quit { all: true, force: true },
        "write" => Command::Write(Some(rest.to_string()).filter(|r| !r.is_empty())),
        "wq" => Command::WriteQuit,
        "search" => Command::Search,
        "search-next" => Command::SearchAgain { forward: true },
        "search-previous" => Command::SearchAgain { forward: false },
        "clear-search" => Command::ClearSearch,
        "help" => Command::Help,
        "back" => Command::Back,
        "forward" => Command::Forward,
        "switch-focus" => Command::SwitchFocus,
        "toggle-explorer" => Command::ToggleExplorer,
        "explorer-width" => Command::ExplorerWidth(signed(first)),
        "move-down" => Command::Move(Motion::Down),
        "move-up" => Command::Move(Motion::Up),
        "move-left" => Command::Move(Motion::Left),
        "move-right" => Command::Move(Motion::Right),
        "jump-down" => Command::Move(Motion::JumpDown),
        "jump-up" => Command::Move(Motion::JumpUp),
        "jump-left" => Command::Move(Motion::JumpLeft),
        "jump-right" => Command::Move(Motion::JumpRight),
        "page-down" => Command::Move(Motion::PageDown),
        "page-up" => Command::Move(Motion::PageUp),
        "first" => Command::Move(Motion::First),
        "last" => Command::Move(Motion::Last),
        "next" => Command::Move(Motion::Next),
        "previous" => Command::Move(Motion::Previous),
        "word-next" => Command::Move(Motion::WordNext),
        "word-previous" => Command::Move(Motion::WordPrevious),
        "line-start" => Command::Move(Motion::LineStart),
        "line-first" => Command::Move(Motion::LineFirst),
        "line-end" => Command::Move(Motion::LineEnd),
        "next-function" => Command::Move(Motion::NextFunction),
        "previous-function" => Command::Move(Motion::PreviousFunction),
        "open" => Command::Open(match first {
            None => OpenMode::Replace,
            Some("tab") => OpenMode::Tab,
            Some("split") => OpenMode::Split(Dir::Down),
            Some("vsplit") => OpenMode::Split(Dir::Right),
            Some(_) => return Err(usage(spec)),
        }),
        "close" => Command::Close,
        "definition" => Command::Definition,
        "callgraph" => Command::CallGraph(first_owned),
        "decompile" => Command::Code(first_owned),
        "source" => Command::Module(first_owned),
        "functions" | "strings" | "imports" | "modules" => Command::Table(spec.name.to_string()),
        "sections" => Command::Table("memmap".to_string()),
        "entry" => Command::Entry,
        "review" => Command::Review,
        "toggle-view" => Command::ToggleView,
        "toggle-code" => Command::ToggleCode,
        "xrefs" => Command::Xrefs,
        "function-call-graph" => Command::FunctionCallGraph,
        "follow" => Command::Follow(match first {
            Some("true" | "t") => true,
            Some("false" | "f") => false,
            _ => return Err(usage(spec)),
        }),
        "center" => Command::Center,
        "detail" => Command::Detail { all: first == Some("all") },
        "depth" => match first {
            Some(d) if d.starts_with('+') || d.starts_with('-') => Command::DepthBy(signed(first).ok_or_else(|| usage(spec))?),
            Some(d) => Command::Depth(d.parse().map_err(|_| anyhow!("Usage in a call graph: depth <n>"))?),
            None => bail!("Usage in a call graph: depth <n>"),
        },
        "toggle-imports" => Command::ToggleImports,
        "reroot" => Command::Reroot,
        "up" => Command::CallGraphUp,
        "accept" | "reject" => {
            let id = match first {
                Some(n) => Some(n.parse::<u64>().map_err(|_| anyhow!("Usage: {} <proposal number>", spec.name))?),
                None => None,
            };

            if spec.name == "accept" { Command::Accept(id) } else { Command::Reject(id) }
        }
        "insert" => Command::Insert(match first {
            None => InsertWhere::Cursor,
            Some("after") => InsertWhere::After,
            Some("end") => InsertWhere::LineEnd,
            Some("start") => InsertWhere::LineStart,
            Some("below") => InsertWhere::Below,
            Some("above") => InsertWhere::Above,
            Some(_) => return Err(usage(spec)),
        }),
        "undo" => Command::Undo,
        "redo" => Command::Redo,
        "delete-line" => Command::DeleteLine,
        "delete" | "change" => {
            let reach = match first {
                Some("word") => Reach::Word,
                Some("word-end") => Reach::WordEnd,
                Some("word-back") => Reach::WordBack,
                Some("line-end") => Reach::LineEnd,
                Some("line-start") => Reach::LineStart,
                Some("line-first") => Reach::LineFirst,
                Some("line") => Reach::Line,
                Some("down") => Reach::Down,
                Some("up") => Reach::Up,
                Some("char") => Reach::Char,
                Some("char-back") => Reach::CharBack,
                _ => return Err(usage(spec)),
            };

            Command::Operator { change: spec.name == "change", reach }
        }
        "next-conflict" => Command::Conflict { forward: true },
        "previous-conflict" => Command::Conflict { forward: false },
        "rename" => match (first, second) {
            (Some(old), Some(new)) => Command::Rename(old.to_string(), new.to_string()),
            _ => bail!("Usage: rename <name> <new name> (- restores the original name)"),
        },
        "retype" => match rest.split_once(char::is_whitespace) {
            Some((var, ty)) => Command::Retype(var.to_string(), ty.trim().to_string()),
            None => bail!("Usage: retype <variable> <C type> (- restores the recovered type)"),
        },
        "sig" => Command::Signature(rest.to_string()),
        "summary" => Command::Summary(rest.to_string()),
        "comment" => Command::Comment(rest.to_string()),
        "string" => Command::StringForms,
        "revert" => Command::Revert,
        "ours" => Command::Resolve { edited: true, decompiled: false },
        "theirs" => Command::Resolve { edited: false, decompiled: true },
        "both" => Command::Resolve { edited: true, decompiled: true },
        "mv" => Command::MoveFunction(first.map(|m| m.to_string()).context("Usage: mv <module path> [function]")?, second.map(|f| f.to_string())),
        "mkmod" => Command::MakeModule(first.map(|m| m.to_string()).context("Usage: mkmod <module path>")?),
        "rmmod" => Command::RemoveModule(first.map(|m| m.to_string()).context("Usage: rmmod <module path>")?),
        "renmod" => match (first, second) {
            (Some(old), Some(new)) => Command::RenameModule(old.to_string(), new.to_string()),
            _ => bail!("Usage: renmod <old module> <new module>"),
        },
        "llm" => match first {
            Some("modules" | "mods") => Command::LlmModules(second.map(|s| s.to_string())),
            Some("rewrite") => Command::Rewrite,
            _ => Command::Improve,
        },
        "rewrite" => Command::Rewrite,
        "export" => Command::Export(first.map(|d| d.to_string()).context("Usage: export <directory>")?),
        "lib" => Command::Library(first.map(|l| l.to_string()).context("Usage: lib <name or path>")?),
        "debug" => Command::Debug(rest.split_whitespace().map(|w| w.to_string()).collect()),
        "continue" => Command::Debugger(DebugAction::Continue),
        "step" => Command::Debugger(DebugAction::Step),
        "step-over" => Command::Debugger(DebugAction::StepOver),
        "finish" => Command::Debugger(DebugAction::Finish),
        "stepi" => Command::Debugger(DebugAction::StepInstruction),
        "nexti" => Command::Debugger(DebugAction::NextInstruction),
        "interrupt" => Command::Debugger(DebugAction::Interrupt),
        "kill" => Command::Debugger(DebugAction::Kill),
        "break" => Command::Break(first_owned),
        "frame" => Command::SelectFrame(first.and_then(|n| n.parse().ok()).ok_or_else(|| usage(spec))?),
        "split" => Command::Split { dir: Dir::Down, target: first_owned },
        "vsplit" => Command::Split { dir: Dir::Right, target: first_owned },
        "tabnew" => Command::TabNew(first_owned),
        "tabclose" => Command::TabClose,
        "tabnext" => Command::TabNext,
        "tabprevious" => Command::TabPrevious,
        "only" => Command::Only,
        "link" => Command::Link,
        "focus-split" => Command::FocusSplit(direction(first).map_err(|e| anyhow!("Usage: focus-split <{}>", e))?),
        "next-split" => Command::NextSplit,
        "previous-split" => Command::PreviousSplit,
        "last-split" => Command::LastSplit,
        "close-split" => Command::CloseSplit,
        "move-tab" => Command::MoveTab(direction(first).map_err(|e| anyhow!("Usage: move-tab <{}>", e))?),
        "equalize" => Command::Equalize,
        "resize-width" => Command::Resize { width: true, delta: signed(first).ok_or_else(|| usage(spec))? },
        "resize-height" => Command::Resize { width: false, delta: signed(first).ok_or_else(|| usage(spec))? },
        other => bail!("Unknown command: {}", other),
    });
}

/*
 * Bindings
 */

/// Where a binding applies, the most specific first
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Context {
    /// A search is active: n / p go to its matches
    Search,
    Graph,
    Source,
    Disasm,
    Table,
    Review,
    Debug,
    /// Any view of the content
    Content,
    Explorer,
    Global,
}

impl Context {
    pub fn title(&self) -> &'static str {
        return match self {
            Context::Search => "While a search is active",
            Context::Graph => "Graphs",
            Context::Source => "C code",
            Context::Disasm => "Linear disassembly",
            Context::Table => "Tables",
            Context::Review => "Review of the proposals",
            Context::Debug => "Debugger",
            Context::Content => "Views",
            Context::Explorer => "Explorer",
            Context::Global => "Global",
        };
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Binding {
    pub context: Context,
    pub keys: Vec<Key>,
    /// The command line it runs
    pub text: String,
    pub command: Command,
}

/// Bindings of the configured keys, then of the fixed ones
pub(crate) fn default_bindings(k: &KeyBindings) -> Vec<Binding> {
    let mut list: Vec<(Context, String, String)> = Vec::new();
    let mut bind = |context: Context, keys: &[String], text: &str| {
        for key in keys {
            list.push((context, key.clone(), text.to_string()));
        }
    };

    let s = |text: &str| text.to_string();
    let c = key_text;
    let upper = |ch: char| key_text(ch.to_ascii_uppercase());
    let ctrl = |ch: char| format!("<C-{}>", ch);

    use Context::*;

    // Global
    bind(Global, &[c(k.quit), s("<C-c>")], "qall");
    bind(Global, &[s("<Tab>")], "switch-focus");
    bind(Global, &[s(":")], "prompt");
    bind(Global, &[s("/")], "search");
    bind(Global, &[s("?")], "help");
    bind(Global, &[s("<C-o>"), s("<BS>")], "back");
    bind(Global, &[s("<C-i>"), s("<C-r>")], "forward");
    bind(Global, &[c(k.toggle_explorer)], "toggle-explorer");

    bind(Global, &[s("<C-w>h"), s("<C-w><Left>")], "focus-split left");
    bind(Global, &[s("<C-w>j"), s("<C-w><Down>")], "focus-split down");
    bind(Global, &[s("<C-w>k"), s("<C-w><Up>")], "focus-split up");
    bind(Global, &[s("<C-w>l"), s("<C-w><Right>")], "focus-split right");
    bind(Global, &[s("<C-w>w")], "next-split");
    bind(Global, &[s("<C-w>W")], "previous-split");
    bind(Global, &[s("<C-w>p")], "last-split");
    bind(Global, &[s("<C-w>s"), s("<C-w>S")], "split");
    bind(Global, &[s("<C-w>v")], "vsplit");
    bind(Global, &[s("<C-w>q"), s("<C-w>c")], "close-split");
    bind(Global, &[s("<C-w>o")], "only");
    bind(Global, &[s("<C-w>H")], "move-tab left");
    bind(Global, &[s("<C-w>J")], "move-tab down");
    bind(Global, &[s("<C-w>K")], "move-tab up");
    bind(Global, &[s("<C-w>L")], "move-tab right");
    bind(Global, &[s("<C-w>=")], "equalize");
    bind(Global, &[s("<C-w><lt>")], "resize-width -5");
    bind(Global, &[s("<C-w>>")], "resize-width +5");
    bind(Global, &[s("<C-w>-")], "resize-height -5");
    bind(Global, &[s("<C-w>+")], "resize-height +5");
    bind(Global, &[s("<C-w>b")], "link");
    bind(Global, &[s("<C-w>t")], "tabnew");
    bind(Global, &[s("gt")], "tabnext");
    bind(Global, &[s("<F5>")], "continue");
    bind(Global, &[s("<F6>")], "interrupt");
    bind(Global, &[s("<F7>")], "step");
    bind(Global, &[s("<F8>")], "step-over");
    bind(Global, &[s("<F4>")], "finish");
    bind(Global, &[s("<F9>")], "break");
    bind(Global, &[s("gT")], "tabprevious");

    // Explorer
    let first = if k.start == 'g' { vec![s("gg")] } else { vec![s("gg"), c(k.start)] };

    bind(Explorer, &[c(k.down), s("<Down>")], "move-down");
    bind(Explorer, &[c(k.up), s("<Up>")], "move-up");
    bind(Explorer, &[c(k.page_down), ctrl(k.page_down), s("<PageDown>")], "page-down");
    bind(Explorer, &[c(k.page_up), ctrl(k.page_up), s("<PageUp>")], "page-up");
    bind(Explorer, &first, "first");
    bind(Explorer, &[c(k.end)], "last");
    bind(Explorer, &[s("<Enter>"), c(k.right)], "open");
    bind(Explorer, &[c(k.left)], "close");
    bind(Explorer, &[s("<lt>")], "explorer-width -4");
    bind(Explorer, &[s(">")], "explorer-width +4");
    bind(Explorer, &[s("=")], "explorer-width");
    bind(Explorer, &[s("t")], "open tab");
    bind(Explorer, &[s("s")], "open split");
    bind(Explorer, &[s("v")], "open vsplit");

    // Any view
    bind(Content, &[c(k.down), s("<Down>")], "move-down");
    bind(Content, &[c(k.up), s("<Up>")], "move-up");
    bind(Content, &[c(k.left), s("<Left>")], "move-left");
    bind(Content, &[c(k.right), s("<Right>")], "move-right");
    bind(Content, &[upper(k.down)], "jump-down");
    bind(Content, &[upper(k.up)], "jump-up");
    bind(Content, &[upper(k.left)], "jump-left");
    bind(Content, &[upper(k.right)], "jump-right");
    bind(Content, &[c(k.page_down), ctrl(k.page_down), s("<PageDown>")], "page-down");
    bind(Content, &[c(k.page_up), ctrl(k.page_up), s("<PageUp>")], "page-up");
    bind(Content, &[first.clone(), vec![s("<Home>")]].concat(), "first");
    bind(Content, &[c(k.end), s("<End>")], "last");
    bind(Content, &[c(k.next_node)], "next");
    bind(Content, &[c(k.prev_node)], "previous");
    bind(Content, &[s("<Enter>")], "open");
    bind(Content, &[s("<Esc>")], "clear-search");
    bind(Content, &[s("gd")], "definition");
    bind(Content, &[c(k.xrefs)], "xrefs");
    bind(Content, &[c(k.call_graph)], "function-call-graph");
    bind(Content, &[c(k.decompile)], "toggle-code");
    bind(Content, &[c(k.toggle_view)], "toggle-view");
    bind(Content, &[s("<lt>")], "resize-width -5");
    bind(Content, &[s(">")], "resize-width +5");
    bind(Content, &[s("=")], "equalize");

    // While a search is active
    bind(Search, &[c(k.next_node)], "search-next");
    bind(Search, &[c(k.prev_node), s("N")], "search-previous");
    bind(Search, &[s("<Esc>")], "clear-search");

    // Graphs
    bind(Graph, &[c(k.center)], "center");
    bind(Graph, &[c(k.follow_true)], "follow true");
    bind(Graph, &[c(k.follow_false)], "follow false");
    bind(Graph, &[c(k.detail)], "detail");
    bind(Graph, &[upper(k.detail)], "detail all");
    bind(Graph, &[s("+")], "depth +1");
    bind(Graph, &[s("-")], "depth -1");
    bind(Graph, &[s("i")], "toggle-imports");
    bind(Graph, &[s("r")], "reroot");
    bind(Graph, &[c(k.call_graph_up)], "up");

    // Linear disassembly and tables: right opens
    bind(Disasm, &[c(k.right)], "open");
    bind(Table, &[c(k.right)], "open");

    // Breakpoints at the cursor
    bind(Source, &[s("gb")], "break");
    bind(Disasm, &[s("gb")], "break");
    bind(Graph, &[s("gb")], "break");

    // Review
    bind(Review, &[s("a")], "accept");
    bind(Review, &[s("r")], "reject");

    // C code
    bind(Source, &[ctrl(k.page_down)], "page-down");
    bind(Source, &[ctrl(k.page_up)], "page-up");
    bind(Source, &[s("w")], "word-next");
    bind(Source, &[s("b")], "word-previous");
    bind(Source, &[s("0")], "line-start");
    bind(Source, &[s("^")], "line-first");
    bind(Source, &[s("$")], "line-end");
    bind(Source, &[s("gs")], "string");
    bind(Source, &[s("i")], "insert");
    bind(Source, &[s("a")], "insert after");
    bind(Source, &[s("A")], "insert end");
    bind(Source, &[s("I")], "insert start");
    bind(Source, &[s("o")], "insert below");
    bind(Source, &[s("O")], "insert above");
    bind(Source, &[s("u")], "undo");
    bind(Source, &[s("U")], "redo");
    bind(Source, &[s("dd")], "delete-line");

    for (motion, reach) in [("w", "word"), ("e", "word-end"), ("b", "word-back"), ("$", "line-end"), ("0", "line-start"), ("^", "line-first"), ("j", "down"), ("k", "up"), ("l", "char"), ("h", "char-back")] {
        bind(Source, &[format!("d{}", motion)], &format!("delete {}", reach));
        bind(Source, &[format!("c{}", motion)], &format!("change {}", reach));
    }

    bind(Source, &[s("cc")], "change line");
    bind(Source, &[s(";")], "prompt comment ");
    bind(Source, &[s("M")], "prompt mv ");
    bind(Source, &[s("cn")], "prompt rename {word} ");
    bind(Source, &[s("ct")], "prompt retype {word} ");
    bind(Source, &[s("cs")], "prompt sig {signature}");
    bind(Source, &[s("]f"), s("]]")], "next-function");
    bind(Source, &[s("[f"), s("[[")], "previous-function");
    bind(Source, &[s("]c")], "next-conflict");
    bind(Source, &[s("[c")], "previous-conflict");
    bind(Source, &[c(k.toggle_view)], "toggle-code");
    bind(Source, &[c(k.improve)], "llm");
    bind(Source, &[s("W")], "rewrite");

    return list
        .into_iter()
        .filter_map(|(context, keys, text)| {
            let command = parse(&text).ok()?;
            Some(Binding { context, keys: parse_keys(&keys), text, command })
        })
        .collect();
}

/// What a sequence of keys is in some contexts
#[derive(Debug, PartialEq)]
pub(crate) enum Resolved {
    Command(Command),
    /// The start of a binding: waits for the next key
    Pending,
    Unbound,
}

/// The first context with a binding starting with the keys decides
pub(crate) fn resolve(bindings: &[Binding], contexts: &[Context], keys: &[Key]) -> Resolved {
    for &context in contexts {
        let starting: Vec<&Binding> = bindings.iter().filter(|b| b.context == context && b.keys.starts_with(keys)).collect();

        if starting.is_empty() {
            continue;
        }

        if starting.iter().any(|b| b.keys.len() > keys.len()) {
            return Resolved::Pending;
        }

        return Resolved::Command(starting[0].command.clone());
    }

    return Resolved::Unbound;
}

/// Lines of the help: the bindings by context, with the commands they run
pub(crate) fn help_lines(bindings: &[Binding]) -> Vec<(String, String)> {
    let mut lines = Vec::new();

    for context in [Context::Global, Context::Explorer, Context::Content, Context::Search, Context::Graph, Context::Disasm, Context::Table, Context::Review, Context::Source, Context::Debug] {
        lines.push((context.title().to_string(), String::new()));
        let mut seen: Vec<&str> = Vec::new();

        for binding in bindings.iter().filter(|b| b.context == context) {
            if seen.contains(&binding.text.as_str()) {
                continue;
            }

            seen.push(&binding.text);

            let keys: Vec<String> = bindings
                .iter()
                .filter(|b| b.context == context && b.text == binding.text)
                .map(|b| sequence_name(&b.keys))
                .collect();

            let name = binding.text.split_whitespace().next().unwrap_or("");

            // A prompt has the help of the command it prepares
            let prepared = if name == "prompt" { binding.text.split_whitespace().nth(1).unwrap_or("") } else { name };
            let help = find_spec(prepared).map_or("command line", |s| s.help);
            let arguments = binding.text[name.len()..].trim();
            let arguments = if arguments.is_empty() || name == "prompt" { String::new() } else { format!(" {}", arguments) };
            let command = if name == "prompt" { format!(":{}", binding.text["prompt".len()..].trim()) } else { format!(":{}{}", name, arguments) };

            lines.push((keys.join(" / "), format!("{:<26} {}", command, help)));
        }
    }

    // The commands without a key, by group
    let unbound: Vec<&Spec> = SPECS.iter().filter(|s| !bindings.iter().any(|b| b.text.split_whitespace().next() == Some(s.name))).collect();
    let mut groups: Vec<&str> = Vec::new();

    for spec in unbound.iter() {
        if !groups.contains(&spec.group) {
            groups.push(spec.group);
        }
    }

    for group in groups {
        lines.push((format!("Commands: {}", group), String::new()));

        for spec in unbound.iter().filter(|s| s.group == group) {
            let aliases = if spec.aliases.is_empty() { String::new() } else { format!(" ({})", spec.aliases.join(", ")) };
            lines.push((format!(":{} {}", spec.name, spec.usage).trim_end().to_string(), format!("{}{}", spec.help, aliases)));
        }
    }

    return lines;
}

/*
 * Dispatch
 */

impl App {
    /// Contexts of the focus, the most specific first
    pub(crate) fn contexts(&self) -> Vec<Context> {
        if self.focus == Focus::Explorer {
            return vec![Context::Explorer, Context::Global];
        }

        let view = match self.view() {
            View::Graph(_) => Some(Context::Graph),
            View::Source(_) => Some(Context::Source),
            View::Disasm(_) => Some(Context::Disasm),
            View::Table(_) => Some(Context::Table),
            View::Review(_) => Some(Context::Review),
            View::Debug(_) => Some(Context::Debug),
            _ => None,
        };

        // n / p go to the matches of an active search (the tables filter instead)
        let search = (self.searching && !matches!(self.view(), View::Table(_))).then_some(Context::Search);

        return search.into_iter().chain(view).chain([Context::Content, Context::Global]).collect();
    }

    /// A key in normal mode: a count, the next key of a sequence, or a binding
    pub(crate) fn sequence_key(&mut self, key: KeyEvent) {
        let key = Key::from_event(key);

        // Counts (3gt, 10j), 0 alone is a key
        if let (true, KeyCode::Char(c @ '0'..='9'), false) = (self.pending.is_empty(), key.code, key.ctrl) {
            if self.focus == Focus::Content && (c != '0' || self.count.is_some()) {
                self.count = Some(self.count.unwrap_or(0).saturating_mul(10).saturating_add(c as usize - '0' as usize));
                return;
            }
        }

        self.pending.push(key);

        match resolve(&self.bindings, &self.contexts(), &self.pending) {
            Resolved::Pending => {}
            Resolved::Command(command) => {
                self.pending.clear();
                let count = self.count.take();
                self.execute(command, count);
            }
            Resolved::Unbound => {
                self.pending.clear();
                self.count = None;
            }
        }
    }

    /// Runs a command line
    pub(crate) fn run_command(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }

        match parse(text) {
            Ok(command) => self.execute(command, None),
            Err(error) => self.error(error.to_string()),
        }
    }

    /// Runs a command: the focus first, then the splits and tabs, then the application
    pub(crate) fn execute(&mut self, command: Command, count: Option<usize>) {
        let handled = match self.focus {
            Focus::Explorer => self.explorer_command(&command, count),
            Focus::Content => false,
        };

        let handled = handled || self.view_command(&command, count) || self.splits_command(&command, count);

        if !handled {
            self.app_command(command, count);
        }

        if self.focus == Focus::Content {
            self.sync_linked();
        }
    }

    /// Commands of the application
    fn app_command(&mut self, command: Command, count: Option<usize>) {
        let program = self.current_program();

        match command {
            Command::Quit { all: false, force } => self.close_tab(force),
            Command::Quit { all: true, force } => self.quit(force),
            Command::Write(location) => self.save(location.map(PathBuf::from)),
            Command::WriteQuit => {
                self.save(None);

                if !self.projects.iter().flatten().any(|p| p.is_dirty()) {
                    self.quit(false);
                }
            }
            Command::Prompt(text) => self.prompt(&text),
            Command::Search => self.input = Some((InputKind::Search, String::new())),
            Command::SearchAgain { forward } => self.search_again(forward),
            Command::ClearSearch => {
                self.searching = false;

                if let View::Table(view) = self.view_mut() {
                    view.set_filter("");
                }
            }
            Command::Help => self.help = true,
            Command::Back => self.go_back(),
            Command::Forward => self.go_forward(),
            Command::SwitchFocus => {
                self.focus = if self.focus == Focus::Explorer { Focus::Content } else { Focus::Explorer };

                if self.focus == Focus::Explorer {
                    self.explorer_visible = true;
                }
            }
            Command::ToggleExplorer => {
                self.explorer_visible = !self.explorer_visible;

                if !self.explorer_visible {
                    self.focus = Focus::Content;
                }
            }
            Command::ExplorerWidth(delta) => self.explorer_resize(delta),
            Command::Goto(text) => match self.resolve_address(program, &text) {
                Some(addr) => self.goto_address(program, addr),
                None => self.error(format!("Unknown command, address or function: {}", text)),
            },
            Command::CallGraph(root) => {
                let root = root.and_then(|a| self.resolve_address(program, &a));
                self.open_call_graph(program, root, DEFAULT_CALL_GRAPH_DEPTH, false);
            }
            Command::Code(function) => {
                let addr = match function {
                    Some(a) => self.resolve_address(program, &a),
                    None => self.current_function().map(|(_, f)| f),
                };

                match addr {
                    Some(addr) => self.open_code(program, addr),
                    None => self.error("Usage: c [function or address]".to_string()),
                }
            }
            Command::Module(module) => match module {
                Some(module) => self.open_module(program, &module),
                None => match self.current_function() {
                    Some((program, addr)) => self.open_code(program, addr),
                    None => self.error("Usage: source <module>".to_string()),
                },
            },
            Command::Table(name) => {
                if let Some(table) = self.table(program, &name) {
                    self.open(View::Table(table));
                }
            }
            Command::Entry => {
                if let Some(entry) = self.programs[program].entry {
                    self.open_function(program, entry, None);
                }
            }
            Command::Depth(_) | Command::DepthBy(_) => self.error("Usage in a call graph: depth <n>".to_string()),
            Command::CallGraphUp => self.error("Not in a call graph".to_string()),
            Command::Review => self.open_review(program),
            Command::Accept(id) | Command::Reject(id) => {
                let accept = matches!(command, Command::Accept(_));

                let Some(id) = id else {
                    return self.error(format!("Usage: {} <proposal number>", if accept { "accept" } else { "reject" }));
                };

                let Some(project) = self.project(program) else {
                    return;
                };

                let result = if accept { project.accept(id) } else { project.reject(id) };
                self.report(result);
            }
            Command::Definition => self.info("No name under the cursor".to_string()),
            Command::Rename(old, new) => self.rename(&old, &new),
            Command::Retype(var, ty) => self.retype(&var, &ty),
            Command::Signature(text) => self.signature(&text),
            Command::Summary(text) => self.with_function(|project, addr| {
                project.set_summary(addr, Some(text.as_str()).filter(|s| !s.is_empty()));
                Ok(())
            }),
            Command::Revert => self.with_function(|project, addr| {
                project.revert(addr);
                Ok(())
            }),
            Command::Comment(_) | Command::StringForms | Command::Resolve { .. } | Command::Insert(_) | Command::Undo | Command::Redo | Command::DeleteLine | Command::Operator { .. } | Command::Conflict { .. } => {
                self.error("Only in the C code (:source)".to_string());
            }
            Command::MoveFunction(module, function) => self.move_function(Some(module), function),
            Command::MakeModule(module) => {
                if let Some(project) = self.project(program) {
                    let result = project.create_module(&module);
                    self.report(result);
                }
            }
            Command::RemoveModule(module) => {
                if let Some(project) = self.project(program) {
                    let result = project.remove_module(&module);
                    self.report(result);
                }
            }
            Command::RenameModule(old, new) => self.rename_module(program, &old, &new),
            Command::Improve => self.improve_code(),
            Command::Rewrite => self.rewrite_code(),
            Command::LlmModules(scope) => self.llm_modules(program, scope),
            Command::Export(dir) => self.export(program, PathBuf::from(dir)),
            Command::Library(name) => self.library_command(&name),
            Command::Move(_) | Command::Open(_) | Command::Close => {}
            Command::ToggleView | Command::ToggleCode | Command::Xrefs | Command::FunctionCallGraph => {}
            Command::ToggleImports | Command::Reroot | Command::Follow(_) | Command::Center | Command::Detail { .. } => {}
            Command::Split { .. } | Command::TabNew(_) | Command::TabClose | Command::TabNext | Command::TabPrevious | Command::Only | Command::Link => {}
            Command::FocusSplit(_) | Command::NextSplit | Command::PreviousSplit | Command::LastSplit | Command::CloseSplit | Command::MoveTab(_) => {}
            Command::Equalize | Command::Resize { .. } => {}
            Command::Debug(args) => self.start_debugger(args),
            Command::Debugger(action) => self.debug_action(action),
            Command::Break(target) => self.toggle_breakpoint(target.as_deref()),
            Command::SelectFrame(index) => self.select_frame(index),
        }

        let _ = count;
    }

    /// Opens the command line with a text, {word} and {signature} replaced
    fn prompt(&mut self, text: &str) {
        let mut text = text.to_string();

        if text.contains("{word}") {
            let word = self.word_under_cursor().unwrap_or_default();
            text = text.replace("{word}", &word);
        }

        if text.contains("{signature}") {
            let signature = self.current_signature().unwrap_or_default();
            text = text.replace("{signature}", &signature);
        }

        self.input = Some((InputKind::Command, text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_notation() {
        assert_eq!(parse_keys("gt"), vec![Key::char('g'), Key::char('t')]);
        assert_eq!(parse_keys("<C-w><lt>"), vec![Key { code: KeyCode::Char('w'), ctrl: true }, Key::char('<')]);
        assert_eq!(parse_keys("<Space><Enter>"), vec![Key::char(' '), Key { code: KeyCode::Enter, ctrl: false }]);
        assert_eq!(parse_keys("<x"), vec![Key::char('<'), Key::char('x')]);
        assert_eq!(parse_keys("<F5>"), vec![Key { code: KeyCode::F(5), ctrl: false }]);
        assert_eq!(Key { code: KeyCode::F(9), ctrl: false }.name(), "F9");
        assert_eq!(Key { code: KeyCode::Char('w'), ctrl: true }.name(), "Ctrl-w");
        assert_eq!(sequence_name(&parse_keys("<C-w>v")), "Ctrl-w v");
        assert_eq!(sequence_name(&parse_keys("gt")), "gt");
    }

    #[test]
    fn command_lines() {
        assert_eq!(parse("q").unwrap(), Command::Quit { all: false, force: false });
        assert_eq!(parse("qa!").unwrap(), Command::Quit { all: true, force: true });
        assert_eq!(parse("rename a1 count").unwrap(), Command::Rename("a1".to_string(), "count".to_string()));
        assert_eq!(parse("retype v1 const char *").unwrap(), Command::Retype("v1".to_string(), "const char *".to_string()));
        assert_eq!(parse("prompt rename x ").unwrap(), Command::Prompt("rename x ".to_string()));
        assert_eq!(parse("resize-width -5").unwrap(), Command::Resize { width: true, delta: -5 });
        assert_eq!(parse("main").unwrap(), Command::Goto("main".to_string()));
        assert_eq!(parse("debug -v input.txt").unwrap(), Command::Debug(vec!["-v".to_string(), "input.txt".to_string()]));
        assert_eq!(parse("n").unwrap(), Command::Debugger(DebugAction::StepOver));
        assert_eq!(parse("b main").unwrap(), Command::Break(Some("main".to_string())));
        assert!(parse("export").unwrap_err().to_string().starts_with("Usage"));
        assert!(parse("").is_err());
    }

    #[test]
    fn bindings_resolve_in_order() {
        let bindings = default_bindings(&KeyBindings::default());
        let keys = |text: &str| parse_keys(text);
        let source = [Context::Source, Context::Content, Context::Global];
        let graph = [Context::Graph, Context::Content, Context::Global];

        // d pages in the views, starts dd in the C code
        assert_eq!(resolve(&bindings, &graph, &keys("d")), Resolved::Command(Command::Move(Motion::PageDown)));
        assert_eq!(resolve(&bindings, &source, &keys("d")), Resolved::Pending);
        assert_eq!(resolve(&bindings, &source, &keys("dd")), Resolved::Command(Command::DeleteLine));
        assert_eq!(resolve(&bindings, &source, &keys("u")), Resolved::Command(Command::Undo));

        assert_eq!(resolve(&bindings, &graph, &keys("g")), Resolved::Pending);
        assert_eq!(resolve(&bindings, &graph, &keys("gt")), Resolved::Command(Command::TabNext));
        assert_eq!(resolve(&bindings, &graph, &keys("<C-w>v")), Resolved::Command(Command::Split { dir: Dir::Right, target: None }));
        assert_eq!(resolve(&bindings, &graph, &keys("Z")), Resolved::Unbound);

        // Every binding runs a command, every command has its help
        assert!(help_lines(&bindings).len() > 50);
    }
}
