/*
 * Project of a program: its decompiled C code (decompiled in the background, cached on disk), what
 * the user says about it (annotations, modules, edited functions), the proposals of the LLM, and
 * their history in a git repository next to the binary.
 *
 * Edited functions keep the text they were edited on (their base). When the decompiler renders a
 * function differently (a callee was renamed, its prototype changed...), the edits are merged
 * into the new rendering, as git merges a branch: conflicts are marked in the text.
 */

use crate::annotations::{valid_module, FunctionNotes, GlobalNotes, ModuleList};
use crate::cache::{Cache, Rendered};
use crate::hash::{build_id, Fnv};
use crate::modules::{auto_modules, Modules};
use crate::service::{Control, Event, Priority, Service};
use crate::store::{diff_text, has_conflicts, map_lines, rebase_text, Store, GENERATED, MAIN, PROPOSALS};

use execdump_core::crash;
use execdump_core::program::{Format, Program};
use execdump_decompiler::analysis::function::CallTarget;
use execdump_decompiler::analysis::Analysis;
use execdump_decompiler::llm::{parse_type, valid_identifier, Assistant, LlmConfig};
use execdump_decompiler::notes::parse_prototype;
use execdump_decompiler::typedb::{Platform, TypeDb};
use execdump_decompiler::types::DataModel;

use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

/// Directory of the git repository inside a project directory
const REPOSITORY: &str = "repo.git";
const SESSION: &str = "session.toml";

#[derive(Clone, Debug)]
pub struct Edit {
    /// Text the edits were made on
    pub base: String,
    pub base_lines: Vec<Option<u64>>,
    pub text: String,
    /// Edited text with the addresses of its lines
    rendered: Arc<Rendered>,
}

impl Edit {
    fn new(base: String, base_lines: Vec<Option<u64>>, text: String, meta: &crate::cache::Meta) -> Self {
        let lines = map_lines(&base, &base_lines, &text);
        let rendered = Arc::new(Rendered { ok: true, text: text.clone(), lines, meta: meta.clone() });

        return Edit { base, base_lines, text, rendered };
    }

    pub fn conflict(&self) -> bool {
        return has_conflicts(&self.text);
    }
}

impl PartialEq for Edit {
    fn eq(&self, other: &Self) -> bool {
        return self.base == other.base && self.text == other.text;
    }
}

/// Everything the user says about the program
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Work {
    pub functions: BTreeMap<u64, FunctionNotes>,
    pub globals: BTreeMap<u64, GlobalNotes>,
    pub modules: BTreeSet<String>,
    pub edits: BTreeMap<u64, Edit>,
}

/// State of the text shown for a function
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    pub edited: bool,
    pub conflict: bool,
    /// Rendered with older annotations, a new rendering is coming
    pub stale: bool,
}

/// Changes proposed by the LLM, waiting for a review
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub label: String,
    /// Notes to add to each function
    pub functions: BTreeMap<u64, FunctionNotes>,
    pub before: String,
    pub after: String,
    /// Waiting for the decompiler to render the proposed code
    pub preview_pending: bool,
}

impl Proposal {
    pub fn diff(&self) -> String {
        return diff_text(&self.before, &self.after, &self.label);
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct ProposalFile {
    label: String,
    before: String,
    after: String,
}

/// Result of a background LLM request
enum Assisted {
    Function { addr: u64, before: String, notes: Result<FunctionNotes, String> },
    Modules { label: String, moves: Result<Vec<(u64, String)>, String> },
}

pub struct Project {
    pub index: usize,
    pub program: Arc<Program>,
    pub analysis: Arc<Analysis>,
    pub typedb: TypeDb,
    /// Path prefix of this program in the repository (fat binaries hold several programs)
    prefix: String,
    location: PathBuf,
    store: Option<Store>,
    pub work: Work,
    saved: Work,
    pub modules: Modules,
    auto: BTreeMap<u64, String>,
    service: Service,
    build: u64,
    /// Functions referring to each address (calls and references)
    referrers: HashMap<u64, Vec<u64>>,
    /// Current names of the functions, and the original ones
    names: HashMap<String, u64>,
    total: usize,
    pub proposals: Vec<Proposal>,
    accepted: Vec<git2::Oid>,
    next_proposal: u64,
    assisted_sender: Sender<Assisted>,
    assisted: Receiver<Assisted>,
    llm_running: usize,
    /// Errors and information for the user, taken by the interface
    pub messages: Vec<(String, bool)>,
    /// Incremented on every change (annotations, modules, proposals), for the views to refresh
    pub version: u64,
}

/// Number of decompilation threads: all the cores but one, for the interface
pub fn default_workers() -> usize {
    return std::thread::available_parallelism().map_or(2, |n| n.get()).saturating_sub(1).clamp(1, 8);
}

/// Default project directory of a binary: next to it, with .edproj appended
pub fn default_location(binary: &Path) -> PathBuf {
    let mut name = binary.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".edproj");

    return binary.with_file_name(name);
}

/// Identifies a binary by its content (git blob id), for the cache
pub fn binary_id(binary: &Path) -> Option<String> {
    let data = std::fs::read(binary).ok()?;
    return git2::Oid::hash_object(git2::ObjectType::Blob, &data).ok().map(|o| o.to_string());
}

impl Project {
    /// Opens the project of a program. The decompilation starts right away, in the background.
    pub fn open(index: usize, programs: usize, program: Arc<Program>, analysis: Arc<Analysis>, binary: &Path, location: Option<PathBuf>, workers: usize) -> Self {
        let location = location.unwrap_or_else(|| default_location(binary));
        let prefix = if programs > 1 { format!("p{}/", index) } else { String::new() };

        // The cache lives in the user cache directory, keyed by the content of the binary
        let cache = binary_id(binary)
            .and_then(|id| dirs::cache_dir().map(|d| d.join("execdump").join(id).join(format!("p{}", index))))
            .and_then(|dir| Cache::open(&dir).ok())
            .unwrap_or_else(Cache::memory);

        return Project::with_cache(index, prefix, program, analysis, binary, location, cache, workers);
    }

    #[allow(clippy::too_many_arguments)]
    fn with_cache(index: usize, prefix: String, program: Arc<Program>, analysis: Arc<Analysis>, binary: &Path, location: PathBuf, cache: Cache, workers: usize) -> Self {
        let windows = program.format == Format::Pe;
        let typedb = TypeDb::bundled(if windows { Platform::Windows } else { Platform::Unix }, DataModel::new(program.architecture(), windows));

        let default = match program.source_names.as_slice() {
            [single] => crate::modules::source_module(single),
            _ => format!("{}.c", binary.file_stem().map_or("main".to_string(), |s| s.to_string_lossy().to_string()).replace(['.', ' '], "_")),
        };

        let auto = auto_modules(&program, &analysis, &default);

        let mut referrers: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut names: HashMap<String, u64> = HashMap::new();

        for function in analysis.functions.values() {
            names.insert(function.name.clone(), function.addr);
            names.insert(sanitize(&function.name), function.addr);
            names.entry(format!("sub_{:x}", function.addr)).or_insert(function.addr);

            for call in function.calls.iter() {
                if let CallTarget::Function(target) = call.target {
                    referrers.entry(target).or_default().push(function.addr);
                }
            }

            for &(_, target) in function.refs.iter() {
                referrers.entry(target).or_default().push(function.addr);
            }
        }

        referrers.values_mut().for_each(|v| {
            v.sort();
            v.dedup();
        });

        let total = auto.len();
        let service = Service::start(program.clone(), analysis.clone(), cache, workers);
        let (assisted_sender, assisted) = channel();

        let mut project = Project {
            index,
            program,
            analysis,
            typedb,
            prefix,
            location,
            store: None,
            work: Work::default(),
            saved: Work::default(),
            modules: Modules::default(),
            auto,
            service,
            build: build_id(),
            referrers,
            names,
            total,
            proposals: Vec::new(),
            accepted: Vec::new(),
            next_proposal: 1,
            assisted_sender,
            assisted,
            llm_running: 0,
            messages: Vec::new(),
            version: 0,
        };

        if project.location.join(REPOSITORY).exists() {
            if let Err(error) = project.load() {
                project.messages.push((format!("Cannot load the project {}: {}", project.location.display(), error), true));
            }
        }

        project.rebuild_modules();
        project.start();

        return project;
    }

    /// Sends the annotations to the decompilers and queues every function that is not cached, callees first
    fn start(&mut self) {
        for (&addr, notes) in self.work.functions.iter() {
            if let Some(name) = notes.name.as_ref() {
                self.service.control(Control::Rename(addr, Some(name.clone())));
                self.names.insert(name.clone(), addr);
            }

            if let Some(prototype) = notes.prototype.as_deref().and_then(|p| parse_prototype(p, &self.typedb).ok()) {
                self.service.control(Control::Prototype(addr, Some(prototype)));
            }
        }

        for (&addr, notes) in self.work.globals.iter() {
            if let Some(name) = notes.name.as_ref() {
                self.service.control(Control::Rename(addr, Some(name.clone())));
            }
        }

        let order = self.analysis.callees_first(self.auto.keys().copied());
        let mut fresh = 0;

        for addr in order {
            let fingerprint = self.fingerprint(addr);

            if self.service.cache().lock().unwrap().fingerprint(addr) == Some(fingerprint) {
                fresh += 1;
                continue;
            }

            self.service.enqueue(addr, fingerprint, Arc::new(self.notes(addr)), Priority::Background);
        }

        // Edits made on texts that were rendered differently since
        let edited: Vec<u64> = self.work.edits.keys().copied().collect();

        for addr in edited {
            self.rebase(addr);
        }

        let _ = fresh;
    }

    /*
     * State
     */

    pub fn location(&self) -> &Path {
        return &self.location;
    }

    pub fn is_dirty(&self) -> bool {
        return self.work != self.saved;
    }

    /// Functions decompiled (with their current annotations), and the total
    pub fn progress(&self) -> (usize, usize) {
        let (pending, running) = self.service.pending();
        return (self.total.saturating_sub(pending + running), self.total);
    }

    pub fn is_idle(&self) -> bool {
        return self.service.is_idle() && self.llm_running == 0;
    }

    pub fn llm_running(&self) -> usize {
        return self.llm_running;
    }

    pub fn notes(&self, addr: u64) -> FunctionNotes {
        return self.work.functions.get(&addr).cloned().unwrap_or_default();
    }

    /// Name of a function: the one given by the user, or the one of the analysis
    pub fn function_name(&self, addr: u64) -> String {
        if let Some(name) = self.work.functions.get(&addr).and_then(|n| n.name.as_ref()) {
            return name.clone();
        }

        return self.analysis.functions.get(&addr).map_or(format!("sub_{:x}", addr), |f| f.name.clone());
    }

    /// Function of a name (current or original name, sub_ADDRESS, C identifier of the name)
    pub fn resolve(&self, name: &str) -> Option<u64> {
        return self.names.get(name).copied().filter(|a| self.analysis.functions.contains_key(a));
    }

    /// Address of a global used by a function, by its name in the C code
    pub fn global(&mut self, function: u64, name: &str) -> Option<u64> {
        let (rendered, _) = self.shown(function)?;
        return rendered.meta.globals.iter().find(|(n, _)| n == name).map(|(_, a)| *a);
    }

    /*
     * C code
     */

    /// Text of a function as shown: the edited text, or the latest rendering of the decompiler
    pub fn shown(&mut self, addr: u64) -> Option<(Arc<Rendered>, Shown)> {
        if let Some(edit) = self.work.edits.get(&addr) {
            return Some((edit.rendered.clone(), Shown { edited: true, conflict: edit.conflict(), stale: false }));
        }

        let fingerprint = self.fingerprint(addr);
        let (cached, rendered) = self.service.cache().lock().unwrap().latest(addr)?;

        return Some((rendered, Shown { stale: cached != fingerprint, ..Shown::default() }));
    }

    /// Number of lines of the shown text, without reading it
    pub fn line_count(&self, addr: u64) -> Option<usize> {
        if let Some(edit) = self.work.edits.get(&addr) {
            return Some(edit.rendered.line_count());
        }

        return self.service.cache().lock().unwrap().line_count(addr);
    }

    /// Decompiled text of a function with the current annotations (not the edited one)
    fn decompiled(&self, addr: u64) -> Option<Arc<Rendered>> {
        let fingerprint = self.fingerprint(addr);
        return self.service.cache().lock().unwrap().get(addr, fingerprint);
    }

    pub fn prioritize(&self, addrs: &[u64], priority: Priority) {
        self.service.prioritize(addrs, priority);
    }

    /// Handles the work done in the background, returns the functions whose text changed
    pub fn poll(&mut self) -> Vec<u64> {
        let mut changed = Vec::new();

        for event in self.service.poll() {
            match event {
                Event::Decompiled { addr, fingerprint } => {
                    if fingerprint == self.fingerprint(addr) && self.work.edits.contains_key(&addr) {
                        self.rebase(addr);
                    }

                    changed.push(addr);
                }
                Event::Preview { id, rendered, .. } => {
                    if let Some(proposal) = self.proposals.iter_mut().find(|p| p.id == id) {
                        proposal.after = rendered.text;
                        proposal.preview_pending = false;
                        let proposal = proposal.clone();
                        self.persist_proposal(&proposal);
                        self.version += 1;
                    }
                }
            }
        }

        while let Ok(assisted) = self.assisted.try_recv() {
            self.llm_running = self.llm_running.saturating_sub(1);
            self.assisted(assisted);
        }

        return changed;
    }

    /// Blocks until everything queued is decompiled (command line export)
    pub fn wait_idle(&mut self) {
        while !self.is_idle() {
            std::thread::sleep(std::time::Duration::from_millis(20));
            self.poll();
        }

        self.poll();
    }

    /// Merges the edits of a function into its new rendering
    fn rebase(&mut self, addr: u64) {
        let Some(rendered) = self.decompiled(addr) else {
            return;
        };

        let Some(edit) = self.work.edits.get(&addr) else {
            return;
        };

        if edit.base == rendered.text {
            // Same text: only the line addresses may be missing (loaded projects)
            if edit.base_lines.len() != rendered.lines.len() {
                let edit = Edit::new(rendered.text.clone(), rendered.lines.clone(), edit.text.clone(), &rendered.meta);
                self.work.edits.insert(addr, edit);
            }

            return;
        }

        let (merged, conflict) = rebase_text(&edit.base, &edit.text, &rendered.text);

        if conflict {
            self.messages.push((format!("{}: the edited code conflicts with the new decompilation, resolve the conflict in the code", self.function_name(addr)), true));
        }

        if merged == rendered.text {
            self.work.edits.remove(&addr);
        } else {
            self.work.edits.insert(addr, Edit::new(rendered.text.clone(), rendered.lines.clone(), merged, &rendered.meta));
        }

        self.version += 1;
    }

    /*
     * Annotations
     */

    /// What the decompilation of a function depends on: the build, its notes, the names and
    /// prototypes of what it calls and refers to
    pub fn fingerprint(&self, addr: u64) -> u64 {
        let mut hash = Fnv::new();
        hash.u64(self.build).u64(addr);

        let empty = FunctionNotes::default();
        let notes = self.work.functions.get(&addr).unwrap_or(&empty);
        hash.opt(notes.name.as_deref()).opt(notes.prototype.as_deref()).opt(notes.summary.as_deref());

        for (var, var_notes) in notes.vars.iter() {
            hash.str(var).opt(var_notes.name.as_deref()).opt(var_notes.ty.as_deref());
        }

        let Some(function) = self.analysis.functions.get(&addr) else {
            return hash.finish();
        };

        let targets = function.calls.iter().filter_map(|c| if let CallTarget::Function(t) = c.target { Some(t) } else { None }).chain(function.refs.iter().map(|&(_, t)| t));

        for target in targets {
            let function_notes = self.work.functions.get(&target);
            let global = self.work.globals.get(&target).and_then(|g| g.name.as_deref());

            if function_notes.is_some_and(|n| n.name.is_some() || n.prototype.is_some()) || global.is_some() {
                hash.u64(target).opt(function_notes.and_then(|n| n.name.as_deref())).opt(function_notes.and_then(|n| n.prototype.as_deref())).opt(global);
            }
        }

        return hash.finish();
    }

    /// Queues again the functions whose rendering depends on these addresses
    fn invalidate(&mut self, addrs: &[u64], dependents: bool) {
        let mut queued: BTreeSet<u64> = addrs.iter().copied().filter(|a| self.auto.contains_key(a)).collect();

        if dependents {
            for addr in addrs {
                queued.extend(self.referrers.get(addr).into_iter().flatten().filter(|a| self.auto.contains_key(a)));
            }
        }

        for addr in queued {
            let priority = if addrs.contains(&addr) { Priority::Visible } else { Priority::Near };
            self.service.enqueue(addr, self.fingerprint(addr), Arc::new(self.notes(addr)), priority);
        }

        self.version += 1;
    }

    fn set_notes(&mut self, addr: u64, notes: FunctionNotes) {
        if notes.is_empty() {
            self.work.functions.remove(&addr);
        } else {
            self.work.functions.insert(addr, notes);
        }
    }

    /// Names a function (None goes back to the name of the symbols)
    pub fn rename_function(&mut self, addr: u64, name: Option<&str>) -> Result<(), String> {
        if !self.analysis.functions.contains_key(&addr) {
            return Err(format!("no function at {:#x}", addr));
        }

        if let Some(name) = name {
            if !valid_identifier(name) {
                return Err(format!("{} is not a valid C identifier", name));
            }

            if self.names.get(name).is_some_and(|&a| a != addr) {
                return Err(format!("{} is already the name of another function", name));
            }
        }

        let mut notes = self.notes(addr);

        if let Some(old) = notes.name.take() {
            self.names.remove(&old);
        }

        notes.name = name.map(|n| n.to_string());

        if let Some(name) = name {
            self.names.insert(name.to_string(), addr);
        }

        self.set_notes(addr, notes);
        self.service.control(Control::Rename(addr, name.map(|n| n.to_string())));
        self.invalidate(&[addr], true);

        return Ok(());
    }

    pub fn rename_global(&mut self, addr: u64, name: Option<&str>) -> Result<(), String> {
        if let Some(name) = name.filter(|n| !valid_identifier(n)) {
            return Err(format!("{} is not a valid C identifier", name));
        }

        let notes = GlobalNotes { name: name.map(|n| n.to_string()) };

        if notes.is_empty() {
            self.work.globals.remove(&addr);
        } else {
            self.work.globals.insert(addr, notes);
        }

        self.service.control(Control::Rename(addr, name.map(|n| n.to_string())));
        self.invalidate(&[addr], true);

        return Ok(());
    }

    /// Name the decompiler gave to a variable shown with a name
    pub fn original_var(&mut self, function: u64, shown: &str) -> Result<String, String> {
        let (rendered, _) = self.shown(function).ok_or("the function is not decompiled yet")?;

        return rendered.meta.vars.iter().find(|(_, s)| s == shown).map(|(o, _)| o.clone()).ok_or_else(|| format!("{} is not a variable of {}", shown, self.function_name(function)));
    }

    pub fn rename_var(&mut self, function: u64, shown: &str, name: &str) -> Result<(), String> {
        if !valid_identifier(name) {
            return Err(format!("{} is not a valid C identifier", name));
        }

        let original = self.original_var(function, shown)?;
        let mut notes = self.notes(function);
        let var = notes.vars.entry(original.clone()).or_default();
        var.name = if name == original { None } else { Some(name.to_string()) };

        self.set_notes(function, notes);
        self.invalidate(&[function], false);

        return Ok(());
    }

    pub fn retype_var(&mut self, function: u64, shown: &str, ty: Option<&str>) -> Result<(), String> {
        if let Some(ty) = ty.filter(|t| parse_type(t, &self.typedb).is_none()) {
            return Err(format!("unknown type {}", ty));
        }

        let original = self.original_var(function, shown)?;
        let mut notes = self.notes(function);
        notes.vars.entry(original).or_default().ty = ty.map(|t| t.trim().to_string());

        self.set_notes(function, notes);
        self.invalidate(&[function], false);

        return Ok(());
    }

    /// Gives a function a prototype, its name in the prototype renames the function
    pub fn set_prototype(&mut self, addr: u64, text: Option<&str>) -> Result<(), String> {
        let prototype = text.map(|t| parse_prototype(t, &self.typedb)).transpose()?;

        if let Some(prototype) = prototype.as_ref() {
            if prototype.name != self.function_name(addr) {
                self.rename_function(addr, Some(&prototype.name))?;
            }
        }

        let mut notes = self.notes(addr);
        notes.prototype = prototype.as_ref().map(|p| p.to_string());

        self.set_notes(addr, notes);
        self.service.control(Control::Prototype(addr, prototype));
        self.invalidate(&[addr], true);

        return Ok(());
    }

    pub fn set_summary(&mut self, addr: u64, summary: Option<&str>) {
        let mut notes = self.notes(addr);
        notes.summary = summary.map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string());

        self.set_notes(addr, notes);
        self.invalidate(&[addr], false);
    }

    /// Replaces the text of a function, the edit is dropped when it is the decompiled text again
    pub fn set_edit(&mut self, addr: u64, text: &str) -> Result<(), String> {
        let text = if text.ends_with('\n') || text.is_empty() { text.to_string() } else { format!("{}\n", text) };

        let edit = match self.work.edits.get(&addr) {
            Some(edit) => Edit::new(edit.base.clone(), edit.base_lines.clone(), text, &edit.rendered.meta),
            None => {
                let rendered = self.decompiled(addr).ok_or("the function is not decompiled yet")?;
                Edit::new(rendered.text.clone(), rendered.lines.clone(), text, &rendered.meta)
            }
        };

        if edit.text == edit.base {
            self.work.edits.remove(&addr);
        } else {
            self.work.edits.insert(addr, edit);
        }

        self.version += 1;
        return Ok(());
    }

    /// Drops the edits of a function
    pub fn revert(&mut self, addr: u64) {
        if self.work.edits.remove(&addr).is_some() {
            self.version += 1;
        }
    }

    /*
     * Modules
     */

    fn rebuild_modules(&mut self) {
        let assignments = self.auto.iter().map(|(&addr, auto)| {
            let module = self.work.functions.get(&addr).and_then(|n| n.module.clone()).unwrap_or_else(|| auto.clone());
            (addr, module)
        });

        self.modules = Modules::new(assignments.collect::<Vec<_>>(), self.work.modules.iter().cloned());
        self.version += 1;
    }

    pub fn module_of(&self, addr: u64) -> Option<&str> {
        return self.modules.module_of(addr);
    }

    pub fn move_function(&mut self, addr: u64, module: &str) -> Result<(), String> {
        if !valid_module(module) {
            return Err(format!("{} is not a valid module path (relative path such as net/socket.c)", module));
        }

        let Some(auto) = self.auto.get(&addr).cloned() else {
            return Err(format!("{:#x} is not a function of the program", addr));
        };

        let mut notes = self.notes(addr);
        notes.module = if auto == module { None } else { Some(module.to_string()) };
        self.set_notes(addr, notes);

        if !self.modules.contains(module) && auto != module {
            self.work.modules.insert(module.to_string());
        }

        self.modules.assign(addr, module);
        self.version += 1;

        return Ok(());
    }

    pub fn create_module(&mut self, module: &str) -> Result<(), String> {
        if !valid_module(module) {
            return Err(format!("{} is not a valid module path (relative path such as net/socket.c)", module));
        }

        self.work.modules.insert(module.to_string());
        self.modules.add(module);
        self.version += 1;

        return Ok(());
    }

    pub fn rename_module(&mut self, old: &str, new: &str) -> Result<(), String> {
        if !valid_module(new) {
            return Err(format!("{} is not a valid module path", new));
        }

        if !self.modules.contains(old) {
            return Err(format!("no module {}", old));
        }

        for addr in self.modules.functions(old).to_vec() {
            self.move_function(addr, new)?;
        }

        self.work.modules.remove(old);
        self.work.modules.insert(new.to_string());
        self.rebuild_modules();

        return Ok(());
    }

    pub fn remove_module(&mut self, module: &str) -> Result<(), String> {
        if !self.modules.functions(module).is_empty() {
            return Err(format!("{} still holds functions, move them first", module));
        }

        self.work.modules.remove(module);
        self.modules.remove(module);
        self.version += 1;

        return Ok(());
    }

    /*
     * Persistence
     */

    fn path(&self, path: &str) -> String {
        return format!("{}{}", self.prefix, path);
    }

    fn store(&mut self) -> Result<&Store, String> {
        if self.store.is_none() {
            self.store = Some(Store::open_or_init(&self.location.join(REPOSITORY))?);
        }

        return Ok(self.store.as_ref().unwrap());
    }

    fn load(&mut self) -> Result<(), String> {
        let store = Store::open_or_init(&self.location.join(REPOSITORY))?;
        let mut work = Work::default();

        let files = store.files(MAIN, &self.path(""));
        let bases = store.files(GENERATED, &self.path("fn"));

        for (path, content) in files.iter() {
            let text = String::from_utf8_lossy(content);
            let addr_of = |name: &str, ext: &str| name.strip_suffix(ext).and_then(|a| u64::from_str_radix(a, 16).ok());

            if let Some(name) = path.strip_prefix("fn/") {
                if let Some(addr) = addr_of(name, ".toml") {
                    work.functions.insert(addr, FunctionNotes::from_toml(&text).map_err(|e| format!("{}: {}", path, e))?);
                } else if let Some(addr) = addr_of(name, ".c") {
                    let base = bases.get(name).map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_else(|| text.to_string());
                    work.edits.insert(addr, Edit::new(base, Vec::new(), text.to_string(), &Default::default()));
                }
            } else if let Some(name) = path.strip_prefix("data/") {
                if let Some(addr) = addr_of(name, ".toml") {
                    work.globals.insert(addr, toml::from_str(&text).map_err(|e| format!("{}: {}", path, e))?);
                }
            } else if path == "modules.toml" {
                let list: ModuleList = toml::from_str(&text).map_err(|e| format!("{}: {}", path, e))?;
                work.modules = list.modules.into_iter().collect();
            }
        }

        // Modules are paths of the export: a project from elsewhere must not write outside of it
        let mut invalid = 0;

        for notes in work.functions.values_mut() {
            if notes.module.as_deref().is_some_and(|m| !valid_module(m)) {
                notes.module = None;
                invalid += 1;
            }
        }

        let count = work.modules.len();
        work.modules.retain(|m| valid_module(m));
        invalid += count - work.modules.len();

        if invalid > 0 {
            self.messages.push((format!("{} invalid module paths of the project were ignored", invalid), true));
        }

        // Pending proposals of the LLM
        for branch in store.branches(PROPOSALS) {
            let Some(id) = branch.strip_prefix(PROPOSALS).and_then(|i| i.parse::<u64>().ok()) else {
                continue;
            };

            let Some(meta) = store.read(&branch, &self.path(&format!("proposals/{}.toml", id))) else {
                continue;
            };

            let meta: ProposalFile = toml::from_str(&String::from_utf8_lossy(&meta)).unwrap_or_default();
            let mut functions = BTreeMap::new();

            for (path, content) in store.files(&branch, &self.path("fn")) {
                let Some(addr) = path.strip_suffix(".toml").and_then(|a| u64::from_str_radix(a, 16).ok()) else {
                    continue;
                };

                let mut proposed = FunctionNotes::from_toml(&String::from_utf8_lossy(&content)).unwrap_or_default();
                proposed.module = proposed.module.filter(|m| valid_module(m));

                if work.functions.get(&addr) != Some(&proposed) {
                    functions.insert(addr, proposed);
                }
            }

            self.next_proposal = self.next_proposal.max(id + 1);
            self.proposals.push(Proposal { id, label: meta.label, functions, before: meta.before, after: meta.after, preview_pending: false });
        }

        self.saved = work.clone();
        self.work = work;
        self.store = Some(store);

        return Ok(());
    }

    /// Commits the work: the bases of the edited functions on generated, everything else on main
    pub fn save(&mut self, location: Option<PathBuf>) -> Result<String, String> {
        if let Some(location) = location {
            if location != self.location {
                self.location = location;
                self.store = None;
                // A new location starts from scratch: everything is written
                self.saved = Work::default();
            }
        }

        let (work, saved) = (self.work.clone(), self.saved.clone());
        let mut generated: Vec<(String, Option<Vec<u8>>)> = Vec::new();
        let mut main: Vec<(String, Option<Vec<u8>>)> = Vec::new();

        for (&addr, edit) in work.edits.iter() {
            let previous = saved.edits.get(&addr);
            let path = self.path(&format!("fn/{:x}.c", addr));

            if previous.map(|p| &p.base) != Some(&edit.base) {
                generated.push((path.clone(), Some(edit.base.clone().into_bytes())));
            }

            if previous.map(|p| &p.text) != Some(&edit.text) {
                main.push((path, Some(edit.text.clone().into_bytes())));
            }
        }

        for &addr in saved.edits.keys().filter(|a| !work.edits.contains_key(a)) {
            let path = self.path(&format!("fn/{:x}.c", addr));
            generated.push((path.clone(), None));
            main.push((path, None));
        }

        for (&addr, notes) in work.functions.iter() {
            if saved.functions.get(&addr) != Some(notes) {
                main.push((self.path(&format!("fn/{:x}.toml", addr)), Some(notes.to_toml().into_bytes())));
            }
        }

        for &addr in saved.functions.keys().filter(|a| !work.functions.contains_key(a)) {
            main.push((self.path(&format!("fn/{:x}.toml", addr)), None));
        }

        for (&addr, notes) in work.globals.iter() {
            if saved.globals.get(&addr) != Some(notes) {
                main.push((self.path(&format!("data/{:x}.toml", addr)), Some(toml::to_string(notes).unwrap_or_default().into_bytes())));
            }
        }

        for &addr in saved.globals.keys().filter(|a| !work.globals.contains_key(a)) {
            main.push((self.path(&format!("data/{:x}.toml", addr)), None));
        }

        if work.modules != saved.modules || self.store.is_none() && !work.modules.is_empty() {
            let list = ModuleList { modules: work.modules.iter().cloned().collect() };
            main.push((self.path("modules.toml"), Some(toml::to_string(&list).unwrap_or_default().into_bytes())));
        }

        let accepted = std::mem::take(&mut self.accepted);
        let edits = work.edits.len();
        let annotated = work.functions.len() + work.globals.len();
        let name = self.program.name.clone();

        let merged: Vec<u64> = self.proposals.iter().filter(|p| p.functions.is_empty()).map(|p| p.id).collect();
        let store = self.store()?;
        let mut parents = accepted.clone();

        if !generated.is_empty() {
            if let Some(oid) = store.commit(GENERATED, &generated, &format!("Decompiled code of the edited functions ({})", name), &[])? {
                parents.push(oid);
            }
        }

        let message = format!("{} annotated functions and globals, {} edited functions ({})", annotated, edits, name);
        let committed = store.commit(MAIN, &main, &message, &parents)?;

        // Accepted proposals are merged, their branches are not needed anymore
        for id in merged {
            store.delete_branch(&format!("{}{}", PROPOSALS, id));
        }

        self.proposals.retain(|p| !p.functions.is_empty());
        self.saved = work;

        return Ok(match committed {
            Some(oid) => format!("Saved to {} ({})", self.location.display(), &oid.to_string()[..10]),
            None => format!("Nothing to save in {}", self.location.display()),
        });
    }

    pub fn session(&self) -> Option<String> {
        return std::fs::read_to_string(self.location.join(SESSION)).ok();
    }

    pub fn save_session(&self, text: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.location).map_err(|e| e.to_string())?;
        return std::fs::write(self.location.join(SESSION), text).map_err(|e| e.to_string());
    }

    /*
     * LLM proposals
     */

    /// Asks the LLM to improve a function (names, types, summary), the answer becomes a proposal
    pub fn llm_function(&mut self, addr: u64, config: &LlmConfig) -> Result<(), String> {
        let (rendered, _) = self.shown(addr).ok_or("the function is not decompiled yet")?;
        let assistant = Assistant::new(config)?;
        let sender = self.assisted_sender.clone();
        let typedb_platform = if self.program.format == Format::Pe { Platform::Windows } else { Platform::Unix };
        let model = DataModel::new(self.program.architecture(), self.program.format == Format::Pe);
        let named = !self.function_name(addr).starts_with("sub_");
        let taken: BTreeSet<String> = self.names.keys().cloned().collect();

        self.llm_running += 1;

        std::thread::spawn(move || {
            let typedb = TypeDb::bundled(typedb_platform, model);

            let notes = crash::catch(|| assistant.suggest(&rendered.text)).and_then(|r| r).map(|suggestions| {
                let mut notes = FunctionNotes::default();

                if !named {
                    notes.name = suggestions.function_name.map(|n| n.trim().to_string()).filter(|n| valid_identifier(n) && !taken.contains(n));
                }

                notes.summary = suggestions.summary.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                for suggestion in suggestions.variables {
                    let Some(original) = rendered.meta.vars.iter().find(|(_, s)| *s == suggestion.name).map(|(o, _)| o.clone()) else {
                        continue;
                    };

                    let name = suggestion.new_name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty() && *n != suggestion.name && valid_identifier(n));
                    let ty = suggestion.ty.map(|t| t.trim().to_string()).filter(|t| !t.is_empty() && parse_type(t, &typedb).is_some());

                    if name.is_some() || ty.is_some() {
                        notes.vars.insert(original, crate::annotations::VarNotes { name, ty });
                    }
                }

                notes
            });

            let _ = sender.send(Assisted::Function { addr, before: rendered.text.clone(), notes });
        });

        return Ok(());
    }

    /// Asks the LLM to organize the functions of a module (or of the whole program) into modules
    pub fn llm_modules(&mut self, module: Option<&str>, config: &LlmConfig) -> Result<(), String> {
        const MAX_FUNCTIONS: usize = 300;

        let assistant = Assistant::modules(config)?;
        let functions: Vec<u64> = match module {
            Some(module) => self.modules.functions(module).to_vec(),
            None => self.auto.keys().copied().collect(),
        };

        let functions: Vec<u64> = functions.into_iter().take(MAX_FUNCTIONS).collect();
        let mut listing = String::new();
        let mut by_name: HashMap<String, u64> = HashMap::new();

        for &addr in functions.iter() {
            let name = self.function_name(addr);
            let calls: Vec<String> = self.analysis.functions.get(&addr).map_or(Vec::new(), |f| {
                f.calls.iter().filter_map(|c| if let CallTarget::Function(t) = c.target { Some(self.function_name(t)) } else { None }).collect::<BTreeSet<_>>().into_iter().collect()
            });

            listing.push_str(&format!("{} | {} | {}\n", name, self.module_of(addr).unwrap_or(""), calls.join(", ")));
            by_name.insert(name, addr);
        }

        let label = format!("modules of {}", module.unwrap_or("the program"));
        let sender = self.assisted_sender.clone();
        self.llm_running += 1;

        std::thread::spawn(move || {
            let moves = crash::catch(|| assistant.suggest_modules(&listing)).and_then(|r| r).map(|suggestions| {
                let mut moves = Vec::new();

                for file in suggestions.files {
                    let path = file.path.trim().trim_start_matches("./").to_string();

                    if !valid_module(&path) {
                        continue;
                    }

                    for name in file.functions {
                        if let Some(&addr) = by_name.get(name.trim()) {
                            moves.push((addr, path.clone()));
                        }
                    }
                }

                moves
            });

            let _ = sender.send(Assisted::Modules { label, moves });
        });

        return Ok(());
    }

    fn assisted(&mut self, assisted: Assisted) {
        let id = self.next_proposal;

        match assisted {
            Assisted::Function { addr, before, notes } => {
                let notes = match notes {
                    Ok(notes) if !notes.is_empty() => notes,
                    Ok(_) => return self.messages.push((format!("LLM: nothing to improve in {}", self.function_name(addr)), false)),
                    Err(error) => return self.messages.push((format!("LLM: {}", error), true)),
                };

                let mut merged = self.notes(addr);
                merged.overlay(&notes);

                self.service.preview(id, addr, merged.clone(), notes.name.clone());
                let label = format!("{} ({:#x})", self.function_name(addr), addr);

                self.proposals.push(Proposal { id, label, functions: [(addr, notes)].into_iter().collect(), before, after: String::new(), preview_pending: true });
                self.messages.push((format!("LLM: proposal {} for {}, review it with :review", id, self.function_name(addr)), false));
            }
            Assisted::Modules { label, moves } => {
                let moves = match moves {
                    Ok(moves) => moves,
                    Err(error) => return self.messages.push((format!("LLM: {}", error), true)),
                };

                let mut functions = BTreeMap::new();
                let (mut before, mut after) = (String::new(), String::new());

                for (addr, module) in moves {
                    if self.module_of(addr) == Some(module.as_str()) || functions.contains_key(&addr) {
                        continue;
                    }

                    before.push_str(&format!("{}: {}\n", self.function_name(addr), self.module_of(addr).unwrap_or("")));
                    after.push_str(&format!("{}: {}\n", self.function_name(addr), module));
                    functions.insert(addr, FunctionNotes { module: Some(module), ..Default::default() });
                }

                if functions.is_empty() {
                    return self.messages.push((format!("LLM: the {} are fine as they are", label), false));
                }

                let proposal = Proposal { id, label, functions, before, after, preview_pending: false };
                self.persist_proposal(&proposal);
                self.messages.push((format!("LLM: proposal {} moves {} functions, review it with :review", id, proposal.functions.len()), false));
                self.proposals.push(proposal);
            }
        }

        self.next_proposal += 1;
        self.version += 1;
    }

    /// Keeps a proposal as a branch of the repository (main with the proposed notes)
    fn persist_proposal(&mut self, proposal: &Proposal) {
        let mut changes = Vec::new();

        for (&addr, notes) in proposal.functions.iter() {
            let mut merged = self.saved.functions.get(&addr).cloned().unwrap_or_default();
            merged.overlay(notes);
            changes.push((self.path(&format!("fn/{:x}.toml", addr)), Some(merged.to_toml().into_bytes())));
        }

        let meta = ProposalFile { label: proposal.label.clone(), before: proposal.before.clone(), after: proposal.after.clone() };
        changes.push((self.path(&format!("proposals/{}.toml", proposal.id)), Some(toml::to_string(&meta).unwrap_or_default().into_bytes())));

        let branch = format!("{}{}", PROPOSALS, proposal.id);
        let result = self.store().and_then(|store| {
            store.branch_from(&branch, MAIN)?;
            store.commit(&branch, &changes, &format!("LLM proposal: {}", proposal.label), &[])
        });

        if let Err(error) = result {
            self.messages.push((format!("Cannot keep the proposal in {}: {}", self.location.display(), error), true));
        }
    }

    /// Applies a proposal to the work (merged into main on the next save)
    pub fn accept(&mut self, id: u64) -> Result<(), String> {
        let index = self.proposals.iter().position(|p| p.id == id).ok_or_else(|| format!("no proposal {}", id))?;
        let functions = std::mem::take(&mut self.proposals[index].functions);

        for (addr, notes) in functions {
            if let Some(name) = notes.name.as_deref() {
                if let Err(error) = self.rename_function(addr, Some(name)) {
                    self.messages.push((error, true));
                }
            }

            if let Some(module) = notes.module.as_deref() {
                self.move_function(addr, module)?;
            }

            let mut merged = self.notes(addr);
            merged.overlay(&FunctionNotes { name: None, module: None, ..notes });
            self.set_notes(addr, merged);
            self.invalidate(&[addr], false);
        }

        if let Some(tip) = self.store.as_ref().and_then(|s| s.tip(&format!("{}{}", PROPOSALS, id))) {
            self.accepted.push(tip);
        }

        self.version += 1;
        return Ok(());
    }

    pub fn reject(&mut self, id: u64) -> Result<(), String> {
        let index = self.proposals.iter().position(|p| p.id == id).ok_or_else(|| format!("no proposal {}", id))?;
        self.proposals.remove(index);

        if let Some(store) = self.store.as_ref() {
            store.delete_branch(&format!("{}{}", PROPOSALS, id));
        }

        self.version += 1;
        return Ok(());
    }

    /*
     * Export
     */

    /// Functions whose text is not ready for an export (not decompiled yet with the current annotations)
    pub fn missing(&self) -> Vec<u64> {
        return self.auto.keys().copied().filter(|&a| !self.work.edits.contains_key(&a) && self.decompiled(a).is_none()).collect();
    }

    pub fn export(&mut self, dir: &Path) -> Result<crate::export::Report, String> {
        return crate::export::export(self, dir);
    }

    pub(crate) fn export_text(&mut self, addr: u64) -> Option<Arc<Rendered>> {
        if let Some(edit) = self.work.edits.get(&addr) {
            return Some(edit.rendered.clone());
        }

        return self.decompiled(addr);
    }
}

fn sanitize(name: &str) -> String {
    return name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use execdump_core::elf::parse_elf;
    use execdump_core::exec::Exec;
    use execdump_core::program::programs_from_exec;
    use execdump_decompiler::analysis::analyze;

    pub fn fixture() -> (Arc<Program>, Arc<Analysis>, PathBuf) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let program = programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();

        return (Arc::new(program), Arc::new(analysis), path);
    }

    pub fn temporary(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("execdump-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        return dir;
    }

    pub fn open(location: &Path) -> Project {
        let (program, analysis, path) = fixture();
        return Project::with_cache(0, String::new(), program, analysis, &path, location.to_path_buf(), Cache::memory(), 2);
    }

    fn text(project: &mut Project, addr: u64) -> String {
        return project.shown(addr).map(|(r, _)| r.text.to_string()).unwrap_or_default();
    }

    #[test]
    fn decompiles_everything_in_the_background() {
        let location = temporary("project-background");
        let mut project = open(&location);
        project.wait_idle();

        let (done, total) = project.progress();
        assert_eq!(done, total);
        assert!(project.missing().is_empty());

        let main = project.resolve("main").unwrap();
        assert!(text(&mut project, main).starts_with("int main("));
        assert_eq!(project.module_of(main), Some("analysis.c"));
        assert!(!project.is_dirty());
    }

    #[test]
    fn modules_outside_the_export_are_ignored() {
        let location = temporary("project-modules");
        let classify = open(&location).resolve("classify").unwrap();

        let store = Store::open_or_init(&location.join(REPOSITORY)).unwrap();
        let notes = FunctionNotes { module: Some("../../outside.c".to_string()), ..FunctionNotes::default() };
        let changes = vec![
            (format!("fn/{:x}.toml", classify), Some(notes.to_toml().into_bytes())),
            ("modules.toml".to_string(), Some(b"modules = [\"/abs.c\", \"lib/ok.c\"]\n".to_vec())),
        ];
        store.commit(MAIN, &changes, "outside", &[]).unwrap();
        drop(store);

        let project = open(&location);
        assert_eq!(project.module_of(classify), Some("analysis.c"));
        assert!(project.modules.names().all(|m| valid_module(m)));
        assert!(project.modules.names().any(|m| m == "lib/ok.c"));
        assert!(project.messages.iter().any(|(m, _)| m.contains("invalid module paths")));

        let _ = std::fs::remove_dir_all(&location);
    }

    #[test]
    fn annotations_edits_and_history() {
        let location = temporary("project-history");
        let mut project = open(&location);
        project.wait_idle();

        let (main, classify) = (project.resolve("main").unwrap(), project.resolve("classify").unwrap());

        // Edit main: a comment above the call of classify
        let edited = text(&mut project, main).replace("    do {", "    // sums the classes\n    do {");
        assert_ne!(edited, text(&mut project, main));
        project.set_edit(main, &edited).unwrap();
        assert!(project.shown(main).unwrap().1.edited);

        // Renaming classify renders main again: the edit is merged into the new rendering
        project.rename_function(classify, Some("classify_value")).unwrap();
        project.wait_idle();

        let merged = text(&mut project, main);
        assert!(merged.contains("// sums the classes"), "{}", merged);
        assert!(merged.contains("classify_value("), "{}", merged);
        assert!(!project.shown(main).unwrap().1.conflict);
        assert_eq!(project.resolve("classify_value"), Some(classify));

        // Variables and modules
        let var = project.shown(classify).unwrap().0.meta.vars[0].1.clone();
        project.rename_var(classify, &var, "value").unwrap();
        project.move_function(classify, "lib/classes.c").unwrap();
        project.wait_idle();
        assert!(text(&mut project, classify).starts_with("int classify_value(int value)"), "{}", text(&mut project, classify));
        assert_eq!(project.modules.functions("lib/classes.c"), [classify]);

        assert!(project.is_dirty());
        let message = project.save(None).unwrap();
        assert!(message.starts_with("Saved"), "{}", message);
        assert!(!project.is_dirty());

        let store = Store::open_or_init(&location.join(REPOSITORY)).unwrap();
        assert!(store.read(MAIN, &format!("fn/{:x}.toml", classify)).is_some());
        assert!(String::from_utf8(store.read(MAIN, &format!("fn/{:x}.c", main)).unwrap()).unwrap().contains("// sums the classes"));
        assert!(store.read(GENERATED, &format!("fn/{:x}.c", main)).is_some());
        drop(store);
        drop(project);

        // Reopened: same annotations, same edits
        let mut project = open(&location);
        project.wait_idle();
        assert_eq!(project.function_name(classify), "classify_value");
        assert_eq!(project.module_of(classify), Some("lib/classes.c"));
        assert!(text(&mut project, main).contains("// sums the classes"));
        assert!(!project.is_dirty(), "{:?}", project.work.edits.keys());

        // Reverting the edit and the rename leaves no trace once saved
        project.revert(main);
        project.rename_function(classify, None).unwrap();
        project.save(None).unwrap();

        let store = Store::open_or_init(&location.join(REPOSITORY)).unwrap();
        assert!(store.read(MAIN, &format!("fn/{:x}.c", main)).is_none());

        let _ = std::fs::remove_dir_all(&location);
    }

    #[test]
    fn proposals() {
        let location = temporary("project-proposals");
        let mut project = open(&location);
        project.wait_idle();

        let classify = project.resolve("classify").unwrap();
        let var = project.shown(classify).unwrap().0.meta.vars[0].0.clone();

        // What the LLM answers for a function: a summary and a variable name
        let mut notes = FunctionNotes { summary: Some("Classifies a value.".to_string()), ..Default::default() };
        notes.vars.insert(var.clone(), crate::annotations::VarNotes { name: Some("value".to_string()), ty: None });

        project.llm_running += 2;
        let before = text(&mut project, classify);
        project.assisted_sender.send(Assisted::Function { addr: classify, before, notes: Ok(notes) }).unwrap();
        project.assisted_sender.send(Assisted::Modules { label: "modules of the program".to_string(), moves: Ok(vec![(classify, "lib/classes.c".to_string())]) }).unwrap();
        project.wait_idle();

        assert_eq!(project.proposals.len(), 2);
        let function = project.proposals[0].clone();
        assert!(!function.preview_pending);
        assert!(function.after.contains("// Classifies a value."), "{}", function.after);
        assert!(function.diff().contains("+int classify(int value)"), "{}", function.diff());
        assert!(project.proposals[1].diff().contains("+classify: lib/classes.c"), "{}", project.proposals[1].diff());

        // Kept as branches of the repository, until accepted or rejected
        drop(project);
        let mut project = open(&location);
        assert_eq!(project.proposals.len(), 2);

        project.accept(function.id).unwrap();
        project.reject(project.proposals[1].id).unwrap();
        project.wait_idle();
        assert!(text(&mut project, classify).starts_with("int classify(int value)"));
        assert_eq!(project.module_of(classify), Some("analysis.c"));

        project.save(None).unwrap();
        let store = Store::open_or_init(&location.join(REPOSITORY)).unwrap();
        assert!(store.branches(PROPOSALS).is_empty());
        assert!(String::from_utf8(store.read(MAIN, &format!("fn/{:x}.toml", classify)).unwrap()).unwrap().contains("Classifies a value."));

        let _ = std::fs::remove_dir_all(&location);
    }

    #[test]
    fn prototypes_and_conflicts() {
        let location = temporary("project-conflicts");
        let mut project = open(&location);
        project.wait_idle();

        let count_chars = project.resolve("count_chars").unwrap();
        let original = text(&mut project, count_chars);
        let first_line = original.lines().next().unwrap().to_string();

        // The edit changes the signature line, the new prototype changes it too
        project.set_edit(count_chars, &original.replacen(&first_line, "int count_chars(char *string) /* edited */", 1)).unwrap();
        project.set_prototype(count_chars, Some("int count_chars(const char *text)")).unwrap();
        project.wait_idle();

        let (rendered, shown) = project.shown(count_chars).unwrap();
        assert!(shown.conflict, "{}", rendered.text);
        assert!(project.messages.iter().any(|(m, _)| m.contains("conflicts")));
        assert!(project.set_prototype(count_chars, Some("int count_chars(unknown_t x)")).is_err());

        assert!(project.rename_function(count_chars, Some("main")).is_err());
        assert!(project.rename_function(count_chars, Some("not valid")).is_err());
        assert!(project.move_function(count_chars, "../x.c").is_err());
    }
}
