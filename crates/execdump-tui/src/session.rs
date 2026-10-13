/*
 * Sessions: the splits and tabs, with what each tab shows, saved with the project and restored when it
 * is opened again
 */

use super::*;

/// What a tab shows, saved in the sessions (addresses in hexadecimal: TOML integers are signed)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Resource {
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

impl Resource {
    /// The resource in another program (saved programs are reloaded at other indices)
    fn with_program(&self, programs: &std::collections::HashMap<usize, usize>) -> Option<Resource> {
        let mut resource = self.clone();

        let program = match &mut resource {
            Resource::Welcome => return Some(resource),
            Resource::Cfg { program, .. }
            | Resource::CallGraph { program, .. }
            | Resource::Linear { program, .. }
            | Resource::Region { program, .. }
            | Resource::Address { program, .. }
            | Resource::Source { program, .. }
            | Resource::Table { program, .. }
            | Resource::Review { program } => program,
        };

        *program = *programs.get(program)?;
        return Some(resource);
    }
}

fn hex(addr: u64) -> String {
    return format!("{:#x}", addr);
}

fn parse_hex(text: &str) -> u64 {
    return u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap_or(0);
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Session {
    pub layout: workspace::Layout<Resource>,
    /// Shared libraries loaded, in the order of their programs
    #[serde(default)]
    pub libraries: Vec<String>,
}

impl App {
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

    pub(crate) fn save_session(&mut self) {
        let Some(project) = self.projects.iter().flatten().next() else {
            return;
        };

        // Sessions are kept with the projects that were saved
        if !project.location().exists() {
            return;
        }

        let layout = self.workspace.save(&|view| self.describe(view));

        if let Ok(text) = toml::to_string(&Session { layout, libraries: self.loaded_libraries() }) {
            let _ = project.save_session(&text);
        }
    }

    pub(crate) fn session(&self) -> Option<Session> {
        let text = self.projects.iter().flatten().next().and_then(|p| p.session())?;
        return toml::from_str::<Session>(&text).ok();
    }

    pub(crate) fn restore_session(&mut self, programs: &std::collections::HashMap<usize, usize>) {
        let Some(session) = self.session() else {
            return;
        };

        // Only when nothing was opened while the analysis was running
        if self.workspace.group_count() > 1 || !matches!(self.view(), View::Welcome) {
            return;
        }

        // Views of libraries that are not there anymore are not restored
        let workspace = Workspace::restore(&session.layout, &mut |r| match r.with_program(programs) {
            Some(resource) => self.reopen(&resource),
            None => View::Welcome,
        });

        if workspace.is_valid() {
            self.workspace = workspace;
            self.focus = Focus::Content;
        }
    }
}
