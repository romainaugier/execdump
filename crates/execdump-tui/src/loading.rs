/*
 * Background work: the analysis and the project of each program (and of each shared library), then
 * what the projects decompiled and answered
 */

use super::*;

/// Background preparation of a program: its analysis, then its project
pub(crate) struct Loading {
    pub functions: Arc<AtomicUsize>,
    /// ANALYSIS, then PROJECT
    pub stage: Arc<AtomicU8>,
}

pub(crate) const ANALYSIS: u8 = 0;
pub(crate) const PROJECT: u8 = 1;

/// A program ready to be explored: parsed, analyzed, with its project open
pub(crate) struct Prepared {
    program: Arc<Program>,
    analysis: Arc<Analysis>,
    project: Project,
    /// Shared libraries it needs (libraries only, the ones of the binary are known when it is opened)
    needed: Vec<Needed>,
}

pub(crate) type Loaded = (usize, Result<Prepared, String>);

/// The program of a binary (the first one of fat binaries), with the libraries it needs
pub(crate) fn parse_binary(path: &Path) -> Result<(Program, Vec<Needed>), String> {
    let path = path.to_path_buf();

    let exec = match guess_exectype(&path).map_err(|e| e.to_string())? {
        ExecType::PE => Exec::PE(parse_pe(&path).map_err(|e| e.to_string())?),
        ExecType::ELF => Exec::ELF(parse_elf(&path).map_err(|e| e.to_string())?),
        ExecType::MachO => Exec::MachO(parse_macho(&path).map_err(|e| e.to_string())?),
    };

    let program = programs_from_exec(&exec).into_iter().next().ok_or("no program in the file")?;
    return Ok((program, needed_libraries(&exec, &path)));
}

impl Loading {
    /// A program of the binary, parsed already
    pub fn start(index: usize, count: usize, program: Arc<Program>, sender: &Sender<Loaded>, path: &Path, location: Option<PathBuf>, workers: usize) -> Self {
        let path = path.to_path_buf();

        return Loading::spawn(index, sender, move |functions, stage| {
            let analysis = Arc::new(analyze(&program, Some(functions)).map_err(|e| e.to_string())?);
            stage.store(PROJECT, Ordering::Relaxed);
            let project = Project::open(index, count, program.clone(), analysis.clone(), &path, location, workers);
            Ok(Prepared { program, analysis, project, needed: Vec::new() })
        });
    }

    /// A shared library, parsed in the background too, with its own project
    pub fn library(index: usize, sender: &Sender<Loaded>, path: &Path, location: PathBuf, workers: usize) -> Self {
        let path = path.to_path_buf();

        return Loading::spawn(index, sender, move |functions, stage| {
            let (program, needed) = parse_binary(&path)?;
            let program = Arc::new(program);
            let analysis = Arc::new(analyze(&program, Some(functions)).map_err(|e| e.to_string())?);
            stage.store(PROJECT, Ordering::Relaxed);
            let project = Project::open(0, 1, program.clone(), analysis.clone(), &path, Some(location), workers);
            Ok(Prepared { program, analysis, project, needed })
        });
    }

    fn spawn(index: usize, sender: &Sender<Loaded>, work: impl FnOnce(&AtomicUsize, &AtomicU8) -> Result<Prepared, String> + Send + 'static) -> Self {
        let loading = Loading { functions: Arc::new(AtomicUsize::new(0)), stage: Arc::new(AtomicU8::new(ANALYSIS)) };
        let (functions, stage, sender) = (loading.functions.clone(), loading.stage.clone(), sender.clone());

        let thread = crash::thread(&format!("analysis-{}", index)).spawn(move || {
            let result = crash::catch(|| work(&functions, &stage)).unwrap_or_else(|error| Err(format!("analysis failed: {}", error)));
            let _ = sender.send((index, result));
        });

        thread.expect("cannot start an analysis thread");
        return loading;
    }
}

impl App {
    pub(crate) fn poll_analysis(&mut self) {
        while let Ok((index, result)) = self.receiver.try_recv() {
            match result {
                Ok(prepared) => {
                    // Libraries are parsed in the background
                    if self.decoders[index].is_none() {
                        self.decoders[index] = Decoder::new(prepared.program.architecture()).ok();
                    }

                    self.programs[index] = prepared.program;
                    self.analyses[index] = Some(prepared.analysis);
                    self.projects[index] = Some(prepared.project);
                    self.explorer_version = u64::MAX;
                    self.add_libraries(prepared.needed);
                    self.program_loaded(index);

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

        // The session is restored once the programs it shows are loaded, libraries included
        let loaded = |app: &App| (0..app.programs.len()).all(|p| app.projects[p].is_some() || app.analysis_errors[p].is_some());

        if self.session_pending && loaded(self) {
            if self.session_programs.is_none() {
                let libraries = self.session().map_or(Vec::new(), |s| s.libraries);
                self.session_programs = Some(self.load_session_libraries(&libraries));
            }

            if loaded(self) {
                self.session_pending = false;
                let programs = self.session_programs.take().unwrap_or_default();
                self.restore_session(&programs);
            }
        }
    }

    /// Work done in the background by the projects: decompiled functions, LLM answers, messages
    pub(crate) fn poll_projects(&mut self) {
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
            self.rebuild_explorer();
        }

        if let Some((program, dir)) = self.pending_export.clone() {
            if self.projects[program].as_ref().is_some_and(|p| p.is_idle()) {
                self.pending_export = None;
                self.export(program, dir);
            }
        }
    }
}
