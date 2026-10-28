// SPDX-License-Identifier: Apache-2.0
/*
 * Actions on the projects: saving, exporting, annotations of the functions, the LLM
 */

use super::*;

use anyhow::{anyhow, Result};

impl App {
    pub(crate) fn save(&mut self, location: Option<PathBuf>) {
        if location.is_some() {
            self.project_location = location.clone();
        }

        let mut messages = Vec::new();

        for program in 0..self.projects.len() {
            // The projects of the libraries are in the libs directory of the project
            let location = match self.libraries.iter().find(|l| l.program == Some(program)) {
                Some(library) => location.as_ref().map(|l| l.join("libs").join(library.file_name())),
                None => location.clone(),
            };

            let Some(project) = self.projects[program].as_mut() else {
                continue;
            };

            match project.save(location) {
                Ok(message) => messages.push(message),
                Err(error) => {
                    self.message = Some((format!("Cannot save: {:#}", error), true));
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

    pub(crate) fn export(&mut self, program: usize, dir: PathBuf) {
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
            Err(error) => self.error(format!("Export failed: {:#}", error)),
        }
    }

    /// Runs an action on the project and the function under the cursor
    pub(crate) fn with_function(&mut self, action: impl FnOnce(&mut Project, u64) -> Result<()>) {
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
    pub(crate) fn with_source(&mut self, action: impl FnOnce(&mut SourceView, &mut Project) -> Result<()>) {
        let App { workspace, projects, .. } = self;

        let result = match workspace.view_mut() {
            View::Source(source) => match projects[source.program].as_mut() {
                Some(project) => action(source, project),
                None => Ok(()),
            },
            _ => Err(anyhow!("Only in the C code (:source)")),
        };

        self.report(result);
    }

    pub(crate) fn current_module(&self) -> Option<String> {
        return match self.view() {
            View::Source(source) => Some(source.module.clone()),
            _ => None,
        };
    }

    /// Renames what a name refers to: a variable of the current function, a function or a global
    pub(crate) fn rename(&mut self, old: &str, new: &str) {
        let new = if new == "-" { None } else { Some(new) };
        let Some((program, function)) = self.current_function() else {
            let program = self.current_program();
            let addr = self.projects[program].as_ref().and_then(|p| p.resolve(old));

            let result = match (addr, self.project(program)) {
                (Some(addr), Some(project)) => project.rename_function(addr, new),
                _ => Err(anyhow!("Unknown function: {}", old)),
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
            Err(anyhow!("{} is not a variable, a function or a global of {}", old, project.function_name(function)))
        };

        self.report(result);
    }

    pub(crate) fn retype(&mut self, var: &str, ty: &str) {
        let ty = if ty == "-" { None } else { Some(ty) };
        self.with_function(|project, addr| project.retype_var(addr, var, ty));
    }

    pub(crate) fn signature(&mut self, text: &str) {
        let text = if text.is_empty() || text == "-" { None } else { Some(text) };
        self.with_function(|project, addr| project.set_prototype(addr, text));
    }

    pub(crate) fn move_function(&mut self, module: Option<String>, function: Option<String>) {
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

        let Some(project) = self.project(program) else {
            return;
        };

        let result = project.move_function(addr, &module).map(|_| format!("{} moved to {}", project.function_name(addr), module));

        match result {
            Ok(message) => self.info(message),
            Err(error) => self.report(Err(error)),
        }
    }

    /// Asks the LLM to improve and document the function under the cursor: the answer is a proposal to review
    pub(crate) fn improve_code(&mut self) {
        let Some((program, function)) = self.current_function() else {
            return self.error("No function under the cursor".to_string());
        };

        if !self.llm.is_enabled() {
            self.error("No [llm] section in ~/.daedalerc (backend, model, api_key_env...)".to_string());
            return;
        }

        let llm = self.llm.clone();

        let result = match self.project(program) {
            Some(project) => project.llm_function(function, &llm),
            None => return,
        };

        match result {
            Ok(()) => self.info("Asking the LLM to improve and document the code, its proposal will show in :review".to_string()),
            Err(error) => self.error(format!("LLM: {:#}", error)),
        }
    }

    pub(crate) fn llm_modules(&mut self, program: usize, scope: Option<String>) {
        let module = match scope.as_deref() {
            Some("all") => None,
            Some(module) => Some(module.to_string()),
            None => self.current_module(),
        };

        let llm = self.llm.clone();

        let Some(project) = self.project(program) else {
            return;
        };

        match project.llm_modules(module.as_deref(), &llm) {
            Ok(()) => self.info(format!("Asking the LLM to organize {}...", module.as_deref().unwrap_or("the program"))),
            Err(error) => self.report(Err(error)),
        }
    }

    pub(crate) fn rename_module(&mut self, program: usize, old: &str, new: &str) {
        let Some(project) = self.project(program) else {
            return;
        };

        let result = project.rename_module(old, new);
        self.report(result);

        for view in self.workspace.views_mut() {
            if let View::Source(source) = view {
                if source.module == old {
                    source.module = new.to_string();
                }
            }
        }
    }

    /// Loads a shared library: one the binary needs (by name), or any file
    pub(crate) fn library_command(&mut self, name: &str) {
        let found = self.libraries.iter().position(|l| l.file_name().starts_with(name) || l.needed.name.starts_with(name));

        let library = found.or_else(|| {
            Path::new(name).is_file().then(|| {
                self.add_libraries(vec![Needed { name: name.to_string(), path: Some(PathBuf::from(name)) }]);
                self.libraries.len() - 1
            })
        });

        match library.map(|l| (l, self.load_library(l))) {
            Some((library, Some(_))) => self.info(format!("Loading {}...", self.libraries[library].file_name())),
            Some((library, None)) => self.error(format!("{} was not found", self.libraries[library].needed.name)),
            None => self.error(format!("No library {}", name)),
        }
    }
}
