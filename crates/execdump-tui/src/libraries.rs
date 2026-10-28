// SPDX-License-Identifier: Apache-2.0
/*
 * Shared libraries: the ones the binary needs are listed in the explorer. A library is loaded (parsed,
 * analyzed, with its own project in the libs/ directory of the project) when it is opened, or when an
 * imported function is followed into it. The libraries a loaded library needs are added to the list.
 */

use super::*;

use execdump_core::libraries::unversioned;
use execdump_core::program::SymbolKind;

use std::collections::HashMap;

pub(crate) struct Library {
    pub needed: Needed,
    /// Program of the library once it is loaded
    pub program: Option<usize>,
    /// Exported functions by name, read when an import is looked for
    exports: Option<HashMap<String, u64>>,
}

/// Imported function to open once its library is loaded
pub(crate) struct PendingImport {
    program: usize,
    addr: u64,
    code: bool,
}

impl Library {
    pub fn new(needed: Needed) -> Self {
        return Library { needed, program: None, exports: None };
    }

    pub fn file_name(&self) -> String {
        return self.needed.path.as_ref().and_then(|p| p.file_name()).map_or(self.needed.name.clone(), |n| n.to_string_lossy().to_string());
    }
}

/// Name of an imported function as its library exports it (no DLL prefix, no ELF version)
fn export_name(import: &str) -> &str {
    let name = import.rsplit_once('!').map_or(import, |(_, name)| name);
    return unversioned(name);
}

fn exports_of(program: &Program) -> HashMap<String, u64> {
    return program
        .symbols
        .values()
        .filter(|s| s.kind == SymbolKind::Function && program.is_executable(s.addr))
        .map(|s| (unversioned(&s.name).to_string(), s.addr))
        .collect();
}

impl App {
    /// Directory of the projects of the libraries
    fn libraries_location(&self) -> PathBuf {
        return self.project_location.clone().unwrap_or_else(|| default_location(&self.exec_path)).join("libs");
    }

    /// Starts loading a library (analysis and project in the background), returns its program
    pub(crate) fn load_library(&mut self, library: usize) -> Option<usize> {
        if let Some(program) = self.libraries[library].program {
            return Some(program);
        }

        let path = self.libraries[library].needed.path.clone()?;
        let index = self.programs.len();
        let location = self.libraries_location().join(self.libraries[library].file_name());

        // Parsed in the background: a placeholder until its analysis is done
        self.programs.push(Arc::new(Program::default()));
        self.decoders.push(None);
        self.analyses.push(None);
        self.analysis_errors.push(None);
        self.projects.push(None);
        self.loading.push(Loading::library(index, &self.sender, &path, location, self.workers));
        self.libraries[library].program = Some(index);
        self.explorer_version = u64::MAX;

        return Some(index);
    }

    /// The libraries a loaded library needs
    pub(crate) fn add_libraries(&mut self, needed: Vec<Needed>) {
        for needed in needed {
            if !self.libraries.iter().any(|l| l.needed.name == needed.name) {
                self.libraries.push(Library::new(needed));
                self.explorer_version = u64::MAX;
            }
        }
    }

    fn library_of_program(&self, program: usize) -> Option<&Library> {
        return self.libraries.iter().find(|l| l.program == Some(program));
    }

    /// Name shown after the items of a program: its library, or its architecture in fat binaries
    pub(crate) fn program_suffix(&self, program: usize) -> String {
        if let Some(library) = self.library_of_program(program) {
            return format!(" ({})", library.file_name());
        }

        return if self.main_programs > 1 { format!(" ({})", self.programs[program].name) } else { String::new() };
    }

    pub(crate) fn library_status(&self, library: usize) -> String {
        let library = &self.libraries[library];

        let Some(program) = library.program else {
            return if library.needed.path.is_some() { "not loaded".to_string() } else { "not found".to_string() };
        };

        if let Some(error) = &self.analysis_errors[program] {
            return error.clone();
        }

        return match &self.analyses[program] {
            Some(analysis) => format!("{} functions", analysis.functions.len()),
            None => "loading...".to_string(),
        };
    }

    fn exports(&mut self, library: usize) -> Option<&HashMap<String, u64>> {
        if self.libraries[library].exports.is_none() {
            let loaded = self.libraries[library].program.filter(|&p| self.analyses[p].is_some()).map(|p| exports_of(&self.programs[p]));

            let exports = match loaded {
                Some(exports) => exports,
                None => {
                    let path = self.libraries[library].needed.path.clone()?;
                    parse_binary(&path).map(|(program, _)| exports_of(&program)).unwrap_or_default()
                }
            };

            self.libraries[library].exports = Some(exports);
        }

        return self.libraries[library].exports.as_ref();
    }

    /// The library that exports a function, and its address there
    pub(crate) fn exporting_library(&mut self, import: &str) -> Option<(usize, u64)> {
        let name = export_name(import).to_string();
        return (0..self.libraries.len()).find_map(|library| self.exports(library).and_then(|e| e.get(&name)).map(|&addr| (library, addr)));
    }

    /// Opens an imported function in the library that exports it (loading the library first)
    pub(crate) fn follow_import(&mut self, import: &str, code: bool) -> bool {
        let name = export_name(import).to_string();

        if let Some((library, addr)) = self.exporting_library(&name) {
            if let Some(program) = self.load_library(library) {
                if self.projects[program].is_some() {
                    self.open_imported(program, addr, code);
                } else {
                    self.pending_import = Some(PendingImport { program, addr, code });
                    self.info(format!("Loading {} for {}...", self.libraries[library].file_name(), name));
                }

                return true;
            }
        }

        let missing: Vec<String> = self.libraries.iter().filter(|l| l.needed.path.is_none()).map(|l| l.needed.name.clone()).collect();
        let missing = if missing.is_empty() { String::new() } else { format!(" (not found: {})", missing.join(", ")) };
        self.error(format!("{} is imported, no library found exports it{}", name, missing));

        return false;
    }

    fn open_imported(&mut self, program: usize, addr: u64, code: bool) {
        if code {
            self.open_code(program, addr);
        } else {
            self.open_function(program, addr, None);
        }
    }

    /// A program finished loading: the imported function waiting for it is opened
    pub(crate) fn program_loaded(&mut self, program: usize) {
        if self.pending_import.as_ref().is_some_and(|p| p.program == program) {
            let pending = self.pending_import.take().unwrap();
            self.open_imported(pending.program, pending.addr, pending.code);
        }
    }

    /// Paths of the loaded libraries, in the order of their programs (kept with the session)
    pub(crate) fn loaded_libraries(&self) -> Vec<String> {
        let mut loaded: Vec<(usize, String)> = self.libraries.iter().filter_map(|l| Some((l.program?, l.needed.path.as_ref()?.to_string_lossy().to_string()))).collect();
        loaded.sort();
        return loaded.into_iter().map(|(_, path)| path).collect();
    }

    /// Loads the libraries of a session, returns the program each of its programs is now
    pub(crate) fn load_session_libraries(&mut self, paths: &[String]) -> HashMap<usize, usize> {
        let mut programs: HashMap<usize, usize> = (0..self.main_programs).map(|p| (p, p)).collect();

        for (index, path) in paths.iter().enumerate() {
            let library = match self.libraries.iter().position(|l| l.needed.path.as_ref().is_some_and(|p| p.to_string_lossy() == path.as_str())) {
                Some(library) => library,
                None if Path::new(path).is_file() => {
                    self.libraries.push(Library::new(Needed { name: path.clone(), path: Some(PathBuf::from(path)) }));
                    self.libraries.len() - 1
                }
                None => continue,
            };

            if let Some(program) = self.load_library(library) {
                programs.insert(self.main_programs + index, program);
            }
        }

        return programs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(export_name("printf@GLIBC_2.2.5"), "printf");
        assert_eq!(export_name("KERNEL32.dll!CreateFileW"), "CreateFileW");
        assert_eq!(export_name("Py_BytesMain"), "Py_BytesMain");
    }
}
