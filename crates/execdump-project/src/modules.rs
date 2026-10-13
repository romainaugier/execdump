/*
 * Modules: the source files the functions are organized in.
 *
 * The initial grouping is found automatically, from the most to the least reliable source:
 * - the ELF FILE symbols, which give the object file of the local functions
 * - the functions between two functions of the same object file (linkers lay out each object file
 *   contiguously)
 * - the namespaces and classes of the demangled C++ names
 * - a default module for the rest
 * The module given by the user to a function always wins.
 */

use execdump_core::program::Program;
use execdump_decompiler::analysis::Analysis;

use std::collections::{BTreeMap, HashMap};

/// Module of each function of the program (thunks are not code of the program and are left out)
pub fn auto_modules(program: &Program, analysis: &Analysis, default: &str) -> BTreeMap<u64, String> {
    let functions: Vec<u64> = analysis.functions.values().filter(|f| f.thunk.is_none()).map(|f| f.addr).collect();
    let mut modules: BTreeMap<u64, String> = BTreeMap::new();

    // Object files of the local functions
    let anchors: Vec<(u64, String)> = functions.iter().filter_map(|a| program.source_files.get(a).map(|f| (*a, source_module(f)))).collect();

    for (addr, module) in anchors.iter() {
        modules.insert(*addr, module.clone());
    }

    // Between two functions of the same object file
    for pair in anchors.windows(2) {
        let ((start, a), (end, b)) = (&pair[0], &pair[1]);

        if a == b {
            for &addr in functions.iter().filter(|&&f| f > *start && f < *end) {
                modules.entry(addr).or_insert_with(|| a.clone());
            }
        }
    }

    for &addr in functions.iter() {
        if modules.contains_key(&addr) {
            continue;
        }

        let class = program.symbol_at(addr).and_then(|s| namespace_module(&s.demangled));
        modules.insert(addr, class.unwrap_or_else(|| default.to_string()));
    }

    return modules;
}

/// Module name of an object file name: its file name, as a C source when it is not one
pub(crate) fn source_module(file: &str) -> String {
    let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
    let name: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+') { c } else { '_' }).collect();

    if name.ends_with(".c") || name.ends_with(".cpp") || name.ends_with(".cc") || name.ends_with(".cxx") || name.ends_with(".s") || name.ends_with(".S") {
        return name;
    }

    return format!("{}.c", name.trim_end_matches(".o"));
}

/// ns::Class::method(int) -> ns/Class.cpp
fn namespace_module(demangled: &str) -> Option<String> {
    let mut depth = 0;
    let mut name = String::new();

    // Template arguments and parameters are dropped
    for c in demangled.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth == 0 => break,
            _ if depth == 0 => name.push(c),
            _ => {}
        }
    }

    let parts: Vec<&str> = name.split("::").map(str::trim).filter(|p| !p.is_empty()).collect();

    if parts.len() < 2 || parts.iter().any(|p| p.contains(' ') || p.starts_with('{')) {
        return None;
    }

    let path: Vec<String> = parts[..parts.len() - 1].iter().map(|p| p.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()).collect();

    return Some(format!("{}.cpp", path.join("/")));
}

/// Functions of each module, in address order
#[derive(Clone, Debug, Default)]
pub struct Modules {
    by_name: BTreeMap<String, Vec<u64>>,
    of: HashMap<u64, String>,
}

impl Modules {
    pub fn new(assignments: impl IntoIterator<Item = (u64, String)>, empty: impl IntoIterator<Item = String>) -> Self {
        let mut modules = Modules::default();

        for name in empty {
            modules.by_name.entry(name).or_default();
        }

        for (addr, name) in assignments {
            modules.by_name.entry(name.clone()).or_default().push(addr);
            modules.of.insert(addr, name);
        }

        modules.by_name.values_mut().for_each(|v| v.sort());

        return modules;
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        return self.by_name.keys();
    }

    pub fn len(&self) -> usize {
        return self.by_name.len();
    }

    pub fn functions(&self, module: &str) -> &[u64] {
        return self.by_name.get(module).map_or(&[], |v| v.as_slice());
    }

    pub fn module_of(&self, addr: u64) -> Option<&str> {
        return self.of.get(&addr).map(|s| s.as_str());
    }

    pub fn contains(&self, module: &str) -> bool {
        return self.by_name.contains_key(module);
    }

    pub fn add(&mut self, module: &str) {
        self.by_name.entry(module.to_string()).or_default();
    }

    /// Moves a function to a module, returns the module it was in
    pub fn assign(&mut self, addr: u64, module: &str) -> Option<String> {
        let old = self.of.insert(addr, module.to_string());

        if let Some(old) = old.as_ref() {
            if let Some(functions) = self.by_name.get_mut(old) {
                if let Ok(index) = functions.binary_search(&addr) {
                    functions.remove(index);
                }
            }
        }

        let functions = self.by_name.entry(module.to_string()).or_default();

        if let Err(index) = functions.binary_search(&addr) {
            functions.insert(index, addr);
        }

        return old;
    }

    /// Removes a module, only when it is empty
    pub fn remove(&mut self, module: &str) -> bool {
        if self.by_name.get(module).is_some_and(|f| f.is_empty()) {
            self.by_name.remove(module);
            return true;
        }

        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(source_module("src/net/socket.c"), "socket.c");
        assert_eq!(source_module("crtstuff.o"), "crtstuff.c");
        assert_eq!(namespace_module("net::Socket::connect(int, char const*)").as_deref(), Some("net/Socket.cpp"));
        assert_eq!(namespace_module("std::vector<int, std::allocator<int> >::push_back(int const&)").as_deref(), Some("std/vector.cpp"));
        assert_eq!(namespace_module("main"), None);
    }

    #[test]
    fn grouping() {
        use execdump_core::elf::parse_elf;
        use execdump_core::exec::Exec;
        use execdump_core::program::programs_from_exec;
        use execdump_decompiler::analysis::analyze;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
        let mut program = programs_from_exec(&Exec::ELF(parse_elf(&path).unwrap())).remove(0);
        let analysis = analyze(&program, None).unwrap();
        let (classify, main) = (analysis.function_by_name("classify").unwrap().addr, analysis.function_by_name("main").unwrap().addr);

        // Two local functions of the same object file: what lies between them belongs to it too
        program.source_files.insert(analysis.function_by_name("fatal").unwrap().addr, "src/analysis.c".to_string());
        program.source_files.insert(main, "src/analysis.c".to_string());

        let modules = auto_modules(&program, &analysis, "default.c");
        assert_eq!(modules[&classify], "analysis.c");
        assert_eq!(modules[&main], "analysis.c");
        assert!(analysis.functions.values().filter(|f| f.thunk.is_some()).all(|f| !modules.contains_key(&f.addr)));

        let mut modules = Modules::new(modules, ["empty.c".to_string()]);
        assert!(modules.functions("empty.c").is_empty());
        assert_eq!(modules.assign(classify, "net/socket.c").as_deref(), Some("analysis.c"));
        assert_eq!(modules.functions("net/socket.c"), [classify]);
        assert!(!modules.functions("analysis.c").contains(&classify));
        assert!(modules.remove("empty.c"));
        assert!(!modules.remove("net/socket.c"));
    }
}
