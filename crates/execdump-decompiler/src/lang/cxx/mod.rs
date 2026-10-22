/*
 * C++: the prototypes of the demangled names, the classes they name (names.rs), the functions of the C++ runtimes that
 * do not return, the modules of the namespaces and classes
 */

pub mod names;

use super::Language;

use crate::types::{DataModel, Prototype};

use execdump_core::demangle::demangle_symbol;
use execdump_core::demangle::symbol::Symbol;
use execdump_core::program::{Language as Kind, Program};

use rustc_hash::{FxHashSet as HashSet};

pub struct Cxx {
    model: DataModel,
    /// The classes the demangled names of the program name: their methods without a member kind take this
    classes: HashSet<String>,
}

impl Cxx {
    pub fn new(program: &Program, model: DataModel) -> Self {
        let symbols: Vec<Symbol> = program.symbols.values().filter_map(|s| demangle_symbol(&s.name)).collect();
        return Cxx { model, classes: names::known_classes(symbols.iter()) };
    }
}

impl Language for Cxx {
    fn kind(&self) -> Kind {
        return Kind::Cxx;
    }

    fn owns(&self, program: &Program, _addr: u64) -> bool {
        return program.language == Kind::Cxx;
    }

    fn demangled_prototype(&self, symbol: &Symbol) -> Option<Prototype> {
        return names::prototype(symbol, &self.model, &self.classes);
    }

    fn guessed_module(&self, program: &Program, addr: u64) -> Option<String> {
        return namespace_module(&program.symbol_at(addr)?.demangled);
    }
}

/// The exceptions of the Itanium ABI and of MSVC, the errors of libstdc++ (names without their leading underscores)
pub fn noreturn(name: &str) -> bool {
    return matches!(
        name,
        "cxa_throw" | "cxa_rethrow" | "cxa_bad_cast" | "cxa_bad_typeid" | "Unwind_Resume" | "CxxThrowException" | "ZSt9terminatev"
            | "ZSt17__throw_bad_allocv" | "ZSt20__throw_length_errorPKc" | "ZSt24__throw_out_of_range_fmtPKcz" | "ZSt19__throw_logic_errorPKc"
            | "ZSt20__throw_out_of_rangePKc" | "ZSt25__throw_bad_function_callv" | "ZSt28__throw_bad_array_new_lengthv" | "ZSt16__throw_bad_castv"
            | "ZSt21__throw_bad_variant_accessPKc"
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules() {
        assert_eq!(namespace_module("net::Socket::connect(int, char const*)").as_deref(), Some("net/Socket.cpp"));
        assert_eq!(namespace_module("std::vector<int, std::allocator<int> >::push_back(int const&)").as_deref(), Some("std/vector.cpp"));
        assert_eq!(namespace_module("main"), None);
    }
}
