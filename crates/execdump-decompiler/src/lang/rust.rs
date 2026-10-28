// SPDX-License-Identifier: Apache-2.0
/*
 * Rust: the panics of core and std, the modules of the paths of the mangled names
 */

use super::Language;

use execdump_core::demangle::{detect_mangling_scheme, ManglingScheme};
use execdump_core::program::{Language as Kind, Program};

pub struct Rust;

/// The allocator and the panics of core
const DATABASE: &str = include_str!("../../data/typedb/rust.h");

impl Language for Rust {
    fn kind(&self) -> Kind {
        return Kind::Rust;
    }

    fn owns(&self, program: &Program, _addr: u64) -> bool {
        return program.language == Kind::Rust;
    }

    fn type_database(&self, program: &Program) -> Option<&'static str> {
        return (program.language == Kind::Rust).then_some(DATABASE);
    }

    /// The module of the path of an item (its object files are codegen units, not source files)
    fn source_module(&self, program: &Program, addr: u64) -> Option<String> {
        let symbol = program.symbol_at(addr).filter(|s| matches!(detect_mangling_scheme(&s.name), ManglingScheme::RustLegacy | ManglingScheme::RustV0))?;
        return module(&symbol.demangled);
    }
}

/// The functions of std::panicking that panic (set_hook, take_hook, panic_count::... return)
const STD_PANICS: &[&str] = &[
    "ZN3std9panicking11begin_panic",
    "ZN3std9panicking15begin_panic_fmt",
    "ZN3std9panicking19begin_panic_handler",
    "ZN3std9panicking20rust_panic_with_hook",
    "ZN3std9panicking23rust_panic_without_hook",
];

/// Panics, exits and allocation failures (names without their leading underscores)
pub fn noreturn(name: &str) -> bool {
    return name.starts_with("ZN4core9panicking")
        || name.starts_with("ZN3std7process4exit")
        || name.starts_with("ZN5alloc5alloc18handle_alloc_error")
        || name.starts_with("rust_panic")
        || name.starts_with("rust_begin_unwind")
        || STD_PANICS.iter().any(|p| name.starts_with(p));
}

/// Path of a Rust item without its generic arguments, closures and vendor suffix
fn path(demangled: &str) -> Vec<String> {
    let text = demangled.split(" (.").next().unwrap_or(demangled);
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ':' if depth == 0 && chars.peek() == Some(&':') => {
                chars.next();
                parts.push(std::mem::take(&mut current));
            }
            _ if depth == 0 => current.push(c),
            _ => {}
        }
    }

    parts.push(current);
    return parts.into_iter().filter(|p| !p.is_empty() && !p.starts_with('{')).collect();
}

/// Module of a Rust item: crate::module::Type::method -> crate/module.rs, the impls are in the module of
/// their type (<alloc::vec::Vec<T> as Drop>::drop -> alloc/vec.rs)
pub fn module(demangled: &str) -> Option<String> {
    let demangled = demangled.trim();

    let path = if let Some(inner) = demangled.strip_prefix('<') {
        // The type of the impl, or its trait when the type is not a path ([T], &str...)
        let mut depth = 0;
        let mut end = inner.len();

        for (i, c) in inner.char_indices() {
            match c {
                '<' => depth += 1,
                '>' if depth == 0 => {
                    end = i;
                    break;
                }
                '>' => depth -= 1,
                _ => {}
            }
        }

        let (ty, tr) = inner[..end].split_once(" as ").map_or((&inner[..end], None), |(t, r)| (t, Some(r)));

        let primitive = match ty.trim_start_matches(['&', '*']).trim_start_matches("mut ").trim_start_matches("const ") {
            "str" => Some("str"),
            "bool" => Some("bool"),
            "char" => Some("char"),
            "f32" | "f64" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => Some("num"),
            t if t.starts_with('[') => Some("slice"),
            _ => None,
        };

        let item = match (primitive, tr) {
            (Some(_), Some(tr)) => tr,
            (Some(module), None) => return Some(format!("core/{}.rs", module)),
            (None, tr) if !ty.starts_with(|c: char| c.is_alphabetic() || c == '_') => tr?,
            (None, _) => ty,
        };

        let mut path = path(item);
        path.push(String::new());
        path
    } else {
        path(demangled)
    };

    // The item itself, and the types and traits it is in
    let name = path.last()?.clone();
    let modules: Vec<&String> = path[..path.len() - 1].iter().take_while(|p| !p.starts_with(|c: char| c.is_uppercase())).collect();
    let (krate, rest) = modules.split_first()?;
    let sanitize = |p: &str| -> String { p.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect() };

    if rest.is_empty() {
        let file = if name == "main" { "main.rs" } else { "lib.rs" };
        return Some(format!("{}/{}", sanitize(krate), file));
    }

    let mut module: Vec<String> = modules.iter().map(|p| sanitize(p)).collect();
    let last = module.pop()?;
    module.push(format!("{}.rs", last));

    return Some(module.join("/"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules() {
        assert_eq!(module("execdump_tui::views::DisasmView::render").as_deref(), Some("execdump_tui/views.rs"));
        assert_eq!(module("<alloc::vec::Vec<u8> as core::ops::drop::Drop>::drop").as_deref(), Some("alloc/vec.rs"));
        assert_eq!(module("<execdump_project::cache::Cache>::put::{closure#0} (.llvm.42)").as_deref(), Some("execdump_project/cache.rs"));
        assert_eq!(module("<str>::starts_with::<char>").as_deref(), Some("core/str.rs"));
        assert_eq!(module("<[u8] as core::fmt::Debug>::fmt").as_deref(), Some("core/fmt.rs"));
        assert_eq!(module("core::ptr::drop_in_place::<alloc::string::String>").as_deref(), Some("core/ptr.rs"));
        assert_eq!(module("execdump::main").as_deref(), Some("execdump/main.rs"));
    }

    #[test]
    fn panics_never_return() {
        assert!(crate::lang::is_noreturn_name("_ZN3std9panicking20rust_panic_with_hook17h0123456789abcdefE"));
        assert!(crate::lang::is_noreturn_name("_ZN3std9panicking19begin_panic_handler17h0123456789abcdefE"));
        assert!(crate::lang::is_noreturn_name("_ZN4core9panicking9panic_fmt17h0123456789abcdefE"));
        assert!(!crate::lang::is_noreturn_name("_ZN3std9panicking8set_hook17hdba0096e3f6ed0afE"));
        assert!(!crate::lang::is_noreturn_name("_ZN3std9panicking11panic_count17is_zero_slow_path17h0123456789abcdefE"));
    }
}
