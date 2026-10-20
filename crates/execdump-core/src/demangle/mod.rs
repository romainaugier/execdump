mod itanium;
mod msvc;
mod rust;
pub mod symbol;

use symbol::Symbol;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManglingScheme {
    /// GCC and Clang on Linux, macOS (with an extra leading underscore), BSDs and MinGW
    Itanium,
    /// MSVC and clang-cl on Windows
    Msvc,
    /// Rust legacy mangling (Itanium-like with a trailing hash)
    RustLegacy,
    /// Rust v0 mangling (_R)
    RustV0,
    Unknown,
}

const IMPORT_PREFIX: &str = "__imp_";

fn strip_import_prefix(symbol: &str) -> (&str, &str) {
    match symbol.strip_prefix(IMPORT_PREFIX) {
        Some(rest) => (IMPORT_PREFIX, rest),
        None => ("", symbol),
    }
}

/// ELF symbol versions (name@VERSION, name@@VERSION), MSVC names use '@' so they are left untouched
fn split_symbol_version(symbol: &str) -> (&str, &str) {
    if symbol.starts_with('?') || symbol.starts_with(".?") {
        return (symbol, "");
    }

    match symbol.find('@') {
        Some(index) if index > 0 => (&symbol[..index], &symbol[index..]),
        _ => (symbol, ""),
    }
}

pub fn detect_mangling_scheme(symbol: &str) -> ManglingScheme {
    let (_, symbol) = strip_import_prefix(symbol);
    let (symbol, _) = split_symbol_version(symbol);

    if symbol.starts_with('?') || symbol.starts_with(".?A") {
        return ManglingScheme::Msvc;
    }

    if rust::is_rust_legacy(symbol) {
        return ManglingScheme::RustLegacy;
    }

    if rust::is_rust_v0(symbol) {
        return ManglingScheme::RustV0;
    }

    if ["_Z", "__Z", "___Z", "____Z"].iter().any(|p| symbol.starts_with(p)) {
        return ManglingScheme::Itanium;
    }

    return ManglingScheme::Unknown;
}

pub fn demangle(symbol: &str) -> Result<String> {
    let (prefix, unprefixed) = strip_import_prefix(symbol);
    let (name, version) = split_symbol_version(unprefixed);

    let demangled = match detect_mangling_scheme(symbol) {
        ManglingScheme::Itanium => itanium::demangle(name),
        ManglingScheme::Msvc => msvc::demangle(name),
        ManglingScheme::RustLegacy => rust::demangle(name),
        ManglingScheme::RustV0 => rust::demangle_v0(name),
        ManglingScheme::Unknown => bail!("Unknown or unmangled symbol: {}", symbol),
    };

    return demangled
        .map(|d| format!("{}{}{}", prefix, d, version))
        .with_context(|| format!("Invalid mangled symbol: {}", symbol));
}

/// Typed description of a mangled symbol (import prefixes and ELF symbol versions are ignored)
pub fn demangle_symbol(symbol: &str) -> Option<Symbol> {
    let (_, unprefixed) = strip_import_prefix(symbol);
    let (name, _) = split_symbol_version(unprefixed);

    match detect_mangling_scheme(symbol) {
        ManglingScheme::Itanium => itanium::demangle_symbol(name),
        ManglingScheme::Msvc => msvc::demangle_symbol(name),
        ManglingScheme::RustLegacy => rust::demangle_symbol(name),
        ManglingScheme::RustV0 => rust::demangle_v0_symbol(name),
        ManglingScheme::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn corpus_files() -> Vec<PathBuf> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/demangle");

        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "tsv"))
            .collect();

        files.sort();

        return files;
    }

    fn corpus(path: &PathBuf) -> Vec<(String, String)> {
        return std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(m, d)| (m.to_string(), d.to_string()))
            .collect();
    }

    #[test]
    fn corpus_matches_llvm() {
        let mut failures = Vec::new();
        let mut total = 0;

        for path in corpus_files() {
            let name = path.file_name().unwrap().to_string_lossy().to_string();

            for (mangled, expected) in corpus(&path) {
                total += 1;

                match demangle(&mangled) {
                    Ok(demangled) if demangled == expected => {}
                    result => failures.push(format!("{}: {}\n  expected: {}\n  got:      {:?}", name, mangled, expected, result)),
                }
            }
        }

        assert!(total > 4000, "corpus is missing, found {} entries", total);
        assert!(failures.is_empty(), "{} / {} mismatches:\n{}", failures.len(), total, failures.join("\n"));
    }

    #[test]
    fn corpus_covers_every_target() {
        let names: Vec<String> = corpus_files().iter().map(|p| p.file_stem().unwrap().to_string_lossy().to_string()).collect();

        for target in [
            "x86_64-linux-gnu",
            "aarch64-linux-gnu",
            "x86_64-apple-macos11",
            "arm64-apple-macos11",
            "x86_64-w64-windows-gnu",
            "i686-w64-windows-gnu",
            "x86_64-pc-windows-msvc",
            "i686-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "arm64ec-pc-windows-msvc",
        ] {
            assert!(names.iter().any(|n| n == target), "missing corpus for {}", target);
        }
    }

    #[test]
    fn truncated_symbols_do_not_panic() {
        for path in corpus_files() {
            for (i, (mangled, _)) in corpus(&path).iter().enumerate() {
                if i % 10 != 0 {
                    continue;
                }

                for end in 0..mangled.len() {
                    if mangled.is_char_boundary(end) {
                        let _ = demangle(&mangled[..end]);
                    }
                }
            }
        }
    }

    #[test]
    fn scheme_detection() {
        assert_eq!(detect_mangling_scheme("_ZN2ns3fooEv"), ManglingScheme::Itanium);
        assert_eq!(detect_mangling_scheme("__ZN2ns3fooEv"), ManglingScheme::Itanium);
        assert_eq!(detect_mangling_scheme("___Z3foov_block_invoke"), ManglingScheme::Itanium);
        assert_eq!(detect_mangling_scheme("?foo@ns@@YAXXZ"), ManglingScheme::Msvc);
        assert_eq!(detect_mangling_scheme(".?AVFoo@@"), ManglingScheme::Msvc);
        assert_eq!(detect_mangling_scheme("__imp_?foo@@YAXXZ"), ManglingScheme::Msvc);
        assert_eq!(detect_mangling_scheme("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE"), ManglingScheme::RustLegacy);
        assert_eq!(detect_mangling_scheme("main"), ManglingScheme::Unknown);
        assert_eq!(detect_mangling_scheme("_start"), ManglingScheme::Unknown);
        assert_eq!(detect_mangling_scheme("_printf"), ManglingScheme::Unknown);
        assert_eq!(detect_mangling_scheme("MessageBoxA"), ManglingScheme::Unknown);
    }

    #[test]
    fn linux() {
        assert_eq!(demangle("_ZNSt6vectorIiSaIiEE9push_backERKi").unwrap(), "std::vector<int, std::allocator<int>>::push_back(int const&)");
        assert_eq!(demangle("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv@@GLIBCXX_3.4.21").unwrap(),
                   "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::size() const@@GLIBCXX_3.4.21");
        assert_eq!(demangle("_ZSt4cout@GLIBCXX_3.4").unwrap(), "std::cout@GLIBCXX_3.4");
        assert_eq!(demangle("_ZN3foo3barEv.cold").unwrap(), "foo::bar() (.cold)");
        assert_eq!(demangle("_ZN3foo3barEv.isra.0").unwrap(), "foo::bar() (.isra.0)");
        assert_eq!(demangle("_ZZ4mainENKUlvE_clEv").unwrap(), "main::'lambda'()::operator()() const");
        assert_eq!(demangle("_ZTV3Foo").unwrap(), "vtable for Foo");
        assert_eq!(demangle("_ZThn8_N3Foo3barEv").unwrap(), "non-virtual thunk to Foo::bar()");
        assert_eq!(demangle("_ZN12_GLOBAL__N_13fooEv").unwrap(), "(anonymous namespace)::foo()");
        assert_eq!(demangle("_Z1fPFivEPA3_i").unwrap(), "f(int (*)(), int (*) [3])");
        assert_eq!(demangle("_Z1fIJidEEvDpT_").unwrap(), "void f<int, double>(int, double)");
        assert_eq!(demangle("_Z1fM3FooFviE").unwrap(), "f(void (Foo::*)(int))");
    }

    #[test]
    fn macos() {
        assert_eq!(demangle("__ZN2ns5twiceEi").unwrap(), "ns::twice(int)");
        assert_eq!(demangle("__ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi").unwrap(),
                   "std::__1::vector<int, std::__1::allocator<int>>::push_back(int const&)");
        assert_eq!(demangle("___Z3foov_block_invoke").unwrap(), "invocation function for block in foo()");
        assert_eq!(demangle("___Z3foov_block_invoke_2").unwrap(), "invocation function for block in foo()");
    }

    #[test]
    fn mingw() {
        assert_eq!(demangle("_Z3addii").unwrap(), "add(int, int)");
        assert_eq!(demangle("__Z3addii").unwrap(), "add(int, int)");
        assert_eq!(demangle("__imp__ZN2ns3fooEv").unwrap(), "__imp_ns::foo()");
    }

    #[test]
    fn windows_msvc() {
        assert_eq!(demangle("?bar@Foo@@QEAAXH@Z").unwrap(), "public: void __cdecl Foo::bar(int)");
        assert_eq!(demangle("?f@Foo@@QAEXXZ").unwrap(), "public: void __thiscall Foo::f(void)");
        assert_eq!(demangle("?f@@YGXXZ").unwrap(), "void __stdcall f(void)");
        assert_eq!(demangle("?f@@YIXXZ").unwrap(), "void __fastcall f(void)");
        assert_eq!(demangle("?f@@YQXXZ").unwrap(), "void __vectorcall f(void)");
        assert_eq!(demangle("??_7Foo@@6B@").unwrap(), "const Foo::`vftable'");
        assert_eq!(demangle("??_GFoo@@UEAAPEAXI@Z").unwrap(), "public: virtual void * __cdecl Foo::`scalar deleting dtor'(unsigned int)");
        assert_eq!(demangle("??_C@_0M@KPLPPDAC@hello?5world?$AA@").unwrap(), "\"hello world\"");
        assert_eq!(demangle("??$f@V?$vector@HV?$allocator@H@std@@@std@@@@YAXXZ").unwrap(),
                   "void __cdecl f<class std::vector<int, class std::allocator<int>>>(void)");
        assert_eq!(demangle("?x@?1??foo@@YAXXZ@4HA").unwrap(), "int `void __cdecl foo(void)'::`2'::x");
        assert_eq!(demangle(".?AVFoo@@").unwrap(), "class Foo `RTTI Type Descriptor Name'");
        assert_eq!(demangle("__imp_?foo@@YAXXZ").unwrap(), "__imp_void __cdecl foo(void)");
    }

    #[test]
    fn windows_arm64ec() {
        assert_eq!(demangle("?foo@ns@@$$hYAXH@Z").unwrap(), "void __cdecl ns::foo(int)");
        assert_eq!(demangle("??$pack@HND@ns@@$$hYAXHND@Z").unwrap(), "void __cdecl ns::pack<int, double, char>(int, double, char)");
    }

    #[test]
    fn rust_legacy() {
        assert_eq!(demangle("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE").unwrap(), "core::fmt::Formatter::pad");
        assert_eq!(demangle("_ZN5alloc3vec16Vec$LT$T$C$A$GT$4push17h0123456789abcdefE").unwrap(), "alloc::vec::Vec<T,A>::push");
        assert_eq!(demangle("_ZN4core3ptr85drop_in_place$LT$std..rt..lang_start$LT$$LP$$RP$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h0123456789abcdefE").unwrap(),
                   "core::ptr::drop_in_place<std::rt::lang_start<()>::{{closure}}>");
        assert_eq!(demangle("_ZN3std2rt10lang_start17h0123456789abcdefE.llvm.1234").unwrap(), "std::rt::lang_start");
        assert_eq!(demangle("__ZN3std2rt10lang_start17h0123456789abcdefE").unwrap(), "std::rt::lang_start");
    }

    #[test]
    fn rust_v0() {
        assert_eq!(detect_mangling_scheme("_RNvCs1234_7mycrate3foo"), ManglingScheme::RustV0);
        assert_eq!(demangle("_RNvCs1234_7mycrate3foo").unwrap(), "mycrate::foo");
        assert_eq!(demangle("_RNCNvCs1234_7mycrate3foo0B3_").unwrap(), "mycrate::foo::{closure#0}");
        assert_eq!(demangle("_RINvNtCs1234_4core3mem7replaceReEB4_").unwrap(), "core::mem::replace::<&str>");
        assert_eq!(demangle("_RNvMNtCs1234_7mycrate5typesNtB2_4Type3new.llvm.42").unwrap(), "<mycrate::types::Type>::new (.llvm.42)");
        assert_eq!(rust::decode_punycode_for_tests("Mnchen_3ya").as_deref(), Some("München"));

        let symbol = demangle_symbol("_RINvNtCs1234_4core3mem7replaceReEB4_").unwrap();
        let path: Vec<&str> = symbol.name.parts.iter().map(|p| p.ident.as_str()).collect();
        assert_eq!(path, ["core", "mem", "replace::<&str>"]);
    }

    #[test]
    fn invalid_symbols() {
        for symbol in ["", "main", "_Z", "_Zv", "_Z1", "_Z3fo", "_ZN3fooEX", "?", "?@", "?f@@YAX", "??_C@_0", "_ZN4core3fmt17h0123E", "_RNvC3foo", "_RB_", "_RC3fo"] {
            assert!(demangle(symbol).is_err(), "{:?} should not demangle", symbol);
        }
    }

    fn function(symbol: &str) -> (Vec<String>, symbol::FunctionType, symbol::Member, bool, Option<symbol::Structor>) {
        let demangled = demangle_symbol(symbol).unwrap();
        let path = demangled.name.parts.iter().map(|p| p.ident.clone()).collect();

        match demangled.kind {
            symbol::SymbolKind::Function { ty, member, const_this, structor } => (path, ty, member, const_this, structor),
            kind => panic!("{}: expected a function, got {:?}", symbol, kind),
        }
    }

    #[test]
    fn typed_itanium() {
        use symbol::{Builtin, Member, Structor, TemplateArg, Type};

        let int = || Type::Builtin(Builtin::Int);

        let (path, ty, member, _, _) = function("_Z3addii");
        assert_eq!(path, ["add"]);
        assert_eq!(ty.params, [int(), int()]);
        assert_eq!(ty.ret, None);
        assert_eq!(member, Member::None);

        let (path, ty, member, _, _) = function("_ZNSt6vectorIiSaIiEE9push_backERKi");
        assert_eq!(path, ["std", "vector", "push_back"]);
        assert_eq!(ty.params, [Type::Reference(Box::new(Type::Const(Box::new(int()))))]);
        assert_eq!(member, Member::Unknown);

        let demangled = demangle_symbol("_ZNSt6vectorIiSaIiEE9push_backERKi").unwrap();
        assert_eq!(demangled.name.parts[1].template_args.len(), 2);
        assert_eq!(demangled.name.parts[1].template_args[0], TemplateArg::Type(int()));

        let (_, _, member, const_this, _) = function("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv@@GLIBCXX_3.4.21");
        assert_eq!((member, const_this), (Member::Instance, true));

        let (path, _, member, _, structor) = function("_ZN3FooC2Ev");
        assert_eq!(path, ["Foo", "Foo"]);
        assert_eq!((member, structor), (Member::Instance, Some(Structor::Ctor)));

        let (path, _, _, _, structor) = function("_ZN3FooD1Ev");
        assert_eq!(path, ["Foo", "~Foo"]);
        assert_eq!(structor, Some(Structor::Dtor));

        let (_, ty, _, _, _) = function("_Z1fIJidEEvDpT_");
        assert_eq!(ty.ret, Some(Type::Builtin(Builtin::Void)));

        let (_, ty, _, _, _) = function("_Z6printfPKcz");
        assert!(ty.variadic);
        assert_eq!(ty.params, [Type::Pointer(Box::new(Type::Const(Box::new(Type::Builtin(Builtin::Char)))))]);

        let (_, ty, _, _, _) = function("_Z1fPFivEPA3_i");
        assert!(matches!(&ty.params[0], Type::Pointer(f) if matches!(**f, Type::Function(_))));
        assert_eq!(ty.params[1], Type::Pointer(Box::new(Type::Array(Box::new(int()), Some(3)))));

        let vtable = demangle_symbol("_ZTV3Foo").unwrap();
        assert_eq!(vtable.name.parts[0].ident, "Foo");
        assert_eq!(vtable.kind, symbol::SymbolKind::Special("vtable for".to_string()));

        let data = demangle_symbol("_ZSt4cout@GLIBCXX_3.4").unwrap();
        assert_eq!(data.kind, symbol::SymbolKind::Variable(None));
    }

    #[test]
    fn typed_msvc() {
        use symbol::{Builtin, CallConv, Member, Structor, Type};

        let (path, ty, member, _, _) = function("?bar@Foo@@QEAAXH@Z");
        assert_eq!(path, ["Foo", "bar"]);
        assert_eq!(ty.params, [Type::Builtin(Builtin::Int)]);
        assert_eq!(ty.ret, Some(Type::Builtin(Builtin::Void)));
        assert_eq!(member, Member::Instance);

        let (_, ty, member, _, _) = function("?f@@YGXXZ");
        assert_eq!((member, ty.call_conv), (Member::None, Some(CallConv::Stdcall)));
        assert!(ty.params.is_empty());

        let (path, ty, member, _, _) = function("??_GFoo@@UEAAPEAXI@Z");
        assert_eq!(path[0], "Foo");
        assert_eq!(member, Member::Virtual);
        assert_eq!(ty.ret, Some(Type::Pointer(Box::new(Type::Builtin(Builtin::Void)))));

        let (path, _, _, _, structor) = function("??0Foo@@QEAA@XZ");
        assert_eq!(path, ["Foo", "Foo"]);
        assert_eq!(structor, Some(Structor::Ctor));

        let vftable = demangle_symbol("??_7Foo@@6B@").unwrap();
        assert_eq!(vftable.name.parts[0].ident, "Foo");
        assert!(matches!(vftable.kind, symbol::SymbolKind::Special(_)));
    }

    #[test]
    fn typed_rust() {
        let demangled = demangle_symbol("_ZN4core3ptr85drop_in_place$LT$std..rt..lang_start$LT$$LP$$RP$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h0123456789abcdefE").unwrap();
        let path: Vec<&str> = demangled.name.parts.iter().map(|p| p.ident.as_str()).collect();
        assert_eq!(path, ["core", "ptr", "drop_in_place<std::rt::lang_start<()>::{{closure}}>"]);
    }

    #[test]
    fn typed_corpus() {
        let mut missing = Vec::new();

        for path in corpus_files() {
            for (mangled, _) in corpus(&path) {
                if demangle(&mangled).is_ok() && demangle_symbol(&mangled).is_none() {
                    missing.push(mangled);
                }
            }
        }

        assert!(missing.is_empty(), "{} symbols without a typed description:\n{}", missing.len(), missing.join("\n"));
    }
}
