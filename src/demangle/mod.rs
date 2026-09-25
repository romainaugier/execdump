mod itanium;
mod msvc;
mod rust;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManglingScheme {
    /// GCC and Clang on Linux, macOS (with an extra leading underscore), BSDs and MinGW
    Itanium,
    /// MSVC and clang-cl on Windows
    Msvc,
    /// Rust legacy mangling (Itanium-like with a trailing hash)
    RustLegacy,
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

    if ["_Z", "__Z", "___Z", "____Z"].iter().any(|p| symbol.starts_with(p)) {
        return ManglingScheme::Itanium;
    }

    return ManglingScheme::Unknown;
}

pub fn demangle(symbol: &str) -> Result<String, String> {
    let (prefix, unprefixed) = strip_import_prefix(symbol);
    let (name, version) = split_symbol_version(unprefixed);

    let demangled = match detect_mangling_scheme(symbol) {
        ManglingScheme::Itanium => itanium::demangle(name),
        ManglingScheme::Msvc => msvc::demangle(name),
        ManglingScheme::RustLegacy => rust::demangle(name),
        ManglingScheme::Unknown => return Err(format!("Unknown or unmangled symbol: {}", symbol)),
    };

    return demangled
        .map(|d| format!("{}{}{}", prefix, d, version))
        .ok_or_else(|| format!("Invalid mangled symbol: {}", symbol));
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn corpus_files() -> Vec<PathBuf> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/demangle");

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
    fn invalid_symbols() {
        for symbol in ["", "main", "_Z", "_Zv", "_Z1", "_Z3fo", "_ZN3fooEX", "?", "?@", "?f@@YAX", "??_C@_0", "_ZN4core3fmt17h0123E"] {
            assert!(demangle(symbol).is_err(), "{:?} should not demangle", symbol);
        }
    }
}
