/*
 * Type database: prototypes, typedefs, structs, unions and enums parsed from C headers
 *
 * The bundled databases are normalized C generated from the system headers by
 * examples/build_typedb.rs (glibc for ELF and Mach-O, mingw-w64 for PE), so a program
 * gets the prototypes of its imports whatever the host. More headers can be parsed at runtime.
 */

mod parse;

use crate::types::{CType, DataModel, FuncType, Prototype};

use anyhow::Result;

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::Mutex;

pub use parse::preprocess;

const BUNDLED_LINUX: &str = include_str!("../../data/typedb/linux.h");
const BUNDLED_WINDOWS: &str = include_str!("../../data/typedb/windows.h");

/// Typedefs of the bundled headers (generated for 64-bit targets) that are as wide as a pointer
const WORDS_LINUX: &[&str] = &[
    "size_t", "__ssize_t", "__intptr_t", "__off_t", "__clock_t", "__time_t", "__suseconds_t", "__blksize_t", "__blkcnt_t", "__syscall_slong_t",
    "__fd_mask", "pthread_t", "wctype_t", "nfds_t", "__cpu_mask", "__ino_t", "__nlink_t", "__rlim_t", "greg_t", "__re_long_size_t", "reg_syntax_t",
];

const WORDS_WINDOWS: &[&str] = &["size_t", "intptr_t", "uintptr_t", "INT_PTR", "UINT_PTR", "LONG_PTR", "ULONG_PTR", "HANDLE_PTR"];

/// The source with the pointer sized typedefs of 32 bits
fn narrowed_words(source: &str, words: &[&str]) -> String {
    let mut out = String::with_capacity(source.len());

    for line in source.split_inclusive('\n') {
        let narrowed = words.iter().find_map(|word| {
            let rest = line.trim_end().strip_prefix("typedef ")?.strip_suffix(&format!("{};", word))?.trim();

            match rest {
                "int64_t" => Some(format!("typedef int {};\n", word)),
                "uint64_t" => Some(format!("typedef unsigned int {};\n", word)),
                _ => None,
            }
        });

        out.push_str(narrowed.as_deref().unwrap_or(line));
    }

    return out;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// glibc, also used for Mach-O (libSystem has the same C prototypes)
    Unix,
    Windows,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: CType,
    /// Offset in bytes of the field (of its storage unit for bitfields)
    pub offset: u64,
    /// Bitfields: offset in the storage unit and width, in bits
    pub bits: Option<(u16, u16)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Aggregate {
    pub fields: Vec<Field>,
    pub size: u64,
    pub align: u64,
    pub union: bool,
    /// #pragma pack or __attribute__((packed)) value, kept to regenerate the C
    pub pack: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Decl {
    Typedef(String),
    Aggregate(String),
    Enum(String),
    Function(String),
}

#[derive(Clone, Debug)]
pub struct TypeDb {
    pub model: DataModel,
    pub functions: HashMap<String, FuncType>,
    pub typedefs: HashMap<String, CType>,
    /// Keyed by tag, structs and unions share the namespace (as in C)
    pub aggregates: HashMap<String, Aggregate>,
    pub enums: HashMap<String, Vec<(String, i64)>>,
    pub constants: HashMap<String, i64>,
    /// Declaration order, definitions come before their uses when regenerating the C
    order: Vec<Decl>,
}

impl TypeDb {
    pub fn new(model: DataModel) -> Self {
        return TypeDb {
            model,
            functions: HashMap::new(),
            typedefs: HashMap::new(),
            aggregates: HashMap::new(),
            enums: HashMap::new(),
            constants: HashMap::new(),
            order: Vec::new(),
        };
    }

    /// Bundled database of a platform, laid out for the target data model (parsed once per process,
    /// every decompiler gets a copy)
    pub fn bundled(platform: Platform, model: DataModel) -> Self {
        static PARSED: Mutex<Vec<(Platform, DataModel, TypeDb)>> = Mutex::new(Vec::new());

        let mut parsed = PARSED.lock().unwrap_or_else(|e| e.into_inner());

        if let Some((_, _, db)) = parsed.iter().find(|(p, m, _)| *p == platform && *m == model) {
            return db.clone();
        }

        let mut db = TypeDb::new(model);
        let (source, words) = match platform {
            Platform::Unix => (BUNDLED_LINUX, WORDS_LINUX),
            Platform::Windows => (BUNDLED_WINDOWS, WORDS_WINDOWS),
        };

        let source = if model.pointer_bits == 32 { narrowed_words(source, words) } else { source.to_string() };
        db.parse(&source).expect("bundled type database must parse");
        parsed.push((platform, model, db.clone()));

        return db;
    }

    /// Adds the declarations of preprocessed C source
    pub fn parse(&mut self, source: &str) -> Result<()> {
        return parse::parse(self, source);
    }

    /*
     * Lookups
     */

    /// Prototype of an imported or exported function, import decorations are ignored
    /// (__imp_ prefix, ELF symbol versions, stdcall @N suffixes, Mach-O and x86 leading underscores)
    pub fn function(&self, symbol: &str) -> Option<Prototype> {
        let name = symbol.strip_prefix("__imp_").unwrap_or(symbol);
        let name = name.split('@').next().unwrap_or(name);

        let candidates = [name, name.strip_prefix('_').unwrap_or(name)];

        return candidates
            .iter()
            .find_map(|c| self.functions.get(*c).map(|ty| Prototype { name: c.to_string(), ty: ty.clone() }));
    }

    /// Follows the typedefs (keeps the qualifiers)
    pub fn resolve<'a>(&'a self, ty: &'a CType) -> &'a CType {
        match ty {
            CType::Typedef(name) => self.typedefs.get(name).map_or(ty, |t| self.resolve(t)),
            _ => ty,
        }
    }

    pub fn size_of(&self, ty: &CType) -> Option<u64> {
        let model = &self.model;

        match self.resolve(ty) {
            CType::Void | CType::Function(_) | CType::Unknown(0) => None,
            CType::Bool | CType::Char => Some(1),
            CType::Int { bits, .. } | CType::Float { bits } | CType::Unknown(bits) => Some(Self::storage_bytes(*bits)),
            CType::Pointer(_) => Some(model.pointer_bits as u64 / 8),
            CType::Const(inner) => self.size_of(inner),
            CType::Array(element, count) => Some(self.size_of(element)? * (*count)?),
            CType::Struct(name) | CType::Union(name) => self.aggregates.get(name).map(|a| a.size),
            CType::Enum(_) => Some(4),
            CType::Typedef(_) => None,
        }
    }

    pub fn align_of(&self, ty: &CType) -> Option<u64> {
        match self.resolve(ty) {
            CType::Const(inner) | CType::Array(inner, _) => self.align_of(inner),
            CType::Struct(name) | CType::Union(name) => self.aggregates.get(name).map(|a| a.align),
            // x86 long double (80 bits) is stored on 16 bytes in 64-bit mode
            other => self.size_of(other).map(|s| s.min(16)),
        }
    }

    fn storage_bytes(bits: u16) -> u64 {
        return match bits {
            80 => 16,
            _ => (bits as u64).div_ceil(8),
        };
    }

    /*
     * Registration (used by the parser)
     */

    // Redeclarations are compatible in C, the first one is kept (and keeps its place in the order)

    fn add_typedef(&mut self, name: String, ty: CType) {
        if !self.typedefs.contains_key(&name) {
            self.typedefs.insert(name.clone(), ty);
            self.order.push(Decl::Typedef(name));
        }
    }

    fn add_aggregate(&mut self, name: String, aggregate: Aggregate) {
        if !self.aggregates.contains_key(&name) {
            self.aggregates.insert(name.clone(), aggregate);
            self.order.push(Decl::Aggregate(name));
        }
    }

    fn add_enum(&mut self, name: String, values: Vec<(String, i64)>) {
        if !self.enums.contains_key(&name) {
            self.enums.insert(name.clone(), values);
            self.order.push(Decl::Enum(name));
        }
    }

    fn add_function(&mut self, name: String, ty: FuncType) {
        if !self.functions.contains_key(&name) {
            self.functions.insert(name.clone(), ty);
            self.order.push(Decl::Function(name));
        }
    }

    /*
     * Normalized C
     */

    /// Keeps the functions and the types they use (directly or through other types)
    pub fn reduce(&mut self) {
        let mut used: HashSet<String> = HashSet::new();
        let mut stack: Vec<CType> = self.functions.values().map(|f| CType::Function(Box::new(f.clone()))).collect();

        while let Some(ty) = stack.pop() {
            match ty {
                CType::Pointer(inner) | CType::Const(inner) | CType::Array(inner, _) => stack.push(*inner),
                CType::Function(func) => {
                    stack.push(func.ret);
                    stack.extend(func.params.into_iter().map(|p| p.ty));
                }
                CType::Typedef(name) => {
                    if used.insert(format!("typedef {}", name)) {
                        stack.extend(self.typedefs.get(&name).cloned());
                    }
                }
                CType::Struct(name) | CType::Union(name) => {
                    if used.insert(format!("tag {}", name)) {
                        stack.extend(self.aggregates.get(&name).iter().flat_map(|a| a.fields.iter().map(|f| f.ty.clone())));
                    }
                }
                CType::Enum(name) => {
                    used.insert(format!("enum {}", name));
                }
                _ => {}
            }
        }

        self.order.retain(|decl| match decl {
            Decl::Typedef(name) => used.contains(&format!("typedef {}", name)),
            Decl::Aggregate(name) => used.contains(&format!("tag {}", name)),
            Decl::Enum(name) => used.contains(&format!("enum {}", name)),
            Decl::Function(_) => true,
        });

        self.typedefs.retain(|name, _| used.contains(&format!("typedef {}", name)));
        self.aggregates.retain(|name, _| used.contains(&format!("tag {}", name)));
        self.enums.retain(|name, _| used.contains(&format!("enum {}", name)));
    }

    /// The database as C declarations, parsed back by TypeDb::parse
    pub fn to_c(&self) -> String {
        let mut out = String::new();

        // Forward declarations, pointers to aggregates can then appear in any order
        for decl in self.order.iter() {
            if let Decl::Aggregate(name) = decl {
                let keyword = if self.aggregates[name].union { "union" } else { "struct" };
                let _ = writeln!(out, "{} {};", keyword, name);
            }
        }

        for decl in self.order.iter() {
            match decl {
                Decl::Typedef(name) => {
                    let _ = writeln!(out, "typedef {};", self.typedefs[name].declare(name));
                }
                Decl::Aggregate(name) => {
                    let aggregate = &self.aggregates[name];

                    if let Some(pack) = aggregate.pack {
                        let _ = writeln!(out, "#pragma pack(push, {})", pack);
                    }

                    let _ = writeln!(out, "{} {} {{", if aggregate.union { "union" } else { "struct" }, name);

                    for field in aggregate.fields.iter() {
                        let width = field.bits.map_or(String::new(), |(_, width)| format!(" : {}", width));
                        let _ = writeln!(out, "    {}{};", field.ty.declare(&field.name), width);
                    }

                    let _ = writeln!(out, "}};");

                    if aggregate.pack.is_some() {
                        let _ = writeln!(out, "#pragma pack(pop)");
                    }
                }
                Decl::Enum(name) => {
                    let values: Vec<String> = self.enums[name].iter().map(|(n, v)| format!("{} = {}", n, v)).collect();
                    let _ = writeln!(out, "enum {} {{ {} }};", name, values.join(", "));
                }
                Decl::Function(name) => {
                    let prototype = Prototype { name: name.clone(), ty: self.functions[name].clone() };
                    let _ = writeln!(out, "{};", prototype);
                }
            }
        }

        return out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use execdump_core::disasm::Architecture;

    fn linux() -> TypeDb {
        return TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
    }

    fn windows() -> TypeDb {
        return TypeDb::bundled(Platform::Windows, DataModel::new(Architecture::X86_64, true));
    }

    #[test]
    fn libc_prototypes() {
        let db = linux();

        assert_eq!(db.function("fputs").unwrap().to_string(), "int fputs(const char *s, FILE *stream)");
        assert_eq!(db.function("printf@GLIBC_2.2.5").unwrap().to_string(), "int printf(const char *format, ...)");
        assert_eq!(db.function("_strlen").unwrap().to_string(), "size_t strlen(const char *s)");
        assert_eq!(db.function("__printf_chk").unwrap().ty.params.len(), 2);
        assert!(db.function("__libc_start_main").is_some());
        assert!(db.function("__stack_chk_fail").is_some());
        assert!(db.function("not_a_function").is_none());
    }

    #[test]
    fn libc_layouts() {
        let db = linux();

        assert_eq!(db.size_of(&CType::Typedef("size_t".to_string())), Some(8));
        assert_eq!(db.size_of(&CType::Struct("stat".to_string())), Some(144));
        assert_eq!(db.size_of(&CType::Struct("timespec".to_string())), Some(16));
        assert_eq!(db.size_of(&CType::Struct("_IO_FILE".to_string())), Some(216));

        let stat = &db.aggregates["stat"];
        let st_size = stat.fields.iter().find(|f| f.name == "st_size").unwrap();
        assert_eq!(st_size.offset, 48);

        // 32-bit targets: pointer sized typedefs of 4 bytes, the 64-bit ones are kept
        let db = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86, false));
        assert_eq!(db.size_of(&CType::Typedef("size_t".to_string())), Some(4));
        assert_eq!(db.size_of(&CType::Typedef("ssize_t".to_string())), Some(4));
        assert_eq!(db.size_of(&CType::Typedef("__off64_t".to_string())), Some(8));
        assert_eq!(db.function("malloc").unwrap().to_string(), "void *malloc(size_t size)");

        let db = TypeDb::bundled(Platform::Windows, DataModel::new(Architecture::X86, true));
        assert_eq!(db.size_of(&CType::Typedef("SIZE_T".to_string())), Some(4));
    }

    #[test]
    fn win32_prototypes() {
        let db = windows();

        assert_eq!(
            db.function("__imp_MessageBoxA").unwrap().to_string(),
            "int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)"
        );
        assert!(db.function("CreateFileW").is_some());
        assert!(db.function("_MessageBoxA@16").is_some());
        assert!(db.function("WSAStartup").is_some());
        assert!(db.function("printf").is_some());

        // Packed and aligned layouts
        assert_eq!(db.size_of(&CType::Typedef("SYSTEMTIME".to_string())), Some(16));
        assert_eq!(db.size_of(&CType::Typedef("CONTEXT".to_string())), Some(1232));
        assert_eq!(db.size_of(&CType::Typedef("OVERLAPPED".to_string())), Some(32));
    }

    #[test]
    fn regenerated_c_parses_to_the_same_database() {
        let db = linux();
        let mut again = TypeDb::new(db.model);
        again.parse(&db.to_c()).unwrap();

        assert_eq!(again.functions, db.functions);
        assert_eq!(again.aggregates, db.aggregates);
        assert_eq!(again.typedefs, db.typedefs);
    }
}
