// SPDX-License-Identifier: Apache-2.0
/*
 * The DWARF debug information of a program in the decompiler: its types become C declarations of the type database
 * (structs, unions, enums, typedefs), its functions get their prototypes, with the names of their parameters.
 *
 * The prototypes are declared with the types as functions named after their address, parsed with the types, then
 * taken out of the database: the parser of the database reads any declarator (pointers to functions, arrays).
 */

use crate::typedb::TypeDb;
use crate::types::Prototype;

use execdump_core::dwarf::{DebugInfo, DebugType, Encoding, TypeId};

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::fmt::Write;

const PROTOTYPE_PREFIX: &str = "__debug_function_";

const C_WORDS: &[&str] = &["unsigned", "signed", "char", "short", "int", "long", "float", "double", "_Bool", "void"];

const KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int",
    "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while", "_Bool",
];

fn identifier(name: &str) -> String {
    let mut out: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();

    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) || KEYWORDS.contains(&out.as_str()) {
        out.insert(0, '_');
    }

    return out;
}

struct Declarations<'a> {
    debug: &'a DebugInfo,
    /// C name of each struct, union, enum and typedef
    names: HashMap<TypeId, String>,
    /// The types declared (the first definition of a name, the others are the same type in other compile units)
    declared: HashSet<TypeId>,
    /// The declared type of each type of the same name
    canonical: HashMap<TypeId, TypeId>,
}

impl Declarations<'_> {
    fn ty(&self, id: Option<TypeId>) -> &DebugType {
        static VOID: DebugType = DebugType::Unknown;
        return id.and_then(|i| self.debug.types.get(i)).unwrap_or(&VOID);
    }

    /// The type of a DIE, its duplicates in the other compile units are the declared one
    fn canonical(&self, id: TypeId) -> TypeId {
        return self.canonical.get(&id).copied().unwrap_or(id);
    }

    fn base(name: &str, size: u64, encoding: Encoding) -> String {
        if !name.is_empty() && name.split_whitespace().all(|w| C_WORDS.contains(&w)) {
            return name.to_string();
        }

        let unsigned = if encoding == Encoding::Unsigned || encoding == Encoding::UnsignedChar { "unsigned " } else { "" };

        return match (encoding, size) {
            (Encoding::Float, 4) => "float".to_string(),
            (Encoding::Float, 8) => "double".to_string(),
            (Encoding::Float, _) => "long double".to_string(),
            (Encoding::Bool, _) => "_Bool".to_string(),
            (_, 1) => format!("{}char", unsigned),
            (_, 2) => format!("{}short", unsigned),
            (_, 4) => format!("{}int", unsigned),
            (_, 8) => format!("{}long long", unsigned),
            (_, 16) => format!("{}__int128", unsigned),
            _ => "int".to_string(),
        };
    }

    /// A declaration of a type: its specifiers around the declarator (int (*name)[4])
    fn declare(&self, id: Option<TypeId>, declarator: &str) -> String {
        let spaced = |spec: &str, d: &str| if d.is_empty() { spec.to_string() } else { format!("{} {}", spec, d) };

        let Some(id) = id else {
            return spaced("void", declarator);
        };

        return match self.ty(Some(id)) {
            DebugType::Unknown => spaced("void", declarator),
            DebugType::Base { name, size, encoding } => spaced(&Self::base(name, *size, *encoding), declarator),
            DebugType::Pointer(to) => {
                let inner = match self.ty(*to) {
                    DebugType::Array { .. } | DebugType::Function { .. } => format!("(*{})", declarator),
                    _ => format!("*{}", declarator),
                };

                self.declare(*to, &inner)
            }
            DebugType::Const(inner) | DebugType::Volatile(inner) => {
                let qualifier = if matches!(self.ty(Some(id)), DebugType::Const(_)) { "const" } else { "volatile" };

                match self.ty(*inner) {
                    // The qualifiers of pointers and arrays are left out
                    DebugType::Pointer(_) | DebugType::Array { .. } | DebugType::Function { .. } => self.declare(*inner, declarator),
                    _ => format!("{} {}", qualifier, self.declare(*inner, declarator)),
                }
            }
            DebugType::Typedef { .. } | DebugType::Aggregate { .. } | DebugType::Enum { .. } => spaced(&self.specifier(id), declarator),
            DebugType::Array { ty, count } => self.declare(*ty, &format!("{}[{}]", declarator, count.map_or(String::new(), |c| c.to_string()))),
            DebugType::Function { ret, params, variadic } => {
                let mut list: Vec<String> = params.iter().map(|p| self.declare(*p, "")).collect();

                if *variadic {
                    list.push("...".to_string());
                }

                let list = if list.is_empty() { "void".to_string() } else { list.join(", ") };
                self.declare(*ret, &format!("{}({})", declarator, list))
            }
        };
    }

    /// struct name, union name, enum name or the name of a typedef
    fn specifier(&self, id: TypeId) -> String {
        let id = self.canonical(id);
        let name = self.names.get(&id).cloned().unwrap_or_else(|| format!("anonymous_{}", id));

        return match &self.debug.types[id] {
            DebugType::Aggregate { union: true, .. } => format!("union {}", name),
            DebugType::Aggregate { .. } => format!("struct {}", name),
            DebugType::Enum { .. } => format!("enum {}", name),
            _ => name,
        };
    }

    /// The typedefs and the aggregates a type needs declared before it: the typedefs it names, the aggregates it holds
    /// (not through a pointer)
    fn dependencies(&self, id: Option<TypeId>, by_value: bool, out: &mut Vec<TypeId>) {
        let Some(id) = id else {
            return;
        };

        match self.ty(Some(id)) {
            DebugType::Pointer(to) => self.dependencies(*to, false, out),
            DebugType::Const(inner) | DebugType::Volatile(inner) => self.dependencies(*inner, by_value, out),
            DebugType::Array { ty, .. } => self.dependencies(*ty, by_value, out),
            DebugType::Function { ret, params, .. } => {
                self.dependencies(*ret, false, out);
                params.iter().for_each(|p| self.dependencies(*p, false, out));
            }
            DebugType::Typedef { ty, .. } => {
                out.push(self.canonical(id));
                self.dependencies(*ty, by_value, out);
            }
            DebugType::Aggregate { .. } | DebugType::Enum { .. } if by_value => out.push(self.canonical(id)),
            _ => {}
        }
    }

    /// The declaration of a typedef, an aggregate or an enum
    fn definition(&self, id: TypeId) -> String {
        let name = &self.names[&id];
        let mut out = String::new();

        match &self.debug.types[id] {
            DebugType::Typedef { ty, .. } => {
                let _ = writeln!(out, "typedef {};", self.declare(*ty, name));
            }
            DebugType::Enum { values, .. } => {
                let values: Vec<String> = values.iter().map(|(n, v)| format!("{} = {}", identifier(n), v)).collect();
                let _ = writeln!(out, "enum {} {{ {} }};", name, values.join(", "));
            }
            DebugType::Aggregate { members, union, .. } => {
                let _ = writeln!(out, "{} {} {{", if *union { "union" } else { "struct" }, name);

                for (index, member) in members.iter().enumerate() {
                    let field = member.name.as_deref().map(identifier).unwrap_or_else(|| format!("field_{}", index));

                    match member.bits {
                        Some(bits) => {
                            let _ = writeln!(out, "    {} : {};", self.declare(member.ty, &field), bits);
                        }
                        None => {
                            let _ = writeln!(out, "    {};", self.declare(member.ty, &field));
                        }
                    }
                }

                let _ = writeln!(out, "}};");
            }
            _ => {}
        }

        return out;
    }
}

/// The C declarations of the types of the debug information, and the prototypes of the functions of an address
pub struct DebugDeclarations {
    pub source: String,
    /// Address of each function: the name of its prototype in the source
    pub prototypes: Vec<(u64, String)>,
}

pub fn declarations(debug: &DebugInfo, typedb: &TypeDb) -> DebugDeclarations {
    let mut decls = Declarations { debug, names: HashMap::default(), declared: HashSet::default(), canonical: HashMap::default() };
    let mut taken: HashMap<String, TypeId> = HashMap::default();
    let mut keys: Vec<(TypeId, String)> = Vec::new();
    let declaration = |id: TypeId| matches!(debug.types[id], DebugType::Aggregate { declaration: true, .. });

    // The names: the first definition of a name is the type (its duplicates are in the other compile units), the
    // anonymous ones are named after their id
    for (id, ty) in debug.types.iter().enumerate() {
        let name = match ty {
            DebugType::Typedef { name, .. } => Some(name.clone()),
            DebugType::Aggregate { name, .. } | DebugType::Enum { name, .. } => name.clone(),
            _ => continue,
        };

        let name = name.as_deref().map(identifier).unwrap_or_else(|| format!("anonymous_{}", id));
        let tag = matches!(ty, DebugType::Aggregate { .. } | DebugType::Enum { .. });
        decls.names.insert(id, name.clone());

        // The bundled database keeps its own types (size_t, FILE, struct stat)
        let bundled = if tag { typedb.aggregates.contains_key(&name) || typedb.enums.contains_key(&name) } else { typedb.typedefs.contains_key(&name) };

        if bundled {
            continue;
        }

        let key = format!("{}{}", if tag { "tag " } else { "" }, name);

        match taken.get(&key) {
            Some(&first) if declaration(first) && !declaration(id) => {
                taken.insert(key.clone(), id);
            }
            Some(_) => {}
            None => {
                taken.insert(key.clone(), id);
            }
        }

        keys.push((id, key));
    }

    for (id, key) in keys {
        let declared = taken[&key];
        decls.declared.insert(declared);
        decls.canonical.insert(id, declared);
    }

    // In the order of their dependencies
    let mut ordered = Vec::new();
    let mut visited = HashSet::default();
    let mut roots: Vec<TypeId> = decls.declared.iter().copied().collect();
    roots.sort_unstable();

    fn visit(decls: &Declarations, id: TypeId, visited: &mut HashSet<TypeId>, ordered: &mut Vec<TypeId>) {
        if !visited.insert(id) {
            return;
        }

        let mut needed = Vec::new();

        match &decls.debug.types[id] {
            DebugType::Typedef { ty, .. } => decls.dependencies(*ty, false, &mut needed),
            DebugType::Aggregate { members, .. } => members.iter().for_each(|m| decls.dependencies(m.ty, true, &mut needed)),
            _ => {}
        }

        for dependency in needed {
            if decls.declared.contains(&dependency) {
                visit(decls, dependency, visited, ordered);
            }
        }

        ordered.push(id);
    }

    for id in roots {
        visit(&decls, id, &mut visited, &mut ordered);
    }

    let mut source = String::new();

    // Pointers to aggregates can then come before their definition
    for &id in ordered.iter() {
        if let DebugType::Aggregate { union, .. } = &debug.types[id] {
            let _ = writeln!(source, "{} {};", if *union { "union" } else { "struct" }, decls.names[&id]);
        }
    }

    for &id in ordered.iter() {
        if matches!(debug.types[id], DebugType::Aggregate { declaration: true, .. }) {
            continue;
        }

        source.push_str(&decls.definition(id));
    }

    // The prototypes, named after the address of the function
    let mut prototypes = Vec::new();

    for function in debug.functions.iter() {
        let name = format!("{}{:x}", PROTOTYPE_PREFIX, function.low);

        let mut params: Vec<String> = function.params.iter().enumerate().map(|(i, p)| {
            let param = p.name.as_deref().map(identifier).unwrap_or_else(|| format!("a{}", i + 1));
            decls.declare(p.ty, &param)
        }).collect();

        if function.variadic {
            params.push("...".to_string());
        }

        let params = if params.is_empty() { "void".to_string() } else { params.join(", ") };
        let _ = writeln!(source, "{};", decls.declare(function.ret, &format!("{}({})", name, params)));
        prototypes.push((function.low, name));
    }

    return DebugDeclarations { source, prototypes };
}

/// Adds the types of the debug information to the database, and gives the prototypes of the functions by address
pub fn apply(debug: &DebugInfo, typedb: &mut TypeDb) -> HashMap<u64, Prototype> {
    let declarations = declarations(debug, typedb);

    if typedb.extend(&declarations.source).is_err() {
        return HashMap::default();
    }

    let mut functions = typedb.take_functions(PROTOTYPE_PREFIX);

    return declarations.prototypes.into_iter().filter_map(|(addr, name)| functions.remove(&name).map(|ty| (addr, Prototype { name, ty }))).collect();
}
