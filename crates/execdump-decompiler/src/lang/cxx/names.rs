/*
 * C++ to C: demangled symbols become C prototypes, classes become structs and methods take
 * the object as their first parameter (struct Class *this), like cfront did
 */

use crate::types::{CType, DataModel, FuncType, Param, Prototype};

use execdump_core::demangle::symbol::{Builtin, Member, Name, NamePart, Structor, Symbol, SymbolKind, TemplateArg, Type};

use rustc_hash::{FxHashSet as HashSet};

/// Inline namespaces of the standard libraries, dropped from the identifiers
const INLINE_NAMESPACES: &[&str] = &["__1", "__cxx11", "__ndk1"];

/// Template arguments the standard library fills by default (std::vector<int, std::allocator<int>>)
const DEFAULT_TEMPLATE_ARGS: &[&str] = &["allocator", "char_traits", "less", "default_delete", "hash", "equal_to"];

const OPERATORS: &[(&str, &str)] = &[
    ("<<=", "shl_assign"),
    (">>=", "shr_assign"),
    ("->*", "arrow_star"),
    ("<=>", "spaceship"),
    ("new[]", "new_array"),
    ("delete[]", "delete_array"),
    ("+=", "add_assign"),
    ("-=", "sub_assign"),
    ("*=", "mul_assign"),
    ("/=", "div_assign"),
    ("%=", "mod_assign"),
    ("&=", "and_assign"),
    ("|=", "or_assign"),
    ("^=", "xor_assign"),
    ("==", "eq"),
    ("!=", "ne"),
    ("<=", "le"),
    (">=", "ge"),
    ("<<", "shl"),
    (">>", "shr"),
    ("&&", "land"),
    ("||", "lor"),
    ("++", "inc"),
    ("--", "dec"),
    ("->", "arrow"),
    ("()", "call"),
    ("[]", "index"),
    ("+", "add"),
    ("-", "sub"),
    ("*", "mul"),
    ("/", "div"),
    ("%", "mod"),
    ("&", "and"),
    ("|", "or"),
    ("^", "xor"),
    ("~", "not"),
    ("!", "lnot"),
    ("=", "assign"),
    ("<", "lt"),
    (">", "gt"),
    (",", "comma"),
    ("new", "new"),
    ("delete", "delete"),
];

/// Replaces everything that is not valid in a C identifier, and collapses the underscores
fn sanitize(text: &str) -> String {
    let mut out = String::new();

    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }

    return out.trim_end_matches('_').to_string();
}

fn operator_ident(ident: &str) -> Option<String> {
    let symbol = ident.strip_prefix("operator")?.trim();

    if let Some((_, name)) = OPERATORS.iter().find(|(op, _)| *op == symbol) {
        return Some(format!("operator_{}", name));
    }

    // Conversion operators (operator bool, operator char const*...)
    return Some(format!("operator_{}", sanitize(symbol)));
}

fn is_default_template_arg(arg: &TemplateArg) -> bool {
    let TemplateArg::Type(Type::Named(name)) = arg else {
        return false;
    };

    let in_std = name.parts.first().is_some_and(|p| p.ident == "std");

    return in_std && name.last().is_some_and(|p| DEFAULT_TEMPLATE_ARGS.contains(&p.ident.as_str()));
}

/// Short name of a type for identifiers (int, uint, char_ptr, std_string...)
fn type_ident(ty: &Type) -> String {
    match ty {
        Type::Builtin(builtin) => builtin_ident(*builtin).to_string(),
        Type::Named(name) => identifier(name),
        Type::Pointer(to) | Type::Reference(to) => format!("{}_ptr", type_ident(to)),
        Type::Const(to) => type_ident(to),
        Type::Array(element, _) => format!("{}_array", type_ident(element)),
        Type::Function(_) => "fn".to_string(),
        Type::MemberPointer { .. } => "member_ptr".to_string(),
        Type::Other(text) => sanitize(text),
    }
}

fn builtin_ident(builtin: Builtin) -> &'static str {
    match builtin {
        Builtin::Void => "void",
        Builtin::Bool => "bool",
        Builtin::Char => "char",
        Builtin::SChar => "schar",
        Builtin::UChar => "uchar",
        Builtin::Short => "short",
        Builtin::UShort => "ushort",
        Builtin::Int => "int",
        Builtin::UInt => "uint",
        Builtin::Long => "long",
        Builtin::ULong => "ulong",
        Builtin::LongLong => "llong",
        Builtin::ULongLong => "ullong",
        Builtin::Int128 => "int128",
        Builtin::UInt128 => "uint128",
        Builtin::Half => "half",
        Builtin::Float => "float",
        Builtin::Double => "double",
        Builtin::LongDouble => "ldouble",
        Builtin::Float128 => "float128",
        Builtin::WChar => "wchar",
        Builtin::Char8 => "char8",
        Builtin::Char16 => "char16",
        Builtin::Char32 => "char32",
        Builtin::Nullptr => "nullptr",
    }
}

fn part_ident(part: &NamePart) -> String {
    let mut ident = operator_ident(&part.ident).unwrap_or_else(|| sanitize(&part.ident));

    for arg in part.template_args.iter().filter(|a| !is_default_template_arg(a)) {
        let arg = match arg {
            TemplateArg::Type(ty) => type_ident(ty),
            TemplateArg::Value(value) => sanitize(value),
        };

        ident.push('_');
        ident.push_str(&arg);
    }

    return ident;
}

/// C identifier of a qualified name: std::vector<int>::push_back -> std_vector_int_push_back
pub fn identifier(name: &Name) -> String {
    let parts: Vec<String> = name
        .parts
        .iter()
        .filter(|p| !INLINE_NAMESPACES.contains(&p.ident.as_str()))
        .map(part_ident)
        .filter(|p| !p.is_empty())
        .collect();

    return parts.join("_");
}

/// Classes seen in the symbols of a program: types of parameters, vtables, typeinfos and method scopes
pub fn known_classes<'a>(symbols: impl Iterator<Item = &'a Symbol>) -> HashSet<String> {
    let mut classes = HashSet::default();

    fn collect_type(ty: &Type, classes: &mut HashSet<String>) {
        match ty {
            Type::Named(name) => {
                classes.insert(identifier(name));
            }
            Type::Pointer(to) | Type::Reference(to) | Type::Const(to) | Type::Array(to, _) => collect_type(to, classes),
            Type::MemberPointer { class, member } => {
                collect_type(class, classes);
                collect_type(member, classes);
            }
            Type::Function(func) => func.params.iter().chain(func.ret.iter()).for_each(|t| collect_type(t, classes)),
            Type::Builtin(_) | Type::Other(_) => {}
        }
    }

    for symbol in symbols {
        match &symbol.kind {
            SymbolKind::Function { ty, member, .. } => {
                ty.params.iter().chain(ty.ret.iter()).for_each(|t| collect_type(t, &mut classes));

                if matches!(member, Member::Instance | Member::Static | Member::Virtual) {
                    classes.insert(identifier(&symbol.name.scope()));
                }
            }
            SymbolKind::Special(_) => {
                classes.insert(identifier(&symbol.name));
            }
            SymbolKind::Variable(Some(ty)) => collect_type(ty, &mut classes),
            _ => {}
        }
    }

    classes.remove("");

    return classes;
}

/// Maps a C++ type to its C equivalent: references become pointers, classes become structs
pub fn c_type(ty: &Type, model: &DataModel) -> CType {
    match ty {
        Type::Builtin(builtin) => builtin_type(*builtin, model),
        Type::Named(name) => CType::Struct(identifier(name)),
        Type::Pointer(to) | Type::Reference(to) => CType::ptr(c_type(to, model)),
        Type::Const(to) => CType::Const(Box::new(c_type(to, model))),
        Type::Array(element, size) => CType::Array(Box::new(c_type(element, model)), *size),
        Type::Function(func) => CType::Function(Box::new(FuncType {
            ret: func.ret.as_ref().map_or(CType::Unknown(0), |r| c_type(r, model)),
            params: func.params.iter().map(|p| Param { name: None, ty: c_type(p, model) }).collect(),
            variadic: func.variadic,
        })),
        // Pointers to data members are offsets, pointers to member functions are two words
        Type::MemberPointer { member, .. } if matches!(**member, Type::Function(_)) => CType::Unknown(model.pointer_bits * 2),
        Type::MemberPointer { .. } => model.pointer_int(true),
        Type::Other(_) => CType::Unknown(0),
    }
}

fn builtin_type(builtin: Builtin, model: &DataModel) -> CType {
    match builtin {
        Builtin::Void => CType::Void,
        Builtin::Bool => CType::Bool,
        Builtin::Char => CType::Char,
        Builtin::SChar => CType::int(8),
        Builtin::UChar => CType::uint(8),
        Builtin::Short => CType::int(16),
        Builtin::UShort => CType::uint(16),
        Builtin::Int => CType::int(32),
        Builtin::UInt => CType::uint(32),
        Builtin::Long => CType::int(model.long_bits),
        Builtin::ULong => CType::uint(model.long_bits),
        Builtin::LongLong => CType::int(64),
        Builtin::ULongLong => CType::uint(64),
        Builtin::Int128 => CType::int(128),
        Builtin::UInt128 => CType::uint(128),
        Builtin::Half => CType::Float { bits: 16 },
        Builtin::Float => CType::Float { bits: 32 },
        Builtin::Double => CType::Float { bits: 64 },
        Builtin::LongDouble => CType::Float { bits: model.long_double_bits },
        Builtin::Float128 => CType::Float { bits: 128 },
        Builtin::WChar => CType::uint(model.wchar_bits),
        Builtin::Char8 => CType::uint(8),
        Builtin::Char16 => CType::uint(16),
        Builtin::Char32 => CType::uint(32),
        Builtin::Nullptr => CType::ptr(CType::Void),
    }
}

/// C name of a function, constructors and destructors are Class_ctor and Class_dtor
fn function_name(name: &Name, structor: Option<Structor>) -> String {
    match structor {
        Some(Structor::Ctor) => format!("{}_ctor", identifier(&name.scope())),
        Some(Structor::Dtor) => format!("{}_dtor", identifier(&name.scope())),
        None => identifier(name),
    }
}

/// C prototype of a demangled function, None for data and special symbols
pub fn prototype(symbol: &Symbol, model: &DataModel, classes: &HashSet<String>) -> Option<Prototype> {
    let SymbolKind::Function { ty, member, const_this, structor } = &symbol.kind else {
        return None;
    };

    let class = identifier(&symbol.name.scope());

    let has_this = match member {
        Member::Instance | Member::Virtual => true,
        Member::Unknown => classes.contains(&class),
        Member::None | Member::Static => false,
    };

    let mut params = Vec::new();

    if has_this {
        let object = CType::Struct(class);
        let object = if *const_this { CType::Const(Box::new(object)) } else { object };

        params.push(Param { name: Some("this".to_string()), ty: CType::ptr(object) });
    }

    params.extend(ty.params.iter().map(|p| Param { name: None, ty: c_type(p, model) }));

    let ret = match (&ty.ret, structor) {
        (Some(ret), _) => c_type(ret, model),
        (None, Some(_)) => CType::Void,
        (None, None) => CType::Unknown(0),
    };

    return Some(Prototype { name: function_name(&symbol.name, *structor), ty: FuncType { ret, params, variadic: ty.variadic } });
}

#[cfg(test)]
mod tests {
    use super::*;

    use execdump_core::demangle::demangle_symbol;
    use execdump_core::disasm::Architecture;

    fn c_prototype(mangled: &[&str], index: usize, windows: bool) -> String {
        let symbols: Vec<Symbol> = mangled.iter().map(|m| demangle_symbol(m).unwrap()).collect();
        let classes = known_classes(symbols.iter());
        let model = DataModel::new(Architecture::X86_64, windows);

        return prototype(&symbols[index], &model, &classes).unwrap().to_string();
    }

    #[test]
    fn methods_take_this() {
        assert_eq!(
            c_prototype(&["_ZNSt6vectorIiSaIiEE9push_backERKi", "_ZNKSt6vectorIiSaIiEE4sizeEv"], 0, false),
            "undefined std_vector_int_push_back(struct std_vector_int *this, const int *)"
        );
        assert_eq!(
            c_prototype(&["_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv"], 0, false),
            "undefined std_basic_string_char_size(const struct std_basic_string_char *this)"
        );
        assert_eq!(c_prototype(&["?bar@Foo@@QEAAXH@Z"], 0, true), "void Foo_bar(struct Foo *this, int)");
        assert_eq!(c_prototype(&["_ZN3FooC2Ev"], 0, false), "void Foo_ctor(struct Foo *this)");
        assert_eq!(c_prototype(&["??1Foo@@QEAA@XZ"], 0, true), "void Foo_dtor(struct Foo *this)");
    }

    #[test]
    fn namespaces_and_free_functions() {
        // ns is never seen as a class, its functions are free functions
        assert_eq!(c_prototype(&["_ZN2ns5twiceEi"], 0, false), "undefined ns_twice(int)");
        assert_eq!(c_prototype(&["_Z3addii"], 0, false), "undefined add(int, int)");
        assert_eq!(c_prototype(&["_Z6printfPKcz"], 0, false), "undefined printf(const char *, ...)");
        assert_eq!(c_prototype(&["?f@@YGXXZ"], 0, true), "void f(void)");
    }

    #[test]
    fn scope_seen_as_class() {
        // Foo is a class since it has a vtable, its methods take this
        assert_eq!(c_prototype(&["_ZN3Foo3barEi", "_ZTV3Foo"], 0, false), "undefined Foo_bar(struct Foo *this, int)");
    }

    #[test]
    fn identifiers() {
        let ident = |m: &str| identifier(&demangle_symbol(m).unwrap().name);

        assert_eq!(ident("_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi"), "std_vector_int_push_back");
        assert_eq!(ident("_ZN3FooplERKS_"), "Foo_operator_add");
        assert_eq!(ident("_ZN3FooixEm"), "Foo_operator_index");
        assert_eq!(ident("_ZN3FoocvbEv"), "Foo_operator_bool");
        assert_eq!(ident("_ZN3foo3barEv.cold"), "foo_bar_cold");
        assert_eq!(ident("_Z1fIJidEEvDpT_"), "f_int_double");
        assert_eq!(ident("_ZNSt3mapIiPKcSt4lessIiESaISt4pairIKiS1_EEE4findERS4_"), "std_map_int_char_ptr_find");
    }

    #[test]
    fn long_depends_on_the_target() {
        assert_eq!(c_prototype(&["_Z1fl"], 0, false), "undefined f(int64_t)");
        assert_eq!(c_prototype(&["_Z1fl"], 0, true), "undefined f(int)");
    }
}
