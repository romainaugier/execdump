/*
 * Typed description of a demangled symbol, shared by the Itanium, MSVC and Rust demanglers
 * The decompiler maps it to C types, the string demanglers stay the reference for display
 */

/// Builtin types, the size of long depends on the target (32 bits on Windows, 64 bits elsewhere)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    Void,
    Bool,
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Int128,
    UInt128,
    Half,
    Float,
    Double,
    LongDouble,
    Float128,
    WChar,
    Char8,
    Char16,
    Char32,
    Nullptr,
}

impl Builtin {
    /// Builtin from its demangled spelling (Itanium and MSVC)
    pub fn from_name(name: &str) -> Option<Self> {
        let builtin = match name {
            "void" => Builtin::Void,
            "bool" => Builtin::Bool,
            "char" => Builtin::Char,
            "signed char" => Builtin::SChar,
            "unsigned char" => Builtin::UChar,
            "short" => Builtin::Short,
            "unsigned short" => Builtin::UShort,
            "int" => Builtin::Int,
            "unsigned int" => Builtin::UInt,
            "long" => Builtin::Long,
            "unsigned long" => Builtin::ULong,
            "long long" | "__int64" => Builtin::LongLong,
            "unsigned long long" | "unsigned __int64" => Builtin::ULongLong,
            "__int128" => Builtin::Int128,
            "unsigned __int128" => Builtin::UInt128,
            "half" | "_Float16" => Builtin::Half,
            "float" | "_Float32" => Builtin::Float,
            "double" | "_Float64" => Builtin::Double,
            "long double" => Builtin::LongDouble,
            "__float128" | "_Float128" => Builtin::Float128,
            "wchar_t" => Builtin::WChar,
            "char8_t" => Builtin::Char8,
            "char16_t" => Builtin::Char16,
            "char32_t" => Builtin::Char32,
            "std::nullptr_t" | "decltype(nullptr)" => Builtin::Nullptr,
            _ => return None,
        };

        return Some(builtin);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Builtin(Builtin),
    /// Class, struct, union or enum
    Named(Name),
    Pointer(Box<Type>),
    /// Lvalue and rvalue references
    Reference(Box<Type>),
    Const(Box<Type>),
    Array(Box<Type>, Option<u64>),
    Function(Box<FunctionType>),
    MemberPointer { class: Box<Type>, member: Box<Type> },
    /// Types without a C equivalent (decltype, packs, vendor types...), as printed
    Other(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallConv {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    Other,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FunctionType {
    /// Not encoded by Itanium for non-template functions
    pub ret: Option<Type>,
    pub params: Vec<Type>,
    pub variadic: bool,
    pub call_conv: Option<CallConv>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TemplateArg {
    Type(Type),
    /// Non-type arguments (integers, expressions...), as printed
    Value(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct NamePart {
    pub ident: String,
    pub template_args: Vec<TemplateArg>,
}

/// Qualified name, ns::Class<T>::method is [ns, Class<T>, method]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Name {
    pub parts: Vec<NamePart>,
}

impl Name {
    pub fn ident(ident: &str) -> Self {
        return Name { parts: vec![NamePart { ident: ident.to_string(), template_args: Vec::new() }] };
    }

    /// Enclosing scope (class or namespace)
    pub fn scope(&self) -> Name {
        return Name { parts: self.parts[..self.parts.len().saturating_sub(1)].to_vec() };
    }

    pub fn last(&self) -> Option<&NamePart> {
        return self.parts.last();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    /// Free function
    None,
    /// Itanium does not tell whether the scope of a function is a class or a namespace
    Unknown,
    Instance,
    Static,
    Virtual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structor {
    Ctor,
    Dtor,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolKind {
    Function { ty: FunctionType, member: Member, const_this: bool, structor: Option<Structor> },
    Variable(Option<Type>),
    /// Only the name is encoded (Rust legacy)
    Name,
    /// vtable, typeinfo, thunks, string literals... described as printed, the name is the target
    Special(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Symbol {
    pub name: Name,
    pub kind: SymbolKind,
}
