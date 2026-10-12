/*
 * C type model used by the decompiler, every recovered or imported type ends up as a CType
 */

use execdump_core::disasm::Architecture;

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CType {
    Void,
    Bool,
    Char,
    Int { bits: u16, signed: bool },
    Float { bits: u16 },
    Pointer(Box<CType>),
    Const(Box<CType>),
    Array(Box<CType>, Option<u64>),
    Function(Box<FuncType>),
    /// Aggregates and aliases by name, defined in the type database (opaque when they are not)
    Struct(String),
    Union(String),
    Enum(String),
    Typedef(String),
    /// Not recovered yet, with its size in bits when known (0 otherwise)
    Unknown(u16),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Param {
    pub name: Option<String>,
    pub ty: CType,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncType {
    pub ret: CType,
    pub params: Vec<Param>,
    pub variadic: bool,
}

/// A named function type, the name is a valid C identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prototype {
    pub name: String,
    pub ty: FuncType,
}

/// Sizes of the C types that depend on the target
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataModel {
    pub pointer_bits: u16,
    pub long_bits: u16,
    pub wchar_bits: u16,
    pub long_double_bits: u16,
}

impl DataModel {
    /// LP64 on Unix-likes, LLP64 on Windows, ILP32 on 32-bit targets
    pub fn new(arch: Architecture, windows: bool) -> Self {
        let pointer_bits = if arch == Architecture::X86 { 32 } else { 64 };
        let long_bits = if windows { 32 } else { pointer_bits };
        let wchar_bits = if windows { 16 } else { 32 };
        let long_double_bits = match (arch, windows) {
            (_, true) => 64,
            (Architecture::Aarch64, false) => 128,
            (_, false) => 80,
        };

        return DataModel { pointer_bits, long_bits, wchar_bits, long_double_bits };
    }

    pub fn pointer_int(&self, signed: bool) -> CType {
        return CType::Int { bits: self.pointer_bits, signed };
    }
}

impl CType {
    pub fn int(bits: u16) -> Self {
        return CType::Int { bits, signed: true };
    }

    pub fn uint(bits: u16) -> Self {
        return CType::Int { bits, signed: false };
    }

    pub fn ptr(to: CType) -> Self {
        return CType::Pointer(Box::new(to));
    }

    pub fn is_unknown(&self) -> bool {
        return matches!(self, CType::Unknown(_));
    }

    /// Strips the qualifiers
    pub fn unqualified(&self) -> &CType {
        match self {
            CType::Const(inner) => inner.unqualified(),
            _ => self,
        }
    }

    /// Declaration of a variable (or parameter) of this type, the name can be empty
    pub fn declare(&self, name: &str) -> String {
        let (left, right) = self.declarator(name.to_string());
        return format!("{}{}", left, right).trim_end().to_string();
    }

    /// Splits a declaration around the declared name, C declarators read inside out
    fn declarator(&self, inner: String) -> (String, String) {
        match self {
            CType::Pointer(to) => {
                let needs_parens = matches!(to.unqualified(), CType::Array(..) | CType::Function(_));
                let inner = if needs_parens { format!("(*{})", inner) } else { format!("*{}", inner) };

                return to.declarator(inner);
            }
            CType::Const(to) if matches!(**to, CType::Pointer(_)) => to.declarator(format!(" const {}", inner.trim_start())),
            CType::Array(element, size) => {
                let size = size.map_or(String::new(), |s| s.to_string());
                return element.declarator(format!("{}[{}]", inner, size));
            }
            CType::Function(func) => {
                let mut params: Vec<String> = func.params.iter().map(|p| p.ty.declare(p.name.as_deref().unwrap_or(""))).collect();

                if func.variadic {
                    params.push("...".to_string());
                }

                if params.is_empty() {
                    params.push("void".to_string());
                }

                return func.ret.declarator(format!("{}({})", inner, params.join(", ")));
            }
            _ => {
                let base = self.to_string();
                let separator = if inner.is_empty() || inner.starts_with('[') || inner.starts_with('(') && !inner.starts_with("(*") { "" } else { " " };

                return (format!("{}{}", base, separator), inner);
            }
        }
    }
}

/// Base type names (declarators are handled by CType::declare)
impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CType::Void => write!(f, "void"),
            CType::Bool => write!(f, "bool"),
            CType::Char => write!(f, "char"),
            CType::Int { bits: 32, signed: true } => write!(f, "int"),
            CType::Int { bits: 32, signed: false } => write!(f, "unsigned int"),
            CType::Int { bits, signed: true } => write!(f, "int{}_t", bits),
            CType::Int { bits, signed: false } => write!(f, "uint{}_t", bits),
            CType::Float { bits: 32 } => write!(f, "float"),
            CType::Float { bits: 64 } => write!(f, "double"),
            CType::Float { .. } => write!(f, "long double"),
            CType::Const(inner) => write!(f, "const {}", inner),
            CType::Struct(name) => write!(f, "struct {}", name),
            CType::Union(name) => write!(f, "union {}", name),
            CType::Enum(name) => write!(f, "enum {}", name),
            CType::Typedef(name) => write!(f, "{}", name),
            CType::Unknown(0) => write!(f, "undefined"),
            CType::Unknown(bits) => write!(f, "undefined{}", bits / 8),
            CType::Pointer(_) | CType::Array(..) | CType::Function(_) => write!(f, "{}", self.declare("")),
        }
    }
}

impl fmt::Display for Prototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{}", CType::Function(Box::new(self.ty.clone())).declare(&self.name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, ty: CType) -> Param {
        return Param { name: Some(name.to_string()), ty };
    }

    #[test]
    fn declarations() {
        let char_ptr = CType::ptr(CType::Const(Box::new(CType::Char)));

        assert_eq!(CType::int(32).declare("x"), "int x");
        assert_eq!(CType::uint(64).declare("x"), "uint64_t x");
        assert_eq!(char_ptr.declare("s"), "const char *s");
        assert_eq!(char_ptr.declare(""), "const char *");
        assert_eq!(CType::Array(Box::new(CType::int(32)), Some(4)).declare("a"), "int a[4]");
        assert_eq!(CType::ptr(CType::Array(Box::new(CType::int(32)), Some(3))).declare("p"), "int (*p)[3]");
        assert_eq!(CType::Const(Box::new(CType::ptr(CType::Char))).declare("p"), "char * const p");

        let callback = CType::ptr(CType::Function(Box::new(FuncType { ret: CType::int(32), params: vec![param("x", CType::int(32))], variadic: false })));
        assert_eq!(callback.declare("cb"), "int (*cb)(int x)");

        let fputs = Prototype {
            name: "fputs".to_string(),
            ty: FuncType {
                ret: CType::int(32),
                params: vec![param("s", char_ptr.clone()), param("stream", CType::ptr(CType::Typedef("FILE".to_string())))],
                variadic: false,
            },
        };
        assert_eq!(fputs.to_string(), "int fputs(const char *s, FILE *stream)");

        let printf = Prototype { name: "printf".to_string(), ty: FuncType { ret: CType::int(32), params: vec![Param { name: None, ty: char_ptr }], variadic: true } };
        assert_eq!(printf.to_string(), "int printf(const char *, ...)");

        let getpid = Prototype { name: "getpid".to_string(), ty: FuncType { ret: CType::int(32), params: Vec::new(), variadic: false } };
        assert_eq!(getpid.to_string(), "int getpid(void)");
    }

    #[test]
    fn data_models() {
        assert_eq!(DataModel::new(Architecture::X86_64, false).long_bits, 64);
        assert_eq!(DataModel::new(Architecture::X86_64, true).long_bits, 32);
        assert_eq!(DataModel::new(Architecture::X86, true).pointer_bits, 32);
    }
}
