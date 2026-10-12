/*
 * C declarations to the type database, the parsing itself is done by lang-c on preprocessed source
 */

use super::{Aggregate, Field, TypeDb};

use crate::types::{CType, FuncType, Param};

use lang_c::ast::*;
use lang_c::driver::{parse_preprocessed, Config, Flavor};
use lang_c::span::Node;

use std::io::Write;
use std::process::{Command, Stdio};

/// Runs the C preprocessor on a list of headers (compiler -E -P)
pub fn preprocess(compiler: &str, args: &[String], headers: &[String]) -> Result<String, String> {
    let includes: String = headers.iter().map(|h| format!("#include <{}>\n", h)).collect();

    let mut child = Command::new(compiler)
        .args(["-E", "-P", "-x", "c"])
        .args(args)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {}", compiler, e))?;

    child.stdin.take().ok_or("no stdin")?.write_all(includes.as_bytes()).map_err(|e| e.to_string())?;

    let output = child.wait_with_output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(format!("{} failed:\n{}", compiler, String::from_utf8_lossy(&output.stderr)));
    }

    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
}

/// Layout attributes found in the source, by offset
#[derive(Clone, Copy, Debug)]
enum Hint {
    /// #pragma pack, None restores the default
    Pack(Option<u64>),
    Packed,
    Aligned(u64),
}

/// Blanks what lang-c does not parse (comments, attributes, declspecs, pragmas) without moving the offsets,
/// the layout related ones are kept as hints
fn sanitize(source: &str) -> (String, Vec<(usize, Hint)>) {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut hints = Vec::new();
    let mut pack_stack: Vec<Option<u64>> = Vec::new();
    let mut pack: Option<u64> = None;
    let mut i = 0;

    let skip_parens = |mut j: usize| -> usize {
        let mut depth = 0;

        while j < bytes.len() {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;

                    if depth == 0 {
                        return j + 1;
                    }
                }
                _ => {}
            }

            j += 1;
        }

        return j;
    };

    while i < bytes.len() {
        let at_line_start = i == 0 || bytes[i - 1] == b'\n';
        let rest = &source[i..];
        let end = if at_line_start { rest.find('\n').map_or(bytes.len(), |e| i + e) } else { i };
        let line = &source[i..end];

        if line.trim_start().starts_with("#pragma") {

            if let Some(args) = line.split_once("pack").map(|(_, a)| a) {
                let args: Vec<&str> = args.trim_matches(|c: char| c == '(' || c == ')' || c.is_whitespace()).split(',').map(|a| a.trim()).collect();
                let value = args.iter().find_map(|a| a.parse::<u64>().ok());

                match args.first().copied() {
                    Some("push") => {
                        pack_stack.push(pack);
                        pack = value.or(pack);
                    }
                    Some("pop") => pack = pack_stack.pop().flatten(),
                    _ => pack = value,
                }

                hints.push((i, Hint::Pack(pack)));
            }

            out[i..end].fill(b' ');
            i = end;
            continue;
        }

        // String and character literals are kept as they are
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;

            while i < bytes.len() && bytes[i] != quote {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }

            i += 1;
            continue;
        }

        if rest.starts_with("/*") || rest.starts_with("//") {
            let end = if rest.starts_with("/*") { rest.find("*/").map_or(bytes.len(), |e| i + e + 2) } else { rest.find('\n').map_or(bytes.len(), |e| i + e) };
            out[i..end].fill(b' ');
            i = end;
            continue;
        }

        for keyword in ["__attribute__", "__declspec"] {
            if rest.starts_with(keyword) {
                let end = skip_parens(i + keyword.len());
                let text = &source[i..end];

                if text.contains("packed") {
                    hints.push((i, Hint::Packed));
                } else if let Some(value) = text.split_once("aligned").and_then(|(_, v)| v.trim_matches(|c: char| !c.is_ascii_digit()).split(|c: char| !c.is_ascii_digit()).next()?.parse::<u64>().ok()) {
                    hints.push((i, Hint::Aligned(value)));
                }

                out[i..end].fill(b' ');
                i = end;
                break;
            }
        }

        // Types lang-c does not know, replaced by types of a close enough size
        if rest.starts_with("__int128") {
            out[i..i + 8].copy_from_slice(b"long    ");
            i += 8;
        }

        i += 1;
    }

    return (String::from_utf8(out).unwrap_or_default(), hints);
}

/// Type names printed by CType, declared for lang-c and mapped back to the builtin types
const PRELUDE: &str = "typedef _Bool bool; typedef signed char int8_t; typedef unsigned char uint8_t; typedef short int16_t; \
typedef unsigned short uint16_t; typedef long long int64_t; typedef unsigned long long uint64_t; typedef long long int128_t; \
typedef unsigned long long uint128_t; typedef char undefined; typedef char undefined1; typedef short undefined2; \
typedef int undefined4; typedef long long undefined8; typedef long long undefined16;\n";

fn builtin_typedef(name: &str) -> Option<CType> {
    if name == "bool" {
        return Some(CType::Bool);
    }

    if let Some(bytes) = name.strip_prefix("undefined") {
        return Some(CType::Unknown(if bytes.is_empty() { 0 } else { bytes.parse::<u16>().ok()? * 8 }));
    }

    let (signed, bits) = match name.strip_prefix('u') {
        Some(rest) => (false, rest),
        None => (true, name),
    };

    let bits = bits.strip_prefix("int")?.strip_suffix("_t")?.parse::<u16>().ok()?;

    return [8, 16, 64, 128].contains(&bits).then_some(CType::Int { bits, signed });
}

pub fn parse(db: &mut TypeDb, source: &str) -> Result<(), String> {
    let (source, hints) = sanitize(&format!("{}{}", PRELUDE, source));

    let mut config = Config::default();
    config.flavor = Flavor::GnuC11;

    let parsed = parse_preprocessed(&config, source.clone()).map_err(|e| {
        let line = source.lines().nth(e.line.saturating_sub(1)).unwrap_or_default().trim();
        format!("line {}, column {}: expected one of {:?} in \"{}\"", e.line, e.column, e.expected, line)
    })?;

    let (packs, hints): (Vec<_>, Vec<_>) = hints.into_iter().partition(|(_, hint)| matches!(hint, Hint::Pack(_)));
    let packs = packs.into_iter().map(|(offset, hint)| (offset, if let Hint::Pack(value) = hint { value } else { None })).collect();

    let mut converter = Converter { db, source: &source, packs, hints, anonymous: 0 };

    for declaration in parsed.unit.0.iter() {
        match &declaration.node {
            ExternalDeclaration::Declaration(declaration) => converter.declaration(declaration),
            ExternalDeclaration::FunctionDefinition(definition) => converter.function_definition(&definition.node),
            ExternalDeclaration::StaticAssert(_) => {}
        }
    }

    return Ok(());
}

struct Converter<'a> {
    db: &'a mut TypeDb,
    source: &'a str,
    /// #pragma pack in effect from an offset
    packs: Vec<(usize, Option<u64>)>,
    hints: Vec<(usize, Hint)>,
    anonymous: usize,
}

/// Type specifiers of a declaration, whatever the syntax they come from
struct Specifiers<'a> {
    types: Vec<&'a Node<TypeSpecifier>>,
    is_const: bool,
    is_typedef: bool,
}

fn declaration_specifiers(specifiers: &[Node<DeclarationSpecifier>]) -> Specifiers<'_> {
    let mut result = Specifiers { types: Vec::new(), is_const: false, is_typedef: false };

    for specifier in specifiers {
        match &specifier.node {
            DeclarationSpecifier::TypeSpecifier(ty) => result.types.push(ty),
            DeclarationSpecifier::TypeQualifier(q) => result.is_const |= q.node == TypeQualifier::Const,
            DeclarationSpecifier::StorageClass(s) => result.is_typedef |= s.node == StorageClassSpecifier::Typedef,
            _ => {}
        }
    }

    return result;
}

fn qualifier_specifiers(specifiers: &[Node<SpecifierQualifier>]) -> Specifiers<'_> {
    let mut result = Specifiers { types: Vec::new(), is_const: false, is_typedef: false };

    for specifier in specifiers {
        match &specifier.node {
            SpecifierQualifier::TypeSpecifier(ty) => result.types.push(ty),
            SpecifierQualifier::TypeQualifier(q) => result.is_const |= q.node == TypeQualifier::Const,
            _ => {}
        }
    }

    return result;
}

fn declarator_name(declarator: &Declarator) -> Option<String> {
    match &declarator.kind.node {
        DeclaratorKind::Identifier(identifier) => Some(identifier.node.name.clone()),
        DeclaratorKind::Declarator(inner) => declarator_name(&inner.node),
        DeclaratorKind::Abstract => None,
    }
}

fn asm_label(declarator: &Declarator) -> Option<String> {
    return declarator.extensions.iter().find_map(|e| match &e.node {
        Extension::AsmLabel(label) => Some(label.node.concat().trim_matches('"').to_string()),
        _ => None,
    });
}

/// Parameter names without the reserved prefixes of the system headers (__stream -> stream)
fn parameter_name(name: Option<String>) -> Option<String> {
    let name = name?;
    let trimmed = name.trim_start_matches('_');

    return if trimmed.is_empty() { None } else { Some(trimmed.to_string()) };
}

impl Converter<'_> {
    fn declaration(&mut self, declaration: &Node<Declaration>) {
        let specifiers = declaration_specifiers(&declaration.node.specifiers);

        // typedef struct { ... } NAME names the anonymous struct after the typedef
        let tag_hint = declaration.node.declarators.iter().find(|d| d.node.declarator.node.derived.is_empty()).or(declaration.node.declarators.first());
        let tag_hint = tag_hint.and_then(|d| declarator_name(&d.node.declarator.node));

        let base = self.base_type(&specifiers, tag_hint);

        for init in declaration.node.declarators.iter() {
            let declarator = &init.node.declarator.node;
            let ty = self.derive(base.clone(), declarator);

            let Some(name) = declarator_name(declarator) else {
                continue;
            };

            if specifiers.is_typedef {
                if builtin_typedef(&name).is_none() {
                    self.db.add_typedef(name, ty);
                }
            } else if let CType::Function(func) = ty {
                if let Some(label) = asm_label(declarator) {
                    self.db.add_function(label, (*func).clone());
                }

                self.db.add_function(name, *func);
            }
        }
    }

    fn function_definition(&mut self, definition: &FunctionDefinition) {
        let specifiers = declaration_specifiers(&definition.specifiers);
        let base = self.base_type(&specifiers, None);
        let ty = self.derive(base, &definition.declarator.node);

        if let (Some(name), CType::Function(func)) = (declarator_name(&definition.declarator.node), ty) {
            self.db.add_function(name, *func);
        }
    }

    fn base_type(&mut self, specifiers: &Specifiers, tag_hint: Option<String>) -> CType {
        let mut longs = 0;
        let mut signed = None;
        let mut base: Option<CType> = None;
        let mut short = false;
        let mut char = false;

        for specifier in specifiers.types.iter() {
            match &specifier.node {
                TypeSpecifier::Void => base = Some(CType::Void),
                TypeSpecifier::Bool => base = Some(CType::Bool),
                TypeSpecifier::Char => char = true,
                TypeSpecifier::Short => short = true,
                TypeSpecifier::Int => {}
                TypeSpecifier::Long => longs += 1,
                TypeSpecifier::Signed => signed = Some(true),
                TypeSpecifier::Unsigned => signed = Some(false),
                TypeSpecifier::Float => base = Some(CType::Float { bits: 32 }),
                TypeSpecifier::Double => base = Some(CType::Float { bits: 64 }),
                TypeSpecifier::Complex => {}
                TypeSpecifier::TS18661Float(float) => base = Some(CType::Float { bits: float.width as u16 }),
                TypeSpecifier::TypedefName(name) => base = Some(builtin_typedef(&name.node.name).unwrap_or_else(|| CType::Typedef(name.node.name.clone()))),
                TypeSpecifier::Struct(aggregate) => base = Some(self.aggregate(aggregate, tag_hint.clone())),
                TypeSpecifier::Enum(enumeration) => base = Some(self.enumeration(&enumeration.node, tag_hint.clone())),
                TypeSpecifier::Atomic(_) | TypeSpecifier::TypeOf(_) => base = Some(CType::Unknown(0)),
            }
        }

        let base = match base {
            Some(CType::Float { bits: 64 }) if longs > 0 => CType::Float { bits: self.db.model.long_double_bits },
            Some(base) => base,
            None if char => match signed {
                None => CType::Char,
                Some(signed) => CType::Int { bits: 8, signed },
            },
            None => {
                let bits = match (short, longs) {
                    (true, _) => 16,
                    (false, 0) => 32,
                    (false, 1) => self.db.model.long_bits,
                    _ => 64,
                };

                CType::Int { bits, signed: signed.unwrap_or(true) }
            }
        };

        return if specifiers.is_const { CType::Const(Box::new(base)) } else { base };
    }

    /// Applies the declarator: pointers first, then arrays and functions from the right
    fn derive(&mut self, base: CType, declarator: &Declarator) -> CType {
        let mut ty = base;

        let (pointers, suffixes): (Vec<_>, Vec<_>) = declarator.derived.iter().partition(|d| matches!(d.node, DerivedDeclarator::Pointer(_)));

        for pointer in pointers {
            let DerivedDeclarator::Pointer(qualifiers) = &pointer.node else {
                continue;
            };

            ty = CType::ptr(ty);

            let is_const = qualifiers.iter().any(|q| matches!(&q.node, PointerQualifier::TypeQualifier(t) if t.node == TypeQualifier::Const));

            if is_const {
                ty = CType::Const(Box::new(ty));
            }
        }

        for suffix in suffixes.iter().rev() {
            ty = match &suffix.node {
                DerivedDeclarator::Array(array) => {
                    let count = match &array.node.size {
                        ArraySize::VariableExpression(e) | ArraySize::StaticExpression(e) => self.evaluate(&e.node).map(|v| v as u64),
                        _ => None,
                    };

                    CType::Array(Box::new(ty), count)
                }
                DerivedDeclarator::Function(function) => CType::Function(Box::new(self.function_type(ty, &function.node))),
                DerivedDeclarator::KRFunction(_) => CType::Function(Box::new(FuncType { ret: ty, params: Vec::new(), variadic: true })),
                _ => ty,
            };
        }

        if let DeclaratorKind::Declarator(inner) = &declarator.kind.node {
            ty = self.derive(ty, &inner.node);
        }

        return ty;
    }

    fn function_type(&mut self, ret: CType, function: &FunctionDeclarator) -> FuncType {
        let mut params = Vec::new();

        for parameter in function.parameters.iter() {
            let specifiers = declaration_specifiers(&parameter.node.specifiers);
            let base = self.base_type(&specifiers, None);

            let (name, ty) = match &parameter.node.declarator {
                Some(declarator) => (declarator_name(&declarator.node), self.derive(base, &declarator.node)),
                None => (None, base),
            };

            // Arrays and functions decay to pointers
            let ty = match ty {
                CType::Array(element, _) => CType::Pointer(element),
                CType::Function(_) => CType::ptr(ty),
                ty => ty,
            };

            params.push(Param { name: parameter_name(name), ty });
        }

        // f(void) has no parameters
        if params.len() == 1 && params[0].ty == CType::Void {
            params.clear();
        }

        return FuncType { ret, params, variadic: function.ellipsis == Ellipsis::Some };
    }

    fn anonymous_name(&mut self, prefix: &str) -> String {
        self.anonymous += 1;
        return format!("{}{}", prefix, self.anonymous);
    }

    fn aggregate(&mut self, node: &Node<StructType>, tag_hint: Option<String>) -> CType {
        let aggregate = &node.node;
        let union = aggregate.kind.node == StructKind::Union;
        let name = aggregate.identifier.as_ref().map(|i| i.node.name.clone());

        let make = |name: String| if union { CType::Union(name) } else { CType::Struct(name) };

        let Some(declarations) = &aggregate.declarations else {
            return make(name.unwrap_or_else(|| self.anonymous_name("anon")));
        };

        let name = name.or(tag_hint).unwrap_or_else(|| self.anonymous_name("anon"));

        let mut fields: Vec<(String, CType, Option<u16>)> = Vec::new();

        for declaration in declarations.iter() {
            let StructDeclaration::Field(field) = &declaration.node else {
                continue;
            };

            let specifiers = qualifier_specifiers(&field.node.specifiers);
            let base = self.base_type(&specifiers, None);

            if field.node.declarators.is_empty() {
                // Anonymous struct or union member
                fields.push((String::new(), base, None));
                continue;
            }

            for declarator in field.node.declarators.iter() {
                let (field_name, ty) = match &declarator.node.declarator {
                    Some(d) => (declarator_name(&d.node).unwrap_or_default(), self.derive(base.clone(), &d.node)),
                    None => (String::new(), base.clone()),
                };

                let width = declarator.node.bit_width.as_ref().and_then(|w| self.evaluate(&w.node)).map(|w| w as u16);
                fields.push((field_name, ty, width));
            }
        }

        let (pack, aligned) = self.layout_hints(node.span.start, node.span.end);
        let aggregate = self.layout(fields, union, pack, aligned);

        self.db.add_aggregate(name.clone(), aggregate);

        return make(name);
    }

    /// Packing and alignment of a struct: #pragma pack in effect, attributes in its header or right after it
    fn layout_hints(&self, start: usize, end: usize) -> (Option<u64>, Option<u64>) {
        let header_end = self.source[start..end].find('{').map_or(end, |i| start + i);
        let mut aligned = None;

        // Hints are sorted by offset: the last pragma before the struct, then the attributes from its start
        let pragmas = self.packs.partition_point(|(offset, _)| *offset < start);
        let mut pack = pragmas.checked_sub(1).and_then(|i| self.packs[i].1);

        let first = self.hints.partition_point(|(offset, _)| *offset < start);

        for &(offset, hint) in self.hints[first..].iter() {
            let in_header = offset < header_end;

            if !in_header && offset < end {
                continue;
            }

            if offset >= end && !self.source[end..offset].trim().is_empty() {
                break;
            }

            match hint {
                Hint::Packed => pack = Some(1),
                Hint::Aligned(value) => aligned = Some(value),
                Hint::Pack(_) => {}
            }
        }

        return (pack, aligned);
    }

    /// System V layout: fields aligned on their natural alignment (capped by the packing),
    /// bitfields share the storage unit of their type while they fit
    fn layout(&self, fields: Vec<(String, CType, Option<u16>)>, union: bool, pack: Option<u64>, aligned: Option<u64>) -> Aggregate {
        let mut laid_out = Vec::new();
        let mut bit = 0u64;
        let mut size = 0u64;
        let mut align = 1u64;

        for (name, ty, width) in fields {
            let field_size = self.db.size_of(&ty).unwrap_or(0);
            let field_align = self.db.align_of(&ty).unwrap_or(1).min(pack.unwrap_or(u64::MAX)).max(1);

            align = align.max(field_align);

            if union {
                size = size.max(field_size);
                laid_out.push(Field { name, ty, offset: 0, bits: width.map(|w| (0, w)) });
                continue;
            }

            match width {
                Some(width) => {
                    let unit = (field_size * 8).max(1);

                    if width == 0 || (bit % unit) + width as u64 > unit {
                        bit = bit.next_multiple_of(unit);
                    }

                    let offset = (bit / unit) * field_size;
                    laid_out.push(Field { name, ty, offset, bits: Some(((bit % unit) as u16, width)) });
                    bit += width as u64;
                }
                None => {
                    let offset = bit.div_ceil(8).next_multiple_of(field_align);
                    laid_out.push(Field { name, ty, offset, bits: None });
                    bit = (offset + field_size) * 8;
                }
            }

            size = bit.div_ceil(8);
        }

        let align = aligned.map_or(align, |a| a.max(align));

        return Aggregate { fields: laid_out, size: size.next_multiple_of(align), align, union, pack };
    }

    fn enumeration(&mut self, enumeration: &EnumType, tag_hint: Option<String>) -> CType {
        let name = enumeration.identifier.as_ref().map(|i| i.node.name.clone());

        if enumeration.enumerators.is_empty() {
            return CType::Enum(name.unwrap_or_else(|| self.anonymous_name("anon_enum")));
        }

        let name = name.or(tag_hint).unwrap_or_else(|| self.anonymous_name("anon_enum"));
        let mut values = Vec::new();
        let mut next = 0i64;

        for enumerator in enumeration.enumerators.iter() {
            let constant = enumerator.node.identifier.node.name.clone();
            let value = enumerator.node.expression.as_ref().and_then(|e| self.evaluate(&e.node)).unwrap_or(next);

            // Visible to the next enumerators
            self.db.constants.insert(constant.clone(), value);
            values.push((constant, value));
            next = value.wrapping_add(1);
        }

        self.db.add_enum(name.clone(), values);

        return CType::Enum(name);
    }

    fn type_name(&mut self, type_name: &TypeName) -> CType {
        let specifiers = qualifier_specifiers(&type_name.specifiers);
        let base = self.base_type(&specifiers, None);

        return match &type_name.declarator {
            Some(declarator) => self.derive(base, &declarator.node),
            None => base,
        };
    }

    /// Integer constant expressions (array sizes, bitfield widths, enumerators)
    fn evaluate(&mut self, expression: &Expression) -> Option<i64> {
        match expression {
            Expression::Constant(constant) => match &constant.node {
                Constant::Integer(integer) => {
                    let radix = match integer.base {
                        IntegerBase::Decimal => 10,
                        IntegerBase::Octal => 8,
                        IntegerBase::Hexadecimal => 16,
                        IntegerBase::Binary => 2,
                    };

                    u64::from_str_radix(&integer.number, radix).ok().map(|v| v as i64)
                }
                Constant::Character(c) => c.trim_matches('\'').chars().next().map(|c| c as i64),
                Constant::Float(_) => None,
            },
            Expression::Identifier(identifier) => self.db.constants.get(&identifier.node.name).copied(),
            Expression::Cast(cast) => self.evaluate(&cast.node.expression.node),
            Expression::SizeOfTy(size) => {
                let ty = self.type_name(&size.node.0.node);
                self.db.size_of(&ty).map(|s| s as i64)
            }
            Expression::AlignOf(align) => {
                let ty = self.type_name(&align.node.0.node);
                self.db.align_of(&ty).map(|a| a as i64)
            }
            Expression::UnaryOperator(unary) => {
                let operand = self.evaluate(&unary.node.operand.node)?;

                match unary.node.operator.node {
                    UnaryOperator::Minus => Some(operand.wrapping_neg()),
                    UnaryOperator::Plus => Some(operand),
                    UnaryOperator::Complement => Some(!operand),
                    UnaryOperator::Negate => Some((operand == 0) as i64),
                    _ => None,
                }
            }
            Expression::BinaryOperator(binary) => {
                let lhs = self.evaluate(&binary.node.lhs.node)?;
                let rhs = self.evaluate(&binary.node.rhs.node)?;

                match binary.node.operator.node {
                    BinaryOperator::Plus => Some(lhs.wrapping_add(rhs)),
                    BinaryOperator::Minus => Some(lhs.wrapping_sub(rhs)),
                    BinaryOperator::Multiply => Some(lhs.wrapping_mul(rhs)),
                    BinaryOperator::Divide => lhs.checked_div(rhs),
                    BinaryOperator::Modulo => lhs.checked_rem(rhs),
                    BinaryOperator::ShiftLeft => Some(lhs.wrapping_shl(rhs as u32)),
                    BinaryOperator::ShiftRight => Some(lhs.wrapping_shr(rhs as u32)),
                    BinaryOperator::BitwiseAnd => Some(lhs & rhs),
                    BinaryOperator::BitwiseOr => Some(lhs | rhs),
                    BinaryOperator::BitwiseXor => Some(lhs ^ rhs),
                    BinaryOperator::Less => Some((lhs < rhs) as i64),
                    BinaryOperator::Greater => Some((lhs > rhs) as i64),
                    BinaryOperator::LessOrEqual => Some((lhs <= rhs) as i64),
                    BinaryOperator::GreaterOrEqual => Some((lhs >= rhs) as i64),
                    BinaryOperator::Equals => Some((lhs == rhs) as i64),
                    BinaryOperator::NotEquals => Some((lhs != rhs) as i64),
                    BinaryOperator::LogicalAnd => Some((lhs != 0 && rhs != 0) as i64),
                    BinaryOperator::LogicalOr => Some((lhs != 0 || rhs != 0) as i64),
                    _ => None,
                }
            }
            Expression::Conditional(conditional) => {
                let condition = self.evaluate(&conditional.node.condition.node)?;
                let branch = if condition != 0 { &conditional.node.then_expression } else { &conditional.node.else_expression };
                self.evaluate(&branch.node)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::DataModel;
    use execdump_core::disasm::Architecture;

    fn db(source: &str) -> TypeDb {
        let mut db = TypeDb::new(DataModel::new(Architecture::X86_64, false));
        db.parse(source).unwrap();
        return db;
    }

    #[test]
    fn declarators() {
        let db = db("typedef unsigned long size_t; int (*signal(int sig, void (*handler)(int)))(int); char *strcpy(char *restrict dest, const char *src); int main(int argc, char *argv[]) { return 0; }");

        assert_eq!(db.typedefs["size_t"], CType::uint(64));
        assert_eq!(
            super::super::Prototype { name: "signal".to_string(), ty: db.functions["signal"].clone() }.to_string(),
            "int (*signal(int sig, void (*handler)(int)))(int)"
        );
        assert_eq!(db.functions["main"].params[1].ty, CType::ptr(CType::ptr(CType::Char)));
    }

    #[test]
    fn layouts() {
        let db = db("
            struct a { char c; int i; short s; };
            struct b { char c; struct a inner; char tail[3]; };
            union u { char c; double d; };
            struct bits { unsigned int x : 3; unsigned int y : 30; char z; };
            #pragma pack(push, 1)
            struct packed { char c; int i; };
            #pragma pack(pop)
            struct __attribute__((aligned(16))) wide { int x; };
            struct after { char c; int i; } __attribute__((packed));
            typedef struct { int x, y; } point, *ppoint;
            enum color { RED, GREEN = 5, BLUE };
            int grid[GREEN * 2][sizeof(struct a)];
        ");

        let size = |name: &str| db.aggregates[name].size;

        assert_eq!(size("a"), 12);
        assert_eq!(size("b"), 20);
        assert_eq!(db.aggregates["b"].fields[2].offset, 16);
        assert_eq!(size("u"), 8);
        assert_eq!(size("bits"), 12);
        assert_eq!(db.aggregates["bits"].fields[1].offset, 4);
        assert_eq!(size("packed"), 5);
        assert_eq!(size("wide"), 16);
        assert_eq!(size("after"), 5);
        assert_eq!(size("point"), 8);
        assert_eq!(db.typedefs["ppoint"], CType::ptr(CType::Struct("point".to_string())));
        assert_eq!(db.constants["BLUE"], 6);
    }
}
