/*
 * Microsoft Visual C++ demangler (MSVC, clang-cl, Windows x86, x64, ARM64 and ARM64EC)
 * The output follows llvm-undname
 */

const QUAL_CONST: u8 = 0x1;
const QUAL_VOLATILE: u8 = 0x2;
const QUAL_RESTRICT: u8 = 0x4;
const QUAL_UNALIGNED: u8 = 0x8;

const FC_PUBLIC: u32 = 1 << 0;
const FC_PROTECTED: u32 = 1 << 1;
const FC_PRIVATE: u32 = 1 << 2;
const FC_GLOBAL: u32 = 1 << 3;
const FC_STATIC: u32 = 1 << 4;
const FC_VIRTUAL: u32 = 1 << 5;
const FC_FAR: u32 = 1 << 6;
const FC_EXTERN_C: u32 = 1 << 7;
const FC_NO_PARAMETER_LIST: u32 = 1 << 8;
const FC_VIRTUAL_THIS_ADJUST: u32 = 1 << 9;
const FC_VIRTUAL_THIS_ADJUST_EX: u32 = 1 << 10;
const FC_STATIC_THIS_ADJUST: u32 = 1 << 11;

const MAX_BACKREFS: usize = 10;
const MAX_DEPTH: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Affinity {
    Pointer,
    Reference,
    RValueReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageClass {
    PrivateStatic,
    ProtectedStatic,
    PublicStatic,
    Global,
    FunctionLocalStatic,
}

#[derive(Clone, Debug)]
enum TemplateParam {
    Type(Type),
    Integer(u64, bool),
    SymbolRef { symbol: Option<Box<Symbol>>, affinity: Affinity, offsets: Vec<i64> },
    Name(QualifiedName),
}

#[derive(Clone, Debug)]
enum Ident {
    Named(String),
    Intrinsic(&'static str),
    Structor { class: Option<Box<IdentNode>>, is_dtor: bool },
    Conversion(Option<Box<Type>>),
    LiteralOperator(String),
    LocalStaticGuard { is_thread: bool, scope_index: u64 },
    DynamicStructor { is_dtor: bool, variable: Option<Box<Symbol>>, name: Option<QualifiedName> },
    VcallThunk(u64),
    RttiBaseClassDescriptor([i64; 4]),
}

#[derive(Clone, Debug)]
struct IdentNode {
    ident: Ident,
    template_params: Option<Vec<TemplateParam>>,
}

impl IdentNode {
    fn new(ident: Ident) -> Self {
        return Self { ident, template_params: None };
    }
}

#[derive(Clone, Debug, Default)]
struct QualifiedName {
    components: Vec<IdentNode>,
}

#[derive(Clone, Debug)]
enum TypeKind {
    Primitive(&'static str),
    Tag(&'static str, QualifiedName),
    Pointer { affinity: Affinity, class_parent: Option<QualifiedName>, pointee: Box<Type> },
    Array { dimensions: Vec<u64>, element: Box<Type> },
    Function(Box<FunctionSignature>),
    Custom(IdentNode),
}

#[derive(Clone, Debug)]
struct Type {
    kind: TypeKind,
    quals: u8,
}

#[derive(Clone, Debug, Default)]
struct ThisAdjust {
    static_offset: i64,
    vbptr_offset: i64,
    vboffset_offset: i64,
    vtordisp_offset: i64,
}

#[derive(Clone, Debug, Default)]
struct FunctionSignature {
    function_class: u32,
    call_conv: &'static str,
    ret: Option<Type>,
    params: Option<Vec<Type>>,
    is_variadic: bool,
    quals: u8,
    ref_qual: &'static str,
    is_noexcept: bool,
    thunk: Option<ThisAdjust>,
}

#[derive(Clone, Debug)]
enum Symbol {
    Function { name: QualifiedName, signature: FunctionSignature },
    Variable { name: QualifiedName, storage: Option<StorageClass>, ty: Option<Type> },
    SpecialTable { name: QualifiedName, quals: u8, target: Option<QualifiedName> },
    StringLiteral { text: String, prefix: &'static str, truncated: bool },
    Raw(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualifierMode {
    Drop,
    Mangle,
    Result,
}

#[derive(Clone, Default)]
struct Backrefs {
    names: Vec<IdentNode>,
    params: Vec<Type>,
}

struct Demangler<'a> {
    input: &'a [u8],
    pos: usize,
    backrefs: Backrefs,
    depth: usize,
}

type DResult<T> = Option<T>;

impl<'a> Demangler<'a> {
    fn new(input: &'a [u8]) -> Self {
        return Self { input, pos: 0, backrefs: Backrefs::default(), depth: 0 };
    }

    fn rest(&self) -> &'a [u8] {
        return &self.input[self.pos..];
    }

    fn front(&self) -> u8 {
        return self.rest().first().copied().unwrap_or(0);
    }

    fn is_empty(&self) -> bool {
        return self.pos >= self.input.len();
    }

    fn starts_with(&self, s: &str) -> bool {
        return self.rest().starts_with(s.as_bytes());
    }

    fn consume(&mut self, s: &str) -> bool {
        if self.starts_with(s) {
            self.pos += s.len();
            return true;
        }

        return false;
    }

    fn pop(&mut self) -> DResult<u8> {
        let c = *self.rest().first()?;
        self.pos += 1;
        return Some(c);
    }

    fn starts_with_digit(&self) -> bool {
        return self.front().is_ascii_digit();
    }

    fn enter(&mut self) -> DResult<()> {
        self.depth += 1;
        return if self.depth > MAX_DEPTH { None } else { Some(()) };
    }

    fn leave<T>(&mut self, result: DResult<T>) -> DResult<T> {
        self.depth -= 1;
        return result;
    }

    /*
     * Numbers
     */

    fn demangle_number(&mut self) -> DResult<(u64, bool)> {
        let negative = self.consume("?");

        if self.starts_with_digit() {
            let value = (self.front() - b'0') as u64 + 1;
            self.pos += 1;
            return Some((value, negative));
        }

        let mut value: u64 = 0;

        while let Some(c) = self.pop() {
            match c {
                b'@' => return Some((value, negative)),
                b'A'..=b'P' => value = value.checked_mul(16)?.checked_add((c - b'A') as u64)?,
                _ => return None,
            }
        }

        return None;
    }

    fn demangle_unsigned(&mut self) -> DResult<u64> {
        let (value, negative) = self.demangle_number()?;
        return if negative { None } else { Some(value) };
    }

    fn demangle_signed_32(&mut self) -> DResult<i64> {
        return Some(self.demangle_signed()? as i32 as i64);
    }

    fn demangle_signed(&mut self) -> DResult<i64> {
        let (value, negative) = self.demangle_number()?;
        let value = i64::try_from(value).ok()?;
        return Some(if negative { -value } else { value });
    }

    /*
     * Back references
     */

    fn memorize_string(&mut self, s: &str) {
        if self.backrefs.names.len() >= MAX_BACKREFS {
            return;
        }

        if self.backrefs.names.iter().any(|n| matches!(&n.ident, Ident::Named(name) if name == s)) {
            return;
        }

        self.backrefs.names.push(IdentNode::new(Ident::Named(s.to_string())));
    }

    fn memorize_identifier(&mut self, ident: &IdentNode) {
        let mut out = String::new();
        output_ident(&mut out, ident);
        self.memorize_string(&out);
    }

    fn demangle_back_ref_name(&mut self) -> DResult<IdentNode> {
        let index = (self.front() - b'0') as usize;
        let name = self.backrefs.names.get(index)?.clone();
        self.pos += 1;
        return Some(name);
    }

    /*
     * Symbols
     */

    fn parse(&mut self) -> DResult<Symbol> {
        self.enter()?;
        let result = self.parse_impl();
        return self.leave(result);
    }

    fn parse_impl(&mut self) -> DResult<Symbol> {
        if self.consume(".") {
            let ty = self.demangle_type(QualifierMode::Result)?;

            if !self.is_empty() {
                return None;
            }

            return Some(synthesize_variable(Some(ty), "`RTTI Type Descriptor Name'"));
        }

        if self.starts_with("??@") {
            let rest = &self.rest()[3..];
            let end = rest.iter().position(|&c| c == b'@')? + 4;
            let start = self.pos;

            self.pos += end;
            self.consume("??_R4@");

            return Some(Symbol::Raw(String::from_utf8_lossy(&self.input[start..self.pos]).to_string()));
        }

        if !self.consume("?") {
            return None;
        }

        if let Some(special) = self.demangle_special_intrinsic() {
            return special;
        }

        return self.demangle_declarator();
    }

    /// Returns None if not a special intrinsic, Some(None) on error
    fn demangle_special_intrinsic(&mut self) -> Option<DResult<Symbol>> {
        const TABLES: [(&str, &str); 4] = [
            ("?_7", "`vftable'"),
            ("?_8", "`vbtable'"),
            ("?_S", "`local vftable'"),
            ("?_R4", "`RTTI Complete Object Locator'"),
        ];

        for (prefix, name) in TABLES {
            if self.consume(prefix) {
                return Some(self.demangle_special_table(name));
            }
        }

        if self.consume("?_9") {
            return Some(self.demangle_vcall_thunk());
        }

        if self.consume("?_B") {
            return Some(self.demangle_local_static_guard(false));
        }

        if self.consume("?__J") {
            return Some(self.demangle_local_static_guard(true));
        }

        if self.consume("?_C") {
            return Some(self.demangle_string_literal());
        }

        if self.consume("?_R0") {
            let result = (|| {
                let ty = self.demangle_type(QualifierMode::Result)?;

                if !self.consume("@8") || !self.is_empty() {
                    return None;
                }

                return Some(synthesize_variable(Some(ty), "`RTTI Type Descriptor'"));
            })();

            return Some(result);
        }

        if self.consume("?_R1") {
            let result = (|| {
                let values = [
                    self.demangle_unsigned()? as u32 as i64,
                    self.demangle_signed_32()?,
                    self.demangle_unsigned()? as u32 as i64,
                    self.demangle_unsigned()? as u32 as i64,
                ];

                let name = self.demangle_name_scope_chain(IdentNode::new(Ident::RttiBaseClassDescriptor(values)))?;
                self.consume("8");

                return Some(Symbol::Variable { name, storage: None, ty: None });
            })();

            return Some(result);
        }

        if self.consume("?_R2") {
            return Some(self.demangle_untyped_variable("`RTTI Base Class Array'"));
        }

        if self.consume("?_R3") {
            return Some(self.demangle_untyped_variable("`RTTI Class Hierarchy Descriptor'"));
        }

        if self.consume("?__E") {
            return Some(self.demangle_init_fini_stub(false));
        }

        if self.consume("?__F") {
            return Some(self.demangle_init_fini_stub(true));
        }

        if self.starts_with("?_A") || self.starts_with("?_P") {
            return Some(None);
        }

        return None;
    }

    fn demangle_special_table(&mut self, name: &str) -> DResult<Symbol> {
        let name = self.demangle_name_scope_chain(IdentNode::new(Ident::Named(name.to_string())))?;

        if !matches!(self.pop()?, b'6' | b'7') {
            return None;
        }

        let (quals, _) = self.demangle_qualifiers()?;

        let target = if self.consume("@") { None } else { Some(self.demangle_fully_qualified_type_name()?) };

        return Some(Symbol::SpecialTable { name, quals, target });
    }

    fn demangle_vcall_thunk(&mut self) -> DResult<Symbol> {
        let mut name = self.demangle_name_scope_chain(IdentNode::new(Ident::VcallThunk(0)))?;

        if !self.consume("$B") {
            return None;
        }

        let offset = self.demangle_unsigned()?;

        if !self.consume("A") {
            return None;
        }

        let call_conv = self.demangle_calling_convention()?;

        name.components.last_mut()?.ident = Ident::VcallThunk(offset);

        let signature = FunctionSignature {
            function_class: FC_NO_PARAMETER_LIST,
            call_conv,
            thunk: Some(ThisAdjust::default()),
            ..Default::default()
        };

        return Some(Symbol::Function { name, signature });
    }

    fn demangle_local_static_guard(&mut self, is_thread: bool) -> DResult<Symbol> {
        let mut name = self.demangle_name_scope_chain(IdentNode::new(Ident::LocalStaticGuard { is_thread, scope_index: 0 }))?;

        if !self.consume("4IA") && !self.consume("5") {
            return None;
        }

        if !self.is_empty() {
            let scope_index = self.demangle_unsigned()?;
            name.components.last_mut()?.ident = Ident::LocalStaticGuard { is_thread, scope_index };
        }

        return Some(Symbol::Variable { name, storage: None, ty: None });
    }

    fn demangle_untyped_variable(&mut self, variable_name: &str) -> DResult<Symbol> {
        let name = self.demangle_name_scope_chain(IdentNode::new(Ident::Named(variable_name.to_string())))?;

        if !self.consume("8") {
            return None;
        }

        return Some(Symbol::Variable { name, storage: None, ty: None });
    }

    fn demangle_init_fini_stub(&mut self, is_dtor: bool) -> DResult<Symbol> {
        let is_static_member = self.consume("?");

        let symbol = self.demangle_declarator()?;

        match symbol {
            Symbol::Variable { .. } => {
                for _ in 0..(if is_static_member { 2 } else { 1 }) {
                    if !self.consume("@") {
                        return None;
                    }
                }

                let Symbol::Function { signature, .. } = self.demangle_function_encoding()? else {
                    return None;
                };

                let ident = Ident::DynamicStructor { is_dtor, variable: Some(Box::new(symbol)), name: None };

                return Some(Symbol::Function { name: QualifiedName { components: vec![IdentNode::new(ident)] }, signature });
            }
            Symbol::Function { name, signature } => {
                if is_static_member {
                    return None;
                }

                let ident = Ident::DynamicStructor { is_dtor, variable: None, name: Some(name) };

                return Some(Symbol::Function { name: QualifiedName { components: vec![IdentNode::new(ident)] }, signature });
            }
            _ => return None,
        }
    }

    fn demangle_string_literal(&mut self) -> DResult<Symbol> {
        if !self.consume("@_") {
            return None;
        }

        let is_wchar = match self.pop()? {
            b'1' => true,
            b'0' => false,
            _ => return None,
        };

        let (mut byte_size, negative) = self.demangle_number()?;

        if negative || byte_size < (if is_wchar { 2 } else { 1 }) {
            return None;
        }

        let crc_end = self.rest().iter().position(|&c| c == b'@')?;
        self.pos += crc_end + 1;

        if self.is_empty() {
            return None;
        }

        let mut text = String::new();

        if is_wchar {
            let truncated = byte_size > 64;

            while !self.consume("@") {
                if self.rest().len() < 2 {
                    return None;
                }

                let high = self.demangle_char_literal()? as u32;
                let low = self.demangle_char_literal()? as u32;

                if byte_size != 2 || truncated {
                    output_escaped_char(&mut text, (high << 8) | low);
                }

                byte_size = byte_size.saturating_sub(2);
            }

            return Some(Symbol::StringLiteral { text, prefix: "L", truncated });
        }

        let mut bytes = Vec::new();

        while !self.consume("@") {
            if self.is_empty() || bytes.len() >= 32 * 4 {
                return None;
            }

            bytes.push(self.demangle_char_literal()?);
        }

        let truncated = byte_size > bytes.len() as u64;
        let char_bytes = guess_char_byte_size(&bytes, byte_size);
        let num_chars = bytes.len() / char_bytes;

        for index in 0..num_chars {
            let mut c: u32 = 0;

            for i in 0..char_bytes {
                c |= (bytes[index * char_bytes + i] as u32) << (8 * i);
            }

            if index + 1 < num_chars || truncated {
                output_escaped_char(&mut text, c);
            }
        }

        let prefix = match char_bytes {
            2 => "u",
            4 => "U",
            _ => "",
        };

        return Some(Symbol::StringLiteral { text, prefix, truncated });
    }

    fn demangle_char_literal(&mut self) -> DResult<u8> {
        if !self.consume("?") {
            return self.pop();
        }

        if self.consume("$") {
            let high = self.pop()?;
            let low = self.pop()?;

            if !(b'A'..=b'P').contains(&high) || !(b'A'..=b'P').contains(&low) {
                return None;
            }

            return Some(((high - b'A') << 4) | (low - b'A'));
        }

        let c = self.pop()?;

        return match c {
            b'0'..=b'9' => Some(b",/\\:. \n\t'-"[(c - b'0') as usize]),
            b'a'..=b'z' => Some(0xe1 + (c - b'a')),
            b'A'..=b'Z' => Some(0xc1 + (c - b'A')),
            _ => None,
        };
    }

    fn demangle_declarator(&mut self) -> DResult<Symbol> {
        let name = self.demangle_fully_qualified_symbol_name()?;
        let mut symbol = self.demangle_encoded_symbol(&name)?;

        let is_conversion = matches!(name.components.last().map(|c| &c.ident), Some(Ident::Conversion(_)));

        match &mut symbol {
            Symbol::Function { name: symbol_name, signature } => {
                *symbol_name = name;

                if is_conversion {
                    let target = signature.ret.clone()?;
                    symbol_name.components.last_mut()?.ident = Ident::Conversion(Some(Box::new(target)));
                }
            }
            Symbol::Variable { name: symbol_name, .. } => {
                if is_conversion {
                    return None;
                }

                *symbol_name = name;
            }
            _ => {}
        }

        return Some(symbol);
    }

    fn demangle_encoded_symbol(&mut self, name: &QualifiedName) -> DResult<Symbol> {
        let storage = match self.front() {
            b'0' => Some(StorageClass::PrivateStatic),
            b'1' => Some(StorageClass::ProtectedStatic),
            b'2' => Some(StorageClass::PublicStatic),
            b'3' => Some(StorageClass::Global),
            b'4' => Some(StorageClass::FunctionLocalStatic),
            _ => None,
        };

        if let Some(storage) = storage {
            self.pos += 1;
            return self.demangle_variable_encoding(storage, name.clone());
        }

        return self.demangle_function_encoding();
    }

    fn demangle_variable_encoding(&mut self, storage: StorageClass, name: QualifiedName) -> DResult<Symbol> {
        let mut ty = self.demangle_type(QualifierMode::Drop)?;

        let has_class_parent = matches!(&ty.kind, TypeKind::Pointer { class_parent: Some(_), .. });

        if let TypeKind::Pointer { .. } = ty.kind {
            ty.quals |= self.demangle_pointer_ext_qualifiers();

            let (extra_quals, _) = self.demangle_qualifiers()?;

            if has_class_parent {
                self.demangle_fully_qualified_type_name()?;
            }

            if let TypeKind::Pointer { pointee, .. } = &mut ty.kind {
                pointee.quals |= extra_quals;
            }
        } else {
            ty.quals = self.demangle_qualifiers()?.0;
        }

        return Some(Symbol::Variable { name, storage: Some(storage), ty: Some(ty) });
    }

    /*
     * Names
     */

    fn demangle_fully_qualified_symbol_name(&mut self) -> DResult<QualifiedName> {
        let ident = self.demangle_unqualified_symbol_name(false)?;
        let mut name = self.demangle_name_scope_chain(ident)?;

        let count = name.components.len();

        if let Ident::Structor { .. } = name.components.last()?.ident {
            if count < 2 {
                return None;
            }

            let class = name.components[count - 2].clone();

            if let Ident::Structor { class: c, .. } = &mut name.components[count - 1].ident {
                *c = Some(Box::new(class));
            }
        }

        return Some(name);
    }

    fn demangle_fully_qualified_type_name(&mut self) -> DResult<QualifiedName> {
        let ident = self.demangle_unqualified_type_name(true)?;
        return self.demangle_name_scope_chain(ident);
    }

    fn demangle_unqualified_type_name(&mut self, memorize: bool) -> DResult<IdentNode> {
        if self.starts_with_digit() {
            return self.demangle_back_ref_name();
        }

        if self.consume("?$") {
            return self.demangle_template_instantiation_name(true);
        }

        return self.demangle_simple_name(memorize);
    }

    fn demangle_unqualified_symbol_name(&mut self, is_template: bool) -> DResult<IdentNode> {
        if self.starts_with_digit() {
            return self.demangle_back_ref_name();
        }

        if self.consume("?$") {
            return self.demangle_template_instantiation_name(is_template);
        }

        if self.consume("?") {
            return self.demangle_function_identifier_code();
        }

        return self.demangle_simple_name(!is_template);
    }

    fn demangle_name_scope_chain(&mut self, ident: IdentNode) -> DResult<QualifiedName> {
        let mut components = vec![ident];

        while !self.consume("@") {
            if self.is_empty() {
                return None;
            }

            if self.consume("$$h") {
                continue;
            }

            components.push(self.demangle_name_scope_piece()?);
        }

        components.reverse();

        return Some(QualifiedName { components });
    }

    fn demangle_name_scope_piece(&mut self) -> DResult<IdentNode> {
        if self.starts_with_digit() {
            return self.demangle_back_ref_name();
        }

        if self.consume("?$") {
            return self.demangle_template_instantiation_name(true);
        }

        if self.consume("?A") {
            let end = self.rest().iter().position(|&c| c == b'@')?;
            let key = String::from_utf8_lossy(&self.rest()[..end]).to_string();

            self.memorize_string(&key);
            self.pos += end + 1;

            return Some(IdentNode::new(Ident::Named("`anonymous namespace'".to_string())));
        }

        if self.starts_with_local_scope_pattern() {
            self.pos += 1;

            let (number, _) = self.demangle_number()?;

            self.consume("?");

            let scope = self.parse()?;

            let mut out = String::from("`");
            output_symbol(&mut out, &scope);
            out.push_str(&format!("'::`{}'", number));

            return Some(IdentNode::new(Ident::Named(out)));
        }

        return self.demangle_simple_name(true);
    }

    fn starts_with_local_scope_pattern(&self) -> bool {
        let rest = self.rest();

        if rest.first() != Some(&b'?') {
            return false;
        }

        let rest = &rest[1..];

        let Some(end) = rest.iter().position(|&c| c == b'?') else {
            return false;
        };

        let candidate = &rest[..end];

        match candidate.len() {
            0 => return false,
            1 => return candidate[0] == b'@' || candidate[0].is_ascii_digit(),
            _ => {}
        }

        if candidate.last() != Some(&b'@') {
            return false;
        }

        let digits = &candidate[..candidate.len() - 1];

        return (b'B'..=b'P').contains(&digits[0]) && digits[1..].iter().all(|c| (b'A'..=b'P').contains(c));
    }

    fn demangle_simple_name(&mut self, memorize: bool) -> DResult<IdentNode> {
        let end = self.rest().iter().position(|&c| c == b'@')?;

        if end == 0 {
            return None;
        }

        let name = String::from_utf8_lossy(&self.rest()[..end]).to_string();
        self.pos += end + 1;

        if memorize {
            self.memorize_string(&name);
        }

        return Some(IdentNode::new(Ident::Named(name)));
    }

    fn demangle_template_instantiation_name(&mut self, memorize: bool) -> DResult<IdentNode> {
        self.enter()?;

        let outer = std::mem::take(&mut self.backrefs);

        let result = (|| {
            let mut ident = self.demangle_unqualified_symbol_name(false)?;
            ident.template_params = Some(self.demangle_template_parameter_list()?);
            return Some(ident);
        })();

        self.backrefs = outer;

        let ident = self.leave(result)?;

        if memorize {
            if matches!(ident.ident, Ident::Conversion(_) | Ident::Structor { .. }) {
                return None;
            }

            self.memorize_identifier(&ident);
        }

        return Some(ident);
    }

    fn demangle_template_parameter_list(&mut self) -> DResult<Vec<TemplateParam>> {
        let mut params = Vec::new();

        while !self.consume("@") {
            if self.is_empty() {
                return None;
            }

            if self.consume("$S") || self.consume("$$V") || self.consume("$$$V") || self.consume("$$Z") || self.consume("$$h") {
                continue;
            }

            let param = if self.consume("$$Y") {
                TemplateParam::Name(self.demangle_fully_qualified_type_name()?)
            } else if self.consume("$$B") {
                TemplateParam::Type(self.demangle_type(QualifierMode::Drop)?)
            } else if self.consume("$$C") {
                TemplateParam::Type(self.demangle_type(QualifierMode::Mangle)?)
            } else if self.starts_with("$1") || self.starts_with("$H") || self.starts_with("$I") || self.starts_with("$J") {
                self.pos += 1;

                let inheritance = self.pop()?;

                let symbol = if self.front() == b'?' {
                    let symbol = self.parse()?;

                    if let Some(ident) = symbol_name(&symbol).and_then(|n| n.components.last()) {
                        let ident = ident.clone();
                        self.memorize_identifier(&ident);
                    }

                    Some(Box::new(symbol))
                } else {
                    None
                };

                let count = match inheritance {
                    b'J' => 3,
                    b'I' => 2,
                    b'H' => 1,
                    _ => 0,
                };

                let mut offsets = Vec::new();

                for _ in 0..count {
                    offsets.push(self.demangle_signed()?);
                }

                TemplateParam::SymbolRef { symbol, affinity: Affinity::Pointer, offsets }
            } else if self.consume("$E") {
                let symbol = self.parse()?;
                TemplateParam::SymbolRef { symbol: Some(Box::new(symbol)), affinity: Affinity::Reference, offsets: Vec::new() }
            } else if self.starts_with("$F") || self.starts_with("$G") {
                self.pos += 1;

                let count = if self.pop()? == b'G' { 3 } else { 2 };
                let mut offsets = Vec::new();

                for _ in 0..count {
                    offsets.push(self.demangle_signed()?);
                }

                TemplateParam::SymbolRef { symbol: None, affinity: Affinity::Pointer, offsets }
            } else if self.consume("$0") {
                let (value, negative) = self.demangle_number()?;
                TemplateParam::Integer(value, negative)
            } else {
                TemplateParam::Type(self.demangle_type(QualifierMode::Drop)?)
            };

            params.push(param);
        }

        return Some(params);
    }

    fn demangle_function_identifier_code(&mut self) -> DResult<IdentNode> {
        let (group, code) = if self.consume("__") {
            (2, self.pop()?)
        } else if self.consume("_") {
            (1, self.pop()?)
        } else {
            (0, self.pop()?)
        };

        let ident = match (group, code) {
            (0, b'0') => Ident::Structor { class: None, is_dtor: false },
            (0, b'1') => Ident::Structor { class: None, is_dtor: true },
            (0, b'B') => Ident::Conversion(None),
            (2, b'K') => {
                let name = self.demangle_simple_name(false)?;

                let Ident::Named(name) = name.ident else {
                    return None;
                };

                Ident::LiteralOperator(name)
            }
            _ => Ident::Intrinsic(intrinsic_function_name(group, code)?),
        };

        return Some(IdentNode::new(ident));
    }

    /*
     * Functions
     */

    fn demangle_function_class(&mut self) -> DResult<u32> {
        let class = match self.pop()? {
            b'9' => FC_EXTERN_C | FC_NO_PARAMETER_LIST,
            b'A' => FC_PRIVATE,
            b'B' => FC_PRIVATE | FC_FAR,
            b'C' => FC_PRIVATE | FC_STATIC,
            b'D' => FC_PRIVATE | FC_STATIC | FC_FAR,
            b'E' => FC_PRIVATE | FC_VIRTUAL,
            b'F' => FC_PRIVATE | FC_VIRTUAL | FC_FAR,
            b'G' => FC_PRIVATE | FC_STATIC_THIS_ADJUST,
            b'H' => FC_PRIVATE | FC_STATIC_THIS_ADJUST | FC_FAR,
            b'I' => FC_PROTECTED,
            b'J' => FC_PROTECTED | FC_FAR,
            b'K' => FC_PROTECTED | FC_STATIC,
            b'L' => FC_PROTECTED | FC_STATIC | FC_FAR,
            b'M' => FC_PROTECTED | FC_VIRTUAL,
            b'N' => FC_PROTECTED | FC_VIRTUAL | FC_FAR,
            b'O' => FC_PROTECTED | FC_VIRTUAL | FC_STATIC_THIS_ADJUST,
            b'P' => FC_PROTECTED | FC_VIRTUAL | FC_STATIC_THIS_ADJUST | FC_FAR,
            b'Q' => FC_PUBLIC,
            b'R' => FC_PUBLIC | FC_FAR,
            b'S' => FC_PUBLIC | FC_STATIC,
            b'T' => FC_PUBLIC | FC_STATIC | FC_FAR,
            b'U' => FC_PUBLIC | FC_VIRTUAL,
            b'V' => FC_PUBLIC | FC_VIRTUAL | FC_FAR,
            b'W' => FC_PUBLIC | FC_VIRTUAL | FC_STATIC_THIS_ADJUST,
            b'X' => FC_PUBLIC | FC_VIRTUAL | FC_STATIC_THIS_ADJUST | FC_FAR,
            b'Y' => FC_GLOBAL,
            b'Z' => FC_GLOBAL | FC_FAR,
            b'$' => {
                let mut flags = FC_VIRTUAL_THIS_ADJUST;

                if self.consume("R") {
                    flags |= FC_VIRTUAL_THIS_ADJUST_EX;
                }

                match self.pop()? {
                    b'0' => FC_PRIVATE | FC_VIRTUAL | flags,
                    b'1' => FC_PRIVATE | FC_VIRTUAL | flags | FC_FAR,
                    b'2' => FC_PROTECTED | FC_VIRTUAL | flags,
                    b'3' => FC_PROTECTED | FC_VIRTUAL | flags | FC_FAR,
                    b'4' => FC_PUBLIC | FC_VIRTUAL | flags,
                    b'5' => FC_PUBLIC | FC_VIRTUAL | flags | FC_FAR,
                    _ => return None,
                }
            }
            _ => return None,
        };

        return Some(class);
    }

    fn demangle_function_encoding(&mut self) -> DResult<Symbol> {
        let mut extra = 0;

        if self.consume("$$J0") {
            extra = FC_EXTERN_C;
        }

        self.consume("$$h");

        let function_class = self.demangle_function_class()? | extra;

        let mut thunk = None;

        if function_class & FC_STATIC_THIS_ADJUST != 0 {
            thunk = Some(ThisAdjust { static_offset: self.demangle_signed_32()?, ..Default::default() });
        } else if function_class & FC_VIRTUAL_THIS_ADJUST != 0 {
            let mut adjust = ThisAdjust::default();

            if function_class & FC_VIRTUAL_THIS_ADJUST_EX != 0 {
                adjust.vbptr_offset = self.demangle_signed_32()?;
                adjust.vboffset_offset = self.demangle_signed_32()?;
            }

            adjust.vtordisp_offset = self.demangle_signed_32()?;
            adjust.static_offset = self.demangle_signed_32()?;

            thunk = Some(adjust);
        }

        let mut signature = if function_class & FC_NO_PARAMETER_LIST != 0 {
            FunctionSignature::default()
        } else {
            self.demangle_function_type(function_class & (FC_GLOBAL | FC_STATIC) == 0)?
        };

        signature.function_class = function_class;
        signature.thunk = thunk;

        return Some(Symbol::Function { name: QualifiedName::default(), signature });
    }

    fn demangle_calling_convention(&mut self) -> DResult<&'static str> {
        let call_conv = match self.pop()? {
            b'A' | b'B' => "__cdecl",
            b'C' | b'D' => "__pascal",
            b'E' | b'F' => "__thiscall",
            b'G' | b'H' => "__stdcall",
            b'I' | b'J' => "__fastcall",
            b'M' | b'N' => "__clrcall",
            b'O' | b'P' => "__eabi",
            b'Q' => "__vectorcall",
            b'S' => "__attribute__((__swiftcall__)) ",
            b'W' => "__attribute__((__swiftasynccall__)) ",
            _ => return None,
        };

        return Some(call_conv);
    }

    fn demangle_function_type(&mut self, has_this_quals: bool) -> DResult<FunctionSignature> {
        let mut signature = FunctionSignature::default();

        if has_this_quals {
            signature.quals = self.demangle_pointer_ext_qualifiers();

            if self.consume("G") {
                signature.ref_qual = " &";
            } else if self.consume("H") {
                signature.ref_qual = " &&";
            }

            signature.quals |= self.demangle_qualifiers()?.0;
        }

        signature.call_conv = self.demangle_calling_convention()?;

        if !self.consume("@") {
            signature.ret = Some(self.demangle_type(QualifierMode::Result)?);
        }

        let (params, is_variadic) = self.demangle_function_parameter_list()?;

        signature.params = params;
        signature.is_variadic = is_variadic;

        if self.consume("_E") {
            signature.is_noexcept = true;
        } else if !self.consume("Z") {
            return None;
        }

        return Some(signature);
    }

    fn demangle_function_parameter_list(&mut self) -> DResult<(Option<Vec<Type>>, bool)> {
        if self.consume("X") {
            return Some((None, false));
        }

        let mut params = Vec::new();

        while !self.starts_with("@") && !self.starts_with("Z") {
            if self.is_empty() {
                return None;
            }

            if self.starts_with_digit() {
                let index = (self.front() - b'0') as usize;
                params.push(self.backrefs.params.get(index)?.clone());
                self.pos += 1;
                continue;
            }

            let start = self.pos;
            let ty = self.demangle_type(QualifierMode::Drop)?;

            if self.backrefs.params.len() < MAX_BACKREFS && self.pos - start > 1 {
                self.backrefs.params.push(ty.clone());
            }

            params.push(ty);
        }

        if self.consume("@") {
            return Some((Some(params), false));
        }

        if self.consume("Z") {
            return Some((Some(params), true));
        }

        return None;
    }

    /*
     * Types
     */

    fn demangle_qualifiers(&mut self) -> DResult<(u8, bool)> {
        let result = match self.pop()? {
            b'Q' => (0, true),
            b'R' => (QUAL_CONST, true),
            b'S' => (QUAL_VOLATILE, true),
            b'T' => (QUAL_CONST | QUAL_VOLATILE, true),
            b'A' => (0, false),
            b'B' => (QUAL_CONST, false),
            b'C' => (QUAL_VOLATILE, false),
            b'D' => (QUAL_CONST | QUAL_VOLATILE, false),
            _ => return None,
        };

        return Some(result);
    }

    fn demangle_pointer_ext_qualifiers(&mut self) -> u8 {
        let mut quals = 0;

        self.consume("E");

        if self.consume("I") {
            quals |= QUAL_RESTRICT;
        }

        if self.consume("F") {
            quals |= QUAL_UNALIGNED;
        }

        return quals;
    }

    fn demangle_type(&mut self, mode: QualifierMode) -> DResult<Type> {
        self.enter()?;
        let result = self.demangle_type_impl(mode);
        return self.leave(result);
    }

    fn demangle_type_impl(&mut self, mode: QualifierMode) -> DResult<Type> {
        let mut quals = 0;

        match mode {
            QualifierMode::Mangle => quals = self.demangle_qualifiers()?.0,
            QualifierMode::Result if self.consume("?") => quals = self.demangle_qualifiers()?.0,
            _ => {}
        }

        if self.is_empty() {
            return None;
        }

        let mut ty = match self.front() {
            b'T' | b'U' | b'V' | b'W' => self.demangle_class_type()?,
            b'A' | b'P' | b'Q' | b'R' | b'S' => {
                if self.is_member_pointer()? {
                    self.demangle_member_pointer_type()?
                } else {
                    self.demangle_pointer_type()?
                }
            }
            b'$' if self.starts_with("$$Q") => self.demangle_pointer_type()?,
            b'Y' => self.demangle_array_type()?,
            b'$' if self.starts_with("$$A8@@") => {
                self.pos += 6;
                Type { kind: TypeKind::Function(Box::new(self.demangle_function_type(true)?)), quals: 0 }
            }
            b'$' if self.starts_with("$$A6") => {
                self.pos += 4;
                Type { kind: TypeKind::Function(Box::new(self.demangle_function_type(false)?)), quals: 0 }
            }
            b'?' => {
                self.pos += 1;
                let ident = self.demangle_unqualified_type_name(true)?;

                if !self.consume("@") {
                    return None;
                }

                Type { kind: TypeKind::Custom(ident), quals: 0 }
            }
            _ => self.demangle_primitive_type()?,
        };

        ty.quals |= quals;

        return Some(ty);
    }

    fn demangle_primitive_type(&mut self) -> DResult<Type> {
        if self.consume("$$T") {
            return Some(Type { kind: TypeKind::Primitive("std::nullptr_t"), quals: 0 });
        }

        let name = match self.pop()? {
            b'X' => "void",
            b'D' => "char",
            b'C' => "signed char",
            b'E' => "unsigned char",
            b'F' => "short",
            b'G' => "unsigned short",
            b'H' => "int",
            b'I' => "unsigned int",
            b'J' => "long",
            b'K' => "unsigned long",
            b'M' => "float",
            b'N' => "double",
            b'O' => "long double",
            b'_' => match self.pop()? {
                b'N' => "bool",
                b'J' => "__int64",
                b'K' => "unsigned __int64",
                b'W' => "wchar_t",
                b'Q' => "char8_t",
                b'S' => "char16_t",
                b'U' => "char32_t",
                _ => return None,
            },
            _ => return None,
        };

        return Some(Type { kind: TypeKind::Primitive(name), quals: 0 });
    }

    fn demangle_class_type(&mut self) -> DResult<Type> {
        let tag = match self.pop()? {
            b'T' => "union",
            b'U' => "struct",
            b'V' => "class",
            b'W' => {
                if !self.consume("4") {
                    return None;
                }

                "enum"
            }
            _ => return None,
        };

        let name = self.demangle_fully_qualified_type_name()?;

        return Some(Type { kind: TypeKind::Tag(tag, name), quals: 0 });
    }

    fn is_member_pointer(&self) -> DResult<bool> {
        let rest = self.rest();

        match rest.first()? {
            b'$' | b'A' => return Some(false),
            _ => {}
        }

        let mut i = 1;

        if rest.get(i)?.is_ascii_digit() {
            return match rest[i] {
                b'6' => Some(false),
                b'8' => Some(true),
                _ => None,
            };
        }

        for q in [b'E', b'I', b'F'] {
            if rest.get(i) == Some(&q) {
                i += 1;
            }
        }

        return match rest.get(i)? {
            b'A' | b'B' | b'C' | b'D' => Some(false),
            b'Q' | b'R' | b'S' | b'T' => Some(true),
            _ => None,
        };
    }

    fn demangle_pointer_cv_qualifiers(&mut self) -> DResult<(u8, Affinity)> {
        if self.consume("$$Q") {
            return Some((0, Affinity::RValueReference));
        }

        let result = match self.pop()? {
            b'A' => (0, Affinity::Reference),
            b'P' => (0, Affinity::Pointer),
            b'Q' => (QUAL_CONST, Affinity::Pointer),
            b'R' => (QUAL_VOLATILE, Affinity::Pointer),
            b'S' => (QUAL_CONST | QUAL_VOLATILE, Affinity::Pointer),
            _ => return None,
        };

        return Some(result);
    }

    fn demangle_pointer_type(&mut self) -> DResult<Type> {
        let (mut quals, affinity) = self.demangle_pointer_cv_qualifiers()?;

        if self.consume("6") {
            let signature = self.demangle_function_type(false)?;
            let pointee = Type { kind: TypeKind::Function(Box::new(signature)), quals: 0 };

            return Some(Type { kind: TypeKind::Pointer { affinity, class_parent: None, pointee: Box::new(pointee) }, quals });
        }

        quals |= self.demangle_pointer_ext_qualifiers();

        let pointee = self.demangle_type(QualifierMode::Mangle)?;

        return Some(Type { kind: TypeKind::Pointer { affinity, class_parent: None, pointee: Box::new(pointee) }, quals });
    }

    fn demangle_member_pointer_type(&mut self) -> DResult<Type> {
        let (mut quals, affinity) = self.demangle_pointer_cv_qualifiers()?;

        quals |= self.demangle_pointer_ext_qualifiers();

        let (class_parent, pointee) = if self.consume("8") {
            let class_parent = self.demangle_fully_qualified_type_name()?;
            let signature = self.demangle_function_type(true)?;

            (class_parent, Type { kind: TypeKind::Function(Box::new(signature)), quals: 0 })
        } else {
            let (pointee_quals, _) = self.demangle_qualifiers()?;
            let class_parent = self.demangle_fully_qualified_type_name()?;
            let mut pointee = self.demangle_type(QualifierMode::Drop)?;

            pointee.quals = pointee_quals;

            (class_parent, pointee)
        };

        return Some(Type {
            kind: TypeKind::Pointer { affinity, class_parent: Some(class_parent), pointee: Box::new(pointee) },
            quals,
        });
    }

    fn demangle_array_type(&mut self) -> DResult<Type> {
        self.pos += 1;

        let (rank, negative) = self.demangle_number()?;

        if negative || rank == 0 || rank > 64 {
            return None;
        }

        let mut dimensions = Vec::new();

        for _ in 0..rank {
            let (dimension, negative) = self.demangle_number()?;

            if negative {
                return None;
            }

            dimensions.push(dimension);
        }

        let mut quals = 0;

        if self.consume("$$C") {
            let (q, is_member) = self.demangle_qualifiers()?;

            if is_member {
                return None;
            }

            quals = q;
        }

        let element = self.demangle_type(QualifierMode::Drop)?;

        return Some(Type { kind: TypeKind::Array { dimensions, element: Box::new(element) }, quals });
    }
}

fn intrinsic_function_name(group: u8, code: u8) -> Option<&'static str> {
    let name = match (group, code) {
        (0, b'2') => "operator new",
        (0, b'3') => "operator delete",
        (0, b'4') => "operator=",
        (0, b'5') => "operator>>",
        (0, b'6') => "operator<<",
        (0, b'7') => "operator!",
        (0, b'8') => "operator==",
        (0, b'9') => "operator!=",
        (0, b'A') => "operator[]",
        (0, b'C') => "operator->",
        (0, b'D') => "operator*",
        (0, b'E') => "operator++",
        (0, b'F') => "operator--",
        (0, b'G') => "operator-",
        (0, b'H') => "operator+",
        (0, b'I') => "operator&",
        (0, b'J') => "operator->*",
        (0, b'K') => "operator/",
        (0, b'L') => "operator%",
        (0, b'M') => "operator<",
        (0, b'N') => "operator<=",
        (0, b'O') => "operator>",
        (0, b'P') => "operator>=",
        (0, b'Q') => "operator,",
        (0, b'R') => "operator()",
        (0, b'S') => "operator~",
        (0, b'T') => "operator^",
        (0, b'U') => "operator|",
        (0, b'V') => "operator&&",
        (0, b'W') => "operator||",
        (0, b'X') => "operator*=",
        (0, b'Y') => "operator+=",
        (0, b'Z') => "operator-=",
        (1, b'0') => "operator/=",
        (1, b'1') => "operator%=",
        (1, b'2') => "operator>>=",
        (1, b'3') => "operator<<=",
        (1, b'4') => "operator&=",
        (1, b'5') => "operator|=",
        (1, b'6') => "operator^=",
        (1, b'D') => "`vbase dtor'",
        (1, b'E') => "`vector deleting dtor'",
        (1, b'F') => "`default ctor closure'",
        (1, b'G') => "`scalar deleting dtor'",
        (1, b'H') => "`vector ctor iterator'",
        (1, b'I') => "`vector dtor iterator'",
        (1, b'J') => "`vector vbase ctor iterator'",
        (1, b'K') => "`virtual displacement map'",
        (1, b'L') => "`eh vector ctor iterator'",
        (1, b'M') => "`eh vector dtor iterator'",
        (1, b'N') => "`eh vector vbase ctor iterator'",
        (1, b'O') => "`copy ctor closure'",
        (1, b'T') => "`local vftable ctor closure'",
        (1, b'U') => "operator new[]",
        (1, b'V') => "operator delete[]",
        (2, b'A') => "`managed vector ctor iterator'",
        (2, b'B') => "`managed vector dtor iterator'",
        (2, b'C') => "`EH vector copy ctor iterator'",
        (2, b'D') => "`EH vector vbase copy ctor iterator'",
        (2, b'G') => "`vector copy ctor iterator'",
        (2, b'H') => "`vector vbase copy constructor iterator'",
        (2, b'I') => "`managed vector vbase copy constructor iterator'",
        (2, b'L') => "operator co_await",
        (2, b'M') => "operator<=>",
        _ => return None,
    };

    return Some(name);
}

fn guess_char_byte_size(bytes: &[u8], byte_size: u64) -> usize {
    if byte_size % 2 == 1 {
        return 1;
    }

    if byte_size < 32 {
        let trailing_nulls = bytes.iter().rev().take_while(|&&b| b == 0).count();

        if trailing_nulls >= 4 && byte_size % 4 == 0 {
            return 4;
        }

        if trailing_nulls >= 2 {
            return 2;
        }

        return 1;
    }

    let nulls = bytes.iter().filter(|&&b| b == 0).count();

    if nulls >= 2 * bytes.len() / 3 && byte_size % 4 == 0 {
        return 4;
    }

    if nulls >= bytes.len() / 3 {
        return 2;
    }

    return 1;
}

fn output_escaped_char(out: &mut String, c: u32) {
    let escaped = match c {
        0x00 => "\\0",
        0x27 => "\\'",
        0x22 => "\\\"",
        0x5c => "\\\\",
        0x07 => "\\a",
        0x08 => "\\b",
        0x0c => "\\f",
        0x0a => "\\n",
        0x0d => "\\r",
        0x09 => "\\t",
        0x0b => "\\v",
        0x20..=0x7e => {
            out.push(c as u8 as char);
            return;
        }
        _ => {
            let mut digits = format!("{:X}", c);

            if digits.len() % 2 == 1 {
                digits.insert(0, '0');
            }

            out.push_str("\\x");
            out.push_str(&digits);
            return;
        }
    };

    out.push_str(escaped);
}

fn synthesize_variable(ty: Option<Type>, name: &str) -> Symbol {
    return Symbol::Variable {
        name: QualifiedName { components: vec![IdentNode::new(Ident::Named(name.to_string()))] },
        storage: None,
        ty,
    };
}

fn symbol_name(symbol: &Symbol) -> Option<&QualifiedName> {
    match symbol {
        Symbol::Function { name, .. } | Symbol::Variable { name, .. } | Symbol::SpecialTable { name, .. } => Some(name),
        _ => None,
    }
}

/*
 * Output
 */

fn output_space_if_necessary(out: &mut String) {
    if let Some(c) = out.chars().last() {
        if c.is_ascii_alphanumeric() || c == '>' {
            out.push(' ');
        }
    }
}

fn output_qualifiers(out: &mut String, quals: u8, space_before: bool, space_after: bool) {
    let start = out.len();
    let mut need_space = space_before;

    for (mask, name) in [(QUAL_CONST, "const"), (QUAL_VOLATILE, "volatile"), (QUAL_RESTRICT, "__restrict")] {
        if quals & mask == 0 {
            continue;
        }

        if need_space {
            out.push(' ');
        }

        out.push_str(name);
        need_space = true;
    }

    if space_after && out.len() > start {
        out.push(' ');
    }
}

fn output_template_params(out: &mut String, params: &Option<Vec<TemplateParam>>) {
    let Some(params) = params else {
        return;
    };

    out.push('<');

    for (i, param) in params.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }

        match param {
            TemplateParam::Type(ty) => output_type(out, ty, false),
            TemplateParam::Integer(value, negative) => {
                if *negative {
                    out.push('-');
                }

                out.push_str(&value.to_string());
            }
            TemplateParam::Name(name) => output_qualified_name(out, name),
            TemplateParam::SymbolRef { symbol, affinity, offsets } => {
                if !offsets.is_empty() {
                    out.push('{');
                } else if *affinity == Affinity::Pointer {
                    out.push('&');
                }

                if let Some(symbol) = symbol {
                    output_symbol(out, symbol);

                    if !offsets.is_empty() {
                        out.push_str(", ");
                    }
                }

                let offsets: Vec<String> = offsets.iter().map(|o| o.to_string()).collect();
                out.push_str(&offsets.join(", "));

                if !offsets.is_empty() {
                    out.push('}');
                }
            }
        }
    }

    out.push('>');
}

fn output_ident(out: &mut String, node: &IdentNode) {
    match &node.ident {
        Ident::Named(name) => {
            out.push_str(name);
            output_template_params(out, &node.template_params);
        }
        Ident::Intrinsic(name) => {
            out.push_str(name);
            output_template_params(out, &node.template_params);
        }
        Ident::Structor { class, is_dtor } => {
            if *is_dtor {
                out.push('~');
            }

            if let Some(class) = class {
                output_ident(out, class);
            }

            output_template_params(out, &node.template_params);
        }
        Ident::Conversion(target) => {
            out.push_str("operator");
            output_template_params(out, &node.template_params);
            out.push(' ');

            if let Some(target) = target {
                output_type(out, target, false);
            }
        }
        Ident::LiteralOperator(name) => {
            out.push_str("operator \"\"");
            out.push_str(name);
            output_template_params(out, &node.template_params);
        }
        Ident::LocalStaticGuard { is_thread, scope_index } => {
            out.push_str(if *is_thread { "`local static thread guard'" } else { "`local static guard'" });

            if *scope_index > 0 {
                out.push_str(&format!("{{{}}}", scope_index));
            }
        }
        Ident::DynamicStructor { is_dtor, variable, name } => {
            out.push_str(if *is_dtor { "`dynamic atexit destructor for " } else { "`dynamic initializer for " });

            if let Some(variable) = variable {
                out.push('`');
                output_symbol(out, variable);
                out.push_str("''");
            } else if let Some(name) = name {
                out.push('\'');
                output_qualified_name(out, name);
                out.push_str("''");
            }
        }
        Ident::VcallThunk(offset) => out.push_str(&format!("`vcall'{{{}, {{flat}}}}", offset)),
        Ident::RttiBaseClassDescriptor(values) => {
            out.push_str(&format!(
                "`RTTI Base Class Descriptor at ({}, {}, {}, {})'",
                values[0], values[1], values[2], values[3]
            ));
        }
    }
}

fn output_qualified_name(out: &mut String, name: &QualifiedName) {
    for (i, component) in name.components.iter().enumerate() {
        if i > 0 {
            out.push_str("::");
        }

        output_ident(out, component);
    }
}

fn output_type(out: &mut String, ty: &Type, no_calling_convention: bool) {
    output_type_pre(out, ty, no_calling_convention);
    output_type_post(out, ty);
}

fn output_type_pre(out: &mut String, ty: &Type, no_calling_convention: bool) {
    match &ty.kind {
        TypeKind::Primitive(name) => {
            out.push_str(name);
            output_qualifiers(out, ty.quals, true, false);
        }
        TypeKind::Tag(tag, name) => {
            out.push_str(tag);
            out.push(' ');
            output_qualified_name(out, name);
            output_qualifiers(out, ty.quals, true, false);
        }
        TypeKind::Custom(ident) => output_ident(out, ident),
        TypeKind::Array { element, .. } => {
            output_type_pre(out, element, false);
            output_qualifiers(out, ty.quals, true, false);
        }
        TypeKind::Function(signature) => output_signature_pre(out, signature, no_calling_convention),
        TypeKind::Pointer { affinity, class_parent, pointee } => {
            if let TypeKind::Function(signature) = &pointee.kind {
                output_signature_pre(out, signature, true);
            } else {
                output_type_pre(out, pointee, false);
            }

            output_space_if_necessary(out);

            if ty.quals & QUAL_UNALIGNED != 0 {
                out.push_str("__unaligned ");
            }

            match &pointee.kind {
                TypeKind::Array { .. } => out.push('('),
                TypeKind::Function(signature) => {
                    out.push('(');
                    out.push_str(signature.call_conv);
                    out.push(' ');
                }
                _ => {}
            }

            if let Some(class_parent) = class_parent {
                output_qualified_name(out, class_parent);
                out.push_str("::");
            }

            out.push_str(match affinity {
                Affinity::Pointer => "*",
                Affinity::Reference => "&",
                Affinity::RValueReference => "&&",
            });

            output_qualifiers(out, ty.quals, false, false);
        }
    }
}

fn output_type_post(out: &mut String, ty: &Type) {
    match &ty.kind {
        TypeKind::Array { dimensions, element } => {
            out.push('[');

            for (i, dimension) in dimensions.iter().enumerate() {
                if i > 0 {
                    out.push_str("][");
                }

                if *dimension != 0 {
                    out.push_str(&dimension.to_string());
                }
            }

            out.push(']');
            output_type_post(out, element);
        }
        TypeKind::Function(signature) => output_signature_post(out, signature),
        TypeKind::Pointer { pointee, .. } => {
            if matches!(pointee.kind, TypeKind::Array { .. } | TypeKind::Function(_)) {
                out.push(')');
            }

            output_type_post(out, pointee);
        }
        _ => {}
    }
}

fn output_signature_pre(out: &mut String, signature: &FunctionSignature, no_calling_convention: bool) {
    let class = signature.function_class;

    if signature.thunk.is_some() {
        out.push_str("[thunk]: ");
    }

    if class & FC_PUBLIC != 0 {
        out.push_str("public: ");
    }

    if class & FC_PROTECTED != 0 {
        out.push_str("protected: ");
    }

    if class & FC_PRIVATE != 0 {
        out.push_str("private: ");
    }

    if class & FC_GLOBAL == 0 && class & FC_STATIC != 0 {
        out.push_str("static ");
    }

    if class & FC_VIRTUAL != 0 {
        out.push_str("virtual ");
    }

    if class & FC_EXTERN_C != 0 {
        out.push_str("extern \"C\" ");
    }

    if let Some(ret) = &signature.ret {
        output_type_pre(out, ret, false);
        out.push(' ');
    }

    if !no_calling_convention {
        out.push_str(signature.call_conv);
    }
}

fn output_signature_post(out: &mut String, signature: &FunctionSignature) {
    let class = signature.function_class;

    if let Some(adjust) = &signature.thunk {
        if class & FC_STATIC_THIS_ADJUST != 0 {
            out.push_str(&format!("`adjustor{{{}}}'", adjust.static_offset));
        } else if class & FC_VIRTUAL_THIS_ADJUST != 0 {
            if class & FC_VIRTUAL_THIS_ADJUST_EX != 0 {
                out.push_str(&format!(
                    "`vtordispex{{{}, {}, {}, {}}}'",
                    adjust.vbptr_offset, adjust.vboffset_offset, adjust.vtordisp_offset, adjust.static_offset
                ));
            } else {
                out.push_str(&format!("`vtordisp{{{}, {}}}'", adjust.vtordisp_offset, adjust.static_offset));
            }
        }
    }

    if class & FC_NO_PARAMETER_LIST == 0 {
        out.push('(');

        match &signature.params {
            Some(params) => {
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }

                    output_type(out, param, false);
                }
            }
            None => out.push_str("void"),
        }

        if signature.is_variadic {
            if !out.ends_with('(') {
                out.push_str(", ");
            }

            out.push_str("...");
        }

        out.push(')');
    }

    if signature.quals & QUAL_CONST != 0 {
        out.push_str(" const");
    }

    if signature.quals & QUAL_VOLATILE != 0 {
        out.push_str(" volatile");
    }

    if signature.quals & QUAL_RESTRICT != 0 {
        out.push_str(" __restrict");
    }

    if signature.quals & QUAL_UNALIGNED != 0 {
        out.push_str(" __unaligned");
    }

    if signature.is_noexcept {
        out.push_str(" noexcept");
    }

    out.push_str(signature.ref_qual);

    if let Some(ret) = &signature.ret {
        output_type_post(out, ret);
    }
}

fn output_symbol(out: &mut String, symbol: &Symbol) {
    match symbol {
        Symbol::Function { name, signature } => {
            output_signature_pre(out, signature, false);
            output_space_if_necessary(out);
            output_qualified_name(out, name);
            output_signature_post(out, signature);
        }
        Symbol::Variable { name, storage, ty } => {
            let access = match storage {
                Some(StorageClass::PrivateStatic) => Some("private"),
                Some(StorageClass::ProtectedStatic) => Some("protected"),
                Some(StorageClass::PublicStatic) => Some("public"),
                _ => None,
            };

            if let Some(access) = access {
                out.push_str(access);
                out.push_str(": static ");
            }

            if let Some(ty) = ty {
                output_type_pre(out, ty, false);
                output_space_if_necessary(out);
            }

            output_qualified_name(out, name);

            if let Some(ty) = ty {
                output_type_post(out, ty);
            }
        }
        Symbol::SpecialTable { name, quals, target } => {
            output_qualifiers(out, *quals, false, true);
            output_qualified_name(out, name);

            if let Some(target) = target {
                out.push_str("{for `");
                output_qualified_name(out, target);
                out.push_str("'}");
            }
        }
        Symbol::StringLiteral { text, prefix, truncated } => {
            out.push_str(prefix);
            out.push('"');
            out.push_str(text);
            out.push('"');

            if *truncated {
                out.push_str("...");
            }
        }
        Symbol::Raw(s) => out.push_str(s),
    }
}

pub fn demangle(symbol: &str) -> Option<String> {
    let mut demangler = Demangler::new(symbol.as_bytes());
    let parsed = demangler.parse()?;

    let mut out = String::new();
    output_symbol(&mut out, &parsed);

    return Some(out);
}
