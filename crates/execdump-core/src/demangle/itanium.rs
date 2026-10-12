use std::cell::RefCell;
use std::rc::Rc;

/*
 * Itanium C++ ABI demangler (GCC, Clang on Linux, macOS, BSDs, MinGW...)
 * https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
 * The output follows llvm-cxxfilt
 */

type N = Rc<Node>;

const QUAL_CONST: u8 = 0x1;
const QUAL_VOLATILE: u8 = 0x2;
const QUAL_RESTRICT: u8 = 0x4;

const MAX_DEPTH: usize = 256;
const MAX_OUTPUT: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Prec {
    Primary,
    Postfix,
    Unary,
    Cast,
    PtrMem,
    Multiplicative,
    Additive,
    Shift,
    Spaceship,
    Relational,
    Equality,
    And,
    Xor,
    Ior,
    AndIf,
    OrIf,
    Conditional,
    Assign,
    Comma,
    Default,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefQual {
    None,
    LValue,
    RValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StdSubst {
    Allocator,
    BasicString,
    String,
    IStream,
    OStream,
    IOStream,
}

impl StdSubst {
    fn base_name(&self, expanded: bool) -> &'static str {
        match (self, expanded) {
            (StdSubst::Allocator, _) => "allocator",
            (StdSubst::BasicString, _) => "basic_string",
            (StdSubst::String, false) => "string",
            (StdSubst::IStream, false) => "istream",
            (StdSubst::OStream, false) => "ostream",
            (StdSubst::IOStream, false) => "iostream",
            (StdSubst::String, true) => "basic_string",
            (StdSubst::IStream, true) => "basic_istream",
            (StdSubst::OStream, true) => "basic_ostream",
            (StdSubst::IOStream, true) => "basic_iostream",
        }
    }

    fn expanded_args(&self) -> &'static str {
        match self {
            StdSubst::String => "<char, std::char_traits<char>, std::allocator<char>>",
            StdSubst::IStream | StdSubst::OStream | StdSubst::IOStream => "<char, std::char_traits<char>>",
            _ => "",
        }
    }
}

#[derive(Debug)]
enum Node {
    Name(String),
    Nested(N, N),
    Template(N, N),
    TemplateArgs(Vec<N>),
    AbiTag(N, String),
    CtorDtor(N, bool),
    StdSubstitution(StdSubst, bool),
    Special(&'static str, N),
    CtorVtable(N, N),
    Qualified(N, u8),
    VendorQualified(N, String, Option<N>),
    PostfixQualified(N, &'static str),
    Pointer(N),
    Reference(N, bool),
    FunctionType { ret: N, params: Vec<N>, quals: u8, ref_qual: RefQual, exception: Option<N> },
    Encoding { ret: Option<N>, name: N, params: Vec<N>, quals: u8, ref_qual: RefQual, attrs: Option<N>, requires: Option<N> },
    Array(N, Option<N>),
    Vector(N, Option<N>),
    MemberPointer(N, N),
    ArgPack(Vec<N>),
    ParamPack(Vec<N>),
    PackExpansion(N),
    ForwardRef(Rc<RefCell<Option<N>>>),
    Local(N, N),
    DotSuffix(N, String),
    Elaborated(&'static str, N),
    ConversionOperator(N),
    LiteralOperator(N),
    Lambda { decls: Vec<N>, requires1: Option<N>, params: Vec<N>, requires2: Option<N>, count: String },
    Unnamed(String),
    StructuredBinding(Vec<N>),
    NoexceptSpec(N),
    DynamicExceptionSpec(Vec<N>),
    Binary(N, String, N, Prec),
    Prefix(String, N, Prec),
    Postfix(N, String),
    Subscript(N, N),
    Member(N, String, N, Prec),
    Call(N, Vec<N>),
    Conversion(N, Vec<N>),
    Conditional(N, N, N),
    Cast(String, N, N),
    Enclosing(String, N, Prec),
    SizeofPack(N),
    Delete(N, bool, bool),
    Throw(N),
    IntegerLiteral(&'static str, String),
    Bool(bool),
    EnumLiteral(N, String),
    StringLiteral(N),
    FunctionParam(String),
    GlobalQualified(N),
    DtorName(N),
    InitList(Option<N>, Vec<N>),
    BitInt(N, bool),
    EnableIf(Vec<N>),
    ExplicitObjectParam(N),
    MemberLikeFriend(N, N),
    ModuleName(Option<N>, N, bool),
    ModuleEntity(N, N),
    ObjCProto(N, String),
    TransformedType(String, N),
    SyntheticParam(usize, usize),
    TypeParamDecl(N),
    ConstrainedTypeParamDecl(N, N),
    NonTypeParamDecl(N, N),
    TemplateTemplateParamDecl(N, Vec<N>, Option<N>),
    ParamPackDecl(N),
    LambdaExpr(N),
    New { exprs: Vec<N>, ty: N, inits: Vec<N>, global: bool, array: bool },
    Fold { is_left: bool, op: String, pack: N, init: Option<N> },
    Braced(N, N, bool),
    BracedRange(N, N, N),
    Subobject(N, N, String),
    PtrMemConversion(N, N),
}

impl Node {
    fn prec(&self) -> Prec {
        match self {
            Node::Binary(_, _, _, p) | Node::Prefix(_, _, p) | Node::Member(_, _, _, p) | Node::Enclosing(_, _, p) => *p,
            Node::Postfix(..) | Node::Subscript(..) | Node::Call(..) | Node::Cast(..) => Prec::Postfix,
            Node::Conversion(..) | Node::PtrMemConversion(..) => Prec::Cast,
            Node::New { .. } => Prec::Unary,
            Node::Conditional(..) => Prec::Conditional,
            Node::Delete(..) => Prec::Unary,
            Node::Throw(..) => Prec::Assign,
            _ => Prec::Primary,
        }
    }
}

/*
 * Operators
 */

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpKind {
    Prefix,
    Postfix,
    Binary,
    Array,
    Member,
    New,
    Del,
    Call,
    CCast,
    Conditional,
    NameOnly,
    NamedCast,
    OfIdOp,
}

struct OperatorInfo {
    enc: &'static str,
    kind: OpKind,
    flag: bool,
    prec: Prec,
    name: &'static str,
}

impl OperatorInfo {
    fn symbol(&self) -> &'static str {
        return self.name.strip_prefix("operator").unwrap_or(self.name);
    }

    fn is_nameable(&self) -> bool {
        return !matches!(self.kind, OpKind::NamedCast | OpKind::OfIdOp) && !(self.kind == OpKind::Member && !self.flag);
    }
}

macro_rules! op {
    ($enc:expr, $kind:ident, $flag:expr, $prec:ident, $name:expr) => {
        OperatorInfo { enc: $enc, kind: OpKind::$kind, flag: $flag, prec: Prec::$prec, name: $name }
    };
}

const OPERATORS: &[OperatorInfo] = &[
    op!("aN", Binary, false, Assign, "operator&="),
    op!("aS", Binary, false, Assign, "operator="),
    op!("aa", Binary, false, AndIf, "operator&&"),
    op!("ad", Prefix, false, Unary, "operator&"),
    op!("an", Binary, false, And, "operator&"),
    op!("at", OfIdOp, true, Unary, "alignof "),
    op!("aw", NameOnly, false, Primary, "operator co_await"),
    op!("az", OfIdOp, false, Unary, "alignof "),
    op!("cc", NamedCast, false, Postfix, "const_cast"),
    op!("cl", Call, false, Postfix, "operator()"),
    op!("cm", Binary, false, Comma, "operator,"),
    op!("co", Prefix, false, Unary, "operator~"),
    op!("cp", Call, true, Postfix, "operator()"),
    op!("cv", CCast, false, Cast, "operator"),
    op!("dV", Binary, false, Assign, "operator/="),
    op!("da", Del, true, Unary, "operator delete[]"),
    op!("dc", NamedCast, false, Postfix, "dynamic_cast"),
    op!("de", Prefix, false, Unary, "operator*"),
    op!("dl", Del, false, Unary, "operator delete"),
    op!("ds", Member, false, PtrMem, "operator.*"),
    op!("dt", Member, false, Postfix, "operator."),
    op!("dv", Binary, false, Multiplicative, "operator/"),
    op!("eO", Binary, false, Assign, "operator^="),
    op!("eo", Binary, false, Xor, "operator^"),
    op!("eq", Binary, false, Equality, "operator=="),
    op!("ge", Binary, false, Relational, "operator>="),
    op!("gt", Binary, false, Relational, "operator>"),
    op!("ix", Array, false, Postfix, "operator[]"),
    op!("lS", Binary, false, Assign, "operator<<="),
    op!("le", Binary, false, Relational, "operator<="),
    op!("ls", Binary, false, Shift, "operator<<"),
    op!("lt", Binary, false, Relational, "operator<"),
    op!("mI", Binary, false, Assign, "operator-="),
    op!("mL", Binary, false, Assign, "operator*="),
    op!("mi", Binary, false, Additive, "operator-"),
    op!("ml", Binary, false, Multiplicative, "operator*"),
    op!("mm", Postfix, false, Postfix, "operator--"),
    op!("na", New, true, Unary, "operator new[]"),
    op!("ne", Binary, false, Equality, "operator!="),
    op!("ng", Prefix, false, Unary, "operator-"),
    op!("nt", Prefix, false, Unary, "operator!"),
    op!("nw", New, false, Unary, "operator new"),
    op!("oR", Binary, false, Assign, "operator|="),
    op!("oo", Binary, false, OrIf, "operator||"),
    op!("or", Binary, false, Ior, "operator|"),
    op!("pL", Binary, false, Assign, "operator+="),
    op!("pl", Binary, false, Additive, "operator+"),
    op!("pm", Member, true, PtrMem, "operator->*"),
    op!("pp", Postfix, false, Postfix, "operator++"),
    op!("ps", Prefix, false, Unary, "operator+"),
    op!("pt", Member, true, Postfix, "operator->"),
    op!("qu", Conditional, false, Conditional, "operator?"),
    op!("rM", Binary, false, Assign, "operator%="),
    op!("rS", Binary, false, Assign, "operator>>="),
    op!("rc", NamedCast, false, Postfix, "reinterpret_cast"),
    op!("rm", Binary, false, Multiplicative, "operator%"),
    op!("rs", Binary, false, Shift, "operator>>"),
    op!("sc", NamedCast, false, Postfix, "static_cast"),
    op!("ss", Binary, false, Spaceship, "operator<=>"),
    op!("st", OfIdOp, true, Unary, "sizeof "),
    op!("sz", OfIdOp, false, Unary, "sizeof "),
    op!("te", OfIdOp, false, Postfix, "typeid "),
    op!("ti", OfIdOp, true, Postfix, "typeid "),
];

/*
 * Parser
 */

#[derive(Default)]
struct NameState {
    quals: u8,
    ref_qual: Option<RefQual>,
    ctor_dtor_conversion: bool,
    ends_with_template_args: bool,
    has_explicit_object_param: bool,
    forward_refs_begin: usize,
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    subs: Vec<N>,
    template_params: Vec<Option<Vec<N>>>,
    forward_refs: Vec<(usize, Rc<RefCell<Option<N>>>)>,
    try_parse_template_args: bool,
    permit_forward_refs: bool,
    parsing_lambda_params_at: Option<usize>,
    in_constraint_expr: bool,
    synthetic_params: [usize; 3],
    depth: usize,
}

type PResult = Option<N>;

fn node(n: Node) -> N {
    return Rc::new(n);
}

fn name(s: &str) -> N {
    return node(Node::Name(s.to_string()));
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        return Self {
            input,
            pos: 0,
            subs: Vec::new(),
            template_params: Vec::new(),
            forward_refs: Vec::new(),
            try_parse_template_args: true,
            permit_forward_refs: false,
            parsing_lambda_params_at: None,
            in_constraint_expr: false,
            synthetic_params: [0; 3],
            depth: 0,
        };
    }

    fn look(&self) -> u8 {
        return self.look_at(0);
    }

    fn look_at(&self, offset: usize) -> u8 {
        return self.input.get(self.pos + offset).copied().unwrap_or(0);
    }

    fn remaining(&self) -> usize {
        return self.input.len() - self.pos;
    }

    fn consume_if(&mut self, s: &str) -> bool {
        if self.input[self.pos..].starts_with(s.as_bytes()) {
            self.pos += s.len();
            return true;
        }

        return false;
    }

    fn consume_char(&mut self, c: u8) -> bool {
        if self.look() == c && self.remaining() > 0 {
            self.pos += 1;
            return true;
        }

        return false;
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        return if self.depth > MAX_DEPTH { None } else { Some(()) };
    }

    fn leave<T>(&mut self, result: Option<T>) -> Option<T> {
        self.depth -= 1;
        return result;
    }

    fn slice(&self, start: usize, end: usize) -> String {
        return String::from_utf8_lossy(&self.input[start..end]).to_string();
    }

    fn parse_number(&mut self, allow_negative: bool) -> Option<String> {
        let start = self.pos;

        if allow_negative {
            self.consume_char(b'n');
        }

        if !self.look().is_ascii_digit() {
            self.pos = start;
            return None;
        }

        while self.look().is_ascii_digit() {
            self.pos += 1;
        }

        return Some(self.slice(start, self.pos));
    }

    fn parse_positive_integer(&mut self) -> Option<usize> {
        if !self.look().is_ascii_digit() {
            return None;
        }

        let mut value: usize = 0;

        while self.look().is_ascii_digit() {
            value = value.checked_mul(10)?.checked_add((self.look() - b'0') as usize)?;
            self.pos += 1;
        }

        return Some(value);
    }

    fn parse_seq_id(&mut self) -> Option<usize> {
        if !self.look().is_ascii_digit() && !self.look().is_ascii_uppercase() {
            return None;
        }

        let mut id: usize = 0;

        while self.look().is_ascii_digit() || self.look().is_ascii_uppercase() {
            let digit = if self.look().is_ascii_digit() { self.look() - b'0' } else { self.look() - b'A' + 10 };
            id = id.checked_mul(36)?.checked_add(digit as usize)?;
            self.pos += 1;
        }

        return Some(id);
    }

    fn parse_discriminator(&mut self) {
        if self.look() == b'_' {
            if self.look_at(1).is_ascii_digit() {
                self.pos += 2;
            } else if self.look_at(1) == b'_' {
                let mut end = self.pos + 2;

                while self.input.get(end).is_some_and(|c| c.is_ascii_digit()) {
                    end += 1;
                }

                if self.input.get(end) == Some(&b'_') {
                    self.pos = end + 1;
                }
            }
        } else if self.look().is_ascii_digit() && self.input[self.pos..].iter().all(|c| c.is_ascii_digit()) {
            self.pos = self.input.len();
        }
    }

    fn parse_cv_qualifiers(&mut self) -> u8 {
        let mut quals = 0;

        if self.consume_char(b'r') {
            quals |= QUAL_RESTRICT;
        }

        if self.consume_char(b'V') {
            quals |= QUAL_VOLATILE;
        }

        if self.consume_char(b'K') {
            quals |= QUAL_CONST;
        }

        return quals;
    }

    /*
     * <mangled-name> ::= _Z <encoding> [. <vendor-specific suffix>]
     */

    fn parse(&mut self) -> PResult {
        if self.consume_if("_Z") || self.consume_if("__Z") {
            let mut encoding = self.parse_encoding()?;

            if self.look() == b'.' {
                encoding = node(Node::DotSuffix(encoding, self.slice(self.pos, self.input.len())));
                self.pos = self.input.len();
            }

            return if self.remaining() == 0 { Some(encoding) } else { None };
        }

        if self.consume_if("___Z") || self.consume_if("____Z") {
            let encoding = self.parse_encoding()?;

            if !self.consume_if("_block_invoke") {
                return None;
            }

            let require_number = self.consume_char(b'_');

            if self.parse_number(false).is_none() && require_number {
                return None;
            }

            if self.look() == b'.' {
                self.pos = self.input.len();
            }

            return if self.remaining() == 0 { Some(node(Node::Special("invocation function for block in ", encoding))) } else { None };
        }

        return None;
    }

    fn is_end_of_encoding(&self) -> bool {
        return self.remaining() == 0 || matches!(self.look(), b'E' | b'.' | b'_');
    }

    fn parse_encoding(&mut self) -> PResult {
        self.enter()?;

        let saved_params = std::mem::take(&mut self.template_params);
        let result = self.parse_encoding_impl();
        self.template_params = saved_params;

        return self.leave(result);
    }

    fn parse_encoding_impl(&mut self) -> PResult {
        if self.look() == b'G' || self.look() == b'T' {
            return self.parse_special_name();
        }

        let mut state = NameState { forward_refs_begin: self.forward_refs.len(), ..Default::default() };

        let name = self.parse_name(Some(&mut state))?;

        self.resolve_forward_refs(&state)?;

        if self.is_end_of_encoding() {
            return Some(name);
        }

        let mut attrs = None;

        if self.consume_if("Ua9enable_ifI") {
            let mut conditions = Vec::new();

            while !self.consume_char(b'E') {
                conditions.push(self.parse_template_arg()?);
            }

            attrs = Some(node(Node::EnableIf(conditions)));
        }

        let ret = if !state.ctor_dtor_conversion && state.ends_with_template_args { Some(self.parse_type()?) } else { None };

        let mut params = Vec::new();

        if !self.consume_char(b'v') {
            loop {
                let mut param = self.parse_type()?;

                if state.has_explicit_object_param && params.is_empty() {
                    param = node(Node::ExplicitObjectParam(param));
                }

                params.push(param);

                if self.is_end_of_encoding() || self.look() == b'Q' {
                    break;
                }
            }
        }

        let requires = if self.consume_char(b'Q') { Some(self.parse_constraint_expr()?) } else { None };

        return Some(node(Node::Encoding {
            ret,
            name,
            params,
            quals: state.quals,
            ref_qual: state.ref_qual.unwrap_or(RefQual::None),
            attrs,
            requires,
        }));
    }

    fn resolve_forward_refs(&mut self, state: &NameState) -> Option<()> {
        for (index, target) in self.forward_refs[state.forward_refs_begin..].iter() {
            let param = self.template_params.first()?.as_ref()?.get(*index)?;
            *target.borrow_mut() = Some(param.clone());
        }

        self.forward_refs.truncate(state.forward_refs_begin);

        return Some(());
    }

    fn parse_call_offset(&mut self) -> Option<()> {
        if self.consume_char(b'h') {
            self.parse_number(true)?;
            return if self.consume_char(b'_') { Some(()) } else { None };
        }

        if self.consume_char(b'v') {
            self.parse_number(true)?;

            if !self.consume_char(b'_') {
                return None;
            }

            self.parse_number(true)?;

            return if self.consume_char(b'_') { Some(()) } else { None };
        }

        return None;
    }

    fn parse_special_name(&mut self) -> PResult {
        match (self.look(), self.look_at(1)) {
            (b'T', b'A') => {
                self.pos += 2;
                let arg = self.parse_template_arg()?;
                return Some(node(Node::Special("template parameter object for ", arg)));
            }
            (b'T', b'V') => {
                self.pos += 2;
                return Some(node(Node::Special("vtable for ", self.parse_type()?)));
            }
            (b'T', b'T') => {
                self.pos += 2;
                return Some(node(Node::Special("VTT for ", self.parse_type()?)));
            }
            (b'T', b'I') => {
                self.pos += 2;
                return Some(node(Node::Special("typeinfo for ", self.parse_type()?)));
            }
            (b'T', b'S') => {
                self.pos += 2;
                return Some(node(Node::Special("typeinfo name for ", self.parse_type()?)));
            }
            (b'T', b'c') => {
                self.pos += 2;
                self.parse_call_offset()?;
                self.parse_call_offset()?;
                return Some(node(Node::Special("covariant return thunk to ", self.parse_encoding()?)));
            }
            (b'T', b'C') => {
                self.pos += 2;
                let first = self.parse_type()?;

                self.parse_number(true)?;

                if !self.consume_char(b'_') {
                    return None;
                }

                let second = self.parse_type()?;

                return Some(node(Node::CtorVtable(second, first)));
            }
            (b'T', b'W') => {
                self.pos += 2;
                return Some(node(Node::Special("thread-local wrapper routine for ", self.parse_name(None)?)));
            }
            (b'T', b'H') => {
                self.pos += 2;
                return Some(node(Node::Special("thread-local initialization routine for ", self.parse_name(None)?)));
            }
            (b'T', _) => {
                self.pos += 1;

                let is_virtual = self.look() == b'v';

                self.parse_call_offset()?;

                let encoding = self.parse_encoding()?;

                return Some(node(Node::Special(if is_virtual { "virtual thunk to " } else { "non-virtual thunk to " }, encoding)));
            }
            (b'G', b'V') => {
                self.pos += 2;
                return Some(node(Node::Special("guard variable for ", self.parse_name(None)?)));
            }
            (b'G', b'R') => {
                self.pos += 2;

                let name = self.parse_name(None)?;
                let parsed_seq_id = self.parse_seq_id().is_some();

                if !self.consume_char(b'_') && parsed_seq_id {
                    return None;
                }

                return Some(node(Node::Special("reference temporary for ", name)));
            }
            (b'G', b'I') => {
                self.pos += 2;
                let module = self.parse_module_name_opt(None)?;
                return Some(node(Node::Special("initializer for module ", module?)));
            }
            (b'G', b'T') if self.look_at(2) == b't' || self.look_at(2) == b'n' => {
                self.pos += 3;
                return Some(node(Node::Special("transaction clone for ", self.parse_encoding()?)));
            }
            _ => return None,
        }
    }

    /*
     * Names
     */

    fn parse_name(&mut self, state: Option<&mut NameState>) -> PResult {
        self.enter()?;
        let result = self.parse_name_impl(state);
        return self.leave(result);
    }

    fn parse_name_impl(&mut self, mut state: Option<&mut NameState>) -> PResult {
        if self.look() == b'N' {
            return self.parse_nested_name(state);
        }

        if self.look() == b'Z' {
            return self.parse_local_name(state);
        }

        let (mut result, is_subst) = self.parse_unscoped_name(state.as_deref_mut())?;

        if self.look() == b'I' {
            if !is_subst {
                self.subs.push(result.clone());
            }

            let args = self.parse_template_args(state.is_some())?;

            if let Some(state) = state {
                state.ends_with_template_args = true;
            }

            result = node(Node::Template(result, args));
        } else if is_subst {
            return None;
        }

        return Some(result);
    }

    fn parse_unscoped_name(&mut self, state: Option<&mut NameState>) -> Option<(N, bool)> {
        let is_std = self.consume_if("St");
        let mut module = None;

        if self.look() == b'S' {
            let subst = self.parse_substitution()?;

            if matches!(*subst, Node::ModuleName(..)) {
                module = Some(subst);
            } else if !is_std {
                return Some((subst, true));
            } else {
                return None;
            }
        }

        let scope = if is_std { Some(name("std")) } else { None };

        return Some((self.parse_unqualified_name(state, scope, module)?, false));
    }

    fn parse_module_name_opt(&mut self, mut module: Option<N>) -> Option<Option<N>> {
        while self.consume_char(b'W') {
            let is_partition = self.consume_char(b'P');
            let sub = self.parse_source_name()?;

            let module_name = node(Node::ModuleName(module.take(), sub, is_partition));
            self.subs.push(module_name.clone());

            module = Some(module_name);
        }

        return Some(module);
    }

    fn parse_unqualified_name(&mut self, state: Option<&mut NameState>, scope: Option<N>, module: Option<N>) -> PResult {
        let mut scope = scope;
        let module = self.parse_module_name_opt(module)?;
        let is_member_like_friend = scope.is_some() && self.consume_char(b'F');

        self.consume_char(b'L');

        let result = if self.look().is_ascii_digit() {
            self.parse_source_name()?
        } else if self.look() == b'U' {
            self.parse_unnamed_type_name(state.is_some())?
        } else if self.consume_if("DC") {
            let mut names = Vec::new();

            while !self.consume_char(b'E') {
                names.push(self.parse_source_name()?);
            }

            node(Node::StructuredBinding(names))
        } else if self.look() == b'C' || (self.look() == b'D' && matches!(self.look_at(1), b'0' | b'1' | b'2' | b'4' | b'5')) {
            if module.is_some() {
                return None;
            }

            let s = scope.take()?;
            let (expanded_scope, ctor) = self.parse_ctor_dtor_name(s, state)?;
            scope = Some(expanded_scope);
            ctor
        } else {
            self.parse_operator_name(state)?
        };

        let result = match module {
            Some(module) => node(Node::ModuleEntity(module, result)),
            None => result,
        };

        let result = self.parse_abi_tags(result)?;

        return match scope {
            Some(scope) if is_member_like_friend => Some(node(Node::MemberLikeFriend(scope, result))),
            Some(scope) => Some(node(Node::Nested(scope, result))),
            None => Some(result),
        };
    }

    fn parse_source_name(&mut self) -> PResult {
        let length = self.parse_positive_integer()?;

        if length == 0 || self.remaining() < length {
            return None;
        }

        let source = self.slice(self.pos, self.pos + length);
        self.pos += length;

        if source.starts_with("_GLOBAL__N") {
            return Some(name("(anonymous namespace)"));
        }

        return Some(node(Node::Name(source)));
    }

    fn parse_bare_source_name(&mut self) -> Option<String> {
        let length = self.parse_positive_integer()?;

        if length == 0 || self.remaining() < length {
            return None;
        }

        let source = self.slice(self.pos, self.pos + length);
        self.pos += length;

        return Some(source);
    }

    fn parse_abi_tags(&mut self, mut n: N) -> PResult {
        while self.consume_char(b'B') {
            let tag = self.parse_bare_source_name()?;
            n = node(Node::AbiTag(n, tag));
        }

        return Some(n);
    }

    fn parse_unnamed_type_name(&mut self, has_state: bool) -> PResult {
        if has_state {
            self.template_params.clear();
        }

        if self.consume_if("Ut") {
            let count = self.parse_number(false).unwrap_or_default();

            if !self.consume_char(b'_') {
                return None;
            }

            return Some(node(Node::Unnamed(count)));
        }

        if self.consume_if("Ul") {
            let saved_lambda_level = self.parsing_lambda_params_at;
            let old_levels = self.template_params.len();

            self.parsing_lambda_params_at = Some(old_levels);
            self.template_params.push(Some(Vec::new()));

            let mut decls = Vec::new();

            while self.is_template_param_decl() {
                decls.push(self.parse_template_param_decl(Some(old_levels))?);
            }

            if decls.is_empty() {
                self.template_params.pop();
            }

            let requires1 = if self.consume_char(b'Q') { Some(self.parse_constraint_expr()?) } else { None };

            let mut params = Vec::new();

            if !self.consume_char(b'v') {
                loop {
                    params.push(self.parse_type()?);

                    if matches!(self.look(), b'E' | b'Q') {
                        break;
                    }
                }
            }

            let requires2 = if self.consume_char(b'Q') { Some(self.parse_constraint_expr()?) } else { None };

            if !self.consume_char(b'E') {
                return None;
            }

            let count = self.parse_number(false).unwrap_or_default();

            if !self.consume_char(b'_') {
                return None;
            }

            self.template_params.truncate(old_levels);
            self.parsing_lambda_params_at = saved_lambda_level;

            return Some(node(Node::Lambda { decls, requires1, params, requires2, count }));
        }

        if self.consume_if("Ub") {
            self.parse_number(false);

            if !self.consume_char(b'_') {
                return None;
            }

            return Some(name("'block-literal'"));
        }

        return None;
    }

    fn parse_ctor_dtor_name(&mut self, scope: N, state: Option<&mut NameState>) -> Option<(N, N)> {
        let scope = match &*scope {
            Node::StdSubstitution(kind, false) => node(Node::StdSubstitution(*kind, true)),
            _ => scope,
        };

        if self.consume_char(b'C') {
            let inherited = self.consume_char(b'I');

            if !matches!(self.look(), b'1'..=b'5') {
                return None;
            }

            self.pos += 1;

            let mut state = state;

            if let Some(s) = state.as_deref_mut() {
                s.ctor_dtor_conversion = true;
            }

            if inherited {
                self.parse_name(state)?;
            }

            return Some((scope.clone(), node(Node::CtorDtor(scope, false))));
        }

        if self.look() == b'D' && matches!(self.look_at(1), b'0' | b'1' | b'2' | b'4' | b'5') {
            self.pos += 2;

            if let Some(s) = state {
                s.ctor_dtor_conversion = true;
            }

            return Some((scope.clone(), node(Node::CtorDtor(scope, true))));
        }

        return None;
    }

    fn parse_operator_encoding(&mut self) -> Option<&'static OperatorInfo> {
        if self.remaining() < 2 {
            return None;
        }

        let enc = &self.input[self.pos..self.pos + 2];
        let op = OPERATORS.iter().find(|op| op.enc.as_bytes() == enc)?;

        self.pos += 2;

        return Some(op);
    }

    fn parse_operator_name(&mut self, state: Option<&mut NameState>) -> PResult {
        let start = self.pos;

        if let Some(op) = self.parse_operator_encoding() {
            if op.kind == OpKind::CCast {
                let saved_try = self.try_parse_template_args;
                let saved_permit = self.permit_forward_refs;

                self.try_parse_template_args = false;
                self.permit_forward_refs = self.permit_forward_refs || state.is_some();

                let ty = self.parse_type();

                self.try_parse_template_args = saved_try;
                self.permit_forward_refs = saved_permit;

                if let Some(s) = state {
                    s.ctor_dtor_conversion = true;
                }

                return Some(node(Node::ConversionOperator(ty?)));
            }

            if !op.is_nameable() {
                self.pos = start;
                return None;
            }

            return Some(name(op.name));
        }

        if self.consume_if("li") {
            return Some(node(Node::LiteralOperator(self.parse_source_name()?)));
        }

        if self.consume_char(b'v') && self.look().is_ascii_digit() {
            self.pos += 1;
            return Some(node(Node::ConversionOperator(self.parse_source_name()?)));
        }

        return None;
    }

    fn parse_nested_name(&mut self, mut state: Option<&mut NameState>) -> PResult {
        if !self.consume_char(b'N') {
            return None;
        }

        if self.consume_char(b'H') {
            if let Some(s) = state.as_deref_mut() {
                s.has_explicit_object_param = true;
            }
        } else {
            let quals = self.parse_cv_qualifiers();

            let ref_qual = if self.consume_char(b'O') {
                RefQual::RValue
            } else if self.consume_char(b'R') {
                RefQual::LValue
            } else {
                RefQual::None
            };

            if let Some(s) = state.as_deref_mut() {
                s.quals = quals;
                s.ref_qual = Some(ref_qual);
            }
        }

        let mut so_far: Option<N> = None;

        while !self.consume_char(b'E') {
            if self.remaining() == 0 {
                return None;
            }

            if let Some(s) = state.as_deref_mut() {
                s.ends_with_template_args = false;
            }

            if self.look() == b'T' {
                if so_far.is_some() {
                    return None;
                }

                so_far = Some(self.parse_template_param()?);
            } else if self.look() == b'I' {
                let prefix = so_far.take()?;

                if matches!(*prefix, Node::Template(..)) {
                    return None;
                }

                let args = self.parse_template_args(state.is_some())?;

                if let Some(s) = state.as_deref_mut() {
                    s.ends_with_template_args = true;
                }

                so_far = Some(node(Node::Template(prefix, args)));
            } else if self.look() == b'D' && matches!(self.look_at(1), b't' | b'T') {
                if so_far.is_some() {
                    return None;
                }

                so_far = Some(self.parse_decltype()?);
            } else {
                let mut module = None;

                if self.look() == b'S' {
                    let subst = if self.look_at(1) == b't' {
                        self.pos += 2;
                        name("std")
                    } else {
                        self.parse_substitution()?
                    };

                    if matches!(*subst, Node::ModuleName(..)) {
                        module = Some(subst);
                    } else if so_far.is_some() {
                        return None;
                    } else {
                        so_far = Some(subst);
                        continue;
                    }
                }

                so_far = Some(self.parse_unqualified_name(state.as_deref_mut(), so_far.take(), module)?);
            }

            self.subs.push(so_far.clone()?);

            self.consume_char(b'M');
        }

        let so_far = so_far?;

        if self.subs.pop().is_none() {
            return None;
        }

        return Some(so_far);
    }

    fn parse_local_name(&mut self, state: Option<&mut NameState>) -> PResult {
        let saved_params = std::mem::take(&mut self.template_params);
        let result = self.parse_local_name_impl(state);
        self.template_params = saved_params;
        return result;
    }

    fn parse_local_name_impl(&mut self, state: Option<&mut NameState>) -> PResult {
        if !self.consume_char(b'Z') {
            return None;
        }

        let encoding = self.parse_encoding()?;

        if !self.consume_char(b'E') {
            return None;
        }

        if self.consume_char(b's') {
            self.parse_discriminator();
            return Some(node(Node::Local(encoding, name("string literal"))));
        }

        if self.consume_char(b'd') {
            self.parse_number(true);

            if !self.consume_char(b'_') {
                return None;
            }

            let entity = self.parse_name(state)?;

            return Some(node(Node::Local(encoding, entity)));
        }

        let entity = self.parse_name(state)?;

        self.parse_discriminator();

        return Some(node(Node::Local(encoding, entity)));
    }

    fn parse_substitution(&mut self) -> PResult {
        if !self.consume_char(b'S') {
            return None;
        }

        if self.look().is_ascii_lowercase() {
            let kind = match self.look() {
                b'a' => StdSubst::Allocator,
                b'b' => StdSubst::BasicString,
                b's' => StdSubst::String,
                b'i' => StdSubst::IStream,
                b'o' => StdSubst::OStream,
                b'd' => StdSubst::IOStream,
                _ => return None,
            };

            self.pos += 1;

            let subst = node(Node::StdSubstitution(kind, false));
            let with_tags = self.parse_abi_tags(subst.clone())?;

            if !Rc::ptr_eq(&subst, &with_tags) {
                self.subs.push(with_tags.clone());
            }

            return Some(with_tags);
        }

        if self.consume_char(b'_') {
            return self.subs.first().cloned();
        }

        let index = self.parse_seq_id()? + 1;

        if !self.consume_char(b'_') {
            return None;
        }

        return self.subs.get(index).cloned();
    }

    /*
     * Templates
     */

    fn parse_template_param(&mut self) -> PResult {
        let begin = self.pos;

        if !self.consume_char(b'T') {
            return None;
        }

        let mut level = 0;

        if self.consume_char(b'L') {
            level = self.parse_positive_integer()? + 1;

            if !self.consume_char(b'_') {
                return None;
            }
        }

        let mut index = 0;

        if !self.consume_char(b'_') {
            index = self.parse_positive_integer()? + 1;

            if !self.consume_char(b'_') {
                return None;
            }
        }

        if self.in_constraint_expr {
            return Some(node(Node::Name(self.slice(begin, self.pos - 1))));
        }

        if self.permit_forward_refs && level == 0 {
            let target = Rc::new(RefCell::new(None));
            self.forward_refs.push((index, target.clone()));
            return Some(node(Node::ForwardRef(target)));
        }

        if let Some(param) = self.template_params.get(level).and_then(|l| l.as_ref()).and_then(|l| l.get(index)) {
            return Some(param.clone());
        }

        if self.parsing_lambda_params_at == Some(level) && level <= self.template_params.len() {
            if level == self.template_params.len() {
                self.template_params.push(None);
            }

            return Some(name("auto"));
        }

        return None;
    }

    fn parse_template_args(&mut self, tag_templates: bool) -> PResult {
        if !self.consume_char(b'I') {
            return None;
        }

        if tag_templates {
            self.template_params.clear();
            self.template_params.push(Some(Vec::new()));
        }

        let mut args = Vec::new();

        while !self.consume_char(b'E') {
            if self.remaining() == 0 {
                return None;
            }

            if self.consume_char(b'Q') {
                self.parse_constraint_expr()?;

                if !self.consume_char(b'E') {
                    return None;
                }

                break;
            }

            if tag_templates {
                let arg = self.parse_template_arg()?;

                let entry = match &*arg {
                    Node::ArgPack(elements) => node(Node::ParamPack(elements.clone())),
                    _ => arg.clone(),
                };

                if let Some(Some(level)) = self.template_params.first_mut() {
                    level.push(entry);
                }

                args.push(arg);
            } else {
                args.push(self.parse_template_arg()?);
            }
        }

        return Some(node(Node::TemplateArgs(args)));
    }

    fn parse_template_arg(&mut self) -> PResult {
        self.enter()?;

        let result = match self.look() {
            b'X' => {
                self.pos += 1;
                let expr = self.parse_expr();
                if self.consume_char(b'E') { expr } else { None }
            }
            b'J' => {
                self.pos += 1;
                let mut args = Vec::new();

                loop {
                    if self.consume_char(b'E') {
                        break Some(node(Node::ArgPack(args)));
                    }

                    match self.parse_template_arg() {
                        Some(arg) => args.push(arg),
                        None => break None,
                    }
                }
            }
            b'L' if self.look_at(1) == b'Z' => {
                self.pos += 2;
                let encoding = self.parse_encoding();
                if self.consume_char(b'E') { encoding } else { None }
            }
            b'L' => self.parse_expr_primary(),
            b'T' if self.is_template_param_decl() => match self.parse_template_param_decl(None) {
                Some(_) => self.parse_template_arg(),
                None => None,
            },
            _ => self.parse_type(),
        };

        return self.leave(result);
    }

    fn is_template_param_decl(&self) -> bool {
        return self.look() == b'T' && matches!(self.look_at(1), b'y' | b'p' | b't' | b'n' | b'k');
    }

    fn invent_template_param_name(&mut self, kind: usize, level: Option<usize>) -> N {
        let index = self.synthetic_params[kind];
        self.synthetic_params[kind] += 1;

        let synthetic = node(Node::SyntheticParam(kind, index));

        if let Some(Some(params)) = level.and_then(|l| self.template_params.get_mut(l)) {
            params.push(synthetic.clone());
        }

        return synthetic;
    }

    fn parse_template_param_decl(&mut self, level: Option<usize>) -> PResult {
        self.enter()?;

        let result = if self.consume_if("Ty") {
            Some(node(Node::TypeParamDecl(self.invent_template_param_name(0, level))))
        } else if self.consume_if("Tk") {
            (|| {
                let constraint = self.parse_name(None)?;
                let name = self.invent_template_param_name(0, level);
                return Some(node(Node::ConstrainedTypeParamDecl(constraint, name)));
            })()
        } else if self.consume_if("Tn") {
            let name = self.invent_template_param_name(1, level);
            self.parse_type().map(|ty| node(Node::NonTypeParamDecl(name, ty)))
        } else if self.consume_if("Tt") {
            let name = self.invent_template_param_name(2, level);
            let old_levels = self.template_params.len();

            self.template_params.push(Some(Vec::new()));

            let result = (|| {
                let mut params = Vec::new();
                let mut requires = None;

                while !self.consume_char(b'E') {
                    params.push(self.parse_template_param_decl(Some(old_levels))?);

                    if self.consume_char(b'Q') {
                        requires = Some(self.parse_constraint_expr()?);

                        if !self.consume_char(b'E') {
                            return None;
                        }

                        break;
                    }
                }

                return Some(node(Node::TemplateTemplateParamDecl(name, params, requires)));
            })();

            self.template_params.truncate(old_levels);

            result
        } else if self.consume_if("Tp") {
            self.parse_template_param_decl(level).map(|p| node(Node::ParamPackDecl(p)))
        } else {
            None
        };

        return self.leave(result);
    }

    fn parse_constraint_expr(&mut self) -> PResult {
        let saved = self.in_constraint_expr;
        self.in_constraint_expr = true;
        let result = self.parse_expr();
        self.in_constraint_expr = saved;
        return result;
    }

    /*
     * Types
     */

    fn parse_type(&mut self) -> PResult {
        self.enter()?;
        let result = self.parse_type_impl();
        return self.leave(result);
    }

    fn builtin_type(&mut self) -> Option<&'static str> {
        let builtin = match self.look() {
            b'v' => "void",
            b'w' => "wchar_t",
            b'b' => "bool",
            b'c' => "char",
            b'a' => "signed char",
            b'h' => "unsigned char",
            b's' => "short",
            b't' => "unsigned short",
            b'i' => "int",
            b'j' => "unsigned int",
            b'l' => "long",
            b'm' => "unsigned long",
            b'x' => "long long",
            b'y' => "unsigned long long",
            b'n' => "__int128",
            b'o' => "unsigned __int128",
            b'f' => "float",
            b'd' => "double",
            b'e' => "long double",
            b'g' => "__float128",
            b'z' => "...",
            _ => return None,
        };

        self.pos += 1;

        return Some(builtin);
    }

    fn parse_type_impl(&mut self) -> PResult {
        if let Some(builtin) = self.builtin_type() {
            return Some(name(builtin));
        }

        let result = match self.look() {
            b'r' | b'V' | b'K' => {
                let mut after = 0;

                for q in [b'r', b'V', b'K'] {
                    if self.look_at(after) == q {
                        after += 1;
                    }
                }

                let is_function = self.look_at(after) == b'F'
                    || (self.look_at(after) == b'D' && matches!(self.look_at(after + 1), b'o' | b'O' | b'w' | b'x'));

                if is_function { self.parse_function_type()? } else { self.parse_qualified_type()? }
            }
            b'U' => self.parse_qualified_type()?,
            b'u' => {
                self.pos += 1;
                let vendor = self.parse_bare_source_name()?;

                if self.consume_char(b'I') {
                    let base = self.parse_type()?;

                    if !self.consume_char(b'E') {
                        return None;
                    }

                    node(Node::TransformedType(vendor, base))
                } else {
                    node(Node::Name(vendor))
                }
            }
            b'D' => match self.look_at(1) {
                b'd' | b'e' | b'f' | b'h' | b'i' | b's' | b'u' | b'a' | b'c' | b'n' => {
                    let builtin = match self.look_at(1) {
                        b'd' => "decimal64",
                        b'e' => "decimal128",
                        b'f' => "decimal32",
                        b'h' => "half",
                        b'i' => "char32_t",
                        b's' => "char16_t",
                        b'u' => "char8_t",
                        b'a' => "auto",
                        b'c' => "decltype(auto)",
                        _ => "std::nullptr_t",
                    };

                    self.pos += 2;

                    return Some(name(builtin));
                }
                b'F' => {
                    self.pos += 2;
                    let bits = self.parse_number(false)?;

                    if !self.consume_char(b'_') {
                        return None;
                    }

                    return Some(node(Node::Name(format!("_Float{}", bits))));
                }
                b't' | b'T' => self.parse_decltype()?,
                b'k' | b'K' => {
                    let decltype_auto = self.look_at(1) == b'K';
                    self.pos += 2;
                    let constraint = self.parse_name(None)?;
                    return Some(node(Node::PostfixQualified(constraint, if decltype_auto { " decltype(auto)" } else { " auto" })));
                }
                b'p' => {
                    self.pos += 2;
                    node(Node::PackExpansion(self.parse_type()?))
                }
                b'o' | b'O' | b'w' | b'x' => self.parse_function_type()?,
                b'B' | b'U' => {
                    let signed = self.look_at(1) == b'B';
                    self.pos += 2;

                    let size = if self.look().is_ascii_digit() { node(Node::Name(self.parse_number(false)?)) } else { self.parse_expr()? };

                    if !self.consume_char(b'_') {
                        return None;
                    }

                    node(Node::BitInt(size, signed))
                }
                b'v' => {
                    self.pos += 2;

                    let dimension = if self.look().is_ascii_digit() {
                        let n = self.parse_number(false)?;
                        Some(node(Node::Name(n)))
                    } else if self.consume_char(b'_') {
                        None
                    } else {
                        let expr = self.parse_expr()?;
                        Some(expr)
                    };

                    if dimension.is_some() && !self.consume_char(b'_') {
                        return None;
                    }

                    node(Node::Vector(self.parse_type()?, dimension))
                }
                _ => return None,
            },
            b'F' => self.parse_function_type()?,
            b'A' => self.parse_array_type()?,
            b'M' => {
                self.pos += 1;
                let class = self.parse_type()?;
                let member = self.parse_type()?;
                node(Node::MemberPointer(class, member))
            }
            b'T' => {
                if matches!(self.look_at(1), b's' | b'u' | b'e') {
                    self.parse_class_enum_type()?
                } else {
                    let mut result = self.parse_template_param()?;

                    if self.try_parse_template_args && self.look() == b'I' {
                        self.subs.push(result.clone());
                        let args = self.parse_template_args(false)?;
                        result = node(Node::Template(result, args));
                    }

                    result
                }
            }
            b'P' => {
                self.pos += 1;
                node(Node::Pointer(self.parse_type()?))
            }
            b'R' => {
                self.pos += 1;
                node(Node::Reference(self.parse_type()?, false))
            }
            b'O' => {
                self.pos += 1;
                node(Node::Reference(self.parse_type()?, true))
            }
            b'C' => {
                self.pos += 1;
                node(Node::PostfixQualified(self.parse_type()?, " complex"))
            }
            b'G' => {
                self.pos += 1;
                node(Node::PostfixQualified(self.parse_type()?, " imaginary"))
            }
            b'S' if self.look_at(1) != b't' => {
                let (mut result, is_subst) = self.parse_unscoped_name(None)?;

                if self.look() == b'I' && (!is_subst || self.try_parse_template_args) {
                    if !is_subst {
                        self.subs.push(result.clone());
                    }

                    let args = self.parse_template_args(false)?;
                    result = node(Node::Template(result, args));
                } else if is_subst {
                    return Some(result);
                }

                result
            }
            _ => self.parse_class_enum_type()?,
        };

        self.subs.push(result.clone());

        return Some(result);
    }

    fn parse_class_enum_type(&mut self) -> PResult {
        let elaborated = if self.consume_if("Ts") {
            Some("struct")
        } else if self.consume_if("Tu") {
            Some("union")
        } else if self.consume_if("Te") {
            Some("enum")
        } else {
            None
        };

        let name = self.parse_name(None)?;

        return match elaborated {
            Some(e) => Some(node(Node::Elaborated(e, name))),
            None => Some(name),
        };
    }

    fn parse_qualified_type(&mut self) -> PResult {
        if self.consume_char(b'U') {
            let qual = self.parse_bare_source_name()?;

            if let Some(proto_source) = qual.strip_prefix("objcproto") {
                let mut proto_parser = Parser::new(proto_source.as_bytes());
                let proto = proto_parser.parse_bare_source_name()?;
                let child = self.parse_qualified_type()?;

                return Some(node(Node::ObjCProto(child, proto)));
            }

            let args = if self.look() == b'I' { Some(self.parse_template_args(false)?) } else { None };
            let child = self.parse_qualified_type()?;

            return Some(node(Node::VendorQualified(child, qual, args)));
        }

        let quals = self.parse_cv_qualifiers();
        let ty = self.parse_type()?;

        if quals != 0 {
            return Some(node(Node::Qualified(ty, quals)));
        }

        return Some(ty);
    }

    fn parse_function_type(&mut self) -> PResult {
        let quals = self.parse_cv_qualifiers();

        let exception = if self.consume_if("Do") {
            Some(name("noexcept"))
        } else if self.consume_if("DO") {
            let expr = self.parse_expr()?;

            if !self.consume_char(b'E') {
                return None;
            }

            Some(node(Node::NoexceptSpec(expr)))
        } else if self.consume_if("Dw") {
            let mut types = Vec::new();

            while !self.consume_char(b'E') {
                types.push(self.parse_type()?);
            }

            Some(node(Node::DynamicExceptionSpec(types)))
        } else {
            None
        };

        self.consume_if("Dx");

        if !self.consume_char(b'F') {
            return None;
        }

        self.consume_char(b'Y');

        let ret = self.parse_type()?;
        let mut ref_qual = RefQual::None;
        let mut params = Vec::new();

        loop {
            if self.consume_char(b'E') {
                break;
            }

            if self.consume_char(b'v') {
                continue;
            }

            if self.consume_if("RE") {
                ref_qual = RefQual::LValue;
                break;
            }

            if self.consume_if("OE") {
                ref_qual = RefQual::RValue;
                break;
            }

            params.push(self.parse_type()?);
        }

        return Some(node(Node::FunctionType { ret, params, quals, ref_qual, exception }));
    }

    fn parse_array_type(&mut self) -> PResult {
        if !self.consume_char(b'A') {
            return None;
        }

        let dimension = if self.look().is_ascii_digit() {
            let n = self.parse_number(false)?;

            if !self.consume_char(b'_') {
                return None;
            }

            Some(node(Node::Name(n)))
        } else if self.consume_char(b'_') {
            None
        } else {
            let expr = self.parse_expr()?;

            if !self.consume_char(b'_') {
                return None;
            }

            Some(expr)
        };

        let ty = self.parse_type()?;

        return Some(node(Node::Array(ty, dimension)));
    }

    fn parse_decltype(&mut self) -> PResult {
        if !self.consume_char(b'D') || !matches!(self.look(), b't' | b'T') {
            return None;
        }

        self.pos += 1;

        let expr = self.parse_expr()?;

        if !self.consume_char(b'E') {
            return None;
        }

        return Some(node(Node::Enclosing("decltype".to_string(), expr, Prec::Primary)));
    }

    /*
     * Expressions
     */

    fn parse_expr(&mut self) -> PResult {
        self.enter()?;
        let result = self.parse_expr_impl();
        return self.leave(result);
    }

    fn parse_expr_impl(&mut self) -> PResult {
        let global = self.consume_if("gs");

        if let Some(op) = self.parse_operator_encoding() {
            let symbol = op.symbol().to_string();

            return match op.kind {
                OpKind::Binary => {
                    let lhs = self.parse_expr()?;
                    let rhs = self.parse_expr()?;
                    Some(node(Node::Binary(lhs, symbol, rhs, op.prec)))
                }
                OpKind::Prefix => Some(node(Node::Prefix(symbol, self.parse_expr()?, op.prec))),
                OpKind::Postfix => {
                    if self.consume_char(b'_') {
                        return Some(node(Node::Prefix(symbol, self.parse_expr()?, op.prec)));
                    }

                    Some(node(Node::Postfix(self.parse_expr()?, symbol)))
                }
                OpKind::Array => {
                    let base = self.parse_expr()?;
                    let index = self.parse_expr()?;
                    Some(node(Node::Subscript(base, index)))
                }
                OpKind::Member => {
                    let lhs = self.parse_expr()?;
                    let rhs = self.parse_expr()?;
                    Some(node(Node::Member(lhs, symbol, rhs, op.prec)))
                }
                OpKind::Del => Some(node(Node::Delete(self.parse_expr()?, global, op.flag))),
                OpKind::Call => {
                    let callee = self.parse_expr()?;
                    let mut args = Vec::new();

                    while !self.consume_char(b'E') {
                        args.push(self.parse_expr()?);
                    }

                    Some(node(Node::Call(callee, args)))
                }
                OpKind::CCast => {
                    let saved = self.try_parse_template_args;
                    self.try_parse_template_args = false;
                    let ty = self.parse_type();
                    self.try_parse_template_args = saved;

                    let ty = ty?;
                    let is_many = self.consume_char(b'_');
                    let mut exprs = Vec::new();

                    while !self.consume_char(b'E') {
                        exprs.push(self.parse_expr()?);

                        if !is_many {
                            break;
                        }
                    }

                    if !is_many && exprs.len() != 1 {
                        return None;
                    }

                    Some(node(Node::Conversion(ty, exprs)))
                }
                OpKind::Conditional => {
                    let cond = self.parse_expr()?;
                    let then = self.parse_expr()?;
                    let other = self.parse_expr()?;
                    Some(node(Node::Conditional(cond, then, other)))
                }
                OpKind::NamedCast => {
                    let ty = self.parse_type()?;
                    let expr = self.parse_expr()?;
                    Some(node(Node::Cast(symbol, ty, expr)))
                }
                OpKind::OfIdOp => {
                    let arg = if op.flag { self.parse_type()? } else { self.parse_expr()? };
                    Some(node(Node::Enclosing(symbol, arg, op.prec)))
                }
                OpKind::New => {
                    let mut exprs = Vec::new();

                    while !self.consume_char(b'_') {
                        exprs.push(self.parse_expr()?);
                    }

                    let ty = self.parse_type()?;
                    let has_inits = self.consume_if("pi");
                    let mut inits = Vec::new();

                    while !self.consume_char(b'E') {
                        if !has_inits {
                            return None;
                        }

                        inits.push(self.parse_expr()?);
                    }

                    Some(node(Node::New { exprs, ty, inits, global, array: op.flag }))
                }
                OpKind::NameOnly => None,
            };
        }

        if self.remaining() < 2 {
            return None;
        }

        if self.look() == b'L' {
            return self.parse_expr_primary();
        }

        if self.look() == b'T' {
            return self.parse_template_param();
        }

        if self.look() == b'f' {
            if self.look_at(1) == b'p' || (self.look_at(1) == b'L' && self.look_at(2).is_ascii_digit()) {
                return self.parse_function_param();
            }

            return self.parse_fold_expr();
        }

        if self.consume_if("mc") {
            let ty = self.parse_type()?;
            let expr = self.parse_expr()?;
            self.parse_number(true);

            if !self.consume_char(b'E') {
                return None;
            }

            return Some(node(Node::PtrMemConversion(ty, expr)));
        }

        if self.consume_if("so") {
            let ty = self.parse_type()?;
            let expr = self.parse_expr()?;
            let offset = self.parse_number(true).unwrap_or_default();

            while self.consume_char(b'_') {
                self.parse_number(false);
            }

            self.consume_char(b'p');

            if !self.consume_char(b'E') {
                return None;
            }

            return Some(node(Node::Subobject(ty, expr, offset)));
        }

        if self.consume_if("sP") {
            let mut args = Vec::new();

            while !self.consume_char(b'E') {
                args.push(self.parse_template_arg()?);
            }

            return Some(node(Node::Enclosing("sizeof... ".to_string(), node(Node::ArgPack(args)), Prec::Unary)));
        }

        if self.look() == b'u' {
            self.pos += 1;

            let vendor = self.parse_source_name()?;
            let mut args = Vec::new();

            if Printer::base_name(&vendor) == "__uuidof" && matches!(self.look(), b't' | b'z') {
                let is_type = self.look() == b't';
                self.pos += 1;
                args.push(if is_type { self.parse_type()? } else { self.parse_expr()? });
            } else {
                while !self.consume_char(b'E') {
                    args.push(self.parse_template_arg()?);
                }
            }

            return Some(node(Node::Call(vendor, args)));
        }

        if self.consume_if("tl") {
            let ty = self.parse_type()?;
            let mut inits = Vec::new();

            while !self.consume_char(b'E') {
                inits.push(self.parse_braced_expr()?);
            }

            return Some(node(Node::InitList(Some(ty), inits)));
        }

        if self.consume_if("il") {
            let mut inits = Vec::new();

            while !self.consume_char(b'E') {
                inits.push(self.parse_braced_expr()?);
            }

            return Some(node(Node::InitList(None, inits)));
        }

        if self.consume_if("nx") {
            return Some(node(Node::Enclosing("noexcept ".to_string(), self.parse_expr()?, Prec::Unary)));
        }

        if self.consume_if("sp") {
            return Some(node(Node::PackExpansion(self.parse_expr()?)));
        }

        if self.consume_if("sZ") {
            if self.look() == b'T' {
                return Some(node(Node::SizeofPack(self.parse_template_param()?)));
            }

            return Some(node(Node::Enclosing("sizeof... ".to_string(), self.parse_function_param()?, Prec::Primary)));
        }

        if self.consume_if("tw") {
            return Some(node(Node::Throw(self.parse_expr()?)));
        }

        if self.consume_if("tr") {
            return Some(name("throw"));
        }

        return self.parse_unresolved_name(global);
    }

    fn parse_braced_expr(&mut self) -> PResult {
        if self.look() == b'd' {
            match self.look_at(1) {
                b'i' => {
                    self.pos += 2;
                    let field = self.parse_source_name()?;
                    let init = self.parse_braced_expr()?;
                    return Some(node(Node::Braced(field, init, false)));
                }
                b'x' => {
                    self.pos += 2;
                    let index = self.parse_expr()?;
                    let init = self.parse_braced_expr()?;
                    return Some(node(Node::Braced(index, init, true)));
                }
                b'X' => {
                    self.pos += 2;
                    let first = self.parse_expr()?;
                    let last = self.parse_expr()?;
                    let init = self.parse_braced_expr()?;
                    return Some(node(Node::BracedRange(first, last, init)));
                }
                _ => {}
            }
        }

        return self.parse_expr();
    }

    fn parse_fold_expr(&mut self) -> PResult {
        if !self.consume_char(b'f') {
            return None;
        }

        let (is_left, has_init) = match self.look() {
            b'L' => (true, true),
            b'R' => (false, true),
            b'l' => (true, false),
            b'r' => (false, false),
            _ => return None,
        };

        self.pos += 1;

        let op = self.parse_operator_encoding()?;

        if !(op.kind == OpKind::Binary || (op.kind == OpKind::Member && op.name.ends_with('*'))) {
            return None;
        }

        let mut pack = self.parse_expr()?;
        let mut init = if has_init { Some(self.parse_expr()?) } else { None };

        if is_left {
            if let Some(i) = init.take() {
                init = Some(pack);
                pack = i;
            }
        }

        return Some(node(Node::Fold { is_left, op: op.symbol().to_string(), pack, init }));
    }

    fn parse_function_param(&mut self) -> PResult {
        if self.consume_if("fpT") {
            return Some(name("this"));
        }

        if self.consume_if("fp") {
            self.parse_cv_qualifiers();
            let number = self.parse_number(false).unwrap_or_default();

            if !self.consume_char(b'_') {
                return None;
            }

            return Some(node(Node::FunctionParam(number)));
        }

        if self.consume_if("fL") {
            self.parse_number(false)?;

            if !self.consume_char(b'p') {
                return None;
            }

            self.parse_cv_qualifiers();
            let number = self.parse_number(false).unwrap_or_default();

            if !self.consume_char(b'_') {
                return None;
            }

            return Some(node(Node::FunctionParam(number)));
        }

        return None;
    }

    fn parse_expr_primary(&mut self) -> PResult {
        if !self.consume_char(b'L') {
            return None;
        }

        let integer_type = match self.look() {
            b'w' => Some("wchar_t"),
            b'c' => Some("char"),
            b'a' => Some("signed char"),
            b'h' => Some("unsigned char"),
            b's' => Some("short"),
            b't' => Some("unsigned short"),
            b'i' => Some(""),
            b'j' => Some("u"),
            b'l' => Some("l"),
            b'm' => Some("ul"),
            b'x' => Some("ll"),
            b'y' => Some("ull"),
            b'n' => Some("__int128"),
            b'o' => Some("unsigned __int128"),
            _ => None,
        };

        if let Some(ty) = integer_type {
            self.pos += 1;
            let value = self.parse_number(true)?;

            if !self.consume_char(b'E') {
                return None;
            }

            return Some(node(Node::IntegerLiteral(ty, value)));
        }

        match self.look() {
            b'b' => {
                if self.consume_if("b0E") {
                    return Some(node(Node::Bool(false)));
                }

                if self.consume_if("b1E") {
                    return Some(node(Node::Bool(true)));
                }

                return None;
            }
            b'_' => {
                if self.consume_if("_Z") {
                    let encoding = self.parse_encoding()?;

                    if self.consume_char(b'E') {
                        return Some(encoding);
                    }
                }

                return None;
            }
            b'A' => {
                let ty = self.parse_type()?;

                if !self.consume_char(b'E') {
                    return None;
                }

                return Some(node(Node::StringLiteral(ty)));
            }
            b'D' => {
                if !self.consume_if("Dn") {
                    return None;
                }

                self.consume_char(b'0');

                return if self.consume_char(b'E') { Some(name("nullptr")) } else { None };
            }
            b'U' if self.look_at(1) == b'l' => {
                let closure = self.parse_unnamed_type_name(false)?;

                if !self.consume_char(b'E') {
                    return None;
                }

                return Some(node(Node::LambdaExpr(closure)));
            }
            b'f' | b'd' | b'e' | b'T' | b'U' => return None,
            _ => {
                let ty = self.parse_type()?;
                let value = self.parse_number(true)?;

                if !self.consume_char(b'E') {
                    return None;
                }

                return Some(node(Node::EnumLiteral(ty, value)));
            }
        }
    }

    fn parse_unresolved_type(&mut self) -> PResult {
        if self.look() == b'T' {
            let param = self.parse_template_param()?;
            self.subs.push(param.clone());
            return Some(param);
        }

        if self.look() == b'D' {
            let decltype = self.parse_decltype()?;
            self.subs.push(decltype.clone());
            return Some(decltype);
        }

        return self.parse_substitution();
    }

    fn parse_simple_id(&mut self) -> PResult {
        let source = self.parse_source_name()?;

        if self.look() == b'I' {
            let args = self.parse_template_args(false)?;
            return Some(node(Node::Template(source, args)));
        }

        return Some(source);
    }

    fn parse_base_unresolved_name(&mut self) -> PResult {
        if self.look().is_ascii_digit() {
            return self.parse_simple_id();
        }

        if self.consume_if("dn") {
            let dtor = if self.look().is_ascii_digit() { self.parse_simple_id()? } else { self.parse_unresolved_type()? };
            return Some(node(Node::DtorName(dtor)));
        }

        self.consume_if("on");

        let op = self.parse_operator_name(None)?;

        if self.look() == b'I' {
            let args = self.parse_template_args(false)?;
            return Some(node(Node::Template(op, args)));
        }

        return Some(op);
    }

    fn parse_unresolved_name(&mut self, global: bool) -> PResult {
        if self.consume_if("srN") {
            let mut so_far = self.parse_unresolved_type()?;

            if self.look() == b'I' {
                let args = self.parse_template_args(false)?;
                so_far = node(Node::Template(so_far, args));
            }

            while !self.consume_char(b'E') {
                let qual = self.parse_simple_id()?;
                so_far = node(Node::Nested(so_far, qual));
            }

            let base = self.parse_base_unresolved_name()?;

            return Some(node(Node::Nested(so_far, base)));
        }

        if !self.consume_if("sr") {
            let base = self.parse_base_unresolved_name()?;
            return Some(if global { node(Node::GlobalQualified(base)) } else { base });
        }

        let mut so_far: Option<N> = None;

        if self.look().is_ascii_digit() {
            loop {
                let qual = self.parse_simple_id()?;

                so_far = Some(match so_far {
                    Some(s) => node(Node::Nested(s, qual)),
                    None if global => node(Node::GlobalQualified(qual)),
                    None => qual,
                });

                if self.consume_char(b'E') {
                    break;
                }
            }
        } else {
            let mut ty = self.parse_unresolved_type()?;

            if self.look() == b'I' {
                let args = self.parse_template_args(false)?;
                ty = node(Node::Template(ty, args));
            }

            so_far = Some(ty);
        }

        let base = self.parse_base_unresolved_name()?;

        return Some(node(Node::Nested(so_far?, base)));
    }
}

/*
 * Printer
 */

struct Printer {
    out: String,
    gt_is_gt: u32,
    pack_index: usize,
    pack_max: usize,
    printing_references: Vec<*const Node>,
    depth: usize,
    overflow: bool,
}

impl Printer {
    fn new() -> Self {
        return Self {
            out: String::new(),
            gt_is_gt: 1,
            pack_index: usize::MAX,
            pack_max: usize::MAX,
            printing_references: Vec::new(),
            depth: 0,
            overflow: false,
        };
    }

    fn push(&mut self, s: &str) {
        if self.out.len() + s.len() > MAX_OUTPUT {
            self.overflow = true;
            return;
        }

        self.out.push_str(s);
    }

    fn print_open(&mut self, c: &str) {
        self.gt_is_gt += 1;
        self.push(c);
    }

    fn print_close(&mut self, c: &str) {
        self.gt_is_gt -= 1;
        self.push(c);
    }

    fn print_quals(&mut self, quals: u8) {
        if quals & QUAL_CONST != 0 {
            self.push(" const");
        }

        if quals & QUAL_VOLATILE != 0 {
            self.push(" volatile");
        }

        if quals & QUAL_RESTRICT != 0 {
            self.push(" restrict");
        }
    }

    fn init_pack_expansion(&mut self, size: usize) {
        if self.pack_max == usize::MAX {
            self.pack_max = size;
            self.pack_index = 0;
        }
    }

    fn current_pack_element<'n>(&mut self, elements: &'n [N]) -> Option<&'n N> {
        self.init_pack_expansion(elements.len());
        return elements.get(self.pack_index);
    }

    /// Follows the nodes that only forward to another one (packs and forward template references)
    fn syntax_node(&mut self, n: &N) -> Option<N> {
        match &**n {
            Node::ParamPack(elements) => {
                let element = self.current_pack_element(elements)?.clone();
                self.syntax_node(&element)
            }
            Node::ForwardRef(target) => {
                let target = target.borrow().clone()?;
                self.syntax_node(&target)
            }
            _ => Some(n.clone()),
        }
    }

    fn has_rhs_component(&mut self, n: &N) -> bool {
        match &**n {
            Node::Pointer(p) | Node::Reference(p, _) | Node::Qualified(p, _) | Node::MemberPointer(_, p) => self.has_rhs_component(p),
            Node::FunctionType { .. } | Node::Encoding { .. } | Node::Array(..) => true,
            Node::ParamPack(_) | Node::ForwardRef(_) => match self.syntax_node(n) {
                Some(s) => self.has_rhs_component(&s),
                None => false,
            },
            _ => false,
        }
    }

    fn has_array(&mut self, n: &N) -> bool {
        match &**n {
            Node::Array(..) => true,
            Node::Qualified(p, _) => self.has_array(p),
            Node::ParamPack(_) | Node::ForwardRef(_) => match self.syntax_node(n) {
                Some(s) => self.has_array(&s),
                None => false,
            },
            _ => false,
        }
    }

    fn has_function(&mut self, n: &N) -> bool {
        match &**n {
            Node::FunctionType { .. } | Node::Encoding { .. } => true,
            Node::Qualified(p, _) => self.has_function(p),
            Node::ParamPack(_) | Node::ForwardRef(_) => match self.syntax_node(n) {
                Some(s) => self.has_function(&s),
                None => false,
            },
            _ => false,
        }
    }

    fn objc_id_protocol(n: &N) -> Option<String> {
        match &**n {
            Node::ObjCProto(child, proto) if matches!(&**child, Node::Name(name) if name == "objc_object") => Some(proto.clone()),
            _ => None,
        }
    }

    fn base_name(n: &N) -> String {
        match &**n {
            Node::Name(s) => s.clone(),
            Node::Nested(_, inner) | Node::Template(inner, _) | Node::AbiTag(inner, _) => Self::base_name(inner),
            Node::ModuleEntity(_, inner) | Node::MemberLikeFriend(_, inner) => Self::base_name(inner),
            Node::StdSubstitution(kind, expanded) => kind.base_name(*expanded).to_string(),
            Node::ForwardRef(target) => target.borrow().as_ref().map_or(String::new(), Self::base_name),
            _ => String::new(),
        }
    }

    fn print(&mut self, n: &N) {
        self.print_left(n);
        self.print_right(n);
    }

    fn print_as_operand(&mut self, n: &N, prec: Prec, strictly_worse: bool) {
        let paren = (n.prec() as u32) >= (prec as u32) + (strictly_worse as u32);

        if paren {
            self.print_open("(");
        }

        self.print(n);

        if paren {
            self.print_close(")");
        }
    }

    fn print_with_comma(&mut self, nodes: &[N]) {
        let mut first = true;

        for n in nodes {
            let before_comma = self.out.len();

            if !first {
                self.push(", ");
            }

            let after_comma = self.out.len();

            self.print_as_operand(n, Prec::Comma, false);

            if after_comma == self.out.len() {
                self.out.truncate(before_comma);
                continue;
            }

            first = false;
        }
    }

    fn print_left(&mut self, n: &N) {
        self.depth += 1;

        if self.depth > MAX_DEPTH * 4 || self.overflow {
            self.overflow = true;
            self.depth -= 1;
            return;
        }

        self.print_left_impl(n);

        self.depth -= 1;
    }

    fn print_right(&mut self, n: &N) {
        self.depth += 1;

        if self.depth > MAX_DEPTH * 4 || self.overflow {
            self.overflow = true;
            self.depth -= 1;
            return;
        }

        self.print_right_impl(n);

        self.depth -= 1;
    }

    fn print_left_impl(&mut self, n: &N) {
        match &**n {
            Node::Name(s) => self.push(s),
            Node::Nested(scope, inner) => {
                self.print(scope);
                self.push("::");
                self.print(inner);
            }
            Node::Template(inner, args) => {
                self.print(inner);
                self.print(args);
            }
            Node::TemplateArgs(args) => {
                let saved = self.gt_is_gt;
                self.gt_is_gt = 0;
                self.push("<");
                self.print_with_comma(args);
                self.push(">");
                self.gt_is_gt = saved;
            }
            Node::AbiTag(base, tag) => {
                self.print_left(base);
                self.push("[abi:");
                self.push(tag);
                self.push("]");
            }
            Node::CtorDtor(scope, is_dtor) => {
                if *is_dtor {
                    self.push("~");
                }

                let base = Self::base_name(scope);
                self.push(&base);
            }
            Node::StdSubstitution(kind, expanded) => {
                self.push("std::");
                self.push(kind.base_name(*expanded));

                if *expanded {
                    self.push(kind.expanded_args());
                }
            }
            Node::Special(prefix, child) => {
                self.push(prefix);
                self.print(child);
            }
            Node::CtorVtable(first, second) => {
                self.push("construction vtable for ");
                self.print(first);
                self.push("-in-");
                self.print(second);
            }
            Node::Qualified(child, quals) => {
                self.print_left(child);
                self.print_quals(*quals);
            }
            Node::VendorQualified(child, qual, args) => {
                self.print(child);
                self.push(" ");
                self.push(qual);

                if let Some(args) = args {
                    self.print(args);
                }
            }
            Node::PostfixQualified(child, postfix) => {
                self.print(child);
                self.push(postfix);
            }
            Node::Pointer(pointee) => {
                if let Some(proto) = Self::objc_id_protocol(pointee) {
                    self.push("id<");
                    self.push(&proto);
                    self.push(">");
                    return;
                }

                self.print_left(pointee);

                let has_array = self.has_array(pointee);

                if has_array {
                    self.push(" ");
                }

                if has_array || self.has_function(pointee) {
                    self.push("(");
                }

                self.push("*");
            }
            Node::Reference(..) => {
                if self.printing_references.contains(&Rc::as_ptr(n)) {
                    return;
                }

                self.printing_references.push(Rc::as_ptr(n));

                if let Some((rvalue, pointee)) = self.collapse_reference(n) {
                    self.print_left(&pointee);

                    let has_array = self.has_array(&pointee);

                    if has_array {
                        self.push(" ");
                    }

                    if has_array || self.has_function(&pointee) {
                        self.push("(");
                    }

                    self.push(if rvalue { "&&" } else { "&" });
                }

                self.printing_references.pop();
            }
            Node::FunctionType { ret, .. } => {
                self.print_left(ret);
                self.push(" ");
            }
            Node::Encoding { ret, name, .. } => {
                if let Some(ret) = ret {
                    self.print_left(ret);

                    if !self.has_rhs_component(ret) {
                        self.push(" ");
                    }
                }

                self.print(name);
            }
            Node::Array(base, _) => self.print_left(base),
            Node::Vector(base, dimension) => {
                self.print(base);
                self.push(" vector[");

                if let Some(d) = dimension {
                    self.print(d);
                }

                self.push("]");
            }
            Node::MemberPointer(class, member) => {
                self.print_left(member);

                if self.has_array(member) || self.has_function(member) {
                    self.push("(");
                } else {
                    self.push(" ");
                }

                self.print(class);
                self.push("::*");
            }
            Node::ArgPack(elements) => self.print_with_comma(elements),
            Node::ParamPack(elements) => {
                if let Some(element) = self.current_pack_element(elements).cloned() {
                    self.print_left(&element);
                }
            }
            Node::PackExpansion(child) => {
                let saved_index = self.pack_index;
                let saved_max = self.pack_max;

                self.pack_index = usize::MAX;
                self.pack_max = usize::MAX;

                let start = self.out.len();

                self.print(child);

                if self.pack_max == usize::MAX {
                    self.push("...");
                } else if self.pack_max == 0 {
                    self.out.truncate(start);
                } else {
                    for i in 1..self.pack_max {
                        self.push(", ");
                        self.pack_index = i;
                        self.print(child);
                    }
                }

                self.pack_index = saved_index;
                self.pack_max = saved_max;
            }
            Node::ForwardRef(target) => {
                let target = target.borrow().clone();

                if let Some(t) = target {
                    self.print_left(&t);
                }
            }
            Node::Local(encoding, entity) => {
                self.print(encoding);
                self.push("::");
                self.print(entity);
            }
            Node::DotSuffix(prefix, suffix) => {
                self.print(prefix);
                self.push(" (");
                self.push(suffix);
                self.push(")");
            }
            Node::Elaborated(kind, child) => {
                self.push(kind);
                self.push(" ");
                self.print(child);
            }
            Node::ConversionOperator(ty) => {
                self.push("operator ");
                self.print(ty);
            }
            Node::LiteralOperator(name) => {
                self.push("operator\"\" ");
                self.print(name);
            }
            Node::Lambda { count, .. } => {
                self.push("'lambda");
                self.push(count);
                self.push("'");
                self.print_lambda_declarator(n);
            }
            Node::Unnamed(count) => {
                self.push("'unnamed");
                self.push(count);
                self.push("'");
            }
            Node::StructuredBinding(names) => {
                self.push("[");
                self.print_with_comma(names);
                self.push("]");
            }
            Node::NoexceptSpec(expr) => {
                self.push("noexcept");
                self.print_open("(");
                self.print(expr);
                self.print_close(")");
            }
            Node::DynamicExceptionSpec(types) => {
                self.push("throw");
                self.print_open("(");
                self.print_with_comma(types);
                self.print_close(")");
            }
            Node::Binary(lhs, op, rhs, prec) => {
                let paren_all = self.gt_is_gt == 0 && (op == ">" || op == ">>");

                if paren_all {
                    self.print_open("(");
                }

                let is_assign = *prec == Prec::Assign;

                self.print_as_operand(lhs, if is_assign { Prec::OrIf } else { *prec }, !is_assign);

                if op != "," {
                    self.push(" ");
                }

                self.push(op);
                self.push(" ");
                self.print_as_operand(rhs, *prec, is_assign);

                if paren_all {
                    self.print_close(")");
                }
            }
            Node::Prefix(op, child, prec) => {
                self.push(op);
                self.print_as_operand(child, *prec, false);
            }
            Node::Postfix(child, op) => {
                self.print_as_operand(child, Prec::Postfix, true);
                self.push(op);
            }
            Node::Subscript(base, index) => {
                self.print_as_operand(base, Prec::Postfix, false);
                self.print_open("[");
                self.print_as_operand(index, Prec::Default, false);
                self.print_close("]");
            }
            Node::Member(lhs, kind, rhs, prec) => {
                self.print_as_operand(lhs, *prec, true);
                self.push(kind);
                self.print_as_operand(rhs, *prec, false);
            }
            Node::Call(callee, args) => {
                self.print(callee);
                self.print_open("(");
                self.print_with_comma(args);
                self.print_close(")");
            }
            Node::Conversion(ty, exprs) => {
                self.print_open("(");
                self.print(ty);
                self.print_close(")");
                self.print_open("(");
                self.print_with_comma(exprs);
                self.print_close(")");
            }
            Node::Conditional(cond, then, other) => {
                self.print_as_operand(cond, Prec::Conditional, false);
                self.push(" ? ");
                self.print_as_operand(then, Prec::Default, false);
                self.push(" : ");
                self.print_as_operand(other, Prec::Assign, true);
            }
            Node::Cast(kind, to, from) => {
                self.push(kind);

                let saved = self.gt_is_gt;
                self.gt_is_gt = 0;
                self.push("<");
                self.print_left(to);
                self.push(">");
                self.gt_is_gt = saved;

                self.print_open("(");
                self.print_as_operand(from, Prec::Default, false);
                self.print_close(")");
            }
            Node::Enclosing(prefix, inner, _) => {
                self.push(prefix);
                self.print_open("(");
                self.print(inner);
                self.print_close(")");
            }
            Node::SizeofPack(pack) => {
                self.push("sizeof...");
                self.print_open("(");
                let expansion = node(Node::PackExpansion(pack.clone()));
                self.print_left(&expansion);
                self.print_close(")");
            }
            Node::Delete(expr, global, array) => {
                if *global {
                    self.push("::");
                }

                self.push("delete");

                if *array {
                    self.push("[]");
                }

                self.push(" ");
                self.print(expr);
            }
            Node::Throw(expr) => {
                self.push("throw ");
                self.print(expr);
            }
            Node::IntegerLiteral(ty, value) => {
                if ty.len() > 3 {
                    self.print_open("(");
                    self.push(ty);
                    self.print_close(")");
                }

                match value.strip_prefix('n') {
                    Some(v) => {
                        self.push("-");
                        self.push(v);
                    }
                    None => self.push(value),
                }

                if ty.len() <= 3 {
                    self.push(ty);
                }
            }
            Node::Bool(value) => self.push(if *value { "true" } else { "false" }),
            Node::EnumLiteral(ty, value) => {
                self.print_open("(");
                self.print(ty);
                self.print_close(")");

                match value.strip_prefix('n') {
                    Some(v) => {
                        self.push("-");
                        self.push(v);
                    }
                    None => self.push(value),
                }
            }
            Node::StringLiteral(ty) => {
                self.push("\"<");
                self.print(ty);
                self.push(">\"");
            }
            Node::FunctionParam(number) => {
                self.push("fp");
                self.push(number);
            }
            Node::GlobalQualified(child) => {
                self.push("::");
                self.print(child);
            }
            Node::DtorName(child) => {
                self.push("~");
                self.print_left(child);
            }
            Node::BitInt(size, signed) => {
                if !*signed {
                    self.push("unsigned ");
                }

                self.push("_BitInt");
                self.print_open("(");
                self.print(size);
                self.print_close(")");
            }
            Node::EnableIf(conditions) => {
                self.push(" [enable_if:");
                self.print_with_comma(conditions);
                self.push("]");
            }
            Node::ExplicitObjectParam(base) => {
                self.push("this ");
                self.print(base);
            }
            Node::MemberLikeFriend(scope, inner) => {
                self.print(scope);
                self.push("::friend ");
                self.print(inner);
            }
            Node::ModuleName(parent, inner, is_partition) => {
                if let Some(parent) = parent {
                    self.print(parent);
                }

                if parent.is_some() || *is_partition {
                    self.push(if *is_partition { ":" } else { "." });
                }

                self.print(inner);
            }
            Node::ModuleEntity(module, inner) => {
                self.print(inner);
                self.push("@");
                self.print(module);
            }
            Node::ObjCProto(child, proto) => {
                self.print(child);
                self.push("<");
                self.push(proto);
                self.push(">");
            }
            Node::TransformedType(transform, base) => {
                self.push(transform);
                self.push("(");
                self.print(base);
                self.push(")");
            }
            Node::SyntheticParam(kind, index) => {
                self.push(["$T", "$N", "$TT"][*kind]);

                if *index > 0 {
                    self.push(&(index - 1).to_string());
                }
            }
            Node::TypeParamDecl(_) => self.push("typename "),
            Node::ConstrainedTypeParamDecl(constraint, _) => {
                self.print(constraint);
                self.push(" ");
            }
            Node::NonTypeParamDecl(_, ty) => {
                self.print_left(ty);

                if !self.has_rhs_component(ty) {
                    self.push(" ");
                }
            }
            Node::TemplateTemplateParamDecl(_, params, _) => {
                let saved = self.gt_is_gt;
                self.gt_is_gt = 0;
                self.push("template<");
                self.print_with_comma(params);
                self.push("> typename ");
                self.gt_is_gt = saved;
            }
            Node::ParamPackDecl(param) => {
                self.print_left(param);
                self.push("...");
            }
            Node::LambdaExpr(closure) => {
                self.push("[]");
                self.print_lambda_declarator(closure);
                self.push("{...}");
            }
            Node::New { exprs, ty, inits, global, array } => {
                if *global {
                    self.push("::");
                }

                self.push("new");

                if *array {
                    self.push("[]");
                }

                if !exprs.is_empty() {
                    self.print_open("(");
                    self.print_with_comma(exprs);
                    self.print_close(")");
                }

                self.push(" ");
                self.print(ty);

                if !inits.is_empty() {
                    self.print_open("(");
                    self.print_with_comma(inits);
                    self.print_close(")");
                }
            }
            Node::Fold { is_left, op, pack, init } => {
                self.print_open("(");

                if !*is_left || init.is_some() {
                    match (is_left, init) {
                        (true, Some(init)) => self.print_as_operand(init, Prec::Cast, true),
                        _ => self.print_fold_pack(pack),
                    }

                    self.push(" ");
                    self.push(op);
                    self.push(" ");
                }

                self.push("...");

                if *is_left || init.is_some() {
                    self.push(" ");
                    self.push(op);
                    self.push(" ");

                    match (is_left, init) {
                        (false, Some(init)) => self.print_as_operand(init, Prec::Cast, true),
                        _ => self.print_fold_pack(pack),
                    }
                }

                self.print_close(")");
            }
            Node::Braced(elem, init, is_array) => {
                if *is_array {
                    self.push("[");
                    self.print(elem);
                    self.push("]");
                } else {
                    self.push(".");
                    self.print(elem);
                }

                if !matches!(**init, Node::Braced(..) | Node::BracedRange(..)) {
                    self.push(" = ");
                }

                self.print(init);
            }
            Node::BracedRange(first, last, init) => {
                self.push("[");
                self.print(first);
                self.push(" ... ");
                self.print(last);
                self.push("]");

                if !matches!(**init, Node::Braced(..) | Node::BracedRange(..)) {
                    self.push(" = ");
                }

                self.print(init);
            }
            Node::Subobject(ty, expr, offset) => {
                self.print(expr);
                self.push(".<");
                self.print(ty);
                self.push(" at offset ");

                match offset.strip_prefix('n') {
                    _ if offset.is_empty() => self.push("0"),
                    Some(v) => {
                        self.push("-");
                        self.push(v);
                    }
                    None => self.push(offset),
                }

                self.push(">");
            }
            Node::PtrMemConversion(ty, expr) => {
                self.print_open("(");
                self.print(ty);
                self.print_close(")");
                self.print_open("(");
                self.print(expr);
                self.print_close(")");
            }
            Node::InitList(ty, inits) => {
                if let Some(ty) = ty {
                    self.print(ty);
                }

                self.push("{");
                self.print_with_comma(inits);
                self.push("}");
            }
        }
    }

    fn print_right_impl(&mut self, n: &N) {
        match &**n {
            Node::Qualified(child, _) => self.print_right(child),
            Node::Pointer(pointee) => {
                if Self::objc_id_protocol(pointee).is_some() {
                    return;
                }

                if self.has_array(pointee) || self.has_function(pointee) {
                    self.push(")");
                }

                self.print_right(pointee);
            }
            Node::Reference(..) => {
                if self.printing_references.contains(&Rc::as_ptr(n)) {
                    return;
                }

                self.printing_references.push(Rc::as_ptr(n));

                if let Some((_, pointee)) = self.collapse_reference(n) {
                    if self.has_array(&pointee) || self.has_function(&pointee) {
                        self.push(")");
                    }

                    self.print_right(&pointee);
                }

                self.printing_references.pop();
            }
            Node::FunctionType { ret, params, quals, ref_qual, exception } => {
                self.print_open("(");
                self.print_with_comma(params);
                self.print_close(")");
                self.print_right(ret);
                self.print_quals(*quals);
                self.print_ref_qual(*ref_qual);

                if let Some(e) = exception {
                    self.push(" ");
                    self.print(e);
                }
            }
            Node::Encoding { ret, params, quals, ref_qual, attrs, requires, .. } => {
                self.print_open("(");
                self.print_with_comma(params);
                self.print_close(")");

                if let Some(ret) = ret {
                    self.print_right(ret);
                }

                self.print_quals(*quals);
                self.print_ref_qual(*ref_qual);

                if let Some(attrs) = attrs {
                    self.print(attrs);
                }

                if let Some(requires) = requires {
                    self.push(" requires ");
                    self.print(requires);
                }
            }
            Node::Array(base, dimension) => {
                if !self.out.ends_with(']') {
                    self.push(" ");
                }

                self.push("[");

                if let Some(d) = dimension {
                    self.print(d);
                }

                self.push("]");
                self.print_right(base);
            }
            Node::MemberPointer(_, member) => {
                if self.has_array(member) || self.has_function(member) {
                    self.push(")");
                }

                self.print_right(member);
            }
            Node::ParamPack(elements) => {
                if let Some(element) = self.current_pack_element(elements).cloned() {
                    self.print_right(&element);
                }
            }
            Node::ForwardRef(target) => {
                let target = target.borrow().clone();

                if let Some(t) = target {
                    self.print_right(&t);
                }
            }
            Node::TypeParamDecl(name) | Node::ConstrainedTypeParamDecl(_, name) => self.print(name),
            Node::NonTypeParamDecl(name, ty) => {
                self.print(name);
                self.print_right(ty);
            }
            Node::TemplateTemplateParamDecl(name, _, requires) => {
                self.print(name);

                if let Some(requires) = requires {
                    self.push(" requires ");
                    self.print(requires);
                }
            }
            Node::ParamPackDecl(param) => self.print_right(param),
            _ => {}
        }
    }

    fn print_lambda_declarator(&mut self, closure: &N) {
        let Node::Lambda { decls, requires1, params, requires2, .. } = &**closure else {
            return;
        };

        if !decls.is_empty() {
            let saved = self.gt_is_gt;
            self.gt_is_gt = 0;
            self.push("<");
            self.print_with_comma(decls);
            self.push(">");
            self.gt_is_gt = saved;
        }

        if let Some(requires) = requires1 {
            self.push(" requires ");
            self.print(requires);
            self.push(" ");
        }

        self.print_open("(");
        self.print_with_comma(params);
        self.print_close(")");

        if let Some(requires) = requires2 {
            self.push(" requires ");
            self.print(requires);
        }
    }

    fn print_fold_pack(&mut self, pack: &N) {
        self.print_open("(");
        let expansion = node(Node::PackExpansion(pack.clone()));
        self.print(&expansion);
        self.print_close(")");
    }

    fn print_ref_qual(&mut self, ref_qual: RefQual) {
        match ref_qual {
            RefQual::LValue => self.push(" &"),
            RefQual::RValue => self.push(" &&"),
            RefQual::None => {}
        }
    }

    /// Reference collapsing: T& & -> T&, T&& & -> T&, T&& && -> T&&
    fn collapse_reference(&mut self, n: &N) -> Option<(bool, N)> {
        let Node::Reference(pointee, rvalue) = &**n else {
            return None;
        };

        let mut rvalue = *rvalue;
        let mut pointee = pointee.clone();
        let mut seen = 0;

        loop {
            let syntax = self.syntax_node(&pointee)?;

            let Node::Reference(inner, inner_rvalue) = &*syntax else {
                return Some((rvalue, syntax));
            };

            rvalue = rvalue && *inner_rvalue;
            pointee = inner.clone();

            seen += 1;

            if seen > MAX_DEPTH {
                return None;
            }
        }
    }
}

pub fn demangle(symbol: &str) -> Option<String> {
    let mut parser = Parser::new(symbol.as_bytes());
    let root = parser.parse()?;

    let mut printer = Printer::new();
    printer.print(&root);

    if printer.overflow {
        return None;
    }

    return Some(printer.out);
}
