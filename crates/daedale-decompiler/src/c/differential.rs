// SPDX-License-Identifier: Apache-2.0
/*
 * Differential test of the C backend: random programs on a few integer variables, with branches and
 * loops, are built as LLVM IR (the variables in allocas), optimized like the lifted code (the phis and
 * the copies at the joins come from mem2reg), decompiled to C, and the C is run by an interpreter: it
 * must return what the program returns for the same arguments.
 */

use super::ast::{BinaryOp, CFunction, Expr, Stmt, StmtKind, UnaryOp};
use super::Context;
use crate::decompiler::PASSES;
use crate::typedb::{Platform, TypeDb};
use crate::types::{CType, DataModel};

use daedale_core::disasm::Architecture;
use daedale_core::program::Program;

use inkwell::context::Context as LlvmContext;
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, InitializationConfig, RelocMode, Target, TargetMachine, TargetTriple};
use inkwell::values::IntValue;
use inkwell::{IntPredicate, OptimizationLevel};

use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

const VARS: usize = 4;
const STEPS: usize = 2000;

#[derive(Clone, Copy, Debug)]
enum Operand {
    Var(usize),
    Const(i32),
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Sub,
    Mul,
    Xor,
    Copy,
}

#[derive(Clone, Copy, Debug)]
enum Cmp {
    Slt,
    Ult,
    Eq,
}

#[derive(Clone, Debug)]
enum Term {
    Ret(Operand),
    Jump(usize),
    Branch(Cmp, Operand, Operand, usize, usize),
}

#[derive(Clone, Debug)]
struct Block {
    stmts: Vec<(usize, Op, Operand, Operand)>,
    term: Term,
}

struct Random(u64);

impl Random {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        return ((self.0 >> 33) % n as u64) as usize;
    }

    fn operand(&mut self) -> Operand {
        return if self.next(4) == 0 { Operand::Const(self.next(7) as i32 - 2) } else { Operand::Var(self.next(VARS)) };
    }
}

fn random_program(seed: u64) -> Vec<Block> {
    let mut r = Random(seed);
    let count = if seed % 4 == 0 { 2 + r.next(16) } else { 2 + r.next(9) };

    return (0..count)
        .map(|i| {
            let stmts = (0..r.next(4))
                .map(|_| {
                    let op = [Op::Add, Op::Sub, Op::Mul, Op::Xor, Op::Copy, Op::Copy][r.next(6)];
                    (r.next(VARS), op, r.operand(), r.operand())
                })
                .collect();

            // Mostly forward, some back edges (the loops), the last block returns
            let target = |r: &mut Random| if r.next(4) == 0 { r.next(count) } else { (i + 1 + r.next(2)).min(count - 1) };

            let term = match r.next(6) {
                _ if i == count - 1 => Term::Ret(r.operand()),
                0 => Term::Ret(r.operand()),
                1 => Term::Jump(target(&mut r)),
                _ => Term::Branch([Cmp::Slt, Cmp::Ult, Cmp::Eq][r.next(3)], r.operand(), r.operand(), target(&mut r), target(&mut r)),
            };

            Block { stmts, term }
        })
        .collect();
}

/// The result of the program for two arguments (the first variables), None when it does not stop soon
fn run_program(blocks: &[Block], a: i32, b: i32) -> Option<i32> {
    let mut vars = [a, b, 3, 7];
    let value = |vars: &[i32; VARS], o: Operand| match o {
        Operand::Var(v) => vars[v],
        Operand::Const(c) => c,
    };

    let mut block = 0;

    for _ in 0..STEPS {
        for &(dst, op, x, y) in blocks[block].stmts.iter() {
            let (x, y) = (value(&vars, x), value(&vars, y));

            vars[dst] = match op {
                Op::Add => x.wrapping_add(y),
                Op::Sub => x.wrapping_sub(y),
                Op::Mul => x.wrapping_mul(y),
                Op::Xor => x ^ y,
                Op::Copy => x,
            };
        }

        block = match &blocks[block].term {
            Term::Ret(o) => return Some(value(&vars, *o)),
            Term::Jump(t) => *t,
            Term::Branch(cmp, x, y, t, f) => {
                let (x, y) = (value(&vars, *x), value(&vars, *y));

                let taken = match cmp {
                    Cmp::Slt => x < y,
                    Cmp::Ult => (x as u32) < (y as u32),
                    Cmp::Eq => x == y,
                };

                if taken { *t } else { *f }
            }
        };
    }

    return None;
}

fn machine() -> TargetMachine {
    Target::initialize_x86(&InitializationConfig::default());
    let triple = TargetTriple::create("x86_64-pc-linux-gnu");
    let target = Target::from_triple(&triple).unwrap();
    return target.create_target_machine(&triple, "generic", "", OptimizationLevel::Default, RelocMode::Default, CodeModel::Default).unwrap();
}

/// The program decompiled: built with its variables in allocas, optimized, then turned into C
fn decompile(blocks: &[Block], machine: &TargetMachine) -> CFunction {
    let cx = LlvmContext::create();
    let module = cx.create_module("program");
    module.set_triple(&machine.get_triple());
    module.set_data_layout(&machine.get_target_data().get_data_layout());

    let i32_type = cx.i32_type();
    let function = module.add_function("f", i32_type.fn_type(&[i32_type.into(), i32_type.into()], false), None);
    let builder = cx.create_builder();
    let entry = cx.append_basic_block(function, "entry");
    let llvm_blocks: Vec<_> = (0..blocks.len()).map(|i| cx.append_basic_block(function, &format!("b{}", i))).collect();

    builder.position_at_end(entry);
    let slots: Vec<_> = (0..VARS).map(|_| builder.build_alloca(i32_type, "").unwrap()).collect();
    let initial = [function.get_nth_param(0).unwrap().into_int_value(), function.get_nth_param(1).unwrap().into_int_value(), i32_type.const_int(3, false), i32_type.const_int(7, false)];

    for (slot, value) in slots.iter().zip(initial.iter()) {
        builder.build_store(*slot, *value).unwrap();
    }

    builder.build_unconditional_branch(llvm_blocks[0]).unwrap();

    let operand = |o: Operand| -> IntValue {
        match o {
            Operand::Var(v) => builder.build_load(i32_type, slots[v], "").unwrap().into_int_value(),
            Operand::Const(c) => i32_type.const_int(c as i64 as u64, true),
        }
    };

    for (block, llvm) in blocks.iter().zip(llvm_blocks.iter()) {
        builder.position_at_end(*llvm);

        for &(dst, op, x, y) in block.stmts.iter() {
            let (x, y) = (operand(x), operand(y));

            let value = match op {
                Op::Add => builder.build_int_add(x, y, "").unwrap(),
                Op::Sub => builder.build_int_sub(x, y, "").unwrap(),
                Op::Mul => builder.build_int_mul(x, y, "").unwrap(),
                Op::Xor => builder.build_xor(x, y, "").unwrap(),
                Op::Copy => x,
            };

            builder.build_store(slots[dst], value).unwrap();
        }

        match &block.term {
            Term::Ret(o) => {
                builder.build_return(Some(&operand(*o))).unwrap();
            }
            Term::Jump(t) => {
                builder.build_unconditional_branch(llvm_blocks[*t]).unwrap();
            }
            Term::Branch(cmp, x, y, t, f) => {
                let predicate = match cmp {
                    Cmp::Slt => IntPredicate::SLT,
                    Cmp::Ult => IntPredicate::ULT,
                    Cmp::Eq => IntPredicate::EQ,
                };

                let condition = builder.build_int_compare(predicate, operand(*x), operand(*y), "").unwrap();
                builder.build_conditional_branch(condition, llvm_blocks[*t], llvm_blocks[*f]).unwrap();
            }
        }
    }

    module.verify().unwrap();
    module.run_passes(PASSES, machine, PassBuilderOptions::create()).unwrap();

    let mut program = Program::default();
    program.arch = Some(Architecture::X86_64);
    program.pointer_size = 8;

    let typedb = TypeDb::bundled(Platform::Unix, DataModel::new(Architecture::X86_64, false));
    let (globals, prototypes, noreturn) = (HashMap::default(), HashMap::default(), HashSet::default());
    let ctx = Context { program: &program, typedb: &typedb, globals: &globals, prototypes: &prototypes, noreturn: &noreturn, instruction: Box::new(|_| String::new()), ret: None, function: Box::new(|_| None), structs: Default::default(), callees: Default::default(), imported: Default::default(), sized: Default::default(), language: &crate::lang::c::C };

    return super::decompile(&module, function, &ctx, None, 0);
}

/*
 * Interpreter of the C: integers of their C type (wrapping, the usual arithmetic conversions)
 */

#[derive(Clone, Copy, Debug)]
struct Value {
    bits: u32,
    signed: bool,
    raw: i128,
}

impl Value {
    fn new(raw: i128, bits: u32, signed: bool) -> Value {
        let masked = raw & ((1i128 << bits) - 1);
        let raw = if signed && masked >> (bits - 1) & 1 == 1 { masked - (1i128 << bits) } else { masked };
        return Value { bits, signed, raw };
    }

    fn of_type(raw: i128, ty: &CType) -> Value {
        return match ty.unqualified() {
            CType::Int { bits, signed } => Value::new(raw, *bits as u32, *signed),
            CType::Bool => Value::new((raw != 0) as i128, 8, false),
            CType::Char => Value::new(raw, 8, true),
            other => panic!("type {:?}", other),
        };
    }

    fn truth(self) -> bool {
        return self.raw != 0;
    }
}

enum Flow {
    Next,
    Break,
    Continue,
    Return(Option<Value>),
    Goto(String),
}

struct Interpreter<'a> {
    function: &'a CFunction,
    vars: HashMap<usize, Value>,
    steps: usize,
}

fn contains_label(stmt: &Stmt, label: &str) -> bool {
    return match &stmt.kind {
        StmtKind::Label(l) => l == label,
        StmtKind::If(_, a, b) => a.iter().chain(b.iter()).any(|s| contains_label(s, label)),
        StmtKind::While(_, body) | StmtKind::DoWhile(body, _) | StmtKind::For(_, _, _, body) => body.iter().any(|s| contains_label(s, label)),
        StmtKind::Switch(_, cases, default) => cases.iter().flat_map(|c| c.body.iter()).chain(default.iter()).any(|s| contains_label(s, label)),
        _ => false,
    };
}

impl Interpreter<'_> {
    fn eval(&mut self, e: &Expr) -> Value {
        return match e {
            Expr::Var(v) => *self.vars.get(v).unwrap_or_else(|| panic!("{} read before it is written", self.function.vars[*v].name)),
            Expr::Int(c) => Value::new(*c, if i32::try_from(*c).is_ok() { 32 } else { 64 }, true),
            Expr::Char(c) => Value::new(*c as i128, 32, true),
            Expr::Cast(ty, inner) => {
                let value = self.eval(inner);
                Value::of_type(value.raw, ty)
            }
            Expr::Unary(op, inner) => {
                let value = self.eval(inner);
                let value = Value::new(value.raw, value.bits.max(32), value.signed || value.bits < 32);

                match op {
                    UnaryOp::Neg => Value::new(-value.raw, value.bits, value.signed),
                    UnaryOp::Not => Value::new(!value.raw, value.bits, value.signed),
                    UnaryOp::LogicalNot => Value::new(!value.truth() as i128, 32, true),
                    _ => panic!("unary {:?}", op),
                }
            }
            Expr::Binary(BinaryOp::LogicalAnd, a, b) => Value::new((self.eval(a).truth() && self.eval(b).truth()) as i128, 32, true),
            Expr::Binary(BinaryOp::LogicalOr, a, b) => Value::new((self.eval(a).truth() || self.eval(b).truth()) as i128, 32, true),
            Expr::Binary(op, a, b) => {
                let (a, b) = (self.eval(a), self.eval(b));

                // Promotion to int, then the type of the operand of higher rank (unsigned wins at equal rank)
                let promote = |v: Value| if v.bits < 32 { Value::new(v.raw, 32, true) } else { v };
                let (a, b) = (promote(a), promote(b));
                let bits = a.bits.max(b.bits);
                let signed = if a.bits == b.bits { a.signed && b.signed } else if a.bits > b.bits { a.signed } else { b.signed };
                let (x, y) = (Value::new(a.raw, bits, signed).raw, Value::new(b.raw, bits, signed).raw);

                let boolean = |c: bool| Value::new(c as i128, 32, true);

                match op {
                    BinaryOp::Add => Value::new(x + y, bits, signed),
                    BinaryOp::Sub => Value::new(x - y, bits, signed),
                    BinaryOp::Mul => Value::new(x.wrapping_mul(y), bits, signed),
                    BinaryOp::And => Value::new(x & y, bits, signed),
                    BinaryOp::Or => Value::new(x | y, bits, signed),
                    BinaryOp::Xor => Value::new(x ^ y, bits, signed),
                    BinaryOp::Shl => Value::new(x << (b.raw & 127), a.bits, a.signed),
                    BinaryOp::Shr => Value::new(Value::new(a.raw, a.bits, a.signed).raw >> (b.raw & 127), a.bits, a.signed),
                    BinaryOp::Lt => boolean(x < y),
                    BinaryOp::Le => boolean(x <= y),
                    BinaryOp::Gt => boolean(x > y),
                    BinaryOp::Ge => boolean(x >= y),
                    BinaryOp::Eq => boolean(x == y),
                    BinaryOp::Ne => boolean(x != y),
                    _ => panic!("binary {:?}", op),
                }
            }
            Expr::Ternary(c, a, b) => {
                if self.eval(c).truth() {
                    self.eval(a)
                } else {
                    self.eval(b)
                }
            }
            Expr::Name(name) if name == "true" || name == "false" => self.eval(&Expr::Int((name == "true") as i128)),
            other => panic!("expression {:?}", other),
        };
    }

    fn run(&mut self, stmts: &[Stmt], mut label: Option<&str>) -> Flow {
        let start = match label {
            Some(l) => match stmts.iter().position(|s| contains_label(s, l)) {
                Some(p) => p,
                None => return Flow::Goto(l.to_string()),
            },
            None => 0,
        };

        for stmt in stmts[start..].iter() {
            self.steps += 1;

            if self.steps > STEPS * 20 {
                return Flow::Return(None);
            }

            let flow = self.stmt(stmt, label.take());

            if !matches!(flow, Flow::Next) {
                return flow;
            }
        }

        return Flow::Next;
    }

    fn assign(&mut self, stmt: &Stmt) {
        if let StmtKind::Assign(Expr::Var(v), value) = &stmt.kind {
            let value = self.eval(value);
            self.vars.insert(*v, Value::of_type(value.raw, &self.function.vars[*v].ty));
        }
    }

    fn stmt(&mut self, stmt: &Stmt, label: Option<&str>) -> Flow {
        match &stmt.kind {
            StmtKind::Assign(Expr::Var(_), _) => self.assign(stmt),
            StmtKind::Label(_) | StmtKind::Comment(_) => {}
            StmtKind::Break => return Flow::Break,
            StmtKind::Continue => return Flow::Continue,
            StmtKind::Return(value) => {
                let value = value.as_ref().map(|e| self.eval(e));
                return Flow::Return(value);
            }
            StmtKind::Goto(l) => return Flow::Goto(l.clone()),
            StmtKind::If(c, a, b) => {
                let inside = |s: &[Stmt]| label.is_some_and(|l| s.iter().any(|x| contains_label(x, l)));

                return if inside(a) {
                    self.run(a, label)
                } else if inside(b) {
                    self.run(b, label)
                } else if self.eval(c).truth() {
                    self.run(a, None)
                } else {
                    self.run(b, None)
                };
            }
            StmtKind::While(c, body) | StmtKind::DoWhile(body, c) | StmtKind::For(_, c, _, body) => {
                let (do_while, step) = match &stmt.kind {
                    StmtKind::DoWhile(..) => (true, None),
                    StmtKind::For(init, _, step, _) => {
                        if label.is_none() {
                            self.assign(init);
                        }

                        (false, Some(step))
                    }
                    _ => (false, None),
                };

                let mut label = label;

                loop {
                    if label.is_none() && !do_while && !self.eval(c).truth() {
                        break;
                    }

                    match self.run(body, label.take()) {
                        Flow::Break => break,
                        Flow::Next | Flow::Continue => {}
                        other => return other,
                    }

                    if self.steps > STEPS * 20 {
                        return Flow::Return(None);
                    }

                    if let Some(step) = step {
                        self.assign(step);
                    }

                    if do_while && !self.eval(c).truth() {
                        break;
                    }
                }
            }
            StmtKind::Switch(value, cases, default) => {
                let mut bodies: Vec<&Vec<Stmt>> = cases.iter().map(|c| &c.body).collect();
                bodies.push(default);

                let start = match label.and_then(|l| bodies.iter().position(|b| b.iter().any(|s| contains_label(s, l)))) {
                    Some(i) => i,
                    // The case values are converted to the type of the switched value
                    None => {
                        let v = self.eval(value);
                        let v = Value::new(v.raw, v.bits.max(32), v.signed || v.bits < 32);
                        cases.iter().position(|c| c.values.iter().any(|&x| Value::new(x, v.bits, v.signed).raw == v.raw)).unwrap_or(cases.len())
                    }
                };

                let mut label = label;

                for body in bodies[start..].iter() {
                    match self.run(body, label.take()) {
                        Flow::Next => {}
                        Flow::Break => break,
                        other => return other,
                    }
                }
            }
            other => panic!("statement {:?}", other),
        }

        return Flow::Next;
    }

    /// Runs the function, following its gotos
    fn call(function: &CFunction, args: &[i32]) -> Option<i32> {
        let mut interpreter = Interpreter { function, vars: HashMap::default(), steps: 0 };

        for (&param, &arg) in function.params.iter().zip(args.iter()) {
            interpreter.vars.insert(param, Value::of_type(arg as i128, &function.vars[param].ty));
        }

        let mut label: Option<String> = None;

        loop {
            match interpreter.run(&function.body, label.as_deref()) {
                Flow::Goto(l) => label = Some(l),
                Flow::Return(Some(value)) => return Some(value.raw as i32),
                _ => return None,
            }
        }
    }
}

/// Calls are the helpers the C cannot express (__builtin_usub...), not run
fn has_calls(stmts: &[Stmt]) -> bool {
    fn calls(e: &Expr) -> bool {
        let mut found = false;
        e.visit(&mut |e| found |= matches!(e, Expr::Call(..)));
        return found;
    }

    return stmts.iter().any(|stmt| match &stmt.kind {
        StmtKind::Expr(e) | StmtKind::NoReturn(e) | StmtKind::Return(Some(e)) => calls(e),
        StmtKind::Assign(a, b) => calls(a) || calls(b),
        StmtKind::If(c, a, b) => calls(c) || has_calls(a) || has_calls(b),
        StmtKind::While(c, body) | StmtKind::DoWhile(body, c) => calls(c) || has_calls(body),
        StmtKind::For(init, c, step, body) => calls(c) || has_calls(std::slice::from_ref(init)) || has_calls(std::slice::from_ref(step)) || has_calls(body),
        StmtKind::Switch(c, cases, default) => calls(c) || cases.iter().any(|case| has_calls(&case.body)) || has_calls(default),
        _ => false,
    });
}

#[test]
fn random_programs_keep_their_results() {
    let machine = machine();
    let inputs: [(i32, i32); 6] = [(0, 0), (1, 2), (-5, 7), (100, -3), (7, 7), (-1, i32::MAX)];
    let (mut checked, mut skipped) = (0, 0);

    for seed in 0..4000u64 {
        let program = random_program(seed);
        let function = decompile(&program, &machine);

        if has_calls(&function.body) {
            skipped += 1;
            continue;
        }

        checked += 1;

        for &(a, b) in inputs.iter() {
            let Some(expected) = run_program(&program, a, b) else {
                continue;
            };

            let actual = Interpreter::call(&function, &[a, b]);

            assert_eq!(actual, Some(expected), "seed {} args ({}, {}):\n{:?}\n{}", seed, a, b, program, function.print().text);
        }
    }

    assert!(skipped * 20 < checked, "{} programs checked, {} skipped", checked, skipped);
}
