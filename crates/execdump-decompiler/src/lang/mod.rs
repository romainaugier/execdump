/*
 * Languages: what the decompiler knows of the code a compiler of a language makes and of its runtime
 *
 * A language is built in and answers hooks at each stage of the decompilation: the functions that do not return
 * (analysis), the calling convention and the signatures of its runtime (signatures), the calls that are not calls
 * (lifting), its idioms in the C (C), the modules of its functions (project) and where its programs start and which
 * calls a step goes over (debugger). The default of every hook is what C does, the C language is the one with no hook.
 *
 * Every program has the built-in languages, in their order of precedence. A function belongs to the first one that
 * owns it (the functions of the pclntab of a Go program are Go, the other ones are C: the C of cgo, called with the
 * calling convention of the platform), its hooks and its calling convention are the ones of its language. The
 * language of the program (Program::language) is the main one.
 *
 * The languages compiled to bytecode (.NET, Java) will be front ends of their own: they replace the disassembly and
 * the lifting, not hooks of them.
 */

pub(crate) mod c;
pub mod cxx;
pub mod go;
mod rust;

use crate::c::ast::CFunction;
use crate::lift::regs::{Abi, Reg, RegisterFile};
use crate::lift::{Env, LType, Lifter, Signature};
use crate::analysis::function::CallTarget;
use crate::types::{CType, DataModel, Prototype};

use execdump_core::demangle::symbol::Symbol;
use execdump_core::program::{Format, Language as Kind, Program};

/// How a prototype of the database of a language becomes the signature of a function
pub enum Mapping {
    /// With the calling convention of the platform (the parameters of C)
    Platform,
    Signature(Signature),
    /// The prototype is not the one of this function (another version of the runtime)
    Mismatch,
}

/// A call the lifter turns into an operation of its own
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intrinsic {
    /// memset(dst, 0, bytes), the register moves past them
    Zero { dst: Reg, bytes: u64 },
    /// memcpy(dst, src, bytes), the registers move past them
    Copy { dst: Reg, src: Reg, bytes: u64 },
}

pub trait Language: Send + Sync {
    fn kind(&self) -> Kind;

    /// Whether the function at an address is code of the language (its hooks and its calling convention are the ones
    /// of the function)
    fn owns(&self, _program: &Program, _addr: u64) -> bool {
        return false;
    }

    /// The calling convention of the functions of the language, None for the one of the platform
    fn abi(&self, _program: &Program, _regs: &RegisterFile) -> Option<Abi> {
        return None;
    }

    /// Signature of a function of the runtime with a convention of its own, before any discovery
    fn runtime_signature(&self, _program: &Program, _abi: &Abi, _regs: &RegisterFile, _symbol: &str, _name: &str) -> Option<Signature> {
        return None;
    }

    /// Types and prototypes of the runtime of the language (C declarations, one parameter per machine word), added to
    /// the type database of a program that has code of the language
    fn type_database(&self, _program: &Program) -> Option<&'static str> {
        return None;
    }

    /// The signature a prototype of the database gives to a function of the language
    fn prototype_signature(&self, _program: &Program, _abi: &Abi, _prototype: &Prototype, _addr: u64, _ltype: &dyn Fn(&CType) -> Option<LType>) -> Mapping {
        return Mapping::Platform;
    }

    /// Name of a global without a symbol from the metadata of the language (the type descriptors of Go)
    fn global_name(&self, _program: &Program, _addr: u64) -> Option<String> {
        return None;
    }

    /// The type a call returns a pointer to, known from the globals it is given (the type descriptor of an allocation
    /// of Go)
    fn returned_pointee(&self, _program: &Program, _callee: &str, _globals: &[Option<u64>]) -> Option<CType> {
        return None;
    }

    /// Prototype of a function from its demangled symbol (the prototypes of C++)
    fn demangled_prototype(&self, _symbol: &Symbol) -> Option<Prototype> {
        return None;
    }

    /// Bounds the discovered signature of a function with what the metadata of the language tells of it
    fn bound_signature(&self, _program: &Program, _abi: &Abi, _addr: u64, _sig: &mut Signature) {}

    /// Whether the callers of a function the program does not call directly may read its result (the function values
    /// without parameters of Go are the func() the runtime runs)
    fn result_read_elsewhere(&self, _program: &Program, _addr: u64) -> bool {
        return true;
    }

    /// The bytes a function of the runtime accesses from a pointer argument, when it is known to access no more (the
    /// object passed ends there in the frame of its caller)
    fn argument_extent(&self, _program: &Program, _callee: &str, _index: u32) -> Option<u64> {
        return None;
    }

    /// A call the lifter turns into an operation of its own (the blocks Go zeroes and copies with its runtime)
    fn intrinsic(&self, _env: &Env, _target: u64) -> Option<Intrinsic> {
        return None;
    }

    /// The signature of a call at the place of the call (arguments the callee finds after its own)
    fn call_signature(&self, _lifter: &Lifter, _target: &CallTarget, sig: Signature) -> Signature {
        return sig;
    }

    /// A call that runs the function again from its start (the growth of the stack of Go): the branch to it is
    /// not code of the function
    fn restarts_function(&self, _callee: &str) -> bool {
        return false;
    }

    /// The idioms of the compiler in the C of a function become what the program does (the write barriers of Go)
    fn rewrite_c(&self, _function: &mut CFunction) {}

    /// Module of a function from the metadata of the language (the source files of Go, the paths of Rust)
    fn source_module(&self, _program: &Program, _addr: u64) -> Option<String> {
        return None;
    }

    /// Module of a function guessed from its name (the namespaces and classes of C++), when nothing better is known
    fn guessed_module(&self, _program: &Program, _addr: u64) -> Option<String> {
        return None;
    }

    /// The functions a program starts with for its user (main.main of Go: its main is the entry of the runtime)
    fn entry_points(&self) -> &'static [&'static str] {
        return &[];
    }

    /// Calls a step into goes over (the growth of the stack of Go)
    fn steps_over(&self, _callee: &str) -> bool {
        return false;
    }
}

/// The built-in languages of a program, in their order of precedence, C last
pub struct Languages {
    list: Vec<Box<dyn Language>>,
    main: usize,
}

impl Languages {
    pub fn new(program: &Program) -> Self {
        let model = DataModel::new(program.architecture(), program.format == Format::Pe);
        let list: Vec<Box<dyn Language>> = vec![Box::new(go::Go), Box::new(rust::Rust), Box::new(cxx::Cxx::new(program, model)), Box::new(c::C)];
        let main = list.iter().position(|l| l.kind() == program.language).unwrap_or(list.len() - 1);

        return Languages { list, main };
    }

    /// The language of the program
    pub fn main(&self) -> &dyn Language {
        return self.list[self.main].as_ref();
    }

    pub fn main_index(&self) -> usize {
        return self.main;
    }

    pub fn get(&self, index: usize) -> &dyn Language {
        return self.list[index].as_ref();
    }

    pub fn len(&self) -> usize {
        return self.list.len();
    }

    pub fn is_empty(&self) -> bool {
        return self.list.is_empty();
    }

    /// Index of the language of a function, C when no other owns it
    pub fn owner_index(&self, program: &Program, addr: u64) -> usize {
        return self.list.iter().position(|l| l.owns(program, addr)).unwrap_or(self.list.len() - 1);
    }

    /// The language of a function
    pub fn owner(&self, program: &Program, addr: u64) -> &dyn Language {
        return self.get(self.owner_index(program, addr));
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Language> {
        return self.list.iter().map(|l| l.as_ref());
    }

    /// The first prototype a language gives to a demangled symbol
    pub fn demangled_prototype(&self, symbol: &Symbol) -> Option<Prototype> {
        return self.iter().find_map(|l| l.demangled_prototype(symbol));
    }

    pub fn global_name(&self, program: &Program, addr: u64) -> Option<String> {
        return self.iter().find_map(|l| l.global_name(program, addr));
    }

    pub fn source_module(&self, program: &Program, addr: u64) -> Option<String> {
        return self.iter().find_map(|l| l.source_module(program, addr));
    }

    pub fn guessed_module(&self, program: &Program, addr: u64) -> Option<String> {
        return self.iter().find_map(|l| l.guessed_module(program, addr));
    }

    /// The functions a program starts with: the ones of its language, then main
    pub fn entry_points(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.main().entry_points().to_vec();
        names.push("main");
        return names;
    }

    pub fn steps_over(&self, callee: &str) -> bool {
        return self.iter().any(|l| l.steps_over(callee));
    }
}

/// Well known functions that never return, of every language (the analysis runs before the languages of a program
/// are known)
pub fn is_noreturn_name(name: &str) -> bool {
    let name = name.rsplit('!').next().unwrap_or(name);
    let name = name.split('@').next().unwrap_or(name);
    let name = name.trim_start_matches('_');

    return c::noreturn(name) || cxx::noreturn(name) || rust::noreturn(name) || go::noreturn(name);
}

#[cfg(test)]
mod tests {
    use super::*;

    use execdump_core::golang::GoRuntime;
    use execdump_core::program::LanguageData;

    #[test]
    fn owners() {
        // A cgo program: the functions of the pclntab are Go, the other ones C
        let mut program = Program { language: Kind::Go, pointer_size: 8, ..Default::default() };
        let runtime = GoRuntime { register_abi: true, functions: [(0x1000, Some(16))].into_iter().collect(), types: None };
        program.language_data = LanguageData::Go(Box::new(runtime));

        let languages = Languages::new(&program);
        assert_eq!(languages.main().kind(), Kind::Go);
        assert_eq!(languages.owner(&program, 0x1000).kind(), Kind::Go);
        assert_eq!(languages.owner(&program, 0x2000).kind(), Kind::Unknown);
        assert_eq!(languages.entry_points(), ["main.main", "main"]);

        let c = Program { pointer_size: 8, ..Default::default() };
        assert_eq!(Languages::new(&c).owner(&c, 0x1000).kind(), Kind::Unknown);
        assert_eq!(Languages::new(&c).entry_points(), ["main"]);
    }
}
