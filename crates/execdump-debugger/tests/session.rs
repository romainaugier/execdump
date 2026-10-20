/*
 * Sessions with the debuggers found on the machine (gdb, lldb) on a program built with the C compiler: the tests
 * of a debugger that is not installed are skipped
 */

use execdump_core::elf::parse_elf;
use execdump_core::exec::Exec;
use execdump_core::program::{programs_from_exec, Program};
use execdump_debugger::session::Config;
use execdump_debugger::{find, Event, Kind, Request, Run, Session, Snapshot, Until};

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(60);

fn sources() -> [PathBuf; 2] {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/src");
    return [dir.join("debuggee.c"), dir.join("debuggee_util.c")];
}

/// The debuggee built in a directory of its own, position independent or not (None without a C compiler)
fn build(dir: &Path, pie: bool) -> Option<PathBuf> {
    let output = dir.join(if pie { "debuggee" } else { "debuggee-no-pie" });
    let pie_flag = if pie { "-pie" } else { "-no-pie" };
    let status = Command::new("cc").args(["-O1", "-g0", "-fno-stack-protector", "-fno-inline", pie_flag]).args(sources()).arg("-o").arg(&output).status().ok()?;
    return status.success().then_some(output);
}

fn registers() -> (Vec<String>, &'static str, &'static str) {
    if cfg!(target_arch = "aarch64") {
        let mut names: Vec<String> = (0..31).map(|i| format!("x{}", i)).collect();
        names.extend(["sp".to_string(), "pc".to_string()]);
        return (names, "sp", "x0");
    }

    let names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags", "xmm0"].iter().map(|s| s.to_string()).collect();
    return (names, "rsp", "rdi");
}

fn next(session: &Session) -> Event {
    let start = Instant::now();

    while start.elapsed() < WAIT {
        match session.poll() {
            Some(Event::Running) => {}
            Some(event) => return event,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }

    panic!("no event from the debugger");
}

fn stopped(session: &Session) -> Snapshot {
    return match next(session) {
        Event::Stopped(snapshot) => snapshot,
        other => panic!("expected a stop, got {:?}", other),
    };
}

fn symbol(program: &Program, name: &str) -> u64 {
    return program.symbols.values().find(|s| s.name == name).unwrap_or_else(|| panic!("no symbol {}", name)).addr;
}

fn session(kind: Kind) {
    for pie in [true, false] {
        session_on(kind, pie);
    }
}

fn session_on(kind: Kind, pie: bool) {
    let Some((kind, debugger)) = find(Some(kind), None) else {
        eprintln!("{} is not installed, skipped", kind.name());
        return;
    };

    let dir = std::env::temp_dir().join(format!("execdump-debugger-{}-{}", kind.name(), std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let Some(binary) = build(&dir, pie) else {
        eprintln!("no C compiler, skipped");
        return;
    };

    let program = programs_from_exec(&Exec::ELF(parse_elf(&binary).unwrap())).remove(0);
    let (registers, sp, first_arg) = registers();
    let output = dir.join("output.txt");

    let config = Config { kind, debugger, program: binary.clone(), args: Vec::new(), output: output.clone(), input: None, link_entry: program.entry.unwrap(), registers, stack_pointer: sp.to_string() };
    let session = Session::start(config);

    let bias = match next(&session) {
        Event::Started { bias, .. } => bias,
        other => panic!("not started: {:?}", other),
    };

    assert_eq!(bias == 0, !pie, "load bias {:#x}", bias);

    // A breakpoint at the start of greet: its argument points to "world", main called it
    let greet = symbol(&program, "greet") + bias;
    session.send(Request::Breakpoints(vec![greet]));
    session.send(Request::Run(Run::Continue));

    let at_greet = stopped(&session);
    assert_eq!(at_greet.pc, greet);
    assert_eq!(at_greet.frames.get(1).map(|f| f.function.as_str()), Some("main"));
    assert!(at_greet.sp != 0 && !at_greet.stack.is_empty());

    let name = at_greet.register(first_arg).unwrap() as u64;
    session.send(Request::Read { addr: name, len: 5 });
    assert_eq!(next(&session), Event::Memory { addr: name, bytes: b"world".to_vec() });

    // Back to main, after the call
    session.send(Request::Run(Run::Finish));
    let in_main = stopped(&session);
    assert_eq!(in_main.pc, at_greet.frames[1].pc);

    // The lines of depth are only stops in the frame the step starts in: the entry of depth, its recursive calls
    // reach it again deeper in the stack (the stack pointer at the entry is the one of the frame minus the return
    // address on x86_64)
    let depth = symbol(&program, "depth") + bias;
    session.send(Request::Breakpoints(vec![depth]));
    session.send(Request::Run(Run::Continue));
    let first = stopped(&session);
    assert_eq!(first.pc, depth);

    session.send(Request::Breakpoints(Vec::new()));
    session.send(Request::Run(Run::Until(Until { stops: vec![(depth, Some(0))], entry_sp: Some(first.sp), returns: vec![first.frames[1].pc] })));
    let returned = stopped(&session);
    assert_eq!(returned.pc, first.frames[1].pc, "stopped in a recursive call instead of the return");

    // A return address that is not code (the unwinding of the entry of a process gives such values): gdb refuses
    // the breakpoint, the step is an error and the program stays where it is; lldb leaves it unresolved and the
    // program runs to its end
    session.send(Request::Run(Run::Until(Until { returns: vec![1], ..Until::default() })));

    match (kind, next(&session)) {
        (Kind::Gdb, Event::Error(_)) => {
            session.send(Request::Run(Run::Continue));
            assert_eq!(next(&session), Event::Exited(Some(0)));
        }
        (Kind::Lldb, Event::Exited(Some(0))) => {}
        (_, other) => panic!("unexpected {:?}", other),
    }

    assert_eq!(std::fs::read_to_string(&output).unwrap(), "hello world\n30 3\n");

    session.send(Request::Kill);
    assert_eq!(next(&session), Event::Ended);

    // A program that does not stop is interrupted
    let config = Config { kind, debugger: find(Some(kind), None).unwrap().1, program: binary, args: vec!["spin".to_string()], output, input: None, link_entry: program.entry.unwrap(), registers: vec![sp.to_string()], stack_pointer: sp.to_string() };
    let spinning = Session::start(config);
    assert!(matches!(next(&spinning), Event::Started { .. }));

    // Interrupted where it runs (the loader at first, the debuggers load the symbols of the libraries slowly), until
    // it is stopped in its loop; the reason depends on the debugger (SIGINT, SIGSTOP, nothing)
    let start = Instant::now();

    loop {
        spinning.send(Request::Run(Run::Continue));
        std::thread::sleep(Duration::from_millis(300));
        spinning.interrupt();

        let interrupted = stopped(&spinning);

        if interrupted.frames.iter().any(|f| f.function == "spin") {
            break;
        }

        assert!(start.elapsed() < WAIT, "never stopped in spin: {:?}", interrupted.frames);
    }

    spinning.stop();

    let _ = std::fs::remove_dir_all(&dir);
}

/// On a terminal the output of the program is there at each line, while it is stopped after it
#[cfg(unix)]
fn terminal(kind: Kind) {
    use execdump_debugger::terminal::Terminal;

    let Some((kind, debugger)) = find(Some(kind), None) else {
        eprintln!("{} is not installed, skipped", kind.name());
        return;
    };

    let dir = std::env::temp_dir().join(format!("execdump-terminal-{}-{}", kind.name(), std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let Some(binary) = build(&dir, true) else {
        eprintln!("no C compiler, skipped");
        return;
    };

    let program = programs_from_exec(&Exec::ELF(parse_elf(&binary).unwrap())).remove(0);
    let (registers, sp, _) = registers();
    let terminal = Terminal::open().unwrap();

    let config = Config { kind, debugger, program: binary, args: Vec::new(), output: terminal.path.clone(), input: Some(terminal.path.clone()), link_entry: program.entry.unwrap(), registers, stack_pointer: sp.to_string() };
    let session = Session::start(config);

    let bias = match next(&session) {
        Event::Started { bias, .. } => bias,
        other => panic!("not started: {:?}", other),
    };

    session.send(Request::Breakpoints(vec![symbol(&program, "depth") + bias]));
    session.send(Request::Run(Run::Continue));
    stopped(&session);

    let mut text = String::new();
    let start = Instant::now();

    while !text.contains("hello world") && start.elapsed() < WAIT {
        text.push_str(&String::from_utf8_lossy(&terminal.read()));
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(text.contains("hello world\r\n") && !text.contains("30 3"), "{:?}", text);

    session.send(Request::Kill);
    assert_eq!(next(&session), Event::Ended);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gdb_terminal() {
    terminal(Kind::Gdb);
}

#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn lldb_terminal() {
    terminal(Kind::Lldb);
}

#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gdb_session() {
    session(Kind::Gdb);
}

#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn lldb_session() {
    session(Kind::Lldb);
}
