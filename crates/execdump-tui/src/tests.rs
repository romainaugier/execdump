/*
 * Tests of the interface on the fixtures: navigation, splits and tabs, editing
 */

use super::*;
use execdump_core::elf::parse_elf;
use crossterm::event::KeyModifiers;
use ratatui::backend::TestBackend;

fn key(c: char) -> KeyEvent {
    return KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
}

fn ctrl(c: char) -> KeyEvent {
    return KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
}

fn keys(app: &mut App, text: &str) {
    for c in text.chars() {
        app.handle_key(key(c));
    }
}

fn enter(app: &mut App) {
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
}

/// App on the analysis fixture, with its project in a temporary directory
fn app(name: &str) -> (App, PathBuf) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_analysis");
    let location = std::env::temp_dir().join(format!("execdump-tui-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&location);

    let mut app = App::new(Exec::ELF(parse_elf(&path).unwrap()), path, KeyBindings::default(), Some(location.clone()), 1);

    for _ in 0..500 {
        app.poll_analysis();
        app.poll_projects();

        if app.projects.iter().all(|p| p.is_some()) {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(app.projects.iter().all(|p| p.is_some()), "Analysis did not finish");
    return (app, location);
}

fn wait_decompiled(app: &mut App) {
    for _ in 0..3000 {
        app.poll_projects();

        if app.projects.iter().flatten().all(|p| p.is_idle()) {
            return;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    panic!("Decompilation did not finish");
}

#[test]
fn navigate_views() {
    let (mut app, location) = app("navigate");
    let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();

    // Entry point graph
    enter(&mut app);
    assert!(matches!(app.view(), View::Graph(_)));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    // Command line: go to main
    keys(&mut app, ":main");
    enter(&mut app);
    let View::Graph(view) = app.view() else { panic!("Expected a graph") };
    assert!(view.title.starts_with("main"));

    for c in "njklhpggGtfc".chars() {
        app.handle_key(key(c));
        terminal.draw(|f| ui(f, &mut app)).unwrap();
    }

    // Linear view and back
    app.handle_key(key(' '));
    assert!(matches!(app.view(), View::Disasm(_)));
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    app.handle_key(key(' '));
    assert!(matches!(app.view(), View::Graph(_)));

    // Call graph from main, then back to the entry point graph
    app.handle_key(key('C'));
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    let View::Graph(view) = app.view() else { panic!("Expected a graph") };
    assert!(matches!(view.kind, GraphKind::CallGraph { .. }));
    app.handle_key(key('i'));
    app.handle_key(key('+'));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    // Up to the parent graph: classify is called from main, which is selected in it
    app.run_command("cg classify");
    app.handle_key(key('U'));
    if let Some(popup) = app.popup.take() {
        app.open_target(popup.items[0].1.clone());
    }
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    let analysis = app.analyses[0].clone().unwrap();
    let classify = analysis.function_by_name("classify").unwrap().addr;
    let View::Graph(view) = app.view() else { panic!("Expected a graph") };
    let GraphKind::CallGraph { root, .. } = view.kind else { panic!("Expected a call graph") };
    assert!(analysis.callers[&classify].contains(&root));
    assert_eq!(view.selected_node().addr, classify);

    for _ in 0..4 {
        app.handle_key(ctrl('o'));
    }

    let View::Graph(view) = app.view() else { panic!("Expected a graph") };
    assert!(matches!(view.kind, GraphKind::Cfg { .. }));

    // Tables
    app.run_command("functions");
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    app.run_search("main");
    enter(&mut app);
    assert!(matches!(app.view(), View::Graph(_)));

    for command in ["strings", "imports", "sections", "modules", ".text", "review"] {
        app.run_command(command);
        terminal.draw(|f| ui(f, &mut app)).unwrap();
    }

    // Every explorer item can be opened and rendered
    for i in 0..app.explorer_items.len() {
        app.explorer_state.select(Some(i));
        app.activate_explorer_item();
        terminal.draw(|f| ui(f, &mut app)).unwrap();
    }

    app.handle_key(key('?'));
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    app.handle_key(key('q'));
    assert!(!app.should_quit);
    app.handle_key(key('q'));
    assert!(app.should_quit);

    let _ = std::fs::remove_dir_all(&location);
}

#[test]
fn imports_open_in_their_library() {
    // ls calls getenv, exported by the C library
    let path = PathBuf::from("/bin/ls");

    if !path.exists() {
        return;
    }

    let location = std::env::temp_dir().join(format!("execdump-tui-libraries-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&location);
    let mut app = App::new(Exec::ELF(parse_elf(&path).unwrap()), path.clone(), KeyBindings::default(), Some(location.clone()), 1);
    let ready = |app: &mut App, program: usize| {
        for _ in 0..3000 {
            app.poll_analysis();
            app.poll_projects();

            if app.projects.get(program).is_some_and(|p| p.is_some()) {
                return;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("{} did not load", program);
    };

    ready(&mut app, 0);
    let libc = app.libraries.iter().position(|l| l.needed.name.starts_with("libc.so")).unwrap();
    assert!(app.explorer_items.contains(&ExplorerItem::Library(libc)));

    let getenv = app.analyses[0].as_ref().unwrap().functions.values().find(|f| f.thunk.as_deref() == Some("getenv")).unwrap().addr;
    app.open_function(0, getenv, None);
    let program = app.libraries[libc].program.unwrap();
    ready(&mut app, program);

    let View::Graph(graph) = app.view() else { panic!("Expected the graph of getenv") };
    assert_eq!(graph.program, program);
    assert!(graph.title.starts_with("getenv"), "{}", graph.title);
    assert!(app.libraries.len() > 2);

    // The library is a node of the explorer tree, under the libraries, with its analysis and modules
    app.poll_projects();
    let key = format!("lib{}", libc);
    let node = app.explorer_items.iter().position(|i| matches!(i, ExplorerItem::Group(k, _) if *k == key)).unwrap();
    assert_eq!(app.explorer_depths[node], 1);
    assert!(app.explorer_items.contains(&ExplorerItem::Functions(program)));
    app.toggle_explorer_group(&key);
    assert!(!app.explorer_items.contains(&ExplorerItem::Functions(program)));

    // The library is loaded again with the session
    app.run_command("w");
    let mut reopened = App::new(Exec::ELF(parse_elf(&path).unwrap()), path.clone(), KeyBindings::default(), Some(location.clone()), 1);
    ready(&mut reopened, 0);
    ready(&mut reopened, program);

    for _ in 0..10 {
        reopened.poll_analysis();
    }

    assert!(matches!(reopened.view(), View::Graph(g) if g.program == program && g.title.starts_with("getenv")));
    let _ = std::fs::remove_dir_all(&location);
}

#[test]
fn splits_tabs_and_links() {
    let (mut app, location) = app("splits");
    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
    wait_decompiled(&mut app);

    app.run_command("main");
    app.handle_key(ctrl('w'));
    app.handle_key(key('v'));
    assert_eq!(app.workspace.group_count(), 2);

    // The new split shows the code of main, linked with the graph
    app.run_command("c main");
    assert!(matches!(app.view(), View::Source(_)));
    app.handle_key(ctrl('w'));
    app.handle_key(key('b'));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    // Moving in the code moves the selection of the graph
    keys(&mut app, "jjjjjjjjjj");
    let source_addr = match app.view() {
        View::Source(_) => {
            let App { workspace, projects, .. } = &mut app;
            App::view_addr(workspace.view(), projects).unwrap().1
        }
        _ => panic!("Expected the C code"),
    };

    app.handle_key(ctrl('w'));
    app.handle_key(key('h'));
    let View::Graph(graph) = app.view() else { panic!("Expected the graph") };
    let analysis = app.analyses[0].clone().unwrap();
    let block = analysis.function_containing(source_addr).unwrap().block_containing(source_addr).unwrap().start;
    assert_eq!(graph.selected_node().addr, block);

    // Tabs in the graph split
    app.run_command("tabnew classify");
    assert_eq!(app.workspace.group(app.workspace.focused).tabs.len(), 2);
    keys(&mut app, "gt");
    assert!(matches!(app.view(), View::Graph(g) if g.title.starts_with("main")));
    keys(&mut app, "2gt");
    assert!(matches!(app.view(), View::Graph(g) if g.title.starts_with("classify")));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    // The tab moves to the code split
    app.handle_key(ctrl('w'));
    app.handle_key(key('L'));
    assert_eq!(app.workspace.group(app.workspace.focused).tabs.len(), 2);
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    app.run_command("q");
    app.run_command("only");
    assert_eq!(app.workspace.group_count(), 1);

    // Sessions: saved with the project, restored when it is opened again
    app.run_command("vs main");
    app.run_command("w");
    assert!(location.join("session.toml").exists());

    let mut reopened = App::new(Exec::ELF(parse_elf(&app.exec_path).unwrap()), app.exec_path.clone(), KeyBindings::default(), Some(location.clone()), 1);

    for _ in 0..500 {
        reopened.poll_analysis();

        if reopened.projects.iter().all(|p| p.is_some()) {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(reopened.workspace.group_count(), 2);
    assert!(matches!(reopened.view(), View::Graph(_)) || matches!(reopened.view(), View::Source(_)));

    let _ = std::fs::remove_dir_all(&location);
}

#[test]
fn code_editing_and_annotations() {
    let (mut app, location) = app("editing");
    let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
    wait_decompiled(&mut app);

    app.run_command("c main");
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    let View::Source(view) = app.view() else { panic!("Expected the C code") };
    assert_eq!(view.module, "analysis.c");
    let main = app.projects[0].as_ref().unwrap().resolve("main").unwrap();
    assert_eq!(view.function(), Some(main));

    // A comment above the first line, typed in insert mode
    keys(&mut app, "O");
    keys(&mut app, "// entry of the program");
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    let project = app.projects[0].as_mut().unwrap();
    let (text, shown) = project.shown(main).map(|(r, s)| (r.text.clone(), s)).unwrap();
    assert!(shown.edited);
    assert!(text.starts_with("// entry of the program\nint main("), "{}", text);

    // Undo, redo
    keys(&mut app, "u");
    assert!(!app.projects[0].as_mut().unwrap().shown(main).unwrap().1.edited);
    keys(&mut app, "U");
    assert!(app.projects[0].as_mut().unwrap().shown(main).unwrap().1.edited);

    // Enter on the call of classify moves to it (same module)
    let classify = app.projects[0].as_ref().unwrap().resolve("classify").unwrap();
    app.run_search("classify(");
    enter(&mut app);
    let View::Source(view) = app.view() else { panic!("Expected the C code") };
    assert_eq!(view.function(), Some(classify));

    // Rename classify from its code, and a variable
    keys(&mut app, "cn");
    assert!(app.input.as_ref().is_some_and(|(kind, t)| *kind == InputKind::Command && t.starts_with("rename ")));
    app.input = None;
    app.run_command("rename classify classify_value");
    app.run_command("rename a1 value");
    app.run_command("mv lib/classes.c");
    wait_decompiled(&mut app);
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    let project = app.projects[0].as_mut().unwrap();
    assert!(project.shown(classify).unwrap().0.text.starts_with("int classify_value(int value)"));
    assert_eq!(project.module_of(classify), Some("lib/classes.c"));

    // The edit of main was rebased on the new name of classify
    let main_text = project.shown(main).unwrap().0.text.clone();
    assert!(main_text.contains("classify_value(") && main_text.starts_with("// entry of the program"), "{}", main_text);

    // The view of analysis.c does not hold classify anymore
    let View::Source(view) = app.view() else { panic!("Expected the C code") };
    assert!(!view.functions.contains(&classify));

    app.run_command("export");
    let out = location.join("export");
    app.run_command(&format!("export {}", out.display()));
    assert!(out.join("src/lib/classes.c").exists(), "{:?}", app.message);

    // Unsaved changes keep the application open
    app.handle_key(key('q'));
    assert!(!app.should_quit);
    app.run_command("w");
    app.run_command("qa");
    assert!(app.should_quit);

    let _ = std::fs::remove_dir_all(&location);
}

#[test]
fn string_literal_forms() {
    let (mut app, location) = app("string");
    let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
    wait_decompiled(&mut app);

    app.run_command("c main");
    app.run_search("hello from");
    keys(&mut app, "gs");
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    let popup = app.popup.take().expect("the forms of the string");
    let labels: Vec<&str> = popup.items.iter().map(|(label, _)| label.split_whitespace().next().unwrap()).collect();
    assert_eq!(labels, ["text", "C", "bytes", "shell", "python", "length"]);
    assert_eq!(popup.items[0].1, Target::Copy("hello from the analysis fixture".to_string()));
    assert_eq!(popup.items[3].1, Target::Copy("$'hello from the analysis fixture'".to_string()));

    // Enter copies the selected form
    app.open_target(popup.items[2].1.clone());
    assert!(app.message.as_ref().is_some_and(|(text, _)| text.starts_with("Copied 68 65 6c 6c 6f")), "{:?}", app.message);

    let _ = std::fs::remove_dir_all(&location);
}

#[test]
fn visual_selection() {
    let (mut app, location) = app("visual");
    let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
    wait_decompiled(&mut app);

    app.run_command("c main");
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    let lines = |app: &mut App| -> (String, String) {
        let App { workspace, projects, .. } = app;
        let View::Source(view) = workspace.view_mut() else { panic!("Expected the C code") };
        let project = projects[0].as_mut().unwrap();
        let first = view.cursor_line(project);
        view.move_lines(project, 1);
        let second = view.cursor_line(project);
        view.move_lines(project, -1);
        (first, second)
    };

    let yanked = |app: &mut App| -> String {
        let App { workspace, projects, .. } = app;
        let View::Source(view) = workspace.view_mut() else { panic!("Expected the C code") };
        view.yank(projects[0].as_mut().unwrap(), 1).0
    };

    let (first, second) = lines(&mut app);

    // By characters: the whole first line, then from its start to the same column of the next one
    keys(&mut app, "0v$");
    assert!(matches!(app.view(), View::Source(v) if v.title().ends_with("-- VISUAL --")));
    assert_eq!(yanked(&mut app), first);

    keys(&mut app, "0vlj");
    let expected: String = second.chars().take(2).collect();
    assert_eq!(yanked(&mut app), format!("{}\n{}", first, expected));

    // By lines, drawn selected, y copies and leaves the mode
    keys(&mut app, "Vj");
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    let buffer = terminal.backend().buffer();
    assert!(buffer.content().iter().filter(|c| c.bg == Theme::codedark().highlight_bg).count() >= 10, "the selection is not drawn: {}", screen(&terminal));

    keys(&mut app, "y");
    // Without a display (the tests out of a desktop) only the terminal gets it
    assert!(app.message.as_ref().is_some_and(|(text, _)| text == "Yanked 2 lines" || text.contains("clipboard of the terminal only")), "{:?}", app.message);
    assert!(matches!(app.view(), View::Source(v) if v.visual.is_none()));

    keys(&mut app, "kkV");
    assert_eq!(yanked(&mut app), format!("{}\n", first));

    // v switches to characters, Esc leaves the mode
    keys(&mut app, "Vv");
    assert!(matches!(app.view(), View::Source(v) if v.visual.is_some_and(|s| !s.lines)));
    esc(&mut app);
    assert!(matches!(app.view(), View::Source(v) if v.visual.is_none()));

    // Deletions: the lines of main as edited, undo restores them
    let main = app.projects[0].as_ref().unwrap().resolve("main").unwrap();
    let code = |app: &mut App| -> Vec<String> { app.projects[0].as_mut().unwrap().shown(main).unwrap().0.text.lines().map(|l| l.to_string()).collect() };
    let original = code(&mut app);
    assert_eq!((original[1].as_str(), original[2].as_str()), ("{", "    int v3;"));

    // A word of a line
    keys(&mut app, "jj^ved");
    assert_eq!(code(&mut app)[2], "     v3;");
    keys(&mut app, "u");
    assert_eq!(code(&mut app), original);

    // From the brace to the first character of the next line, the end of the line between them included
    keys(&mut app, "k0vj0x");
    assert_eq!(code(&mut app)[1], "   int v3;");
    assert_eq!(code(&mut app).len(), original.len() - 1);
    keys(&mut app, "u");

    // Lines
    keys(&mut app, "gg");
    app.run_command("c main");
    keys(&mut app, "jjVjd");
    assert_eq!(code(&mut app).len(), original.len() - 2);
    assert_eq!(code(&mut app)[2], original[4]);
    keys(&mut app, "u");
    assert_eq!(code(&mut app), original);

    // A change deletes, then inserts
    keys(&mut app, "vec");
    assert!(matches!(app.view(), View::Source(v) if v.visual.is_none() && v.insert.is_some()));
    esc(&mut app);
    keys(&mut app, "u");
    assert_eq!(code(&mut app), original);

    // Not over two functions
    keys(&mut app, "vk]f");
    keys(&mut app, "d");
    assert!(app.message.as_ref().is_some_and(|(text, error)| *error && text.contains("several functions")), "{:?}", app.message);
    assert_eq!(code(&mut app), original);

    let _ = std::fs::remove_dir_all(&location);
}

fn esc(app: &mut App) {
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
}

#[test]
fn search_operators_and_completion() {
    let (mut app, location) = app("search");
    let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
    wait_decompiled(&mut app);

    app.run_command("c main");
    let main = app.projects[0].as_ref().unwrap().resolve("main").unwrap();
    let cursor = |app: &App| match app.view() {
        View::Source(view) => (view.cursor.block, view.cursor.line),
        _ => panic!("Expected the C code"),
    };

    // n / p go through the matches while the search is active, then through the functions again
    keys(&mut app, "/return");
    enter(&mut app);
    assert!(app.searching);
    let first = cursor(&app);
    keys(&mut app, "n");
    let second = cursor(&app);
    assert_ne!(first, second);
    keys(&mut app, "p");
    assert_eq!(cursor(&app), first);
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    esc(&mut app);
    assert!(!app.searching);
    keys(&mut app, "gg");
    keys(&mut app, "n");
    assert_eq!(cursor(&app), (1, 0));

    // dw deletes the first word of the line, u brings it back
    app.run_command("c main");
    let View::Source(view) = app.view() else { panic!("Expected the C code") };
    assert_eq!((view.function(), view.cursor.line), (Some(main), 0));
    let before = app.projects[0].as_mut().unwrap().shown(main).unwrap().0.text.clone();
    keys(&mut app, "0dw");
    let after = app.projects[0].as_mut().unwrap().shown(main).unwrap().0.text.clone();
    let first_line = before.lines().next().unwrap();
    let rest = first_line.split_once(' ').unwrap().1;
    assert_eq!(after.lines().next().unwrap(), rest, "{}", after);
    keys(&mut app, "u");
    assert_eq!(app.projects[0].as_mut().unwrap().shown(main).unwrap().0.text, before);

    // cw changes the word: insert mode in its place
    keys(&mut app, "cw");
    keys(&mut app, "long");
    esc(&mut app);
    let changed = app.projects[0].as_mut().unwrap().shown(main).unwrap().0.text.clone();
    assert!(changed.starts_with("long main("), "{}", changed);
    keys(&mut app, "u");

    // < > resize the explorer without splits, the splits with them
    let width = app.explorer_fit;
    keys(&mut app, "<");
    assert_eq!(app.explorer_width, Some(width + 5));
    keys(&mut app, "=");
    assert_eq!(app.explorer_width, None);
    app.run_command("vs");
    keys(&mut app, ">");
    assert_eq!(app.explorer_width, None);
    app.run_command("only");

    app.run_command("toggle-explorer");
    assert!(!app.explorer_visible);
    app.run_command("explorer");
    assert!(app.explorer_visible);

    // Suggestions: commands, then their arguments
    keys(&mut app, ":spl");
    assert_eq!(app.completion.as_ref().unwrap().items[0].text, "split");
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(app.input.as_ref().is_some_and(|(_, t)| t == "split"));
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    esc(&mut app);

    keys(&mut app, ":c clas");
    assert!(app.completion.as_ref().unwrap().items.iter().any(|s| s.text == "classify"));
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    enter(&mut app);
    let View::Source(view) = app.view() else { panic!("Expected the C code") };
    assert_eq!(view.function(), app.projects[0].as_ref().unwrap().resolve("classify"));

    // The command line keeps its history
    keys(&mut app, ":");
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    assert!(app.input.as_ref().is_some_and(|(_, t)| t == "c classify"));
    esc(&mut app);

    let _ = std::fs::remove_dir_all(&location);
}

/// Waits for the program under the debugger to stop (or to end)
fn wait_stopped(app: &mut App) {
    for _ in 0..6000 {
        app.poll_debugger();
        app.poll_projects();

        if app.debugger.as_ref().is_some_and(|d| matches!(d.state, debug::DebugState::Stopped | debug::DebugState::Exited(_) | debug::DebugState::Ended)) {
            return;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    panic!("The program did not stop");
}

/// Address in the binary the program is stopped at (in the selected frame)
fn stopped_at(app: &App) -> Option<u64> {
    let debugger = app.debugger.as_ref()?;
    return debugger.program_addr(&app.programs[0], debugger.frame_pc()?);
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    return buffer.content().chunks(buffer.area.width as usize).map(|row| row.iter().map(|c| c.symbol()).collect::<String>()).collect::<Vec<_>>().join("\n");
}

#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn debugging() {
    if execdump_debugger::find(None, None).is_none() {
        eprintln!("no debugger installed, skipped");
        return;
    }

    let dir = std::env::temp_dir().join(format!("execdump-tui-debug-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let sources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/src");
    let binary = dir.join("debuggee");
    // In the order of the sources: the static functions of debuggee_util.c are around its other functions
    let built = std::process::Command::new("cc").args(["-O1", "-fno-stack-protector", "-fno-inline", "-fno-toplevel-reorder"]).arg(sources.join("debuggee.c")).arg(sources.join("debuggee_util.c")).arg("-o").arg(&binary).status();

    if !built.is_ok_and(|s| s.success()) {
        eprintln!("no C compiler, skipped");
        return;
    }

    let mut app = App::new(Exec::ELF(parse_elf(&binary).unwrap()), binary.clone(), KeyBindings::default(), Some(dir.join("project")), 2);

    for _ in 0..1000 {
        app.poll_analysis();
        app.poll_projects();

        if app.projects[0].is_some() {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    wait_decompiled(&mut app);

    let function = |app: &App, name: &str| app.analyses[0].as_ref().unwrap().function_by_name(name).unwrap().addr;
    let (main, square_sum, depth) = (function(&app, "main"), function(&app, "square_sum"), function(&app, "depth"));
    let module = |app: &App, addr: u64| app.projects[0].as_ref().unwrap().module_of(addr).map(|m| m.to_string());
    assert_ne!(module(&app, main), module(&app, square_sum), "the two source files are two modules");

    let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();

    // Without a breakpoint the program stops at main, the C code of main and the debug view are shown
    app.run_command("debug");
    wait_stopped(&mut app);
    assert_eq!(stopped_at(&app), Some(main));
    assert!(app.workspace.group_ids().len() >= 2);
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    let shown = screen(&terminal);
    assert!(shown.contains('▶') && shown.contains("Call stack") && shown.contains("Registers"), "{}", shown);

    // Steps into the calls, until square_sum: the code of its module replaces the one of main
    for _ in 0..20 {
        if stopped_at(&app).is_some_and(|pc| app.analyses[0].as_ref().unwrap().function_containing(pc).is_some_and(|f| f.addr == square_sum)) {
            break;
        }

        app.run_command("step");
        wait_stopped(&mut app);
    }

    assert_eq!(stopped_at(&app), Some(square_sum));

    let sources_shown: Vec<String> = app.workspace.group_ids().into_iter().filter_map(|g| match &app.workspace.group(g).tabs[app.workspace.group(g).active].view {
        View::Source(source) => Some(source.module.clone()),
        _ => None,
    }).collect();

    assert!(sources_shown.contains(&module(&app, square_sum).unwrap()), "{:?}", sources_shown);

    // Its argument: argc + 3
    let variables = app.variables();
    assert!(variables.iter().any(|v| v.value.as_deref() == Some("4")), "{:?}", variables.iter().map(|v| (&v.name, &v.value, &v.location)).collect::<Vec<_>>());

    // Over the lines of square_sum, then out of it, back in main
    app.run_command("n");
    wait_stopped(&mut app);
    assert!(stopped_at(&app).is_some_and(|pc| pc > square_sum && app.analyses[0].as_ref().unwrap().function_containing(pc).is_some_and(|f| f.addr == square_sum)));

    app.run_command("finish");
    wait_stopped(&mut app);
    assert!(stopped_at(&app).is_some_and(|pc| app.analyses[0].as_ref().unwrap().function_containing(pc).is_some_and(|f| f.addr == main)));

    // A breakpoint in a recursion: the second stop is one frame deeper, the caller frame can be selected
    app.run_command("break depth");
    assert!(app.breakpoints.contains(&(0, depth)));
    app.run_command("continue");
    wait_stopped(&mut app);
    assert_eq!(stopped_at(&app), Some(depth));

    // The program runs on a terminal: what it printed is there while it is stopped
    for _ in 0..100 {
        app.poll_debugger();

        if !app.debugger.as_ref().unwrap().output_tail.is_empty() {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(app.debugger.as_ref().unwrap().output_tail, ["hello world"]);

    app.run_command("continue");
    wait_stopped(&mut app);
    let frames = app.debugger.as_ref().unwrap().snapshot.as_ref().unwrap().frames.clone();
    assert!(frames.len() >= 3 && app.frame_name(frames[1].pc, &frames[1].function).starts_with("depth+"), "{:?}", frames);

    app.run_command("frame 1");
    wait_stopped(&mut app);
    assert_eq!(app.debugger.as_ref().unwrap().snapshot.as_ref().unwrap().frame, 1);
    assert!(stopped_at(&app).is_some_and(|pc| pc > depth));
    terminal.draw(|f| ui(f, &mut app)).unwrap();

    // To the end: the output of the program in the debug view
    app.run_command("break depth");
    app.run_command("continue");
    wait_stopped(&mut app);
    assert!(matches!(app.debugger.as_ref().unwrap().state, debug::DebugState::Exited(Some(0))));

    for _ in 0..100 {
        app.poll_debugger();

        if !app.debugger.as_ref().unwrap().output_tail.is_empty() {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(app.debugger.as_ref().unwrap().output_tail, ["hello world", "30 3"]);
    terminal.draw(|f| ui(f, &mut app)).unwrap();
    assert!(screen(&terminal).contains("hello world"));

    app.run_command("kill");
    assert!(app.debugger.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
