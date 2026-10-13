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
