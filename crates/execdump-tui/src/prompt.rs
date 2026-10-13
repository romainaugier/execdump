/*
 * Command line and search: the text typed after : or /, run with Enter (the tables are filtered while
 * the search is typed)
 */

use super::*;

impl App {
    /// Keys of the command line or of the search
    pub(crate) fn prompt_key(&mut self, key: KeyEvent) {
        let Some((kind, mut text)) = self.input.take() else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                if kind == InputKind::Search {
                    if let View::Table(view) = self.view_mut() {
                        view.set_filter("");
                    }
                }
            }
            KeyCode::Enter => match kind {
                InputKind::Command => self.run_command(&text),
                InputKind::Search => self.run_search(&text),
            },
            KeyCode::Backspace => {
                if text.pop().is_some() {
                    self.input = Some((kind, text.clone()));
                }

                if kind == InputKind::Search {
                    if let View::Table(view) = self.view_mut() {
                        view.set_filter(&text);
                    }
                }
            }
            KeyCode::Char(c) => {
                text.push(c);

                // Tables are filtered while typing
                if kind == InputKind::Search {
                    if let View::Table(view) = self.view_mut() {
                        view.set_filter(&text);
                    }
                }

                self.input = Some((kind, text));
            }
            _ => self.input = Some((kind, text)),
        }
    }

    pub(crate) fn run_search(&mut self, pattern: &str) {
        let pattern = if pattern.is_empty() { self.last_search.clone() } else { pattern.to_string() };
        self.last_search = pattern.clone();

        let App { workspace, projects, programs, decoders, .. } = self;

        let found = match workspace.view_mut() {
            View::Table(view) => {
                view.set_filter(&pattern);
                true
            }
            View::Graph(view) => view.search(&pattern),
            View::Disasm(view) => decoders[view.program].as_ref().is_some_and(|d| view.search(&pattern, &programs[view.program], d)),
            View::Source(view) => projects[view.program].as_mut().is_some_and(|p| view.search(p, &pattern)),
            View::Dump(view) => view.search(&pattern),
            _ => false,
        };

        if !found {
            self.error(format!("Pattern not found: {}", pattern));
        }
    }
}
