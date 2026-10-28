// SPDX-License-Identifier: Apache-2.0
/*
 * Command line and search: the text typed after : or /, run with Enter (the tables are filtered while
 * the search is typed).
 *
 * The command line suggests what can be typed: the commands (with their arguments and their help) while
 * the name is typed, then the values of the argument being typed (functions, modules, libraries, files,
 * variables...). Tab and Shift-Tab go through the suggestions, Up and Down through the history.
 */

use super::*;

use crate::commands::{find_spec, Complete, SPECS};

/// Suggestions shown at most
const SUGGESTIONS: usize = 10;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Suggestion {
    /// Replaces the word being typed
    pub text: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Completion {
    /// Text before the word being typed
    pub prefix: String,
    pub items: Vec<Suggestion>,
    pub selected: Option<usize>,
    /// Usage and help of the command typed, when there is nothing to suggest
    pub hint: Option<String>,
}

/// The best candidates for a word: the ones starting with it, then the ones containing it
fn matching(candidates: impl Iterator<Item = (String, String)>, word: &str) -> Vec<Suggestion> {
    let lower = word.to_lowercase();
    let (mut starting, mut containing) = (Vec::new(), Vec::new());

    for (text, detail) in candidates {
        let candidate = text.to_lowercase();

        if candidate == lower {
            continue;
        }

        if candidate.starts_with(&lower) {
            starting.push(Suggestion { text, detail });
        } else if !lower.is_empty() && candidate.contains(&lower) {
            containing.push(Suggestion { text, detail });
        }
    }

    starting.sort_by(|a, b| a.text.len().cmp(&b.text.len()).then(a.text.cmp(&b.text)));
    containing.sort_by(|a, b| a.text.len().cmp(&b.text.len()).then(a.text.cmp(&b.text)));
    starting.dedup_by(|a, b| a.text == b.text);
    containing.dedup_by(|a, b| a.text == b.text);

    starting.extend(containing);
    starting.truncate(SUGGESTIONS);
    return starting;
}

/// Files and directories starting with a path
fn paths(word: &str) -> Vec<(String, String)> {
    let (dir, _) = word.rsplit_once('/').map_or(("", word), |(d, f)| (d, f));
    let read = if dir.is_empty() && !word.starts_with('/') { "." } else if dir.is_empty() { "/" } else { dir };

    let Ok(entries) = std::fs::read_dir(read) else {
        return Vec::new();
    };

    return entries
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let directory = e.file_type().is_ok_and(|t| t.is_dir());
            let path = if dir.is_empty() && !word.starts_with('/') { name } else { format!("{}/{}", dir, name) };
            (if directory { format!("{}/", path) } else { path }, if directory { "directory".to_string() } else { "file".to_string() })
        })
        .collect();
}

impl App {
    /// Keys of the command line or of the search
    pub(crate) fn prompt_key(&mut self, key: KeyEvent) {
        let Some((kind, mut text)) = self.input.take() else {
            return;
        };

        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        match key.code {
            KeyCode::Esc => {
                self.completion = None;
                self.history_index = None;

                if kind == InputKind::Search && self.focus == Focus::Explorer {
                    self.filter_explorer("");
                } else if kind == InputKind::Search {
                    if let View::Table(view) = self.view_mut() {
                        view.set_filter("");
                    }
                }

                return;
            }
            KeyCode::Enter => {
                self.completion = None;
                self.history_index = None;

                match kind {
                    InputKind::Command => {
                        if !text.trim().is_empty() && self.history.last() != Some(&text) {
                            self.history.push(text.clone());
                        }

                        self.run_command(&text);
                    }
                    InputKind::Search => self.run_search(&text),
                }

                return;
            }
            KeyCode::Tab | KeyCode::BackTab if kind == InputKind::Command => {
                self.input = Some((kind, text));
                return self.cycle_suggestion(!(key.code == KeyCode::BackTab || shift));
            }
            KeyCode::Up | KeyCode::Down if kind == InputKind::Command => {
                let older = key.code == KeyCode::Up;

                self.history_index = match (self.history_index, older) {
                    (None, true) => self.history.len().checked_sub(1),
                    (Some(i), true) => Some(i.saturating_sub(1)),
                    (Some(i), false) if i + 1 < self.history.len() => Some(i + 1),
                    _ => None,
                };

                text = self.history_index.map_or(String::new(), |i| self.history[i].clone());
            }
            KeyCode::Backspace => {
                if text.pop().is_none() {
                    self.completion = None;
                    return;
                }
            }
            KeyCode::Char(c) => text.push(c),
            _ => {
                self.input = Some((kind, text));
                return;
            }
        }

        // The explorer and the tables are filtered while typing
        if kind == InputKind::Search && self.focus == Focus::Explorer {
            self.filter_explorer(&text);
        } else if kind == InputKind::Search {
            if let View::Table(view) = self.view_mut() {
                view.set_filter(&text);
            }
        }

        if kind == InputKind::Command {
            self.completion = Some(self.complete(&text));
        }

        self.input = Some((kind, text));
    }

    /// Puts the next (or previous) suggestion in the command line
    fn cycle_suggestion(&mut self, forward: bool) {
        let Some(completion) = self.completion.as_mut().filter(|c| !c.items.is_empty()) else {
            return;
        };

        let count = completion.items.len();

        let selected = match (completion.selected, forward) {
            (None, true) => 0,
            (None, false) => count - 1,
            (Some(i), true) => (i + 1) % count,
            (Some(i), false) => (i + count - 1) % count,
        };

        completion.selected = Some(selected);
        let text = format!("{}{}", completion.prefix, completion.items[selected].text);

        if let Some((_, input)) = self.input.as_mut() {
            *input = text;
        }
    }

    /// Suggestions for a command line
    pub(crate) fn complete(&mut self, text: &str) -> Completion {
        let word_start = text.rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let (prefix, word) = text.split_at(word_start);
        let mut completion = Completion { prefix: prefix.to_string(), ..Default::default() };

        // The name of the command, or an address or a function to go to
        if prefix.trim().is_empty() {
            if word.is_empty() {
                return completion;
            }

            let commands = SPECS.iter().flat_map(|spec| {
                let detail = if spec.usage.is_empty() { spec.help.to_string() } else { format!("{}  {}", spec.usage, spec.help) };
                std::iter::once((spec.name.to_string(), detail.clone())).chain(spec.aliases.iter().map(move |a| (a.to_string(), format!("= {}", spec.name))))
            });

            completion.items = matching(commands, word);

            if completion.items.len() < SUGGESTIONS {
                let functions = matching(self.functions_named(), word);
                let room = SUGGESTIONS - completion.items.len();
                completion.items.extend(functions.into_iter().take(room));
            }

            return completion;
        }

        let mut words = prefix.split_whitespace();
        let name = words.next().unwrap_or("");
        let previous: Vec<&str> = words.collect();

        let Some(spec) = find_spec(name) else {
            return completion;
        };

        let candidates: Vec<(String, String)> = match (spec.complete, previous.as_slice()) {
            (Complete::Function, []) => self.functions_named().collect(),
            (Complete::Module, []) => self.module_names(),
            (Complete::Module, [_]) if spec.name == "mv" => self.functions_named().collect(),
            (Complete::Library, []) => self.libraries.iter().map(|l| (l.file_name(), if l.program.is_some() { "loaded".to_string() } else { l.needed.name.clone() })).chain(paths(word)).collect(),
            (Complete::Name, []) => {
                let names = self.names_in_function();
                names.into_iter().chain(self.functions_named()).collect()
            }
            (Complete::Llm, []) => vec![("modules".to_string(), "organize the modules".to_string())],
            (Complete::Llm, ["modules" | "mods"]) => std::iter::once(("all".to_string(), "every module".to_string())).chain(self.module_names()).collect(),
            (Complete::Path, []) => paths(word),
            (Complete::Proposal, []) => self.pending_proposals(),
            (Complete::Words(words), []) => words.iter().map(|w| (w.to_string(), String::new())).collect(),
            _ => Vec::new(),
        };

        completion.items = matching(candidates.into_iter(), word);

        if completion.items.is_empty() {
            completion.hint = Some(format!(":{} {}  {}", spec.name, spec.usage, spec.help));
        }

        return completion;
    }

    /// Functions of the current program by name, with their address
    fn functions_named(&self) -> impl Iterator<Item = (String, String)> + '_ {
        let program = self.current_program();
        let project = self.projects[program].as_ref();

        return self.analyses[program].iter().flat_map(|a| a.functions.values()).map(move |f| {
            let name = project.map_or(f.name.clone(), |p| p.function_name(f.addr));
            (name, format!("{:#x}", f.addr))
        });
    }

    fn module_names(&self) -> Vec<(String, String)> {
        let program = self.current_program();

        return self.projects[program]
            .as_ref()
            .map(|p| p.modules.names().map(|m| (m.clone(), format!("{} functions", p.modules.functions(m).len()))).collect())
            .unwrap_or_default();
    }

    /// Variables of the function under the cursor
    fn names_in_function(&mut self) -> Vec<(String, String)> {
        let App { workspace, projects, .. } = self;

        let View::Source(view) = workspace.view() else {
            return Vec::new();
        };

        let (Some(function), Some(project)) = (view.function(), projects[view.program].as_mut()) else {
            return Vec::new();
        };

        return project.shown(function).map_or(Vec::new(), |(rendered, _)| rendered.meta.vars.iter().map(|(_, shown)| (shown.clone(), "variable".to_string())).collect());
    }

    fn pending_proposals(&self) -> Vec<(String, String)> {
        let program = self.current_program();

        return self.projects[program]
            .as_ref()
            .map(|p| p.proposals.iter().filter(|p| p.is_pending()).map(|p| (p.id.to_string(), p.label.clone())).collect())
            .unwrap_or_default();
    }

    pub(crate) fn run_search(&mut self, pattern: &str) {
        let pattern = if pattern.is_empty() { self.last_search.clone() } else { pattern.to_string() };
        self.last_search = pattern.clone();

        if pattern.is_empty() {
            return;
        }

        if self.focus == Focus::Explorer {
            self.filter_explorer(&pattern);

            if self.explorer_items.is_empty() {
                self.error(format!("Pattern not found: {}", pattern));
            }

            return;
        }

        if let View::Table(view) = self.view_mut() {
            view.set_filter(&pattern);
            return;
        }

        // n / p go to the other matches until Esc
        self.searching = self.search_step(true);

        if !self.searching {
            self.error(format!("Pattern not found: {}", pattern));
        }
    }

    /// Next (or previous) match of the active search
    pub(crate) fn search_again(&mut self, forward: bool) {
        if self.last_search.is_empty() {
            return self.error("No search: / starts one".to_string());
        }

        if !self.search_step(forward) {
            self.error(format!("Pattern not found: {}", self.last_search));
        }
    }

    fn search_step(&mut self, forward: bool) -> bool {
        let App { workspace, projects, programs, decoders, last_search, .. } = self;
        let pattern = last_search.as_str();

        return match workspace.view_mut() {
            View::Graph(view) => view.search(pattern, forward),
            View::Disasm(view) => decoders[view.program].as_ref().is_some_and(|d| view.search(pattern, &programs[view.program], d, forward)),
            View::Source(view) => projects[view.program].as_mut().is_some_and(|p| view.search(p, pattern, forward)),
            View::Dump(view) => view.search(pattern, forward),
            _ => false,
        };
    }
}

/// The suggestions above the command line
pub(crate) fn render_completion(f: &mut Frame, theme: &Theme, completion: &Completion, line: Rect) {
    let rows: Vec<(String, String)> = match &completion.hint {
        Some(hint) => vec![(hint.clone(), String::new())],
        None => completion.items.iter().map(|s| (s.text.clone(), s.detail.clone())).collect(),
    };

    if rows.is_empty() {
        return;
    }

    let text_width = rows.iter().map(|(t, _)| t.chars().count()).max().unwrap_or(0);
    let width = rows.iter().map(|(_, d)| text_width + if d.is_empty() { 0 } else { d.chars().count() + 3 }).max().unwrap_or(0) as u16 + 2;
    let width = width.min(line.width);
    let height = (rows.len() as u16 + 2).min(line.y);
    let x = (line.x + 1 + completion.prefix.chars().count() as u16).min(line.x + line.width.saturating_sub(width));
    let area = Rect::new(x, line.y - height, width, height);

    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(index, (text, detail))| {
            let selected = completion.selected == Some(index);
            let style = if selected { Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg) } else { Style::default().fg(theme.fg) };
            let mut spans = vec![Span::styled(format!("{:<width$}", text, width = text_width), style)];

            if !detail.is_empty() {
                spans.push(Span::styled(format!("   {}", detail), if selected { style } else { Style::default().fg(theme.dim) }));
            }

            Line::from(spans)
        })
        .collect();

    f.render_widget(Clear, area);
    f.render_widget(Paragraph::new(Text::from(lines)).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.border)).style(theme.base())), area);
}
