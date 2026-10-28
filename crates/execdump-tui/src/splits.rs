// SPDX-License-Identifier: Apache-2.0
/*
 * Splits and tabs: the workspace of the content, the jumplist of each tab (Ctrl-o / Ctrl-i), the links
 * between splits (their cursors follow each other)
 */

use super::*;

use crate::commands::Command;

impl App {
    pub(crate) fn open(&mut self, view: View) {
        match std::mem::replace(&mut self.open_mode, OpenMode::Replace) {
            OpenMode::Replace => {
                let tab = self.workspace.tab_mut();
                let previous = std::mem::replace(&mut tab.view, view);

                if !matches!(previous, View::Welcome) {
                    tab.back.push(previous);
                }

                tab.forward.clear();
            }
            OpenMode::Tab => self.workspace.new_tab(view),
            OpenMode::Split(dir) => {
                self.workspace.split(dir, view);
            }
        }

        self.focus = Focus::Content;
    }

    pub(crate) fn go_back(&mut self) {
        let tab = self.workspace.tab_mut();

        if let Some(view) = tab.back.pop() {
            let current = std::mem::replace(&mut tab.view, view);
            tab.forward.push(current);
        } else {
            self.info("Already at the oldest view".to_string());
        }
    }

    pub(crate) fn go_forward(&mut self) {
        let tab = self.workspace.tab_mut();

        if let Some(view) = tab.forward.pop() {
            let current = std::mem::replace(&mut tab.view, view);
            tab.back.push(current);
        } else {
            self.info("Already at the newest view".to_string());
        }
    }

    /// Opens the next view in a split, or in the current tab when there is no target
    pub(crate) fn split(&mut self, dir: Dir, target: Option<&str>) {
        match target {
            Some(target) => {
                let program = self.current_program();

                match self.resolve_address(program, target) {
                    Some(addr) => {
                        self.open_mode = OpenMode::Split(dir);
                        self.goto_address(program, addr);
                        self.open_mode = OpenMode::Replace;
                    }
                    None => self.error(format!("Unknown address or function: {}", target)),
                }
            }
            None => {
                let view = self.view().clone();
                self.workspace.split(dir, view);
            }
        }

        self.focus = Focus::Content;
    }

    pub(crate) fn close_tab(&mut self, force: bool) {
        if !self.workspace.close_tab() {
            self.quit(force);
        }
    }

    pub(crate) fn focus_dir(&mut self, dir: Dir) {
        if !self.workspace.focus_dir(dir) && dir == Dir::Left && self.explorer_visible {
            self.focus = Focus::Explorer;
        }
    }

    /// Commands of the splits and the tabs
    pub(crate) fn splits_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let times = count.unwrap_or(1).max(1) as i32;

        match command {
            Command::Split { dir, target } => self.split(*dir, target.as_deref()),
            Command::TabNew(target) => match target {
                Some(target) => {
                    let program = self.current_program();

                    match self.resolve_address(program, target) {
                        Some(addr) => {
                            self.open_mode = OpenMode::Tab;
                            self.goto_address(program, addr);
                            self.open_mode = OpenMode::Replace;
                        }
                        None => self.error(format!("Unknown address or function: {}", target)),
                    }
                }
                None => {
                    let view = self.view().clone();
                    self.workspace.new_tab(view);
                    self.focus = Focus::Content;
                }
            },
            Command::TabClose => self.close_tab(false),
            Command::TabNext => match count {
                Some(n) => self.workspace.goto_tab(n),
                None => self.workspace.cycle_tab(true),
            },
            Command::TabPrevious => self.workspace.cycle_tab(false),
            // From the explorer, the splits are on the right
            Command::FocusSplit(Dir::Right) if self.focus == Focus::Explorer => self.focus = Focus::Content,
            Command::FocusSplit(dir) => {
                self.focus = Focus::Content;
                self.focus_dir(*dir);
            }
            _ => {
                match command {
                    Command::Only => self.workspace.only(),
                    Command::Link => self.toggle_link(),
                    Command::NextSplit => self.workspace.cycle_group(true),
                    Command::PreviousSplit => self.workspace.cycle_group(false),
                    Command::LastSplit => self.workspace.focus_previous(),
                    Command::CloseSplit => {
                        let focused = self.workspace.focused;

                        if !self.workspace.close_group(focused) {
                            self.quit(false);
                        }
                    }
                    Command::MoveTab(dir) => self.workspace.move_tab(*dir),
                    // Without splits side by side, the explorer gives or takes the width
                    Command::Equalize if self.workspace.group_count() == 1 => self.explorer_resize(None),
                    Command::Equalize => self.workspace.equalize(),
                    Command::Resize { width, delta } => {
                        if !self.workspace.resize(*width, delta * times) && *width {
                            self.explorer_resize(Some(-delta * times));
                        }
                    }
                    _ => return false,
                }

                self.focus = Focus::Content;
            }
        }

        return true;
    }

    pub(crate) fn toggle_link(&mut self) {
        if self.workspace.toggle_link() {
            self.synced = None;
            self.info("Linked with the previous split: their cursors follow each other".to_string());
        } else {
            self.info("Unlinked".to_string());
        }
    }

    /// Moves the linked split to the address under the cursor of the focused one
    pub(crate) fn sync_linked(&mut self) {
        let Some(linked) = self.workspace.linked(self.workspace.focused) else {
            return;
        };

        let App { workspace, projects, .. } = self;
        let Some((program, addr)) = Self::view_addr(workspace.view(), projects) else {
            return;
        };

        if self.synced == Some((program, addr)) {
            return;
        }

        self.synced = Some((program, addr));

        let function = self.analyses[program].as_ref().and_then(|a| a.function_containing(addr)).map(|f| f.addr);

        // The linked view follows in place when it can, otherwise it is replaced by the same kind of view
        enum Replace {
            Source,
            Linear(u64),
            Cfg(u64),
        }

        let replace = {
            let App { workspace, projects, .. } = self;
            let group = workspace.group_mut(linked);
            let active = group.active;

            match &mut group.tabs[active].view {
                View::Source(source) if source.program == program => match projects[program].as_mut() {
                    Some(project) => if source.goto(project, addr) { None } else { Some(Replace::Source) },
                    None => None,
                },
                View::Disasm(disasm) if disasm.program == program => {
                    if disasm.goto(addr) { None } else { function.map(Replace::Linear) }
                }
                View::Graph(graph) if graph.program == program => match graph.kind {
                    GraphKind::Cfg { function: shown } if Some(shown) == function => {
                        graph.select_addr(addr);
                        None
                    }
                    GraphKind::Cfg { .. } => function.map(Replace::Cfg),
                    GraphKind::CallGraph { .. } => {
                        if let Some(index) = function.and_then(|f| graph.nodes.iter().position(|n| n.kind == NodeKind::Function && n.addr == f)) {
                            graph.select(index);
                        }

                        None
                    }
                },
                _ => None,
            }
        };

        let view = match replace {
            None => return,
            Some(Replace::Source) => self.source_view(program, addr).map(View::Source),
            Some(Replace::Linear(function)) => match (self.analyses[program].clone(), self.decoders[program].as_ref()) {
                (Some(analysis), Some(decoder)) => DisasmView::function(program, &self.programs[program], &analysis, decoder, function).map(|mut v| {
                    v.goto(addr);
                    View::Disasm(v)
                }),
                _ => None,
            },
            Some(Replace::Cfg(function)) => self.cfg_view(program, function).map(|mut g| {
                g.select_addr(addr);
                View::Graph(g)
            }),
        };

        if let Some(view) = view {
            let group = self.workspace.group_mut(linked);
            let active = group.active;
            group.tabs[active].view = view;
        }
    }
}

/// A split: its border, its tab bar when it has several tabs, and the view of its active tab
pub(crate) fn render_group(f: &mut Frame, app: &mut App, theme: &Theme, id: workspace::GroupId, area: Rect, focused: bool) {
    let active = focused && app.focus == Focus::Content;
    let linked = app.workspace.linked(id).is_some();
    let group = app.workspace.group(id);
    let view = &group.tabs[group.active].view;

    let title = format!(" {}{} ", view.title(), if linked { " [linked]" } else { "" });

    let block = Block::default()
        .title(Span::styled(title, theme.title_style()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if active { theme.highlight_bg } else { theme.border }))
        .style(theme.base());

    let mut inner = block.inner(area);
    f.render_widget(block, area);

    if group.tabs.len() > 1 && inner.height > 1 {
        let mut spans = Vec::new();

        for (index, tab) in group.tabs.iter().enumerate() {
            let style = if index == group.active { Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg) } else { Style::default().fg(theme.dim) };
            spans.push(Span::styled(format!(" {}:{} ", index + 1, tab.view.tab_title()), style));
            spans.push(Span::raw(" "));
        }

        f.render_widget(Paragraph::new(Line::from(spans)).style(theme.base()), Rect::new(inner.x, inner.y, inner.width, 1));
        inner = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    }

    app.render_view(f, theme, id, inner);
}
