/*
 * Review of the proposals of the LLM: the diff of each proposal (the C code before and after it, or
 * the moves of functions between modules), accepted or rejected one by one
 */

use crate::theme::Theme;
use crate::views::follow_cursor;

use execdump_project::Project;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

#[derive(Clone, Debug)]
struct ReviewLine {
    text: String,
    /// Proposal the line belongs to
    proposal: u64,
    header: bool,
}

#[derive(Clone, Debug)]
pub struct ReviewView {
    pub program: usize,
    lines: Vec<ReviewLine>,
    version: u64,
    pub cursor: usize,
    pub scroll: usize,
    pub height: usize,
}

impl ReviewView {
    pub fn new(program: usize, project: &Project) -> Self {
        let mut view = ReviewView { program, lines: Vec::new(), version: u64::MAX, cursor: 0, scroll: 0, height: 20 };
        view.refresh(project);
        return view;
    }

    pub fn title(&self) -> String {
        let count = self.lines.iter().filter(|l| l.header).count();
        return format!("LLM proposals ({}): a accept, r reject", count);
    }

    pub fn refresh(&mut self, project: &Project) {
        if self.version == project.version {
            return;
        }

        self.version = project.version;
        self.lines.clear();

        for proposal in project.proposals.iter().filter(|p| p.is_pending()) {
            let addrs: Vec<u64> = proposal.functions.keys().chain(proposal.edits.keys()).copied().collect();
            let functions: Vec<String> = addrs.iter().take(3).map(|&a| project.function_name(a)).collect();
            let more = if addrs.len() > 3 { format!(" and {} more", addrs.len() - 3) } else { String::new() };

            self.lines.push(ReviewLine { text: format!("[{}] {}: {}{}", proposal.id, proposal.label, functions.join(", "), more), proposal: proposal.id, header: true });

            let diff = if proposal.preview_pending { "  (decompiling the proposed code...)".to_string() } else { proposal.diff() };

            for line in diff.lines().filter(|l| !l.starts_with("diff ") && !l.starts_with("index ") && !l.starts_with("--- ") && !l.starts_with("+++ ")) {
                self.lines.push(ReviewLine { text: line.to_string(), proposal: proposal.id, header: false });
            }

            self.lines.push(ReviewLine { text: String::new(), proposal: proposal.id, header: false });
        }

        self.cursor = self.cursor.min(self.lines.len().saturating_sub(1));
    }

    /// Proposal under the cursor
    pub fn proposal(&self) -> Option<u64> {
        return self.lines.get(self.cursor).map(|l| l.proposal);
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let max = self.lines.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max.max(0)) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    /// Next (or previous) proposal
    pub fn jump(&mut self, forward: bool) {
        let found = if forward {
            self.lines.iter().enumerate().skip(self.cursor + 1).find(|(_, l)| l.header).map(|(i, _)| i)
        } else {
            self.lines.iter().enumerate().take(self.cursor).rev().find(|(_, l)| l.header).map(|(i, _)| i)
        };

        if let Some(index) = found {
            self.cursor = index;
            self.scroll = index;
        }
    }

    pub fn render(&mut self, project: &Project, theme: &Theme, height: usize) -> Vec<Line<'static>> {
        self.height = height.max(1);
        self.refresh(project);
        follow_cursor(self.cursor, &mut self.scroll, self.height);

        if self.lines.is_empty() {
            let running = if project.llm_running() > 0 { format!(" yet ({} {} running)", super::spinner(), project.llm_running()) } else { String::new() };
            return vec![Line::from(Span::styled(format!("No proposal to review{}. Ask the LLM with L in the code, or :llm modules", running), Style::default().fg(theme.dim)))];
        }

        let mut lines = Vec::new();

        for (index, line) in self.lines.iter().enumerate().skip(self.scroll).take(height) {
            let style = if line.header {
                theme.title_style()
            } else if line.text.starts_with('+') {
                Style::default().fg(theme.edge_true)
            } else if line.text.starts_with('-') {
                Style::default().fg(theme.edge_false)
            } else if line.text.starts_with("@@") {
                Style::default().fg(theme.dim)
            } else {
                Style::default().fg(theme.fg)
            };

            let mut rendered = Line::from(Span::styled(line.text.clone(), style));

            if index == self.cursor {
                rendered = rendered.style(Style::default().bg(theme.cursor_bg).add_modifier(Modifier::BOLD));
            }

            lines.push(rendered);
        }

        return lines;
    }
}
