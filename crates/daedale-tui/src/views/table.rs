// SPDX-License-Identifier: Apache-2.0
/*
 * Table view (functions, strings, imports, modules, memory map)
 */

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::{follow_cursor, Target};
use crate::commands::{Command, Motion};
use crate::theme::Theme;
use crate::views::View;
use crate::{App, OpenMode};

use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

#[derive(Clone, Debug)]
pub struct TableRow {
    pub cells: Vec<String>,
    pub target: Target,
    pub style: Option<Style>,
}

#[derive(Clone, Debug)]
pub struct TableView {
    pub title: String,
    pub headers: Vec<String>,
    pub rows: Vec<TableRow>,
    pub filtered: Vec<usize>,
    pub filter: String,
    pub cursor: usize,
    pub scroll: usize,
    pub height: usize,
    /// Optional line drawn above the table (memory map bar)
    pub banner: Option<Line<'static>>,
}

impl TableView {
    pub fn new(title: String, headers: Vec<&str>, rows: Vec<TableRow>) -> Self {
        let filtered = (0..rows.len()).collect();

        return Self {
            title,
            headers: headers.into_iter().map(|h| h.to_string()).collect(),
            rows,
            filtered,
            filter: String::new(),
            cursor: 0,
            scroll: 0,
            height: 1,
            banner: None,
        };
    }

    pub fn set_filter(&mut self, filter: &str) {
        self.filter = filter.to_string();
        let pattern = filter.to_lowercase();

        self.filtered = (0..self.rows.len())
            .filter(|&i| pattern.is_empty() || self.rows[i].cells.iter().any(|c| c.to_lowercase().contains(&pattern)))
            .collect();

        self.cursor = 0;
        self.scroll = 0;
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let max = self.filtered.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, max) as usize;
        follow_cursor(self.cursor, &mut self.scroll, self.height);
    }

    pub fn selected(&self) -> Option<&TableRow> {
        return self.filtered.get(self.cursor).map(|&i| &self.rows[i]);
    }

    pub fn render(&mut self, theme: &Theme, height: usize, width: usize) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        if let Some(banner) = &self.banner {
            lines.push(banner.clone());
            lines.push(Line::from(""));
        }

        // Column widths from the visible rows, the last column takes the remaining space
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();

        for &i in self.filtered.iter().take(2000) {
            for (c, cell) in self.rows[i].cells.iter().enumerate() {
                if c < widths.len() {
                    widths[c] = widths[c].max(cell.chars().count().min(64));
                }
            }
        }

        let format_row = |cells: &[String]| -> String {
            let mut text = String::new();

            for (c, cell) in cells.iter().enumerate() {
                if c + 1 == cells.len() {
                    text.push_str(cell);
                } else {
                    let cell: String = cell.chars().take(widths[c]).collect();
                    text.push_str(&format!("{:<width$}  ", cell, width = widths[c]));
                }
            }

            return text.chars().take(width).collect();
        };

        lines.push(Line::from(Span::styled(format_row(&self.headers), theme.title_style())));

        let rows_height = height.saturating_sub(lines.len()).max(1);
        self.height = rows_height;
        follow_cursor(self.cursor, &mut self.scroll, rows_height);

        for (pos, &i) in self.filtered.iter().enumerate().skip(self.scroll).take(rows_height) {
            let row = &self.rows[i];
            let mut style = row.style.unwrap_or(Style::default().fg(theme.fg));

            if pos == self.cursor {
                style = style.bg(theme.highlight_bg).fg(theme.highlight_fg);
            }

            lines.push(Line::from(Span::styled(format_row(&row.cells), style)));
        }

        if self.filtered.is_empty() {
            lines.push(Line::from(Span::styled("No entries", Style::default().fg(theme.dim))));
        }

        return lines;
    }
}


/*
 * Tables of a program, commands
 */

impl App {
    pub(crate) fn functions_table(&mut self, program: usize) -> Option<TableView> {
        let analysis = self.analysis(program)?;

        let rows = analysis.functions.values().map(|f| {
            let mut flags = Vec::new();

            if f.thunk.is_some() {
                flags.push("thunk");
            }

            if f.noreturn {
                flags.push("noreturn");
            }

            if f.unresolved_jumps > 0 {
                flags.push("indirect");
            }

            let project = self.projects[program].as_ref();
            let module = project.and_then(|p| p.module_of(f.addr)).unwrap_or("").to_string();
            let name = project.map_or(f.name.clone(), |p| p.function_name(f.addr));

            TableRow {
                cells: vec![
                    format!("{:#x}", f.addr),
                    format!("{}", f.size()),
                    format!("{}", f.blocks.len()),
                    format!("{}", analysis.callers.get(&f.addr).map_or(0, |c| c.len())),
                    f.source.name().to_string(),
                    flags.join(","),
                    module,
                    name,
                ],
                target: Target::Function(program, f.addr),
                style: if f.thunk.is_some() { Some(Style::default().fg(self.theme.dim)) } else { None },
            }
        }).collect();

        return Some(TableView::new(
            format!("Functions ({})", analysis.functions.len()),
            vec!["Address", "Size", "Blocks", "Xrefs", "Source", "Flags", "Module", "Name"],
            rows,
        ));
    }

    pub(crate) fn modules_table(&mut self, program: usize) -> Option<TableView> {
        let project = self.project(program)?;

        let rows = project.modules.names().map(|name| {
            let functions = project.modules.functions(name);
            let edited = functions.iter().filter(|a| project.work.edits.contains_key(a)).count();

            TableRow {
                cells: vec![format!("{}", functions.len()), format!("{}", edited), name.clone()],
                target: Target::Module(program, name.clone()),
                style: None,
            }
        }).collect();

        return Some(TableView::new(format!("Modules ({})", project.modules.len()), vec!["Functions", "Edited", "Module"], rows));
    }

    pub(crate) fn strings_table(&mut self, program: usize) -> Option<TableView> {
        let analysis = self.analysis(program)?;
        let program_ref = self.programs[program].clone();

        // Code referencing each string
        let mut xrefs: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

        for function in analysis.functions.values() {
            for &(_, target) in function.refs.iter() {
                if analysis.strings.contains_key(&target) {
                    *xrefs.entry(target).or_default() += 1;
                }
            }
        }

        let rows = analysis.strings.iter().map(|(&addr, string)| TableRow {
            cells: vec![
                format!("{:#x}", addr),
                program_ref.region_at(addr).map_or(String::new(), |r| r.name.clone()),
                format!("{}", xrefs.get(&addr).copied().unwrap_or(0)),
                daedale_decompiler::analysis::strings::escape(string, 200),
            ],
            target: Target::Address(program, addr),
            style: None,
        }).collect();

        return Some(TableView::new(format!("Strings ({})", analysis.strings.len()), vec!["Address", "Section", "Xrefs", "String"], rows));
    }

    pub(crate) fn imports_table(&mut self, program: usize) -> TableView {
        let program_ref = self.programs[program].clone();
        let analysis = self.analyses[program].clone();

        let mut rows: Vec<TableRow> = Vec::new();

        // Thunks (PLT entries, stubs) first: they are what the code calls
        if let Some(analysis) = &analysis {
            for function in analysis.functions.values().filter(|f| f.thunk.is_some()) {
                rows.push(TableRow {
                    cells: vec![format!("{:#x}", function.addr), "thunk".to_string(), function.name.clone()],
                    target: Target::Function(program, function.addr),
                    style: None,
                });
            }
        }

        let mut slots: Vec<(&u64, &String)> = program_ref.import_slots.iter().collect();
        slots.sort();

        for (&addr, name) in slots {
            rows.push(TableRow {
                cells: vec![format!("{:#x}", addr), "pointer".to_string(), daedale_core::demangle::demangle(name).unwrap_or(name.clone())],
                target: Target::Address(program, addr),
                style: Some(Style::default().fg(self.theme.dim)),
            });
        }

        return TableView::new(format!("Imports ({})", rows.len()), vec!["Address", "Kind", "Name"], rows);
    }

    pub(crate) fn memory_map(&self, program: usize) -> TableView {
        let program_ref = &self.programs[program];

        let rows = program_ref.regions.iter().map(|r| {
            let color = if r.perms.exec { self.theme.perm_exec } else if r.perms.write { self.theme.perm_write } else { self.theme.perm_read };

            TableRow {
                cells: vec![
                    format!("{:#x}", r.vaddr),
                    format!("{:#x}", r.end()),
                    format!("{:#x}", r.size),
                    r.perms.as_string(),
                    if r.data.is_empty() { "bss".to_string() } else { String::new() },
                    r.name.clone(),
                ],
                target: Target::Address(program, r.vaddr),
                style: Some(Style::default().fg(color)),
            }
        }).collect();

        let mut table = TableView::new(format!("Memory map ({})", program_ref.name), vec!["Start", "End", "Size", "Perms", "Kind", "Name"], rows);

        // Proportional bar of the address space: one character per region slice, colored by permissions
        let (start, end) = (
            program_ref.regions.iter().map(|r| r.vaddr).min().unwrap_or(0),
            program_ref.regions.iter().map(|r| r.end()).max().unwrap_or(0),
        );

        if end > start {
            const BAR_WIDTH: u64 = 64;
            let mut spans = Vec::new();

            for i in 0..BAR_WIDTH {
                let addr = start + (end - start) * i / BAR_WIDTH;
                let region = program_ref.region_at(addr);

                let (ch, color) = match region {
                    Some(r) if r.perms.exec => ('█', self.theme.perm_exec),
                    Some(r) if r.perms.write => ('█', self.theme.perm_write),
                    Some(_) => ('█', self.theme.perm_read),
                    None => ('░', self.theme.dim),
                };

                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }

            spans.push(Span::styled(format!("  {:#x} - {:#x}   ", start, end), Style::default().fg(self.theme.dim)));
            spans.push(Span::styled("■ x ", Style::default().fg(self.theme.perm_exec)));
            spans.push(Span::styled("■ w ", Style::default().fg(self.theme.perm_write)));
            spans.push(Span::styled("■ r", Style::default().fg(self.theme.perm_read)));

            table.banner = Some(Line::from(spans));
        }

        return table;
    }

    pub(crate) fn table(&mut self, program: usize, name: &str) -> Option<TableView> {
        return match name {
            "functions" => self.functions_table(program),
            "strings" => self.strings_table(program),
            "imports" => Some(self.imports_table(program)),
            "modules" => self.modules_table(program),
            _ => Some(self.memory_map(program)),
        };
    }

    pub(crate) fn table_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let repeat = count.unwrap_or(1).max(1) as isize;

        let View::Table(view) = self.view_mut() else {
            return false;
        };

        let page = (view.height / 2).max(1) as isize;

        match command {
            Command::Move(motion) => match motion {
                Motion::PageDown => view.move_cursor(page),
                Motion::PageUp => view.move_cursor(-page),
                Motion::Down => view.move_cursor(repeat),
                Motion::Up => view.move_cursor(-repeat),
                Motion::First => view.move_cursor(isize::MIN / 2),
                Motion::Last => view.move_cursor(isize::MAX / 2),
                _ => return false,
            },
            Command::ClearSearch => view.set_filter(""),
            Command::Open(OpenMode::Replace) => {
                if let Some(row) = view.selected() {
                    let target = row.target.clone();
                    self.open_target(target);
                }
            }
            _ => return false,
        }

        return true;
    }
}

pub(crate) fn render(view: &mut TableView, f: &mut Frame, theme: &Theme, area: Rect) {
    let lines = view.render(theme, area.height as usize, area.width as usize);
    f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_filter_and_cursor() {
        let rows = vec![
            TableRow { cells: vec!["0x1000".to_string(), "main".to_string()], target: Target::Function(0, 0x1000), style: None },
            TableRow { cells: vec!["0x2000".to_string(), "helper".to_string()], target: Target::Function(0, 0x2000), style: None },
        ];

        let mut table = TableView::new("Functions".to_string(), vec!["Address", "Name"], rows);
        table.set_filter("help");

        assert_eq!(table.filtered, vec![1]);
        assert_eq!(table.selected().unwrap().target, Target::Function(0, 0x2000));

        table.set_filter("");
        table.move_cursor(10);
        assert_eq!(table.cursor, 1);
    }
}
