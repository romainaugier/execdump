// SPDX-License-Identifier: Apache-2.0
/*
 * Drawing of the interface: the title bar with the progress of the background work, the explorer, the
 * splits, the status or command line, the popups and the help
 */

use super::*;

use crate::commands::{help_lines, Binding};
use crate::popup::render_popup;
use crate::prompt::render_completion;
use crate::splits::render_group;

/// 157204 -> 157.2k
pub(crate) fn count(n: usize) -> String {
    return match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1e3),
        _ => format!("{:.1}M", n as f64 / 1e6),
    };
}

/// Frame of the animation of the work in the background
pub(crate) fn spinner() -> char {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let frame = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis()) / 100;
    return FRAMES[frame as usize % FRAMES.len()];
}

pub(crate) fn duration(seconds: f64) -> String {
    let seconds = seconds as u64;

    return match seconds {
        0..=59 => format!("{}s", seconds),
        60..=3599 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h{:02}m", seconds / 3600, seconds / 60 % 60),
    };
}

impl App {
    pub(crate) fn status_text(&mut self) -> String {
        let spinner = spinner();

        // Programs still loading: the stage of the first one
        let loading = (0..self.programs.len()).find(|&i| self.projects[i].is_none() && self.analysis_errors[i].is_none());

        if let Some(index) = loading {
            let found: usize = self.loading[..self.main_programs].iter().map(|l| l.functions.load(Ordering::Relaxed)).sum();

            let found = if index < self.main_programs { found } else { self.loading[index].functions.load(Ordering::Relaxed) };
            let name = self.program_suffix(index);

            return match self.loading[index].stage.load(Ordering::Relaxed) {
                ANALYSIS => format!("{} 1/3 analysis{}: {} functions found", spinner, name, count(found)),
                _ => format!("{} 2/3 project{}: modules and cache of {} functions", spinner, name, count(found)),
            };
        }

        let functions: usize = self.analyses.iter().flatten().map(|a| a.functions.len()).sum();
        let (decompiled, decompilable) = self.projects.iter().flatten().map(|p| p.progress()).fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
        let llm: usize = self.projects.iter().flatten().map(|p| p.llm_running()).sum();
        let dirty = self.projects.iter().flatten().any(|p| p.is_dirty());

        let mut text = format!("{} functions", count(functions));

        if decompiled < decompilable {
            let (start, at_start) = *self.decompile_start.get_or_insert((std::time::Instant::now(), decompiled));
            let ratio = decompiled as f64 / decompilable as f64;
            let bar: String = (0..16).map(|i| if (i as f64 + 0.5) / 16.0 < ratio { '█' } else { '░' }).collect();
            text.push_str(&format!("  {} 3/3 decompiling {} {:>3}% {}/{}", spinner, bar, (ratio * 100.0) as usize, count(decompiled), count(decompilable)));

            // Remaining time, from the rate since the decompilation started
            let elapsed = start.elapsed().as_secs_f64();
            let done = decompiled.saturating_sub(at_start);

            if elapsed > 5.0 && done > 0 {
                let left = (decompilable - decompiled) as f64 * elapsed / done as f64;
                text.push_str(&format!(" ~{} left", duration(left)));
            }
        } else if decompilable > 0 {
            self.decompile_start = None;
            text.push_str("  all decompiled");
        }

        if llm > 0 {
            let start = *self.llm_start.get_or_insert_with(std::time::Instant::now);
            let dots = ".".repeat((start.elapsed().as_millis() / 400 % 4) as usize);
            let running = if llm > 1 { format!(" ({} requests)", llm) } else { String::new() };
            text.push_str(&format!("  {} LLM thinking{:<3}{} {}", spinner, dots, running, duration(start.elapsed().as_secs_f64())));
        } else {
            self.llm_start = None;
        }

        if dirty {
            text.push_str("  [+]");
        }

        if let Some(debug) = self.debug_status() {
            text.push_str(&format!("  {}", debug));
        }

        return text;
    }

    pub(crate) fn hints(&self) -> &'static str {
        if self.focus == Focus::Explorer {
            return "j/k move  Enter open/fold  h parent  t tab  s/v split  </>/= width  Tab content  e hide  : command  ? help  q quit";
        }

        match self.view() {
            View::Graph(view) => match view.kind {
                GraphKind::Cfg { .. } => "hjkl scroll  n/p node  t/f branch  Enter calls  v/V C/asm in nodes  Space linear  D code  x xrefs  ^w splits  ? help",
                GraphKind::CallGraph { .. } => "hjkl scroll  n/p node  Enter open  v/V C/asm in nodes  +/- depth  i imports  r re-root  U up  ^w splits  ? help",
            },
            View::Disasm(_) => "j/k move  n/p function  Enter follow  Space graph  D code  x xrefs  / search  ^o back  ? help",
            View::Source(view) if view.insert.is_some() => "-- INSERT --  Esc normal mode",
            View::Source(_) => "hjkl move  Enter/gd go to  i/a/o insert  dd/dw/cw  u/U undo/redo  cn rename  ct retype  cs signature  ; comment  M move  L LLM  :w save",
            View::Review(_) => "j/k move  n/p proposal  a accept  r reject  Enter open the code  :w save",
            View::Table(_) => "j/k move  Enter open  / filter  Esc clear  ^o back  ? help",
            View::Debug(_) => "j/k move  Enter select the frame / show the breakpoint  F5 continue  F7 step  F8 over  F4 finish  F6 interrupt  F9 break",
            _ => "j/k scroll  ^d/^u page  g/G top/bottom  / search  ^o back  ? help",
        }
    }
}

pub(crate) fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));

    return Rect::new(area.x + (area.width - width) / 2, area.y + (area.height - height) / 2, width, height);
}

impl App {
    /// Keys of the help: it scrolls, any other key closes it
    pub(crate) fn help_key(&mut self, key: KeyEvent) {
        self.help_scroll = match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.help_scroll + 1,
            KeyCode::Char('k') | KeyCode::Up => self.help_scroll.saturating_sub(1),
            KeyCode::Char('d') | KeyCode::PageDown => self.help_scroll + 10,
            KeyCode::Char('u') | KeyCode::PageUp => self.help_scroll.saturating_sub(10),
            KeyCode::Char('g') => 0,
            KeyCode::Char('G') => usize::MAX / 2,
            _ => {
                self.help = false;
                0
            }
        };
    }
}

/// Keys and commands, from the bindings
fn render_help(f: &mut Frame, theme: &Theme, bindings: &[Binding], scroll: &mut usize) {
    let lines: Vec<Line> = help_lines(bindings)
        .into_iter()
        .map(|(key, description)| {
            if description.is_empty() {
                Line::from(Span::styled(key, theme.title_style()))
            } else {
                Line::from(vec![Span::styled(format!("  {:<26}", key), Style::default().fg(theme.key)), Span::styled(description, Style::default().fg(theme.fg))])
            }
        })
        .collect();

    let area = centered_rect(140, lines.len() as u16 + 2, f.area());
    let visible = area.height.saturating_sub(2) as usize;
    *scroll = (*scroll).min(lines.len().saturating_sub(visible));

    let title = if lines.len() > visible { " Keys and commands (j/k d/u scroll, any other key to close) " } else { " Keys and commands (any key to close) " };
    let lines: Vec<Line> = lines.into_iter().skip(*scroll).collect();

    f.render_widget(Clear, area);
    f.render_widget(Paragraph::new(Text::from(lines)).block(Block::default().title(title).borders(Borders::ALL).style(theme.base())), area);
}

pub(crate) fn ui(f: &mut Frame, app: &mut App) {
    let theme = app.theme.clone();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0), Constraint::Length(1)])
        .split(f.area());

    // Title bar
    let program_names: Vec<String> = app.programs.iter().map(|p| p.name.clone()).collect();

    let title = Line::from(vec![
        Span::styled(" daedale ", Style::default().fg(theme.bg).bg(theme.title).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", app.exec_path.file_name().map_or(app.exec_path.display().to_string(), |n| n.to_string_lossy().to_string())), Style::default().fg(theme.fg)),
        Span::styled(format!(" {} ", program_names.join(", ")), Style::default().fg(theme.dim)),
        Span::styled(format!(" {}", app.status_text()), Style::default().fg(theme.comment)),
    ]);

    f.render_widget(Paragraph::new(title).style(theme.base()), chunks[0]);

    let content_area = app.render_explorer(f, &theme, chunks[1]);

    // Splits
    let groups = app.workspace.layout(content_area);
    let focused = app.workspace.focused;

    for (id, area) in groups {
        render_group(f, app, &theme, id, area, id == focused);
    }

    // Status / command line
    let status = match (&app.input, &app.message) {
        (Some((kind, text)), _) => Line::from(vec![
            Span::styled(if *kind == InputKind::Command { ":" } else { "/" }, Style::default().fg(theme.title)),
            Span::styled(text.clone(), Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.fg)),
        ]),
        (None, Some((message, error))) => Line::from(Span::styled(message.clone(), Style::default().fg(if *error { theme.warning } else { theme.fg }))),
        (None, None) => {
            let pending = match (app.count, app.pending.is_empty()) {
                (None, true) => String::new(),
                (count, _) => format!("{}{}  ", count.map_or(String::new(), |c| c.to_string()), crate::commands::sequence_name(&app.pending)),
            };

            let search = if app.searching && !matches!(app.view(), View::Table(_)) { format!("/{}  n/p match  Esc clear  ", app.last_search) } else { String::new() };

            Line::from(Span::styled(format!("{}{}{}", pending, search, app.hints()), Style::default().fg(theme.dim)))
        }
    };

    f.render_widget(Paragraph::new(status).style(theme.base()), chunks[2]);

    if let (Some((InputKind::Command, _)), Some(completion)) = (&app.input, &app.completion) {
        render_completion(f, &theme, completion, chunks[2]);
    }

    if let Some(popup) = &app.popup {
        render_popup(f, &theme, popup);
    }

    if app.help {
        render_help(f, &theme, &app.bindings, &mut app.help_scroll);
    }
}
