use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

use serde::{Deserialize, Serialize};
use std::{error::Error, io, path::PathBuf};

use crate::dump::{Dump, DumpRawData};
use crate::exec::Exec;

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct Theme {
    bg: Color,
    fg: Color,
    highlight_bg: Color,
    highlight_fg: Color,
    border: Color,
    title: Color,
    key: Color,
    value: Color,
    hex_offset: Color,
    hex_data: Color,
    hex_ascii: Color,
    comment: Color,
    string: Color,
}

impl Theme {
    fn codedark() -> Self {
        Theme {
            bg: Color::Rgb(30, 30, 30),
            fg: Color::Rgb(212, 212, 212),
            highlight_bg: Color::Rgb(38, 79, 120),
            highlight_fg: Color::Rgb(255, 255, 255),
            border: Color::Rgb(84, 84, 84),
            title: Color::Rgb(86, 156, 214),
            key: Color::Rgb(156, 220, 254),
            value: Color::Rgb(206, 145, 120),
            hex_offset: Color::Rgb(128, 128, 128),
            hex_data: Color::Rgb(181, 206, 168),
            hex_ascii: Color::Rgb(206, 145, 120),
            comment: Color::Rgb(70, 70, 70),
            string: Color::Rgb(124, 227, 139),
        }
    }
}

// Key bindings configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyBindings {
    quit: char,
    next_pane: char,
    prev_pane: char,
    down: char,
    up: char,
    left: char,
    right: char,
    page_down: char,
    page_up: char,
    home: char,
    end: char,
}

impl Default for KeyBindings {
    fn default() -> Self {
        KeyBindings {
            quit: 'q',
            next_pane: 'l',
            prev_pane: 'h',
            down: 'j',
            up: 'k',
            left: 'h',
            right: 'l',
            page_down: 'd',
            page_up: 'u',
            home: 'g',
            end: 'G',
        }
    }
}

impl KeyBindings {
    fn load() -> Self {
        if let Some(home) = dirs::home_dir() {
            let config_path = home.join(".pedumprc");
            if let Ok(contents) = std::fs::read_to_string(config_path) {
                if let Ok(bindings) = toml::from_str(&contents) {
                    return bindings;
                }
            }
        }
        KeyBindings::default()
    }
}

// Explorer tree items
#[derive(Clone, Debug)]
enum ExplorerItem {
    Headers,
    PEDosHeader,
    PENtHeader,
    PEOptionalHeader,
    Sections,
    Section(String),
    PEDataDirectories,
    PEImportTable,
    PEExportTable,
    PEResourceTable,
    PEExceptionTable,
    PEDebugDirectory,
}

impl ExplorerItem {
    fn display_name(&self) -> String {
        match self {
            ExplorerItem::Headers => "Headers/".to_string(),
            ExplorerItem::PEDosHeader => "  DOS Header".to_string(),
            ExplorerItem::PENtHeader => "  NT Header".to_string(),
            ExplorerItem::PEOptionalHeader => "  Optional Header".to_string(),
            ExplorerItem::Sections => "Sections/".to_string(),
            ExplorerItem::Section(name) => format!("  {}", name),
            ExplorerItem::PEDataDirectories => "Data Directories/".to_string(),
            ExplorerItem::PEImportTable => "  Import Table".to_string(),
            ExplorerItem::PEExportTable => "  Export Table".to_string(),
            ExplorerItem::PEResourceTable => "  Resource Table".to_string(),
            ExplorerItem::PEExceptionTable => "  Exception Table".to_string(),
            ExplorerItem::PEDebugDirectory => "  Debug Directory".to_string(),
        }
    }
}

// View types
#[allow(dead_code)]
#[derive(Clone, Debug)]
enum ViewType {
    Welcome,
    Header(Dump),
    Section(Dump),
    PEImportTable,
    PEExportTable,
    PEResourceTable,
    PEExceptionTable,
    PEDebugDirectory,
}

// Active pane
#[derive(Clone, Copy, Debug, PartialEq)]
enum ActivePane {
    Explorer,
    Content,
}

// Application state
struct App {
    exec: Exec,
    exec_path: PathBuf,
    theme: Theme,
    key_bindings: KeyBindings,
    explorer_items: Vec<ExplorerItem>,
    explorer_state: ListState,
    active_pane: ActivePane,
    current_view: ViewType,
    hex_offset: usize,
    content_scroll: usize,
    should_quit: bool,
}

impl App {
    fn new(exec: Exec, exec_path: PathBuf) -> Self {
        let mut explorer_items = vec![ExplorerItem::Headers];

        match &exec {
            Exec::PE(_) => {
                explorer_items.push(ExplorerItem::PEDosHeader);
                explorer_items.push(ExplorerItem::PENtHeader);
                explorer_items.push(ExplorerItem::PEOptionalHeader);
            }
            Exec::ELF(_) => { /* TODO ELF */ }
        }

        explorer_items.push(ExplorerItem::Sections);

        let mut sections: Vec<String> = match &exec {
            Exec::PE(pe) => pe.sections.keys().cloned().collect(),
            Exec::ELF(_) =>
            /* TODO ELF */
            {
                Vec::new()
            }
        };

        sections.sort();

        for name in sections {
            explorer_items.push(ExplorerItem::Section(name));
        }

        match &exec {
            Exec::PE(_) => {
                explorer_items.push(ExplorerItem::PEDataDirectories);
                explorer_items.push(ExplorerItem::PEImportTable);
                explorer_items.push(ExplorerItem::PEExportTable);
                explorer_items.push(ExplorerItem::PEResourceTable);
                explorer_items.push(ExplorerItem::PEExceptionTable);
                explorer_items.push(ExplorerItem::PEDebugDirectory);
            }
            Exec::ELF(_) => { /* TODO ELF */ }
        }

        let mut state = ListState::default();
        state.select(Some(0));

        return App {
            exec: exec,
            exec_path: exec_path,
            theme: Theme::codedark(),
            key_bindings: KeyBindings::load(),
            explorer_items,
            explorer_state: state,
            active_pane: ActivePane::Explorer,
            current_view: ViewType::Welcome,
            hex_offset: 0,
            content_scroll: 0,
            should_quit: false,
        };
    }

    fn handle_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        let bindings = self.key_bindings.clone();

        match key {
            KeyCode::Char(c) if c == bindings.quit => {
                self.should_quit = true;
            }
            KeyCode::Char(c) if c == bindings.next_pane && modifiers.is_empty() => {
                self.active_pane = match self.active_pane {
                    ActivePane::Explorer => ActivePane::Content,
                    ActivePane::Content => ActivePane::Explorer,
                };
            }
            KeyCode::Char(c) if c == bindings.prev_pane && modifiers.is_empty() => {
                self.active_pane = match self.active_pane {
                    ActivePane::Explorer => ActivePane::Content,
                    ActivePane::Content => ActivePane::Explorer,
                };
            }
            KeyCode::Char(c) if self.active_pane == ActivePane::Explorer => {
                if c == bindings.down {
                    self.explorer_next();
                } else if c == bindings.up {
                    self.explorer_previous();
                } else if c == bindings.page_up {
                    self.explorer_state.select(Some(0));
                } else if c == bindings.page_down {
                    self.explorer_state
                        .select(Some(self.explorer_items.len() - 1));
                }
            }
            KeyCode::Char(c) if self.active_pane == ActivePane::Content => {
                if c == bindings.down {
                    self.content_scroll_down();
                } else if c == bindings.up {
                    self.content_scroll_up();
                } else if c == bindings.page_down {
                    self.content_page_down();
                } else if c == bindings.page_up {
                    self.content_page_up();
                } else if c == 'g' {
                    self.content_scroll = 0;
                    self.hex_offset = 0;
                } else if c == 'G' {
                    self.content_scroll = usize::MAX;
                }
            }
            KeyCode::Enter if self.active_pane == ActivePane::Explorer => {
                self.activate_selected_item();
            }
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    ActivePane::Explorer => ActivePane::Content,
                    ActivePane::Content => ActivePane::Explorer,
                };
            }
            _ => {}
        }
    }

    fn explorer_next(&mut self) {
        let i = match self.explorer_state.selected() {
            Some(i) => {
                if i >= self.explorer_items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.explorer_state.select(Some(i));
    }

    fn explorer_previous(&mut self) {
        let i = match self.explorer_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.explorer_items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.explorer_state.select(Some(i));
    }

    fn content_scroll_down(&mut self) {
        self.content_scroll = self.content_scroll.saturating_add(1);
        if matches!(self.current_view, ViewType::Section(_)) {
            self.hex_offset = self.hex_offset.saturating_add(16);
        }
    }

    fn content_scroll_up(&mut self) {
        self.content_scroll = self.content_scroll.saturating_sub(1);
        if matches!(self.current_view, ViewType::Section(_)) {
            self.hex_offset = self.hex_offset.saturating_sub(16);
        }
    }

    fn content_page_down(&mut self) {
        self.content_scroll = self.content_scroll.saturating_add(10);
        if matches!(self.current_view, ViewType::Section(_)) {
            self.hex_offset = self.hex_offset.saturating_add(160);
        }
    }

    fn content_page_up(&mut self) {
        self.content_scroll = self.content_scroll.saturating_sub(10);
        if matches!(self.current_view, ViewType::Section(_)) {
            self.hex_offset = self.hex_offset.saturating_sub(160);
        }
    }

    fn activate_selected_item(&mut self) {
        if let Some(idx) = self.explorer_state.selected() {
            if let Some(item) = self.explorer_items.get(idx) {
                match &self.exec {
                    Exec::PE(pe) => {
                        self.current_view = match item {
                            ExplorerItem::PEDosHeader => {
                                ViewType::Header(pe.get_dos_header().dump())
                            }
                            ExplorerItem::PENtHeader => ViewType::Header(pe.get_nt_header().dump()),
                            ExplorerItem::PEOptionalHeader => {
                                ViewType::Header(pe.get_optional_header().dump())
                            }
                            ExplorerItem::Section(name) => {
                                let section = pe.sections.get(name).unwrap();

                                ViewType::Section(section.dump(section.contains_code()))
                            }
                            ExplorerItem::PEImportTable => ViewType::PEImportTable,
                            ExplorerItem::PEExportTable => ViewType::PEExportTable,
                            ExplorerItem::PEResourceTable => ViewType::PEResourceTable,
                            ExplorerItem::PEExceptionTable => ViewType::PEExceptionTable,
                            ExplorerItem::PEDebugDirectory => ViewType::PEDebugDirectory,
                            _ => self.current_view.clone(),
                        };
                    }
                    Exec::ELF(_) => { /* TODO ELF */ }
                }

                self.content_scroll = 0;
                self.hex_offset = 0;
                self.active_pane = ActivePane::Content;
            }
        }
    }

    fn render_content(&self) -> Text<'_> {
        match &self.current_view {
            ViewType::Welcome => self.render_welcome(),
            ViewType::Header(dump) => self.render_header(dump),
            ViewType::Section(dump) => self.render_section(dump),
            ViewType::PEImportTable => self.render_import_table(),
            ViewType::PEDebugDirectory => self.render_debug_directory(),
            ViewType::PEExceptionTable => self.render_exception_table(),
            _ => Text::from("Not implemented yet"),
        }
    }

    #[rustfmt::skip]
    fn render_welcome(&self) -> Text<'_> {
        return Text::from(vec![
            Line::from(Span::styled("Welcome to execdump", Style::default().fg(self.theme.title).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("Navigate using vim-like keybindings:"),
            Line::from("  h/l - Switch panes"),
            Line::from("  j/k - Move up/down"),
            Line::from("  Enter - Select item"),
            Line::from("  q - Quit"),
            Line::from(""),
            Line::from("Select an item from the explorer to view details."),
        ]).centered();
    }

    fn label(&'_ self, label: &str, indent: usize) -> Line<'_> {
        return Line::from(Span::styled(
            format!("{:>width$}{}", "", label, width = indent),
            Style::default()
                .fg(self.theme.title)
                .add_modifier(Modifier::BOLD),
        ));
    }

    fn line_from_key_value_comment(
        &self,
        key: &'static str,
        value: &str,
        comment: Option<&'static str>,
        indent: usize,
        align: usize,
    ) -> Line<'_> {
        return Line::from(vec![
            Span::styled(
                format!(
                    "{:>width$}{key:<align$}: ",
                    "",
                    width = indent,
                    align = align
                ),
                Style::default().fg(self.theme.key),
            ),
            Span::styled(format!("{}", value), Style::default().fg(self.theme.value)),
            Span::styled(
                format!(
                    "{}",
                    if let Some(text) = comment {
                        format!(" {text}")
                    } else {
                        "".to_string()
                    }
                ),
                Style::default()
                    .fg(self.theme.comment)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]);
    }

    fn line_from_value(&self, value: &str, indent: usize) -> Line<'_> {
        return Line::from(vec![Span::styled(
            format!("{:>width$}{}", "", value, width = indent),
            Style::default().fg(self.theme.value),
        )]);
    }

    fn lines_from_dump(&self, dump: &Dump, indent: usize, indent_size: usize) -> Vec<Line<'_>> {
        let mut lines = Vec::new();

        lines.push(self.label(dump.label(), indent * indent_size));

        let align = dump.fields_align();
        let fields_indent = (indent + 1) * indent_size;

        for field in dump.iter_fields() {
            if field.key.len() == 0 {
                lines.push(self.line_from_value(field.value.as_str(), fields_indent));
            } else {
                lines.push(self.line_from_key_value_comment(
                    field.key,
                    field.value.as_str(),
                    field.comment,
                    fields_indent,
                    align,
                ));
            }
        }

        for child in dump.iter_children() {
            lines.extend_from_slice(
                self.lines_from_dump(child, indent + 1, indent_size)
                    .as_slice(),
            );
        }

        return lines;
    }

    fn render_header(&self, dump: &Dump) -> Text<'_> {
        let indent = 4;

        return Text::from(self.lines_from_dump(dump, 0, indent));
    }

    fn render_section_hex(&self, name: &str, data: &[u8]) -> Text<'_> {
        let mut lines = vec![
            Line::from(Span::styled(
                format!("Section: {}", name),
                Style::default()
                    .fg(self.theme.title)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        let start = self.hex_offset.min(data.len());
        let end = (start + 2048).min(data.len());

        for offset in (start..end).step_by(16) {
            let mut hex_parts = vec![Span::styled(
                format!("{:08X}  ", offset),
                Style::default().fg(self.theme.hex_offset),
            )];

            let chunk_end = (offset + 16).min(data.len());
            let chunk = &data[offset..chunk_end];

            // Hex bytes
            for (i, byte) in chunk.iter().enumerate() {
                hex_parts.push(Span::styled(
                    format!("{:02X} ", byte),
                    Style::default().fg(self.theme.hex_data),
                ));
                if i == 7 {
                    hex_parts.push(Span::raw(" "));
                }
            }

            // Padding
            for _ in chunk.len()..16 {
                hex_parts.push(Span::raw("   "));
            }

            hex_parts.push(Span::raw(" "));

            // ASCII
            for byte in chunk {
                let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                };
                hex_parts.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(self.theme.hex_ascii),
                ));
            }

            lines.push(Line::from(hex_parts));
        }

        return Text::from(lines);
    }

    fn render_section_code(&self, name: &str, code: &[String]) -> Text<'_> {
        let mut lines = vec![
            Line::from(Span::styled(
                format!("Section: {}", name),
                Style::default()
                    .fg(self.theme.title)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        for loc in code {
            lines.push(Line::from(loc.clone()));
        }

        return Text::from(lines);
    }

    fn render_section(&self, dump: &Dump) -> Text<'_> {
        match dump.raw_data() {
            DumpRawData::Bytes(data) => self.render_section_hex(dump.label(), &data),
            DumpRawData::Code(code) => self.render_section_code(dump.label(), code),
            DumpRawData::None() => Text::from("No data found in section"),
        }
    }

    fn render_import_table(&self) -> Text<'_> {
        if let Exec::PE(pe) = &self.exec {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Import Table",
                    Style::default()
                        .fg(self.theme.title)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if let Some(hint_name_table) = &pe.hint_name_table {
                lines.extend_from_slice(&self.lines_from_dump(&hint_name_table.dump(), 0, 4));
            } else {
                lines.push(Line::from("No import table found"));
            }

            return Text::from(lines);
        }

        return Text::from("Not supported for executable type other than PE");
    }

    fn render_debug_directory(&self) -> Text<'_> {
        if let Exec::PE(pe) = &self.exec {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Debug Directory",
                    Style::default()
                        .fg(self.theme.title)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if let Some(debug) = &pe.debug_directory {
                lines.extend_from_slice(&self.lines_from_dump(&debug.dump(), 0, 4));
            } else {
                lines.push(Line::from("No debug directory found"));
            }

            return Text::from(lines);
        }

        return Text::from("Not supported for executable type other than PE");
    }

    fn render_exception_table(&self) -> Text<'_> {
        if let Exec::PE(pe) = &self.exec {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Exception Table",
                    Style::default()
                        .fg(self.theme.title)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if let Some(exc_table) = &pe.exception_table {
                lines.extend_from_slice(&self.lines_from_dump(&exc_table.dump(), 0, 4));
            } else {
                lines.push(Line::from("No exception table found"));
            }

            return Text::from(lines);
        }

        return Text::from("Not supported for executable type other than PE");
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Title bar
    let title = format!("execdump - {}", app.exec_path.display());
    let title_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .style(Style::default().bg(app.theme.bg));
    let title_para = Paragraph::new(Span::styled(
        title,
        Style::default()
            .fg(app.theme.title)
            .add_modifier(Modifier::BOLD),
    ))
    .centered()
    .block(title_block);
    f.render_widget(title_para, chunks[0]);

    // Main content area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(chunks[1]);

    // Explorer pane
    let explorer_items: Vec<ListItem> = app
        .explorer_items
        .iter()
        .map(|item| ListItem::new(item.display_name()))
        .collect();

    let explorer_style = if app.active_pane == ActivePane::Explorer {
        Style::default()
            .fg(app.theme.highlight_fg)
            .bg(app.theme.highlight_bg)
    } else {
        Style::default().fg(app.theme.fg)
    };

    let explorer_border_style = if app.active_pane == ActivePane::Explorer {
        Style::default().fg(app.theme.highlight_bg)
    } else {
        Style::default().fg(app.theme.border)
    };

    let explorer = List::new(explorer_items)
        .block(
            Block::default()
                .title("Explorer")
                .borders(Borders::ALL)
                .border_style(explorer_border_style)
                .style(Style::default().bg(app.theme.bg)),
        )
        .highlight_style(explorer_style)
        .highlight_symbol("> ");

    f.render_stateful_widget(explorer, main_chunks[0], &mut app.explorer_state);

    // Content pane
    let content_border_style = if app.active_pane == ActivePane::Content {
        Style::default().fg(app.theme.highlight_bg)
    } else {
        Style::default().fg(app.theme.border)
    };

    let content_text = app.render_content();

    let content = Paragraph::new(content_text)
        .block(
            Block::default()
                .title("Content")
                .borders(Borders::ALL)
                .border_style(content_border_style)
                .style(Style::default().bg(app.theme.bg)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.content_scroll as u16, 0));

    f.render_widget(content, main_chunks[1]);

    // Status bar
    let status = format!(
        "q: Quit | Tab/h/l: Switch pane | j/k: Navigate | Enter: Select | Active: {:?}",
        app.active_pane
    );
    let status_para =
        Paragraph::new(status).style(Style::default().bg(app.theme.bg).fg(app.theme.fg));
    f.render_widget(status_para.centered(), chunks[2]);
}

pub fn main(exec_path: &PathBuf, exec: Exec) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);

    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(exec, exec_path.clone());

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.handle_key(key.code, key.modifiers);
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;

    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;

    terminal.show_cursor()?;

    return Ok(());
}
