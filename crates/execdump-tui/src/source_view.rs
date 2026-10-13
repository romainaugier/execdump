/*
 * Source view: the C code of a module, every function of it one after the other.
 *
 * Modules can hold any number of functions: the view is a list of blocks (one per function) whose
 * heights are kept in a Fenwick tree, only the visible blocks are read and highlighted. Functions not
 * decompiled yet are a one line placeholder until their code arrives (they are decompiled first, as
 * they are shown). The cursor is a block, a line in it and a column, so that it stays on the same
 * code when the blocks above it change.
 *
 * The code can be edited (insert mode, as in vim), the edits are kept by the project.
 */

use crate::theme::Theme;

use execdump_project::{Priority, Project};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

const KEYWORDS: &[&str] = &["if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return", "goto", "sizeof"];

const TYPES: &[&str] = &["void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "bool", "struct", "union", "enum", "const", "undefined"];

/// Blocks after the visible ones that are decompiled before the others
const LOOKAHEAD: usize = 16;

/*
 * Fenwick tree of the block heights
 */

#[derive(Clone, Debug, Default)]
struct Fenwick {
    tree: Vec<usize>,
    values: Vec<usize>,
}

impl Fenwick {
    fn new(values: Vec<usize>) -> Self {
        let n = values.len();
        let mut tree = vec![0; n + 1];
        tree[1..].copy_from_slice(&values);

        for i in 1..=n {
            let j = i + (i & i.wrapping_neg());

            if j <= n {
                tree[j] += tree[i];
            }
        }

        return Fenwick { tree, values };
    }

    fn get(&self, i: usize) -> usize {
        return self.values.get(i).copied().unwrap_or(0);
    }

    fn set(&mut self, i: usize, value: usize) {
        let old = self.values[i];
        self.values[i] = value;

        let mut j = i + 1;

        while j < self.tree.len() {
            self.tree[j] = self.tree[j] + value - old;
            j += j & j.wrapping_neg();
        }
    }

    /// Sum of the values before index i
    fn prefix(&self, i: usize) -> usize {
        let mut sum = 0;
        let mut j = i.min(self.values.len());

        while j > 0 {
            sum += self.tree[j];
            j -= j & j.wrapping_neg();
        }

        return sum;
    }

    fn total(&self) -> usize {
        return self.prefix(self.values.len());
    }

    /// Index and offset of a position (the index whose range contains it)
    fn find(&self, position: usize) -> (usize, usize) {
        let mut index = 0;
        let mut remaining = position;
        let mut step = self.tree.len().next_power_of_two() / 2;

        while step > 0 {
            if index + step < self.tree.len() && self.tree[index + step] <= remaining {
                index += step;
                remaining -= self.tree[index];
            }

            step /= 2;
        }

        return (index.min(self.values.len().saturating_sub(1)), remaining);
    }
}

/*
 * Syntax highlighting
 */

fn is_type(word: &str) -> bool {
    return TYPES.contains(&word) || (word.ends_with("_t") && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
}

/// Whether a block comment is still open after some lines
pub fn comment_after<'a>(lines: impl Iterator<Item = &'a str>) -> bool {
    let theme = Theme::codedark();
    let mut comment = false;

    for line in lines {
        highlight_with(&theme, line, &mut comment);
    }

    return comment;
}

/// Highlights a line, comment tells whether it starts in a block comment and whether one is still open at its end
pub fn highlight_with(theme: &Theme, line: &str, comment: &mut bool) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    let style = |color| Style::default().fg(color);

    if line.starts_with("<<<<<<<") || line.starts_with("=======") || line.starts_with(">>>>>>>") {
        return vec![Span::styled(line.to_string(), Style::default().fg(theme.warning).add_modifier(Modifier::BOLD))];
    }

    // End of a block comment, from the start of the line or of the comment
    let block_end = |from: usize| (from..chars.len().saturating_sub(1)).find(|&j| chars[j] == '*' && chars[j + 1] == '/').map(|j| j + 2);

    while i < chars.len() {
        let c = chars[i];
        let start = i;

        let color = if *comment || (c == '/' && chars.get(i + 1) == Some(&'*')) {
            let from = if *comment { i } else { i + 2 };

            match block_end(from) {
                Some(end) => {
                    i = end;
                    *comment = false;
                }
                None => {
                    i = chars.len();
                    *comment = true;
                }
            }

            theme.comment
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            i = chars.len();
            theme.comment
        } else if c == '"' || c == '\'' {
            i += 1;

            while i < chars.len() && chars[i] != c {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }

            i = (i + 1).min(chars.len());
            theme.hex_ascii
        } else if c.is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                i += 1;
            }

            theme.asm_immediate
        } else if c.is_ascii_alphabetic() || c == '_' {
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }

            let word: String = chars[start..i].iter().collect();

            if KEYWORDS.contains(&word.as_str()) {
                theme.asm_call
            } else if is_type(&word) {
                theme.asm_instruction
            } else if chars.get(i) == Some(&'(') {
                theme.asm_label
            } else {
                theme.asm_register
            }
        } else {
            i += 1;
            theme.fg
        };

        spans.push(Span::styled(chars[start..i.min(chars.len())].iter().collect::<String>(), style(color)));
    }

    return spans;
}

/// Identifier at a column of a line (or the closest one after it)
pub fn word_at(line: &str, col: usize) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut start = col.min(chars.len());

    if !chars.get(start).is_some_and(|c| is_word(*c)) {
        start = (start..chars.len()).find(|&i| is_word(chars[i]))?;
    }

    while start > 0 && is_word(chars[start - 1]) {
        start -= 1;
    }

    let end = (start..chars.len()).find(|&i| !is_word(chars[i])).unwrap_or(chars.len());
    let word: String = chars[start..end].iter().collect();

    return Some(word).filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'));
}

/*
 * View
 */

#[derive(Clone, Debug)]
pub struct Insert {
    pub addr: u64,
    pub lines: Vec<String>,
    /// Text before the insertion, for undo
    before: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pos {
    pub block: usize,
    pub line: usize,
}

#[derive(Clone, Debug)]
pub struct SourceView {
    pub program: usize,
    pub module: String,
    pub functions: Vec<u64>,
    heights: Fenwick,
    /// Version of the project the blocks were listed for
    version: u64,
    pub cursor: Pos,
    pub col: usize,
    top: Pos,
    pub height: usize,
    pub insert: Option<Insert>,
    undo: Vec<(u64, String)>,
    redo: Vec<(u64, String)>,
}

pub enum InsertWhere {
    Cursor,
    After,
    LineEnd,
    LineStart,
    Below,
    Above,
}

impl SourceView {
    pub fn new(program: usize, module: &str, project: &Project) -> Self {
        let mut view = SourceView {
            program,
            module: module.to_string(),
            functions: Vec::new(),
            heights: Fenwick::default(),
            version: u64::MAX,
            cursor: Pos::default(),
            col: 0,
            top: Pos::default(),
            height: 20,
            insert: None,
            undo: Vec::new(),
            redo: Vec::new(),
        };

        view.refresh(project);
        return view;
    }

    pub fn title(&self) -> String {
        let mode = if self.insert.is_some() { " -- INSERT --" } else { "" };
        return format!("{} ({} functions){}", self.module, self.functions.len(), mode);
    }

    fn block_height(&self, project: &Project, addr: u64) -> usize {
        if let Some(insert) = self.insert.as_ref().filter(|i| i.addr == addr) {
            return insert.lines.len() + 1;
        }

        return project.line_count(addr).unwrap_or(1) + 1;
    }

    /// Lists the functions of the module again when the project changed
    pub fn refresh(&mut self, project: &Project) {
        if self.version == project.version {
            return;
        }

        let (cursor_addr, top_addr) = (self.functions.get(self.cursor.block).copied(), self.functions.get(self.top.block).copied());
        self.version = project.version;
        self.functions = project.modules.functions(&self.module).to_vec();
        self.heights = Fenwick::new(self.functions.iter().map(|&a| self.block_height(project, a)).collect());

        // The cursor stays on its function, or near where it was
        let block_of = |addr: Option<u64>, fallback: usize, functions: &[u64]| match addr.map(|a| functions.binary_search(&a)) {
            Some(Ok(i)) => i,
            Some(Err(i)) => i.min(functions.len().saturating_sub(1)),
            None => fallback.min(functions.len().saturating_sub(1)),
        };

        self.cursor.block = block_of(cursor_addr, self.cursor.block, &self.functions);
        self.top.block = block_of(top_addr, self.top.block, &self.functions);
        self.clamp();
    }

    /// The text of some functions changed
    pub fn changed(&mut self, project: &Project, addrs: &[u64]) {
        for addr in addrs {
            if let Ok(index) = self.functions.binary_search(addr) {
                let height = self.block_height(project, *addr);
                self.heights.set(index, height);
            }
        }

        self.clamp();
    }

    fn clamp(&mut self) {
        if self.functions.is_empty() {
            self.cursor = Pos::default();
            self.top = Pos::default();
            return;
        }

        self.cursor.line = self.cursor.line.min(self.heights.get(self.cursor.block).saturating_sub(1));
        self.top.line = self.top.line.min(self.heights.get(self.top.block).saturating_sub(1));
    }

    fn abs(&self, pos: Pos) -> usize {
        return self.heights.prefix(pos.block) + pos.line;
    }

    fn pos(&self, abs: usize) -> Pos {
        let total = self.heights.total();

        if total == 0 {
            return Pos::default();
        }

        let (block, line) = self.heights.find(abs.min(total - 1));
        return Pos { block, line };
    }

    pub fn function(&self) -> Option<u64> {
        return self.functions.get(self.cursor.block).copied();
    }

    /// Lines of a block as shown (the insert buffer, the code or a placeholder)
    fn block_lines(&self, project: &mut Project, block: usize) -> Vec<String> {
        let Some(&addr) = self.functions.get(block) else {
            return Vec::new();
        };

        if let Some(insert) = self.insert.as_ref().filter(|i| i.addr == addr) {
            return insert.lines.clone();
        }

        return match project.shown(addr) {
            Some((rendered, _)) => rendered.text.lines().map(|l| l.to_string()).collect(),
            None => vec![placeholder(project, addr)],
        };
    }

    pub fn cursor_line(&self, project: &mut Project) -> String {
        let Some(&addr) = self.functions.get(self.cursor.block) else {
            return String::new();
        };

        if let Some(insert) = self.insert.as_ref().filter(|i| i.addr == addr) {
            return insert.lines.get(self.cursor.line).cloned().unwrap_or_default();
        }

        return match project.shown(addr) {
            Some((rendered, _)) => rendered.text.lines().nth(self.cursor.line).unwrap_or_default().to_string(),
            None if self.cursor.line == 0 => placeholder(project, addr),
            None => String::new(),
        };
    }

    /// Address of the line under the cursor (or of the closest line above with one)
    pub fn cursor_addr(&self, project: &mut Project) -> Option<u64> {
        let addr = self.function()?;

        let Some((rendered, _)) = project.shown(addr) else {
            return Some(addr);
        };

        let end = (self.cursor.line + 1).min(rendered.lines.len());
        return rendered.lines[..end].iter().rev().flatten().next().copied().or(Some(addr));
    }

    pub fn word(&self, project: &mut Project) -> Option<String> {
        return word_at(&self.cursor_line(project), self.col);
    }

    /*
     * Moves
     */

    pub fn move_lines(&mut self, project: &mut Project, delta: isize) {
        let total = self.heights.total();

        if total == 0 {
            return;
        }

        let abs = (self.abs(self.cursor) as isize + delta).clamp(0, total as isize - 1) as usize;
        self.cursor = self.pos(abs);
        self.clamp_col(project);
        self.follow();
    }

    pub fn move_col(&mut self, project: &mut Project, delta: isize) {
        let len = self.cursor_line(project).chars().count();
        self.col = (self.col as isize + delta).clamp(0, len.saturating_sub(1) as isize) as usize;
    }

    fn clamp_col(&mut self, project: &mut Project) {
        let len = self.cursor_line(project).chars().count();
        self.col = self.col.min(len.saturating_sub(1));
    }

    pub fn line_start(&mut self, project: &mut Project, first_word: bool) {
        self.col = if first_word { self.cursor_line(project).chars().take_while(|c| c.is_whitespace()).count() } else { 0 };
    }

    pub fn line_end(&mut self, project: &mut Project) {
        self.col = self.cursor_line(project).chars().count().saturating_sub(1);
    }

    /// Next (or previous) word start on the line, then on the next lines
    pub fn word_move(&mut self, project: &mut Project, forward: bool) {
        let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';

        for _ in 0..64 {
            let chars: Vec<char> = self.cursor_line(project).chars().collect();

            if forward {
                let mut i = self.col;
                let class = chars.get(i).map(|c| is_word(*c));

                while i < chars.len() && chars.get(i).map(|c| is_word(*c)) == class && !chars[i].is_whitespace() {
                    i += 1;
                }

                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }

                if i < chars.len() && i != self.col {
                    self.col = i;
                    return;
                }

                let before = self.cursor;
                self.move_lines(project, 1);
                self.col = 0;

                if self.cursor == before {
                    return;
                }

                if self.cursor_line(project).chars().next().is_some_and(|c| !c.is_whitespace()) {
                    return;
                }
            } else {
                let mut i = self.col;

                while i > 0 && chars.get(i - 1).is_some_and(|c| c.is_whitespace()) {
                    i -= 1;
                }

                if i > 0 {
                    let class = is_word(chars[i - 1]);

                    while i > 0 && is_word(chars[i - 1]) == class && !chars[i - 1].is_whitespace() {
                        i -= 1;
                    }

                    self.col = i;
                    return;
                }

                let before = self.cursor;
                self.move_lines(project, -1);

                if self.cursor == before {
                    self.col = 0;
                    return;
                }

                self.col = self.cursor_line(project).chars().count();
            }
        }
    }

    pub fn first_line(&mut self) {
        self.cursor = Pos::default();
        self.col = 0;
        self.follow();
    }

    pub fn last_line(&mut self) {
        self.cursor = self.pos(self.heights.total().saturating_sub(1));
        self.col = 0;
        self.follow();
    }

    /// Next (or previous) function
    pub fn jump_function(&mut self, forward: bool) {
        let block = if forward { (self.cursor.block + 1).min(self.functions.len().saturating_sub(1)) } else if self.cursor.line > 0 { self.cursor.block } else { self.cursor.block.saturating_sub(1) };

        self.cursor = Pos { block, line: 0 };
        self.col = 0;
        self.top = self.cursor;
    }

    /// Moves the cursor to the line of an address, false when it is not in the module
    pub fn goto(&mut self, project: &mut Project, addr: u64) -> bool {
        let function = project.analysis.function_containing(addr).map(|f| f.addr);

        let Some(block) = function.and_then(|f| self.functions.binary_search(&f).ok()) else {
            return false;
        };

        let line = match project.shown(self.functions[block]) {
            Some((rendered, _)) => {
                let best = rendered.lines.iter().enumerate().filter_map(|(i, a)| a.filter(|&a| a <= addr).map(|a| (i, a))).max_by_key(|(i, a)| (*a, usize::MAX - i));
                best.map_or(0, |(i, _)| i)
            }
            None => 0,
        };

        self.cursor = Pos { block, line };
        self.clamp();
        self.clamp_col(project);
        self.center();

        return true;
    }

    fn center(&mut self) {
        let abs = self.abs(self.cursor);
        self.top = self.pos(abs.saturating_sub(self.height / 3));
    }

    /// Keeps the cursor in the viewport
    fn follow(&mut self) {
        let (cursor, top) = (self.abs(self.cursor), self.abs(self.top));
        let height = self.height.max(1);

        if cursor < top {
            self.top = self.cursor;
        } else if cursor >= top + height {
            self.top = self.pos(cursor + 1 - height);
        }
    }

    /// Next line (after the cursor, wrapping) containing a pattern, in the decompiled functions
    pub fn search(&mut self, project: &mut Project, pattern: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.functions.len();

        for step in 0..=count {
            let block = (self.cursor.block + step) % count.max(1);
            let start = if step == 0 { self.cursor.line + 1 } else { 0 };

            let Some((rendered, _)) = project.shown(self.functions[block]) else {
                continue;
            };

            for (line, text) in rendered.text.lines().enumerate().skip(start) {
                // Lowercasing may change the length of the characters: the column is counted in the lowercased text
                let lower = text.to_lowercase();

                if let Some(byte) = lower.find(&pattern) {
                    self.cursor = Pos { block, line };
                    self.col = lower[..byte].chars().count();
                    self.center();
                    return true;
                }
            }
        }

        return false;
    }

    /*
     * Editing
     */

    pub fn start_insert(&mut self, project: &mut Project, at: InsertWhere) -> Result<(), String> {
        let addr = self.function().ok_or("no function here")?;

        if project.shown(addr).is_none() {
            return Err("this function is not decompiled yet".to_string());
        }

        let mut lines = self.block_lines(project, self.cursor.block);
        let before = format!("{}\n", lines.join("\n"));

        // The blank line after a function is not part of it
        if self.cursor.line >= lines.len() {
            self.cursor.line = lines.len().saturating_sub(1);
        }

        let line = lines.get(self.cursor.line).cloned().unwrap_or_default();
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();

        match at {
            InsertWhere::Cursor => self.col = self.col.min(line.chars().count()),
            InsertWhere::After => self.col = (self.col + 1).min(line.chars().count()),
            InsertWhere::LineEnd => self.col = line.chars().count(),
            InsertWhere::LineStart => self.col = indent.chars().count(),
            InsertWhere::Below => {
                lines.insert(self.cursor.line + 1, indent.clone());
                self.cursor.line += 1;
                self.col = indent.chars().count();
            }
            InsertWhere::Above => {
                lines.insert(self.cursor.line, indent.clone());
                self.col = indent.chars().count();
            }
        }

        self.insert = Some(Insert { addr, lines, before });
        self.update_insert_height();

        return Ok(());
    }

    fn update_insert_height(&mut self) {
        if let Some(insert) = self.insert.as_ref() {
            if let Ok(index) = self.functions.binary_search(&insert.addr) {
                let height = insert.lines.len() + 1;
                self.heights.set(index, height);
            }
        }

        self.follow();
    }

    /// Key in insert mode, false when it leaves the insert mode
    pub fn insert_key(&mut self, project: &mut Project, key: KeyEvent) -> Result<bool, String> {
        let Some(insert) = self.insert.as_mut() else {
            return Ok(false);
        };

        if insert.lines.is_empty() {
            insert.lines.push(String::new());
        }

        let line = self.cursor.line.min(insert.lines.len() - 1);
        let chars: Vec<char> = insert.lines.get(line).map_or(Vec::new(), |l| l.chars().collect());
        let col = self.col.min(chars.len());
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Esc => return self.finish_insert(project).map(|_| false),
            KeyCode::Char('c') if ctrl => return self.finish_insert(project).map(|_| false),
            KeyCode::Char(c) => {
                let mut chars = chars;
                chars.insert(col, c);
                insert.lines[line] = chars.into_iter().collect();
                self.col = col + 1;
            }
            KeyCode::Tab => {
                let mut chars = chars;
                (0..4).for_each(|_| chars.insert(col, ' '));
                insert.lines[line] = chars.into_iter().collect();
                self.col = col + 4;
            }
            KeyCode::Enter => {
                let indent: String = chars.iter().take_while(|c| c.is_whitespace()).collect();
                let rest: String = chars[col..].iter().collect();
                insert.lines[line] = chars[..col].iter().collect();
                insert.lines.insert(line + 1, format!("{}{}", indent, rest.trim_start()));
                self.cursor.line = line + 1;
                self.col = indent.chars().count();
            }
            KeyCode::Backspace => {
                if col > 0 {
                    let mut chars = chars;
                    chars.remove(col - 1);
                    insert.lines[line] = chars.into_iter().collect();
                    self.col = col - 1;
                } else if line > 0 {
                    let previous = insert.lines.remove(line);
                    self.col = insert.lines[line - 1].chars().count();
                    insert.lines[line - 1].push_str(&previous);
                    self.cursor.line = line - 1;
                }
            }
            KeyCode::Delete => {
                if col < chars.len() {
                    let mut chars = chars;
                    chars.remove(col);
                    insert.lines[line] = chars.into_iter().collect();
                } else if line + 1 < insert.lines.len() {
                    let next = insert.lines.remove(line + 1);
                    insert.lines[line].push_str(&next);
                }
            }
            KeyCode::Left => self.col = col.saturating_sub(1),
            KeyCode::Right => self.col = (col + 1).min(chars.len()),
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = chars.len(),
            KeyCode::Up => {
                self.cursor.line = line.saturating_sub(1);
                self.col = col.min(insert.lines[self.cursor.line].chars().count());
            }
            KeyCode::Down => {
                self.cursor.line = (line + 1).min(insert.lines.len() - 1);
                self.col = col.min(insert.lines[self.cursor.line].chars().count());
            }
            _ => {}
        }

        self.update_insert_height();
        return Ok(true);
    }

    fn finish_insert(&mut self, project: &mut Project) -> Result<(), String> {
        let Some(insert) = self.insert.take() else {
            return Ok(());
        };

        let text = format!("{}\n", insert.lines.join("\n"));
        self.col = self.col.saturating_sub(1);

        if text != insert.before {
            self.undo.push((insert.addr, insert.before));
            self.redo.clear();
        }

        let result = project.set_edit(insert.addr, &text);
        self.changed(project, &[insert.addr]);

        return result;
    }

    /// Replaces the text of the function under the cursor (undoable)
    pub fn replace(&mut self, project: &mut Project, text: &str) -> Result<(), String> {
        let addr = self.function().ok_or("no function here")?;
        let (rendered, _) = project.shown(addr).ok_or("this function is not decompiled yet")?;
        let before = rendered.text.clone();

        project.set_edit(addr, text)?;
        self.undo.push((addr, before));
        self.redo.clear();
        self.changed(project, &[addr]);
        self.clamp();

        return Ok(());
    }

    /// Deletes the line under the cursor
    pub fn delete_line(&mut self, project: &mut Project) -> Result<(), String> {
        let mut lines = self.block_lines(project, self.cursor.block);

        if self.cursor.line >= lines.len() {
            return Ok(());
        }

        lines.remove(self.cursor.line);
        self.replace(project, &format!("{}\n", lines.join("\n")))?;
        self.clamp_col(project);

        return Ok(());
    }

    /// Adds a comment line above the cursor
    pub fn comment(&mut self, project: &mut Project, text: &str) -> Result<(), String> {
        let mut lines = self.block_lines(project, self.cursor.block);
        let line = self.cursor.line.min(lines.len().saturating_sub(1));
        let indent: String = lines.get(line).map_or(String::new(), |l| l.chars().take_while(|c| c.is_whitespace()).collect());

        lines.insert(line, format!("{}// {}", indent, text.trim()));
        return self.replace(project, &format!("{}\n", lines.join("\n")));
    }

    pub fn undo(&mut self, project: &mut Project, redo: bool) -> Result<(), String> {
        let (from, to) = if redo { (&mut self.redo, &mut self.undo) } else { (&mut self.undo, &mut self.redo) };
        let (addr, text) = from.pop().ok_or(if redo { "Already at the newest change" } else { "Already at the oldest change" })?;

        if let Some((rendered, _)) = project.shown(addr) {
            to.push((addr, rendered.text.clone()));
        }

        project.set_edit(addr, &text)?;
        self.changed(project, &[addr]);

        if let Ok(block) = self.functions.binary_search(&addr) {
            self.cursor.block = block;
            self.clamp();
            self.follow();
        }

        return Ok(());
    }

    /// Resolves the conflict under the cursor: keeps the edited side, the decompiled one, or both
    pub fn resolve(&mut self, project: &mut Project, keep_edited: bool, keep_decompiled: bool) -> Result<(), String> {
        let lines = self.block_lines(project, self.cursor.block);

        if lines.is_empty() {
            return Err("no conflict under the cursor".to_string());
        }

        let line = self.cursor.line.min(lines.len() - 1);
        let start = (0..=line).rev().find(|&i| lines[i].starts_with("<<<<<<<")).ok_or("no conflict under the cursor")?;
        let middle = (start..lines.len()).find(|&i| lines[i].starts_with("=======")).ok_or("unterminated conflict")?;
        let end = (middle..lines.len()).find(|&i| lines[i].starts_with(">>>>>>>")).ok_or("unterminated conflict")?;

        if line > end {
            return Err("no conflict under the cursor".to_string());
        }

        let mut out: Vec<String> = lines[..start].to_vec();

        if keep_edited {
            out.extend_from_slice(&lines[start + 1..middle]);
        }

        if keep_decompiled {
            out.extend_from_slice(&lines[middle + 1..end]);
        }

        out.extend_from_slice(&lines[end + 1..]);
        self.cursor.line = start;

        return self.replace(project, &format!("{}\n", out.join("\n")));
    }

    /// Next (or previous) conflict marker of the module
    pub fn jump_conflict(&mut self, project: &mut Project, forward: bool) -> bool {
        let count = self.functions.len();

        for step in 0..=count {
            let block = if forward { (self.cursor.block + step) % count.max(1) } else { (self.cursor.block + count * 2 - step) % count.max(1) };
            let addr = self.functions[block];

            if !project.shown(addr).is_some_and(|(_, s)| s.conflict) {
                continue;
            }

            let lines = self.block_lines(project, block);
            let mut candidates: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l.starts_with("<<<<<<<")).map(|(i, _)| i).collect();

            if !forward {
                candidates.reverse();
            }

            let found = candidates.into_iter().find(|&i| step != 0 || if forward { i > self.cursor.line } else { i < self.cursor.line });

            if let Some(line) = found {
                self.cursor = Pos { block, line };
                self.col = 0;
                self.center();
                return true;
            }
        }

        return false;
    }

    /*
     * Rendering
     */

    pub fn render(&mut self, project: &mut Project, theme: &Theme, height: usize, width: usize) -> Vec<Line<'static>> {
        self.height = height.max(1);
        self.refresh(project);
        self.follow();

        if self.functions.is_empty() {
            return vec![Line::from(Span::styled("This module holds no function yet, move some with :mv", Style::default().fg(theme.dim)))];
        }

        let mut lines = Vec::with_capacity(height);
        let mut pos = self.top;
        let mut visible = Vec::new();

        while lines.len() < height && pos.block < self.functions.len() {
            let addr = self.functions[pos.block];
            visible.push(addr);

            // Only the lines that fit are read
            let wanted = height - lines.len();
            let shown = project.shown(addr);
            let (text, addrs, state, count): (Vec<String>, &[Option<u64>], _, usize) = match (self.insert.as_ref().filter(|i| i.addr == addr), shown.as_ref()) {
                (Some(insert), _) => (insert.lines.iter().skip(pos.line).take(wanted).cloned().collect(), &[], None, insert.lines.len()),
                (None, Some((rendered, state))) => (rendered.text.lines().skip(pos.line).take(wanted).map(|l| l.to_string()).collect(), &rendered.lines, Some(*state), rendered.line_count()),
                (None, None) => (vec![placeholder(project, addr)].into_iter().skip(pos.line).collect(), &[], None, 1),
            };

            let block_height = count + 1;

            // A block comment opened above the first line shown
            let mut comment = match (self.insert.as_ref().filter(|i| i.addr == addr), shown.as_ref()) {
                _ if pos.line == 0 => false,
                (Some(insert), _) => comment_after(insert.lines.iter().take(pos.line).map(|l| l.as_str())),
                (None, Some((rendered, _))) => comment_after(rendered.text.lines().take(pos.line)),
                (None, None) => false,
            };

            for line in pos.line..block_height {
                if lines.len() >= height {
                    break;
                }

                let content = text.get(line - pos.line);
                let gutter = match addrs.get(line).copied().flatten() {
                    Some(a) => format!("{:>10x}", a),
                    None => " ".repeat(10),
                };

                let (flag, flag_color) = match (state, content) {
                    (_, None) => (' ', theme.dim),
                    (Some(s), Some(l)) if s.conflict && (l.starts_with("<<<<<<<") || l.starts_with("=======") || l.starts_with(">>>>>>>")) => ('!', theme.warning),
                    (Some(s), _) if s.edited => ('~', theme.edge_true),
                    (Some(s), _) if s.stale => ('·', theme.dim),
                    (None, _) if self.insert.as_ref().is_some_and(|i| i.addr == addr) => ('~', theme.edge_true),
                    _ => (' ', theme.dim),
                };

                let mut spans = vec![
                    Span::styled(gutter, Style::default().fg(theme.asm_address)),
                    Span::styled(format!(" {} ", flag), Style::default().fg(flag_color)),
                ];

                let is_cursor = pos.block == self.cursor.block && line == self.cursor.line;

                match content {
                    Some(text) if shown.is_none() && self.insert.is_none() => spans.push(Span::styled(text.clone(), Style::default().fg(theme.dim).add_modifier(Modifier::ITALIC))),
                    Some(text) if is_cursor => spans.extend(with_cursor(highlight_with(theme, text, &mut comment), self.col, theme)),
                    Some(text) => spans.extend(highlight_with(theme, text, &mut comment)),
                    None if is_cursor => spans.push(Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED))),
                    None => {}
                }

                let mut rendered = Line::from(truncate(spans, width));

                if is_cursor {
                    rendered = rendered.style(Style::default().bg(theme.cursor_bg));
                }

                lines.push(rendered);
            }

            pos = Pos { block: pos.block + 1, line: 0 };
        }

        // What is shown is decompiled first, then what comes after
        let next: Vec<u64> = self.functions.iter().skip(pos.block).take(LOOKAHEAD).copied().collect();
        project.prioritize(&next, Priority::Near);
        project.prioritize(&visible, Priority::Visible);

        return lines;
    }
}

fn placeholder(project: &Project, addr: u64) -> String {
    return format!("// {} ({:#x}): decompiling...", project.function_name(addr), addr);
}

/// Spans with the character at a column reversed (the cursor)
fn with_cursor(spans: Vec<Span<'static>>, col: usize, theme: &Theme) -> Vec<Span<'static>> {
    let mut out = Vec::with_capacity(spans.len() + 2);
    let mut position = 0;
    let mut placed = false;

    for span in spans {
        let len = span.content.chars().count();

        if !placed && col >= position && col < position + len {
            let chars: Vec<char> = span.content.chars().collect();
            let offset = col - position;
            let before: String = chars[..offset].iter().collect();
            let at: String = chars[offset..offset + 1].iter().collect();
            let after: String = chars[offset + 1..].iter().collect();

            if !before.is_empty() {
                out.push(Span::styled(before, span.style));
            }

            out.push(Span::styled(at, span.style.add_modifier(Modifier::REVERSED)));

            if !after.is_empty() {
                out.push(Span::styled(after, span.style));
            }

            placed = true;
        } else {
            out.push(span);
        }

        position += len;
    }

    if !placed {
        out.push(Span::styled(" ".repeat(col.saturating_sub(position)), Style::default()));
        out.push(Span::styled(" ", Style::default().fg(theme.fg).add_modifier(Modifier::REVERSED)));
    }

    return out;
}

fn truncate(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut used = 0;

    for span in spans {
        let len = span.content.chars().count();

        if used + len <= width {
            used += len;
            out.push(span);
        } else {
            let keep: String = span.content.chars().take(width.saturating_sub(used)).collect();
            out.push(Span::styled(keep, span.style));
            break;
        }
    }

    return out;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fenwick() {
        let mut tree = Fenwick::new(vec![3, 1, 4, 1, 5]);
        assert_eq!(tree.total(), 14);
        assert_eq!(tree.prefix(2), 4);
        assert_eq!(tree.find(0), (0, 0));
        assert_eq!(tree.find(3), (1, 0));
        assert_eq!(tree.find(5), (2, 1));
        assert_eq!(tree.find(13), (4, 4));

        tree.set(1, 10);
        assert_eq!(tree.total(), 23);
        assert_eq!(tree.find(12), (1, 9));
        assert_eq!(tree.find(13), (2, 0));

        let big = Fenwick::new(vec![2; 1000]);
        assert_eq!(big.find(1999), (999, 1));
        assert_eq!(big.prefix(500), 1000);
    }

    #[test]
    fn words_and_highlighting() {
        assert_eq!(word_at("    v1 = classify(a1);", 9).as_deref(), Some("classify"));
        assert_eq!(word_at("    v1 = classify(a1);", 2).as_deref(), Some("v1"));
        assert_eq!(word_at("return 0x10;", 7), None);

        let theme = Theme::codedark();
        // Block comments, over several lines, not in strings
        let mut comment = false;
        let spans = highlight_with(&theme, "x = \"/*\"; /* summary", &mut comment);
        assert!(comment);
        assert_eq!(spans.last().map(|s| (s.content.to_string(), s.style.fg)), Some(("/* summary".to_string(), Some(theme.comment))));
        let spans = highlight_with(&theme, "   of it */ y = 1;", &mut comment);
        assert!(!comment);
        assert_eq!(spans[0].content, "   of it */");
        assert!(comment_after(["/* a", "b */", "/* c"].into_iter()));

        let text: String = highlight_with(&theme, "    if (x == \"a\") { return 0x10; } // done", &mut false).iter().map(|s| s.content.to_string()).collect();
        assert_eq!(text, "    if (x == \"a\") { return 0x10; } // done");

        let spans = with_cursor(highlight_with(&theme, "int x;", &mut false), 4, &theme);
        assert!(spans.iter().any(|s| s.content == "x" && s.style.add_modifier.contains(Modifier::REVERSED)));
    }
}
