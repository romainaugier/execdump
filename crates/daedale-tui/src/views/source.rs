// SPDX-License-Identifier: Apache-2.0
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

use crate::commands::{Command, Motion};
use crate::debug::Marks;
use crate::syntax::{self, Syntax};
use crate::theme::Theme;
use crate::views::View;
use crate::{App, OpenMode, VERTICAL_STEP};

use anyhow::{anyhow, bail, Context, Result};

use std::collections::HashSet;
use std::sync::Arc;

use daedale_project::{Priority, Project};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

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
 * Syntax highlighting (see syntax)
 */

/// Highlights a line of C, comment tells whether it starts in a block comment and whether one is still open at its end
pub fn highlight_with(theme: &Theme, line: &str, comment: &mut bool) -> Vec<Span<'static>> {
    return syntax::C.highlight(theme, line, comment, &|_| false);
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

/// Visual mode: the selection goes from where it started to the cursor, by characters (v) or by lines (V)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Visual {
    pub anchor: Pos,
    pub col: usize,
    pub lines: bool,
}

/// What is selected: from a line and a column to a line and a column (included), in lines from the top of the module
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Selection {
    start: (usize, usize),
    end: (usize, usize),
    lines: bool,
}

impl Selection {
    /// Characters of a line of a length selected (start, end excluded), the end of the line included past its last
    /// character
    fn range(&self, line: usize, len: usize) -> Option<(usize, usize)> {
        if line < self.start.0 || line > self.end.0 {
            return None;
        }

        if self.lines {
            return Some((0, len.max(1)));
        }

        let start = if line == self.start.0 { self.start.1 } else { 0 };
        let end = if line == self.end.0 { self.end.1 + 1 } else { len + 1 };
        return Some((start.min(len), end.min(len + 1).max(start.min(len) + 1)));
    }
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
    pub visual: Option<Visual>,
    /// Language of the code shown
    pub syntax: &'static Syntax,
    /// Names of the types the code may use (the typedefs and the structs of the type database)
    types: Arc<HashSet<String>>,
    undo: Vec<(u64, String)>,
    redo: Vec<(u64, String)>,
}

/// What an operator (delete, change) goes over from the cursor
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Word,
    WordEnd,
    WordBack,
    LineEnd,
    LineStart,
    LineFirst,
    /// Whole lines: the cursor line, the lines below, the lines above
    Line,
    Down,
    Up,
    Char,
    CharBack,
    /// The selection of the visual mode
    Selection,
}

/// Kind of a character for the word moves: blank, identifier or punctuation
fn char_class(c: char) -> u8 {
    return if c.is_whitespace() { 0 } else if c.is_ascii_alphanumeric() || c == '_' { 1 } else { 2 };
}

/// Start of the next word of a line (its length at the last word)
fn next_word(chars: &[char], mut i: usize) -> usize {
    let class = chars.get(i).map(|&c| char_class(c));

    while i < chars.len() && class != Some(0) && Some(char_class(chars[i])) == class {
        i += 1;
    }

    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }

    return i;
}

/// End of the word (after its last character), from the next character
fn word_end(chars: &[char], i: usize) -> usize {
    let mut i = (i + 1).min(chars.len());

    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }

    let class = chars.get(i).map(|&c| char_class(c));

    while i < chars.len() && Some(char_class(chars[i])) == class {
        i += 1;
    }

    return i;
}

/// Start of the previous word of a line
fn previous_word(chars: &[char], mut i: usize) -> usize {
    while i > 0 && chars[i - 1].is_whitespace() {
        i -= 1;
    }

    let class = i.checked_sub(1).map(|j| char_class(chars[j]));

    while i > 0 && Some(char_class(chars[i - 1])) == class {
        i -= 1;
    }

    return i;
}

/// Characters of a line an operator goes over (start, end), repeated count times
fn reach_range(chars: &[char], col: usize, reach: Reach, count: usize, change: bool) -> (usize, usize) {
    let indent = chars.iter().take_while(|c| c.is_whitespace()).count();
    let ends = |mut end: usize, times: usize| {
        for _ in 0..times {
            end = word_end(chars, end.saturating_sub(1));
        }

        end
    };

    return match reach {
        // cw changes to the end of the word under the cursor, as in vim
        Reach::Word if change && chars.get(col).is_some_and(|c| !c.is_whitespace()) => {
            let class = char_class(chars[col]);
            let end = (col..chars.len()).find(|&i| char_class(chars[i]) != class).unwrap_or(chars.len());
            (col, ends(end, count - 1))
        }
        Reach::Word => (col, (0..count).fold(col, |i, _| next_word(chars, i))),
        Reach::WordEnd => (col, ends(word_end(chars, col), count - 1)),
        Reach::WordBack => ((0..count).fold(col, |i, _| previous_word(chars, i)), col),
        Reach::LineEnd => (col, chars.len()),
        Reach::LineStart => (0, col),
        Reach::LineFirst => (indent.min(col), indent.max(col)),
        Reach::Char => (col, (col + count).min(chars.len())),
        Reach::CharBack => (col.saturating_sub(count), col),
        Reach::Line | Reach::Down | Reach::Up | Reach::Selection => (0, chars.len()),
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            visual: None,
            syntax: &syntax::C,
            types: Arc::new(project.typedb.typedefs.keys().chain(project.typedb.aggregates.keys()).cloned().collect()),
            undo: Vec::new(),
            redo: Vec::new(),
        };

        view.refresh(project);
        return view;
    }

    pub fn title(&self) -> String {
        let mode = match (&self.insert, &self.visual) {
            (Some(_), _) => " -- INSERT --",
            (None, Some(visual)) if visual.lines => " -- VISUAL LINE --",
            (None, Some(_)) => " -- VISUAL --",
            (None, None) => "",
        };

        let mode = if std::ptr::eq(self.syntax, &syntax::C) { mode.to_string() } else { format!(" [{}]{}", self.syntax.name, mode) };
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

        if let Some(visual) = self.visual.as_mut() {
            visual.anchor.block = visual.anchor.block.min(self.functions.len() - 1);
            visual.anchor.line = visual.anchor.line.min(self.heights.get(visual.anchor.block).saturating_sub(1));
        }
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
    /// End of the word (e): the last character of the next word end, on the next lines past the end of the line
    pub fn word_end_move(&mut self, project: &mut Project) {
        for _ in 0..64 {
            let chars: Vec<char> = self.cursor_line(project).chars().collect();
            let end = word_end(&chars, self.col);

            if end > self.col + 1 && chars.get(end - 1).is_some_and(|c| !c.is_whitespace()) {
                self.col = end - 1;
                return;
            }

            let before = self.cursor;
            self.move_lines(project, 1);

            if self.cursor == before {
                return;
            }

            // From before the start of the line: its first word counts
            self.col = 0;
            let chars: Vec<char> = self.cursor_line(project).chars().collect();

            if chars.first().is_some_and(|c| !c.is_whitespace()) {
                let class = char_class(chars[0]);
                self.col = chars.iter().take_while(|&&c| char_class(c) == class).count() - 1;
                return;
            }
        }
    }

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
            Some((rendered, _)) => line_of(&rendered.lines, addr).unwrap_or(0),
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

    /// Next (or previous) line containing a pattern, from the cursor and wrapping, in the decompiled functions
    pub fn search(&mut self, project: &mut Project, pattern: &str, forward: bool) -> bool {
        let pattern = pattern.to_lowercase();
        let count = self.functions.len();

        if count == 0 {
            return false;
        }

        for step in 0..=count {
            let block = if forward { (self.cursor.block + step) % count.max(1) } else { (self.cursor.block + count * 2 - step) % count.max(1) };

            let Some((rendered, _)) = project.shown(self.functions[block]) else {
                continue;
            };

            let mut lines: Vec<(usize, &str)> = rendered.text.lines().enumerate().collect();

            // The lines after the cursor (before it backwards), then the whole blocks
            if step == 0 {
                lines.retain(|(line, _)| if forward { *line > self.cursor.line } else { *line < self.cursor.line });
            } else if step == count {
                lines.retain(|(line, _)| if forward { *line <= self.cursor.line } else { *line >= self.cursor.line });
            }

            if !forward {
                lines.reverse();
            }

            for (line, text) in lines {
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

    /*
     * Visual mode
     */

    /// v and V: starts the selection at the cursor, switches between characters and lines, or leaves it (None, or the
    /// mode it is in)
    pub fn visual(&mut self, lines: Option<bool>) {
        self.visual = match (self.visual, lines) {
            (_, None) => None,
            (Some(visual), Some(lines)) if visual.lines == lines => None,
            (Some(visual), Some(lines)) => Some(Visual { lines, ..visual }),
            (None, Some(lines)) => Some(Visual { anchor: self.cursor, col: self.col, lines }),
        };
    }

    fn selection(&self) -> Option<Selection> {
        let visual = self.visual?;
        let anchor = (self.abs(visual.anchor), visual.col);
        let cursor = (self.abs(self.cursor), self.col);
        let (start, end) = if anchor <= cursor { (anchor, cursor) } else { (cursor, anchor) };

        return Some(Selection { start, end, lines: visual.lines });
    }

    /// Text of the selection, or of lines from the cursor without one (yy), and the number of lines
    pub fn yank(&mut self, project: &mut Project, count: usize) -> (String, usize) {
        let cursor = self.abs(self.cursor);
        let selection = self.selection().unwrap_or(Selection { start: (cursor, 0), end: (cursor + count.max(1) - 1, 0), lines: true });
        let mut text = String::new();
        let mut cached: Option<(usize, Vec<String>)> = None;
        let total = self.heights.total();

        for abs in selection.start.0..=selection.end.0.min(total.saturating_sub(1)) {
            let pos = self.pos(abs);

            if cached.as_ref().is_none_or(|(block, _)| *block != pos.block) {
                cached = Some((pos.block, self.block_lines(project, pos.block)));
            }

            let line = cached.as_ref().and_then(|(_, lines)| lines.get(pos.line)).cloned().unwrap_or_default();
            let chars: Vec<char> = line.chars().collect();

            if let Some((start, end)) = selection.range(abs, chars.len()) {
                text.extend(chars[start.min(chars.len())..end.min(chars.len())].iter());

                if selection.lines || end > chars.len() {
                    text.push('\n');
                }
            }
        }

        self.visual = None;
        return (text, selection.end.0 - selection.start.0 + 1);
    }

    pub fn start_insert(&mut self, project: &mut Project, at: InsertWhere) -> Result<()> {
        let addr = self.function().context("no function here")?;
        self.visual = None;

        if project.shown(addr).is_none() {
            bail!("this function is not decompiled yet");
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
    pub fn insert_key(&mut self, project: &mut Project, key: KeyEvent) -> Result<bool> {
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

    fn finish_insert(&mut self, project: &mut Project) -> Result<()> {
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
    pub fn replace(&mut self, project: &mut Project, text: &str) -> Result<()> {
        let addr = self.function().context("no function here")?;
        let (rendered, _) = project.shown(addr).context("this function is not decompiled yet")?;
        let before = rendered.text.clone();

        project.set_edit(addr, text)?;
        self.undo.push((addr, before));
        self.redo.clear();
        self.changed(project, &[addr]);
        self.clamp();

        return Ok(());
    }

    /// Deletes the line under the cursor
    pub fn delete_line(&mut self, project: &mut Project) -> Result<()> {
        let mut lines = self.block_lines(project, self.cursor.block);

        if self.cursor.line >= lines.len() {
            return Ok(());
        }

        lines.remove(self.cursor.line);
        self.replace(project, &format!("{}\n", lines.join("\n")))?;
        self.clamp_col(project);

        return Ok(());
    }

    /// Deletes what a motion goes over from the cursor (lines, or characters of the line), then starts the
    /// insert mode there when it changes it
    pub fn operate(&mut self, project: &mut Project, reach: Reach, count: usize, change: bool) -> Result<()> {
        if reach == Reach::Selection {
            return self.delete_selection(project, change);
        }

        let addr = self.function().context("no function here")?;

        if project.shown(addr).is_none() {
            bail!("this function is not decompiled yet");
        }

        let mut lines = self.block_lines(project, self.cursor.block);
        let line = self.cursor.line;
        let count = count.max(1);

        // The blank line after a function is not part of it
        if line >= lines.len() {
            return Ok(());
        }

        if matches!(reach, Reach::Line | Reach::Down | Reach::Up) {
            let (first, last) = match reach {
                Reach::Line => (line, line + count - 1),
                Reach::Down => (line, line + count),
                _ => (line.saturating_sub(count), line),
            };

            let last = last.min(lines.len() - 1);
            let indent: String = lines[first].chars().take_while(|c| c.is_whitespace()).collect();
            lines.drain(first..=last);

            if change || lines.is_empty() {
                lines.insert(first, if change { indent.clone() } else { String::new() });
            }

            self.cursor.line = first.min(lines.len() - 1);
            self.replace(project, &format!("{}\n", lines.join("\n")))?;

            if change {
                self.col = indent.chars().count();
                return self.start_insert(project, InsertWhere::Cursor);
            }

            self.line_start(project, true);
            return Ok(());
        }

        let chars: Vec<char> = lines[line].chars().collect();
        let col = self.col.min(chars.len());
        let (start, end) = reach_range(&chars, col, reach, count, change);

        if start < end {
            lines[line] = chars[..start].iter().chain(chars[end..].iter()).collect();
            self.replace(project, &format!("{}\n", lines.join("\n")))?;
        }

        self.col = start;

        if change {
            return self.start_insert(project, InsertWhere::Cursor);
        }

        self.clamp_col(project);
        return Ok(());
    }

    /// Deletes the selection of the visual mode (in one function), then starts the insert mode there when it changes it
    fn delete_selection(&mut self, project: &mut Project, change: bool) -> Result<()> {
        let selection = self.selection().context("nothing selected")?;
        let (start, end) = (self.pos(selection.start.0), self.pos(selection.end.0));

        if start.block != end.block {
            bail!("the selection goes over several functions: their code is edited one function at a time");
        }

        self.cursor = start;
        let addr = self.function().context("no function here")?;

        if project.shown(addr).is_none() {
            bail!("this function is not decompiled yet");
        }

        let mut lines = self.block_lines(project, start.block);
        self.visual = None;

        // The blank line after a function is not part of it
        if start.line >= lines.len() {
            return Ok(());
        }

        let last = end.line.min(lines.len() - 1);

        if selection.lines {
            let indent: String = lines[start.line].chars().take_while(|c| c.is_whitespace()).collect();
            lines.drain(start.line..=last);

            if change || lines.is_empty() {
                lines.insert(start.line, if change { indent.clone() } else { String::new() });
            }

            self.cursor.line = start.line.min(lines.len() - 1);
            self.replace(project, &format!("{}\n", lines.join("\n")))?;

            if change {
                self.col = indent.chars().count();
                return self.start_insert(project, InsertWhere::Cursor);
            }

            self.line_start(project, true);
            return Ok(());
        }

        // The characters from the start to the end (included), the end of a line selected joins it with the next one
        let mut chars: Vec<char> = lines.join("\n").chars().collect();
        let offset = |line: usize, col: usize| lines[..line].iter().map(|l| l.chars().count() + 1).sum::<usize>() + col.min(lines[line].chars().count());
        let end_col = if last < end.line { usize::MAX } else { selection.end.1 };
        let from = offset(start.line, selection.start.1);
        let to = (offset(last, end_col) + 1).min(chars.len());

        if from < to {
            chars.drain(from..to);
        }

        let text: String = chars.into_iter().collect();
        self.replace(project, &format!("{}\n", text))?;
        self.col = selection.start.1.min(lines[start.line].chars().count());

        if change {
            return self.start_insert(project, InsertWhere::Cursor);
        }

        self.clamp_col(project);
        return Ok(());
    }

    /// Adds a comment line above the cursor
    pub fn comment(&mut self, project: &mut Project, text: &str) -> Result<()> {
        let mut lines = self.block_lines(project, self.cursor.block);
        let line = self.cursor.line.min(lines.len().saturating_sub(1));
        let indent: String = lines.get(line).map_or(String::new(), |l| l.chars().take_while(|c| c.is_whitespace()).collect());

        lines.insert(line, format!("{}// {}", indent, text.trim()));
        return self.replace(project, &format!("{}\n", lines.join("\n")));
    }

    pub fn undo(&mut self, project: &mut Project, redo: bool) -> Result<()> {
        let (from, to) = if redo { (&mut self.redo, &mut self.undo) } else { (&mut self.undo, &mut self.redo) };
        let (addr, text) = from.pop().with_context(|| if redo { "Already at the newest change" } else { "Already at the oldest change" })?;

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
    pub fn resolve(&mut self, project: &mut Project, keep_edited: bool, keep_decompiled: bool) -> Result<()> {
        let lines = self.block_lines(project, self.cursor.block);

        if lines.is_empty() {
            bail!("no conflict under the cursor");
        }

        let line = self.cursor.line.min(lines.len() - 1);
        let start = (0..=line).rev().find(|&i| lines[i].starts_with("<<<<<<<")).context("no conflict under the cursor")?;
        let middle = (start..lines.len()).find(|&i| lines[i].starts_with("=======")).context("unterminated conflict")?;
        let end = (middle..lines.len()).find(|&i| lines[i].starts_with(">>>>>>>")).context("unterminated conflict")?;

        if line > end {
            bail!("no conflict under the cursor");
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

    pub fn render(&mut self, project: &mut Project, theme: &Theme, height: usize, width: usize, marks: &Marks) -> Vec<Line<'static>> {
        self.height = height.max(1);
        self.refresh(project);
        self.follow();

        if self.functions.is_empty() {
            return vec![Line::from(Span::styled("This module holds no function yet, move some with :mv", Style::default().fg(theme.dim)))];
        }

        let mut lines = Vec::with_capacity(height);
        let mut pos = self.top;
        let mut visible = Vec::new();
        let selection = self.selection();
        let selected = Style::default().bg(theme.highlight_bg);
        let types = self.types.clone();
        let pc_function = marks.pc.and_then(|pc| project.analysis.function_containing(pc)).map(|f| f.addr);

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
            let pc_line = marks.pc.filter(|_| pc_function == Some(addr) && self.insert.is_none()).and_then(|pc| line_of(addrs, pc));

            // A block comment opened above the first line shown
            let mut comment = match (self.insert.as_ref().filter(|i| i.addr == addr), shown.as_ref()) {
                _ if pos.line == 0 => false,
                (Some(insert), _) => self.syntax.comment_after(insert.lines.iter().take(pos.line).map(|l| l.as_str())),
                (None, Some((rendered, _))) => self.syntax.comment_after(rendered.text.lines().take(pos.line)),
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

                // The line the program is stopped at, the breakpoints
                let stopped = pc_line == Some(line);

                if !marks.is_empty() {
                    let breakpoint = addrs.get(line).copied().flatten().is_some_and(|a| marks.breakpoint(a));

                    let (mark, color) = match (stopped, breakpoint) {
                        (true, true) => ("◉", theme.breakpoint),
                        (true, false) => ("▶", theme.node_selected),
                        (false, true) => ("●", theme.breakpoint),
                        (false, false) => (" ", theme.dim),
                    };

                    spans.insert(0, Span::styled(mark, Style::default().fg(color)));
                }

                let is_cursor = pos.block == self.cursor.block && line == self.cursor.line;
                let range = selection.and_then(|s| s.range(self.abs(Pos { block: pos.block, line }), content.map_or(0, |t| t.chars().count())));

                let code = match content {
                    Some(text) if shown.is_none() && self.insert.is_none() => vec![Span::styled(text.clone(), Style::default().fg(theme.dim).add_modifier(Modifier::ITALIC))],
                    Some(text) => self.syntax.highlight(theme, text, &mut comment, &|word| types.contains(word)),
                    None => Vec::new(),
                };

                let code = match range {
                    Some((start, end)) => with_selection(code, start, end, selected),
                    None => code,
                };

                match is_cursor {
                    true => spans.extend(with_cursor(code, self.col, theme)),
                    false => spans.extend(code),
                }

                let mut rendered = Line::from(truncate(spans, width));

                if is_cursor {
                    rendered = rendered.style(Style::default().bg(theme.cursor_bg));
                } else if stopped {
                    rendered = rendered.style(Style::default().bg(theme.stopped_bg));
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

/// Line of an address in the lines of a function: the last line with the highest address at or before it
pub fn line_of(lines: &[Option<u64>], addr: u64) -> Option<usize> {
    let best = lines.iter().enumerate().filter_map(|(i, a)| a.filter(|&a| a <= addr).map(|a| (i, a))).max_by_key(|(i, a)| (*a, usize::MAX - i));
    return best.map(|(i, _)| i);
}

fn placeholder(project: &Project, addr: u64) -> String {
    return format!("// {} ({:#x}): decompiling...", project.function_name(addr), addr);
}

/// Spans with the characters from a column to another (excluded) in a style, the end of the line padded when the
/// selection goes past it
fn with_selection(spans: Vec<Span<'static>>, start: usize, end: usize, style: Style) -> Vec<Span<'static>> {
    let mut out = Vec::with_capacity(spans.len() + 2);
    let mut position = 0;

    for span in spans {
        let chars: Vec<char> = span.content.chars().collect();
        let (from, to) = (start.clamp(position, position + chars.len()) - position, end.clamp(position, position + chars.len()) - position);

        for (a, b, selected) in [(0, from, false), (from, to, true), (to, chars.len(), false)] {
            if a < b {
                let text: String = chars[a..b].iter().collect();
                out.push(Span::styled(text, if selected { span.style.patch(style) } else { span.style }));
            }
        }

        position += chars.len();
    }

    if end > position {
        out.push(Span::styled(" ".repeat(start.saturating_sub(position)), Style::default()));
        out.push(Span::styled(" ".repeat(end - start.max(position)), style));
    }

    return out;
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

/*
 * Commands
 */

impl App {
    /// Source view of the module of a function, on the line of an address
    pub(crate) fn source_view(&mut self, program: usize, addr: u64) -> Option<SourceView> {
        let project = self.project(program)?;
        let function = project.analysis.function_containing(addr).map(|f| f.addr);

        let Some(module) = function.and_then(|f| project.module_of(f)).map(|m| m.to_string()) else {
            match function.and_then(|f| project.analysis.functions.get(&f)).and_then(|f| f.thunk.clone()) {
                Some(import) => {
                    self.follow_import(&import, true);
                }
                None => self.error(format!("No function at {:#x}", addr)),
            }

            return None;
        };

        let mut view = SourceView::new(program, &module, project);
        view.height = 20;
        view.goto(project, addr);

        return Some(view);
    }

    /// Opens the C code of the module of a function, on the line of an address
    pub(crate) fn open_code(&mut self, program: usize, addr: u64) {
        if let Some(view) = self.source_view(program, addr) {
            self.open(View::Source(view));
        }
    }

    pub(crate) fn open_module(&mut self, program: usize, module: &str) {
        let Some(project) = self.project(program) else {
            return;
        };

        if !project.modules.contains(module) {
            self.error(format!("No module {}", module));
            return;
        }

        let view = SourceView::new(program, module, project);
        self.open(View::Source(view));
    }

    /// Identifier under the cursor of the C code
    pub(crate) fn word_under_cursor(&mut self) -> Option<String> {
        let App { workspace, projects, .. } = self;

        return match workspace.view_mut() {
            View::Source(view) => projects[view.program].as_mut().and_then(|p| view.word(p)),
            _ => None,
        };
    }

    pub(crate) fn current_signature(&mut self) -> Option<String> {
        let (program, addr) = self.current_function()?;
        let project = self.projects[program].as_mut()?;

        return project.shown(addr).map(|(r, _)| r.meta.signature.clone());
    }

    /// Goes to what the identifier under the cursor refers to: a function or a global
    pub(crate) fn definition(&mut self) {
        let Some(word) = self.word_under_cursor() else {
            return self.info("No name under the cursor".to_string());
        };

        let Some((program, function)) = self.current_function() else {
            return;
        };

        let Some(project) = self.projects[program].as_mut() else {
            return;
        };

        if let Some(addr) = project.resolve(&word).or_else(|| word.strip_prefix("sub_").and_then(|a| u64::from_str_radix(a, 16).ok())).filter(|a| project.analysis.functions.contains_key(a)) {
            // Imported: its code is in a library
            if let Some(import) = project.analysis.functions[&addr].thunk.clone() {
                self.follow_import(&import, true);
                return;
            }

            // Same module: the cursor moves, otherwise the module of the function opens
            if let View::Source(view) = self.workspace.view_mut() {
                if view.goto(project, addr) {
                    return;
                }
            }

            return self.open_code(program, addr);
        }

        if let Some(addr) = project.global(function, &word) {
            return self.goto_address(program, addr);
        }

        // Functions of the libraries called without a stub (through the GOT)
        if self.exporting_library(&word).is_some() {
            self.follow_import(&word, true);
            return;
        }

        self.info(format!("{} is not a function or a global", word));
    }

    /// Commands of the C code (normal mode)
    pub(crate) fn source_command(&mut self, command: &Command, count: Option<usize>) -> bool {
        let repeat = count.unwrap_or(1).max(1) as isize;

        match command {
            Command::Open(OpenMode::Replace) | Command::Definition => {
                self.definition();
                return true;
            }
            Command::Comment(text) => {
                self.with_source(|source, project| source.comment(project, text));
                return true;
            }
            Command::StringForms => {
                self.string_forms();
                return true;
            }
            Command::Resolve { edited, decompiled } => {
                let (edited, decompiled) = (*edited, *decompiled);
                self.with_source(|source, project| source.resolve(project, edited, decompiled));
                return true;
            }
            Command::Conflict { forward } => {
                let forward = *forward;
                self.with_source(|source, project| if source.jump_conflict(project, forward) { Ok(()) } else { Err(anyhow!("No conflict in this module")) });
                return true;
            }
            Command::Yank => {
                let yanked = {
                    let App { workspace, projects, .. } = self;

                    match workspace.view_mut() {
                        View::Source(view) => projects[view.program].as_mut().map(|project| view.yank(project, repeat as usize)),
                        _ => None,
                    }
                };

                if let Some((text, lines)) = yanked {
                    if self.copy(&text) {
                        self.info(if lines == 1 { format!("Yanked {} characters", text.chars().count()) } else { format!("Yanked {} lines", lines) });
                    }
                }

                return true;
            }
            _ => {}
        }

        let App { workspace, projects, .. } = self;

        let View::Source(view) = workspace.view_mut() else {
            return false;
        };

        let Some(project) = projects[view.program].as_mut() else {
            return false;
        };

        let page = (view.height / 2).max(1) as isize;

        // The edits leave the visual mode, Esc leaves it before clearing the search
        if matches!(command, Command::Insert(_) | Command::Undo | Command::Redo | Command::DeleteLine) || matches!(command, Command::Operator { reach, .. } if *reach != Reach::Selection) {
            view.visual = None;
        }

        let result = match command {
            Command::Visual(lines) => {
                view.visual(*lines);
                Ok(())
            }
            Command::Syntax(name) => match syntax::find(name) {
                Some(syntax) => {
                    view.syntax = syntax;
                    Ok(())
                }
                None => Err(anyhow!("No highlighting for {}: c, c++, go or rust", name)),
            },
            Command::ClearSearch if view.visual.is_some() => {
                view.visual = None;
                Ok(())
            }
            Command::Move(motion) => {
                match motion {
                    Motion::PageDown => view.move_lines(project, page),
                    Motion::PageUp => view.move_lines(project, -page),
                    Motion::Down => view.move_lines(project, repeat),
                    Motion::Up => view.move_lines(project, -repeat),
                    Motion::Left => view.move_col(project, -repeat),
                    Motion::Right => view.move_col(project, repeat),
                    Motion::JumpDown => view.move_lines(project, VERTICAL_STEP as isize),
                    Motion::JumpUp => view.move_lines(project, -VERTICAL_STEP as isize),
                    Motion::First => view.first_line(),
                    Motion::Last => match count {
                        Some(n) => {
                            view.first_line();
                            view.move_lines(project, n as isize - 1);
                        }
                        None => view.last_line(),
                    },
                    Motion::Next | Motion::NextFunction => view.jump_function(true),
                    Motion::Previous | Motion::PreviousFunction => view.jump_function(false),
                    Motion::WordNext => (0..repeat).for_each(|_| view.word_move(project, true)),
                    Motion::WordPrevious => (0..repeat).for_each(|_| view.word_move(project, false)),
                    Motion::WordEnd => (0..repeat).for_each(|_| view.word_end_move(project)),
                    Motion::LineStart => view.line_start(project, false),
                    Motion::LineFirst => view.line_start(project, true),
                    Motion::LineEnd => view.line_end(project),
                    Motion::JumpLeft | Motion::JumpRight => return false,
                }

                Ok(())
            }
            Command::Insert(at) => view.start_insert(project, *at),
            Command::Undo => view.undo(project, false),
            Command::Redo => view.undo(project, true),
            Command::DeleteLine => view.delete_line(project),
            Command::Operator { change, reach } => view.operate(project, *reach, repeat as usize, *change),
            _ => return false,
        };

        self.report(result);
        return true;
    }
}

pub(crate) fn render(view: &mut SourceView, f: &mut Frame, theme: &Theme, area: Rect, projects: &mut [Option<Project>], marks: &Marks) {
    let lines = match projects[view.program].as_mut() {
        Some(project) => view.render(project, theme, area.height as usize, area.width as usize, marks),
        None => vec![Line::from("Analysis in progress...")],
    };

    f.render_widget(Paragraph::new(Text::from(lines)).style(theme.base()), area);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_reaches() {
        let chars: Vec<char> = "    v1 = sub_1000(a1, 2);".chars().collect();
        let text = |(start, end): (usize, usize)| chars[start..end].iter().collect::<String>();

        assert_eq!(text(reach_range(&chars, 4, Reach::Word, 1, false)), "v1 ");
        assert_eq!(text(reach_range(&chars, 4, Reach::Word, 1, true)), "v1");
        assert_eq!(text(reach_range(&chars, 4, Reach::Word, 2, true)), "v1 =");
        assert_eq!(text(reach_range(&chars, 9, Reach::WordEnd, 1, false)), "sub_1000");
        assert_eq!(text(reach_range(&chars, 9, Reach::WordEnd, 2, false)), "sub_1000(");
        assert_eq!(text(reach_range(&chars, 18, Reach::WordBack, 1, false)), "(");
        assert_eq!(text(reach_range(&chars, 18, Reach::WordBack, 2, false)), "sub_1000(");
        assert_eq!(text(reach_range(&chars, 9, Reach::LineEnd, 1, false)), "sub_1000(a1, 2);");
        assert_eq!(text(reach_range(&chars, 9, Reach::LineFirst, 1, false)), "v1 = ");
        assert_eq!(text(reach_range(&chars, 9, Reach::Char, 3, false)), "sub");
        assert_eq!(text(reach_range(&chars, 9, Reach::CharBack, 2, false)), "= ");
    }

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
        assert!(syntax::C.comment_after(["/* a", "b */", "/* c"].into_iter()));

        let text: String = highlight_with(&theme, "    if (x == \"a\") { return 0x10; } // done", &mut false).iter().map(|s| s.content.to_string()).collect();
        assert_eq!(text, "    if (x == \"a\") { return 0x10; } // done");

        let spans = with_cursor(highlight_with(&theme, "int x;", &mut false), 4, &theme);
        assert!(spans.iter().any(|s| s.content == "x" && s.style.add_modifier.contains(Modifier::REVERSED)));
    }
}
