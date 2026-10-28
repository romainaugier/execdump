// SPDX-License-Identifier: Apache-2.0
/*
 * Explorer: the tree of what can be opened, one node per program (its analysis, modules, headers,
 * sections and tables) and the shared libraries
 */

use super::*;

use crate::commands::{Command, Motion};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExplorerItem {
    /// Node of the tree (key of its collapsed state, title)
    Group(String, String),
    EntryPoint(usize),
    CallGraph(usize),
    Functions(usize),
    Strings(usize),
    Imports(usize),
    MemoryMap(usize),
    Proposals(usize),
    /// Module of a program (program index, module path)
    Module(usize, String),
    PEDosHeader,
    PENtHeader,
    PEOptionalHeader,
    PEImportTable,
    PEExportTable,
    PEExceptionTable,
    PEDebugDirectory,
    PEDelayImports,
    PETls,
    PELoadConfig,
    ELFHeader,
    ELFProgramHeaders,
    ELFSymbols,
    ELFDynamic,
    ELFRelocations,
    ELFImports,
    ELFNotes,
    MachOFatHeader,
    MachOHeader(usize),
    MachOLoadCommands(usize),
    MachOSymbols(usize),
    MachOImports(usize),
    MachOFixups(usize),
    MachOExports(usize),
    /// Section of a program (program index, section name)
    Section(usize, String),
    /// Shared library needed by the binary or by a library
    Library(usize),
}

impl ExplorerItem {
    fn display_name(&self, app: &App) -> String {
        // The tree tells which program an item belongs to
        let suffix = |_: &usize| String::new();

        match self {
            ExplorerItem::Group(_, title) => title.clone(),
            ExplorerItem::EntryPoint(p) => format!("  Entry point{}", suffix(p)),
            ExplorerItem::CallGraph(p) => format!("  Call graph{}", suffix(p)),
            ExplorerItem::Functions(p) => {
                let count = app.analyses[*p].as_ref().map_or(String::new(), |a| format!(" ({})", a.functions.len()));
                format!("  Functions{}{}", count, suffix(p))
            }
            ExplorerItem::Strings(p) => {
                let count = app.analyses[*p].as_ref().map_or(String::new(), |a| format!(" ({})", a.strings.len()));
                format!("  Strings{}{}", count, suffix(p))
            }
            ExplorerItem::Imports(p) => format!("  Imports{}", suffix(p)),
            ExplorerItem::MemoryMap(p) => format!("  Memory map{}", suffix(p)),
            ExplorerItem::Proposals(p) => {
                let count = app.projects[*p].as_ref().map_or(0, |project| project.proposals.iter().filter(|p| p.is_pending()).count());
                format!("  LLM proposals ({}){}", count, suffix(p))
            }
            ExplorerItem::Module(p, name) => {
                let count = app.projects[*p].as_ref().map_or(0, |project| project.modules.functions(name).len());
                format!("  {} ({}){}", name, count, suffix(p))
            }
            ExplorerItem::PEDosHeader => "  DOS Header".to_string(),
            ExplorerItem::PENtHeader => "  NT Header".to_string(),
            ExplorerItem::PEOptionalHeader => "  Optional Header".to_string(),
            ExplorerItem::PEImportTable => "  Import Table".to_string(),
            ExplorerItem::PEExportTable => "  Export Table".to_string(),
            ExplorerItem::PEExceptionTable => "  Exception Table".to_string(),
            ExplorerItem::PEDebugDirectory => "  Debug Directory".to_string(),
            ExplorerItem::PEDelayImports => "  Delay Imports".to_string(),
            ExplorerItem::PETls => "  TLS Directory".to_string(),
            ExplorerItem::PELoadConfig => "  Load Configuration".to_string(),
            ExplorerItem::ELFHeader => "  Header".to_string(),
            ExplorerItem::ELFProgramHeaders => "  Program Headers".to_string(),
            ExplorerItem::ELFSymbols => "  Symbols".to_string(),
            ExplorerItem::ELFDynamic => "  Dynamic".to_string(),
            ExplorerItem::ELFRelocations => "  Relocations".to_string(),
            ExplorerItem::ELFImports => "  Imports".to_string(),
            ExplorerItem::ELFNotes => "  Notes".to_string(),
            ExplorerItem::MachOFatHeader => "  Fat Header".to_string(),
            ExplorerItem::MachOHeader(p) => format!("  Header{}", suffix(p)),
            ExplorerItem::MachOLoadCommands(p) => format!("  Load Commands{}", suffix(p)),
            ExplorerItem::MachOSymbols(p) => format!("  Symbols{}", suffix(p)),
            ExplorerItem::MachOImports(p) => format!("  Imports{}", suffix(p)),
            ExplorerItem::MachOFixups(p) => format!("  Fixups{}", suffix(p)),
            ExplorerItem::MachOExports(p) => format!("  Exports{}", suffix(p)),
            ExplorerItem::Section(p, name) => format!("  {}{}", name, suffix(p)),
            ExplorerItem::Library(library) => format!("  {} ({})", app.libraries[*library].file_name(), app.library_status(*library)),
        }
    }
}

/// Explorer items in tree order, with their depth (the children of collapsed nodes are left out)
pub(crate) struct Tree<'a> {
    items: Vec<ExplorerItem>,
    depths: Vec<u8>,
    collapsed: &'a std::collections::HashSet<String>,
}

impl Tree<'_> {
    fn item(&mut self, depth: u8, item: ExplorerItem) {
        self.items.push(item);
        self.depths.push(depth);
    }

    /// Adds a node, true when its children are shown
    fn group(&mut self, depth: u8, key: String, title: String) -> bool {
        let expanded = !self.collapsed.contains(&key);
        self.item(depth, ExplorerItem::Group(key, title));
        return expanded;
    }
}

/// What the explorer shows of a program: its analysis and its modules
fn program_tree(tree: &mut Tree, app: &App, p: usize, depth: u8, key: &str) {
    if tree.group(depth, format!("{}/analysis", key), "Analysis".to_string()) {
        if p < app.main_programs {
            tree.item(depth + 1, ExplorerItem::EntryPoint(p));
        }

        for item in [ExplorerItem::CallGraph(p), ExplorerItem::Functions(p), ExplorerItem::Strings(p), ExplorerItem::Imports(p), ExplorerItem::MemoryMap(p), ExplorerItem::Proposals(p)] {
            tree.item(depth + 1, item);
        }
    }

    if let Some(project) = app.projects[p].as_ref() {
        if tree.group(depth, format!("{}/modules", key), format!("Modules ({})", project.modules.len())) {
            for module in project.modules.names() {
                tree.item(depth + 1, ExplorerItem::Module(p, module.clone()));
            }
        }
    }
}

pub(crate) fn explorer_items(app: &App) -> (Vec<ExplorerItem>, Vec<u8>) {
    // A filter looks in the closed nodes too
    let open = std::collections::HashSet::new();
    let collapsed = if app.explorer_filter.is_empty() { &app.explorer_collapsed } else { &open };
    let (items, depths) = tree_items(app, collapsed);

    return match app.explorer_filter.is_empty() {
        true => (items, depths),
        false => filtered(app, items, depths),
    };
}

/// The items whose name has the text of the filter (case insensitive), with the nodes above them
fn filtered(app: &App, items: Vec<ExplorerItem>, depths: Vec<u8>) -> (Vec<ExplorerItem>, Vec<u8>) {
    let filter = app.explorer_filter.to_lowercase();
    let mut keep = vec![false; items.len()];

    for (index, item) in items.iter().enumerate() {
        let name = match item {
            ExplorerItem::Group(..) => continue,
            ExplorerItem::Module(_, path) => path.to_lowercase(),
            other => other.display_name(app).trim().to_lowercase(),
        };

        if !name.contains(&filter) {
            continue;
        }

        keep[index] = true;
        let mut depth = depths[index];

        // The nodes above it
        for parent in (0..index).rev() {
            if depth == 0 {
                break;
            }

            if depths[parent] < depth {
                keep[parent] = true;
                depth = depths[parent];
            }
        }
    }

    return items.into_iter().zip(depths).zip(keep).filter(|(_, keep)| *keep).map(|(pair, _)| pair).unzip();
}

fn tree_items(app: &App, collapsed: &std::collections::HashSet<String>) -> (Vec<ExplorerItem>, Vec<u8>) {
    let exec = &app.exec;
    let mut tree = Tree { items: Vec::new(), depths: Vec::new(), collapsed };
    let file = app.exec_path.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string());

    // One node per program of the binary, its headers, sections and tables in the first one (Mach-O: each)
    for p in 0..app.main_programs {
        let key = format!("p{}", p);

        if !tree.group(0, key.clone(), format!("{} ({})", file, app.programs[p].name)) {
            continue;
        }

        program_tree(&mut tree, app, p, 1, &key);

        let macho = matches!(exec, Exec::MachO(_));

        if p > 0 && !macho {
            continue;
        }

        if tree.group(1, format!("{}/headers", key), "Headers".to_string()) {
            match exec {
                Exec::PE(_) => [ExplorerItem::PEDosHeader, ExplorerItem::PENtHeader, ExplorerItem::PEOptionalHeader].into_iter().for_each(|i| tree.item(2, i)),
                Exec::ELF(_) => [ExplorerItem::ELFHeader, ExplorerItem::ELFProgramHeaders].into_iter().for_each(|i| tree.item(2, i)),
                Exec::MachO(macho) => {
                    if p == 0 && macho.fat_header.is_some() {
                        tree.item(2, ExplorerItem::MachOFatHeader);
                    }

                    tree.item(2, ExplorerItem::MachOHeader(p));
                    tree.item(2, ExplorerItem::MachOLoadCommands(p));
                }
            }
        }

        if tree.group(1, format!("{}/sections", key), "Sections".to_string()) {
            let sections: Vec<String> = match exec {
                Exec::PE(pe) => {
                    let mut sections: Vec<&execdump_core::pe::Section> = pe.sections.values().collect();
                    sections.sort_by_key(|s| s.header.virtual_address);
                    sections.iter().map(|s| s.header.name.clone()).collect()
                }
                Exec::ELF(elf) => {
                    let mut sections: Vec<&execdump_core::elf::ELFSection> = elf.sections.values().filter(|s| !s.name.is_empty()).collect();
                    sections.sort_by_key(|s| s.offset());
                    sections.iter().map(|s| s.name.clone()).collect()
                }
                Exec::MachO(macho) => {
                    let mut sections: Vec<&execdump_core::macho::MachOSection> = macho.binaries[p].sections.values().collect();
                    sections.sort_by_key(|s| s.header.addr);
                    sections.iter().map(|s| s.header.full_name()).collect()
                }
            };

            sections.into_iter().for_each(|name| tree.item(2, ExplorerItem::Section(p, name)));
        }

        let title = if matches!(exec, Exec::PE(_)) { "Data Directories" } else { "Tables" };

        if tree.group(1, format!("{}/tables", key), title.to_string()) {
            match exec {
                Exec::PE(_) => {
                    [ExplorerItem::PEImportTable, ExplorerItem::PEExportTable, ExplorerItem::PEExceptionTable, ExplorerItem::PEDebugDirectory, ExplorerItem::PEDelayImports, ExplorerItem::PETls, ExplorerItem::PELoadConfig]
                        .into_iter()
                        .for_each(|i| tree.item(2, i))
                }
                Exec::ELF(_) => [ExplorerItem::ELFSymbols, ExplorerItem::ELFDynamic, ExplorerItem::ELFRelocations, ExplorerItem::ELFImports, ExplorerItem::ELFNotes].into_iter().for_each(|i| tree.item(2, i)),
                Exec::MachO(_) => {
                    [ExplorerItem::MachOSymbols(p), ExplorerItem::MachOImports(p), ExplorerItem::MachOFixups(p), ExplorerItem::MachOExports(p)].into_iter().for_each(|i| tree.item(2, i))
                }
            }
        }
    }

    // The libraries: loaded ones are nodes like the programs of the binary
    if !app.libraries.is_empty() && tree.group(0, "libs".to_string(), format!("Libraries ({})", app.libraries.len())) {
        for (library, entry) in app.libraries.iter().enumerate() {
            match entry.program.filter(|&p| app.projects[p].is_some()) {
                Some(p) => {
                    let key = format!("lib{}", library);

                    if tree.group(1, key.clone(), format!("{} ({})", entry.file_name(), app.library_status(library))) {
                        program_tree(&mut tree, app, p, 2, &key);
                    }
                }
                None => tree.item(1, ExplorerItem::Library(library)),
            }
        }
    }

    return (tree.items, tree.depths);
}

impl App {
    /// Items of the explorer again (the selection stays on its item), and the width that fits them
    pub(crate) fn rebuild_explorer(&mut self) {
        let selected = self.explorer_state.selected().and_then(|i| self.explorer_items.get(i)).cloned();
        let (items, depths) = explorer_items(self);
        self.explorer_items = items;
        self.explorer_depths = depths;

        let width = self.explorer_items.iter().zip(self.explorer_depths.iter()).map(|(item, &depth)| item.display_name(self).trim().chars().count() + 2 * depth as usize + 2).max().unwrap_or(0);
        self.explorer_fit = width as u16 + 4;

        if let Some(index) = selected.and_then(|s| self.explorer_items.iter().position(|i| *i == s)) {
            self.explorer_state.select(Some(index));
        }
    }

    /// Filters the items of the explorer, the selection on the first item found (on the item it was on without a
    /// filter)
    pub(crate) fn filter_explorer(&mut self, text: &str) {
        if self.explorer_filter == text {
            return;
        }

        // Without the filter, the nodes above the item found open
        if text.is_empty() {
            let selected = self.explorer_state.selected().unwrap_or(0).min(self.explorer_items.len().saturating_sub(1));
            let mut depth = self.explorer_depths.get(selected).copied().unwrap_or(0);

            for parent in (0..selected).rev() {
                if depth == 0 {
                    break;
                }

                if self.explorer_depths[parent] < depth {
                    depth = self.explorer_depths[parent];

                    if let ExplorerItem::Group(key, _) = &self.explorer_items[parent] {
                        self.explorer_collapsed.remove(key);
                    }
                }
            }
        }

        self.explorer_filter = text.to_string();
        self.rebuild_explorer();

        if !text.is_empty() {
            let first = self.explorer_items.iter().position(|i| !matches!(i, ExplorerItem::Group(..)));
            self.explorer_state.select(Some(first.unwrap_or(0)));
        }
    }

    /// Collapses or expands a node of the explorer
    pub(crate) fn toggle_explorer_group(&mut self, key: &str) {
        if !self.explorer_collapsed.remove(key) {
            self.explorer_collapsed.insert(key.to_string());
        }

        self.rebuild_explorer();
    }

    fn section_view(&mut self, program: usize, name: &str) -> Option<View> {
        let program_ref = self.programs[program].clone();

        if let Some(region) = program_ref.regions.iter().find(|r| r.name == name) {
            if region.perms.exec && !region.data.is_empty() {
                return self.region_disasm(program, name).map(View::Disasm);
            }

            return Some(View::Hex(HexView::new(format!("{} ({:#x})", region.name, region.vaddr), region.vaddr, region.data.clone())));
        }

        // Sections not loaded in memory (symbol tables, debug information...), shown from the file
        let data = match &self.exec {
            Exec::ELF(elf) => elf.sections.get(name).map(|s| (s.header.virtual_address(), s.data.clone())),
            Exec::PE(pe) => pe.sections.get(name).map(|s| (s.header.virtual_address as u64, s.data.clone())),
            Exec::MachO(macho) => macho.binaries.get(program).and_then(|b| b.sections.get(name)).map(|s| (s.header.addr, s.data.clone())),
        };

        return data.map(|(base, data)| View::Hex(HexView::new(name.to_string(), base, data)));
    }

    fn dump_view(&self, dump: Dump) -> View {
        return View::Dump(DumpView::new(&self.theme, &dump));
    }

    pub(crate) fn activate_explorer_item(&mut self) {
        let Some(item) = self.explorer_state.selected().and_then(|i| self.explorer_items.get(i)).cloned() else {
            return;
        };

        let view = match &item {
            ExplorerItem::Group(key, _) => {
                self.toggle_explorer_group(key);
                self.open_mode = OpenMode::Replace;
                return;
            }
            ExplorerItem::EntryPoint(p) => {
                match self.programs[*p].entry {
                    Some(entry) => self.open_function(*p, entry, None),
                    None => self.error("No entry point".to_string()),
                }

                return;
            }
            ExplorerItem::CallGraph(p) => {
                self.open_call_graph(*p, None, DEFAULT_CALL_GRAPH_DEPTH, false);
                return;
            }
            ExplorerItem::Proposals(p) => {
                self.open_review(*p);
                return;
            }
            ExplorerItem::Module(p, module) => {
                self.open_module(*p, module);
                return;
            }
            ExplorerItem::Library(library) => {
                match self.libraries[*library].program {
                    Some(p) if self.projects[p].is_some() => self.open_call_graph(p, None, DEFAULT_CALL_GRAPH_DEPTH, false),
                    Some(_) => self.info(format!("{} is loading", self.libraries[*library].file_name())),
                    None => match self.load_library(*library) {
                        Some(_) => self.info(format!("Loading {}...", self.libraries[*library].file_name())),
                        None => self.error(format!("{} was not found", self.libraries[*library].needed.name)),
                    },
                }

                self.open_mode = OpenMode::Replace;
                return;
            }
            ExplorerItem::Functions(p) => self.functions_table(*p).map(View::Table),
            ExplorerItem::Strings(p) => self.strings_table(*p).map(View::Table),
            ExplorerItem::Imports(p) => Some(View::Table(self.imports_table(*p))),
            ExplorerItem::MemoryMap(p) => Some(View::Table(self.memory_map(*p))),
            ExplorerItem::Section(p, name) => self.section_view(*p, name),
            _ => {
                let dump = match (&self.exec, &item) {
                    (Exec::PE(pe), ExplorerItem::PEDosHeader) => pe.get_dos_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PENtHeader) => pe.get_nt_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PEOptionalHeader) => pe.get_optional_header().dump(),
                    (Exec::PE(pe), ExplorerItem::PEImportTable) => pe.hint_name_table.as_ref().map_or(Dump::new("No import table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEExportTable) => pe.export_data.as_ref().map_or(Dump::new("No export table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEExceptionTable) => pe.exception_table.as_ref().map_or(Dump::new("No exception table found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEDebugDirectory) => pe.debug_directory.as_ref().map_or(Dump::new("No debug directory found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PEDelayImports) => {
                        let mut dump = Dump::new_from_string(format!("Delay Imports ({})", pe.delay_imports.len()));
                        pe.delay_imports.iter().for_each(|i| dump.push_child(i.dump()));
                        dump
                    }
                    (Exec::PE(pe), ExplorerItem::PETls) => pe.tls.as_ref().map_or(Dump::new("No TLS directory found"), |t| t.dump()),
                    (Exec::PE(pe), ExplorerItem::PELoadConfig) => pe.load_config.as_ref().map_or(Dump::new("No load configuration found"), |t| t.dump()),
                    (Exec::ELF(elf), ExplorerItem::ELFHeader) => elf.get_elf_header().dump(),
                    (Exec::ELF(elf), ExplorerItem::ELFProgramHeaders) => elf.dump_program_headers(),
                    (Exec::ELF(elf), ExplorerItem::ELFSymbols) => {
                        let mut dump = Dump::new("Symbols");
                        elf.symbol_tables.iter().for_each(|t| dump.push_child(t.dump()));
                        dump
                    }
                    (Exec::ELF(elf), ExplorerItem::ELFDynamic) => elf.dynamic.as_ref().map_or(Dump::new("No dynamic section found"), |d| d.dump()),
                    (Exec::ELF(elf), ExplorerItem::ELFRelocations) => {
                        let mut dump = Dump::new("Relocations");
                        elf.relocation_tables.iter().for_each(|t| dump.push_child(t.dump()));
                        dump
                    }
                    (Exec::ELF(elf), ExplorerItem::ELFImports) => elf.dump_imports(),
                    (Exec::ELF(elf), ExplorerItem::ELFNotes) => elf.dump_notes(),
                    (Exec::MachO(macho), ExplorerItem::MachOFatHeader) => macho.fat_header.as_ref().map_or(Dump::new("No fat header found"), |h| h.dump()),
                    (Exec::MachO(macho), ExplorerItem::MachOHeader(p)) => macho.binaries[*p].header.dump(),
                    (Exec::MachO(macho), ExplorerItem::MachOLoadCommands(p)) => macho.binaries[*p].dump_load_commands(),
                    (Exec::MachO(macho), ExplorerItem::MachOSymbols(p)) => macho.binaries[*p].dump_symbols(),
                    (Exec::MachO(macho), ExplorerItem::MachOImports(p)) => macho.binaries[*p].dump_dylibs(),
                    (Exec::MachO(macho), ExplorerItem::MachOFixups(p)) => macho.binaries[*p].dump_fixups(),
                    (Exec::MachO(macho), ExplorerItem::MachOExports(p)) => macho.binaries[*p].dump_exports(),
                    _ => return,
                };

                Some(self.dump_view(dump))
            }
        };

        match view {
            Some(view) => self.open(view),
            None => self.open_mode = OpenMode::Replace,
        }
    }

    /// Commands of the explorer when it has the focus
    pub(crate) fn explorer_command(&mut self, command: &Command, _count: Option<usize>) -> bool {
        let count = self.explorer_items.len();
        let selected = self.explorer_state.selected().unwrap_or(0);
        let select = |state: &mut ListState, index: usize| state.select(Some(index.min(count.saturating_sub(1))));

        match command {
            Command::ClearSearch if !self.explorer_filter.is_empty() => self.filter_explorer(""),
            // n / p: the next (previous) item found
            Command::Move(Motion::Next | Motion::Previous) if !self.explorer_filter.is_empty() => {
                let leaf = |i: usize| !matches!(self.explorer_items[i], ExplorerItem::Group(..));
                let found = match command {
                    Command::Move(Motion::Next) => (selected + 1..count).find(|&i| leaf(i)),
                    _ => (0..selected).rev().find(|&i| leaf(i)),
                };

                if let Some(index) = found {
                    select(&mut self.explorer_state, index);
                }
            }
            Command::Move(Motion::Down) => select(&mut self.explorer_state, selected + 1),
            Command::Move(Motion::Up) => select(&mut self.explorer_state, selected.saturating_sub(1)),
            Command::Move(Motion::PageDown) => select(&mut self.explorer_state, selected + 10),
            Command::Move(Motion::PageUp) => select(&mut self.explorer_state, selected.saturating_sub(10)),
            Command::Move(Motion::First) => select(&mut self.explorer_state, 0),
            Command::Move(Motion::Last) => select(&mut self.explorer_state, count),
            Command::Open(mode) => {
                self.open_mode = *mode;
                self.activate_explorer_item();
            }
            // An open node closes, an item goes to its node
            Command::Close => match self.explorer_items.get(selected).cloned() {
                Some(ExplorerItem::Group(key, _)) if !self.explorer_collapsed.contains(&key) => self.toggle_explorer_group(&key),
                _ => {
                    let depth = self.explorer_depths.get(selected).copied().unwrap_or(0);

                    if let Some(parent) = (0..selected).rev().find(|&i| self.explorer_depths[i] < depth) {
                        select(&mut self.explorer_state, parent);
                    }
                }
            },
            _ => return false,
        }

        return true;
    }

    /// Wider or narrower explorer, the width that fits its items without a size
    pub(crate) fn explorer_resize(&mut self, delta: Option<i32>) {
        self.explorer_width = delta.map(|d| (self.explorer_width.unwrap_or(self.explorer_fit) as i32 + d).max(12) as u16);
    }

    /// Draws the explorer, returns the area left for the content
    pub(crate) fn render_explorer(&mut self, f: &mut Frame, theme: &Theme, area: Rect) -> Rect {
        if !self.explorer_visible {
            return area;
        }

        let width = self.explorer_width.unwrap_or(self.explorer_fit).clamp(12, (area.width * 2 / 3).max(12));
        let chunks = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Length(width), Constraint::Min(0)]).split(area);

        // Only the visible items are built (programs can have thousands of modules)
        let visible = chunks[0].height.saturating_sub(2).max(1) as usize;
        let selected = self.explorer_state.selected().unwrap_or(0).min(self.explorer_items.len().saturating_sub(1));

        if selected < self.explorer_offset {
            self.explorer_offset = selected;
        } else if selected >= self.explorer_offset + visible {
            self.explorer_offset = selected + 1 - visible;
        }

        let items: Vec<ListItem> = self.explorer_items.iter().zip(self.explorer_depths.iter()).skip(self.explorer_offset).take(visible).map(|(item, &depth)| {
            let indent = "  ".repeat(depth as usize);

            let (marker, style) = match item {
                ExplorerItem::Group(key, _) if self.explorer_collapsed.contains(key) => ("▸ ", theme.title_style()),
                ExplorerItem::Group(..) => ("▾ ", theme.title_style()),
                _ => ("  ", Style::default().fg(theme.fg)),
            };

            ListItem::new(format!("{}{}{}", indent, marker, item.display_name(self).trim())).style(style)
        }).collect();

        let active = self.focus == Focus::Explorer;

        let explorer = List::new(items)
            .block(
                Block::default()
                    .title(if self.explorer_filter.is_empty() { " Explorer ".to_string() } else { format!(" Explorer [/{}] ", self.explorer_filter) })
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if active { theme.highlight_bg } else { theme.border }))
                    .style(theme.base()),
            )
            .highlight_style(if active { Style::default().fg(theme.highlight_fg).bg(theme.highlight_bg) } else { Style::default().fg(theme.fg).bg(theme.cursor_bg) })
            .highlight_symbol("");

        let mut state = ListState::default();
        state.select(Some(selected - self.explorer_offset));
        f.render_stateful_widget(explorer, chunks[0], &mut state);

        return chunks[1];
    }
}
