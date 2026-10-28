// SPDX-License-Identifier: Apache-2.0
/*
 * Workspace: a tree of splits whose leaves are groups of tabs, as in vim (Ctrl-w to move between
 * the splits, gt/gT between the tabs). Each tab shows a view and has its own jumplist.
 */

use ratatui::layout::Rect;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

pub type GroupId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Left,
    Down,
    Up,
    Right,
}

impl Dir {
    /// Splits along this direction put the groups side by side
    fn side_by_side(self) -> bool {
        return matches!(self, Dir::Left | Dir::Right);
    }

    /// The new group goes before the current one
    fn before(self) -> bool {
        return matches!(self, Dir::Left | Dir::Up);
    }
}

#[derive(Clone, Debug)]
enum Node {
    /// side_by_side: a is left of b (otherwise above it), ratio is the share of a in percent
    Split { side_by_side: bool, ratio: u16, a: Box<Node>, b: Box<Node> },
    Leaf(GroupId),
}

impl Node {
    fn contains(&self, group: GroupId) -> bool {
        match self {
            Node::Leaf(g) => *g == group,
            Node::Split { a, b, .. } => a.contains(group) || b.contains(group),
        }
    }

    fn first(&self) -> GroupId {
        match self {
            Node::Leaf(g) => *g,
            Node::Split { a, .. } => a.first(),
        }
    }

    fn leaves(&self, out: &mut Vec<GroupId>) {
        match self {
            Node::Leaf(g) => out.push(*g),
            Node::Split { a, b, .. } => {
                a.leaves(out);
                b.leaves(out);
            }
        }
    }

    /// Replaces a leaf by a split of it and a new group
    fn split(&mut self, group: GroupId, new: GroupId, side_by_side: bool, before: bool) -> bool {
        match self {
            Node::Leaf(g) if *g == group => {
                let (a, b) = if before { (new, group) } else { (group, new) };
                *self = Node::Split { side_by_side, ratio: 50, a: Box::new(Node::Leaf(a)), b: Box::new(Node::Leaf(b)) };
                true
            }
            Node::Leaf(_) => false,
            Node::Split { a, b, .. } => a.split(group, new, side_by_side, before) || b.split(group, new, side_by_side, before),
        }
    }

    /// Removes a leaf, its sibling takes the place of their split
    fn remove(&mut self, group: GroupId) -> bool {
        let Node::Split { a, b, .. } = self else {
            return false;
        };

        if matches!(**a, Node::Leaf(g) if g == group) {
            *self = (**b).clone();
            return true;
        }

        if matches!(**b, Node::Leaf(g) if g == group) {
            *self = (**a).clone();
            return true;
        }

        return a.remove(group) || b.remove(group);
    }

    /// Resizes the closest split of an orientation around a group
    fn resize(&mut self, group: GroupId, side_by_side: bool, delta: i32) -> bool {
        let Node::Split { side_by_side: s, ratio, a, b } = self else {
            return false;
        };

        // The innermost split first
        if a.contains(group) && a.resize(group, side_by_side, delta) || b.contains(group) && b.resize(group, side_by_side, delta) {
            return true;
        }

        if *s == side_by_side && self_contains(a, b, group) {
            let grow = if a.contains(group) { delta } else { -delta };
            *ratio = (*ratio as i32 + grow).clamp(10, 90) as u16;
            return true;
        }

        return false;
    }

    fn equalize(&mut self) {
        if let Node::Split { ratio, a, b, .. } = self {
            *ratio = 50;
            a.equalize();
            b.equalize();
        }
    }

    fn layout(&self, area: Rect, out: &mut Vec<(GroupId, Rect)>) {
        match self {
            Node::Leaf(g) => out.push((*g, area)),
            Node::Split { side_by_side, ratio, a, b } => {
                let (first, second) = if *side_by_side {
                    let w = (area.width as u32 * *ratio as u32 / 100) as u16;
                    (Rect::new(area.x, area.y, w, area.height), Rect::new(area.x + w, area.y, area.width - w, area.height))
                } else {
                    let h = (area.height as u32 * *ratio as u32 / 100) as u16;
                    (Rect::new(area.x, area.y, area.width, h), Rect::new(area.x, area.y + h, area.width, area.height - h))
                };

                a.layout(first, out);
                b.layout(second, out);
            }
        }
    }
}

fn self_contains(a: &Node, b: &Node, group: GroupId) -> bool {
    return a.contains(group) || b.contains(group);
}

#[derive(Clone, Debug)]
pub struct Tab<V> {
    pub view: V,
    pub back: Vec<V>,
    pub forward: Vec<V>,
}

impl<V> Tab<V> {
    pub fn new(view: V) -> Self {
        return Tab { view, back: Vec::new(), forward: Vec::new() };
    }
}

#[derive(Clone, Debug)]
pub struct Group<V> {
    pub tabs: Vec<Tab<V>>,
    pub active: usize,
}

/// Layout of a workspace, with something describing each tab (saved in the sessions)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "node")]
pub enum Layout<R> {
    Split { side_by_side: bool, ratio: u16, a: Box<Layout<R>>, b: Box<Layout<R>> },
    Group { tabs: Vec<R>, active: usize },
}

pub struct Workspace<V> {
    root: Node,
    groups: HashMap<GroupId, Group<V>>,
    pub focused: GroupId,
    /// Previously focused group (Ctrl-w p)
    previous: GroupId,
    next: GroupId,
    /// Areas of the groups at the last render, for the directional moves
    rects: HashMap<GroupId, Rect>,
    /// Groups whose cursors follow each other
    links: Vec<(GroupId, GroupId)>,
}

impl<V: Clone> Workspace<V> {
    pub fn new(view: V) -> Self {
        let mut groups = HashMap::new();
        groups.insert(0, Group { tabs: vec![Tab::new(view)], active: 0 });

        return Workspace { root: Node::Leaf(0), groups, focused: 0, previous: 0, next: 1, rects: HashMap::new(), links: Vec::new() };
    }

    pub fn group(&self, id: GroupId) -> &Group<V> {
        return &self.groups[&id];
    }

    pub fn group_mut(&mut self, id: GroupId) -> &mut Group<V> {
        return self.groups.get_mut(&id).unwrap();
    }

    pub fn tab(&self) -> &Tab<V> {
        let group = self.group(self.focused);
        return &group.tabs[group.active];
    }

    pub fn tab_mut(&mut self) -> &mut Tab<V> {
        let group = self.group_mut(self.focused);
        let active = group.active;
        return &mut group.tabs[active];
    }

    pub fn view(&self) -> &V {
        return &self.tab().view;
    }

    pub fn view_mut(&mut self) -> &mut V {
        return &mut self.tab_mut().view;
    }

    /// Groups in reading order
    pub fn group_ids(&self) -> Vec<GroupId> {
        let mut ids = Vec::new();
        self.root.leaves(&mut ids);
        return ids;
    }

    pub fn group_count(&self) -> usize {
        return self.groups.len();
    }

    /// Every view (shown and in the jumplists)
    pub fn views_mut(&mut self) -> impl Iterator<Item = &mut V> {
        return self.groups.values_mut().flat_map(|g| g.tabs.iter_mut()).flat_map(|t| std::iter::once(&mut t.view).chain(t.back.iter_mut()).chain(t.forward.iter_mut()));
    }

    fn focus(&mut self, group: GroupId) {
        if group != self.focused && self.groups.contains_key(&group) {
            self.previous = self.focused;
            self.focused = group;
        }
    }

    /*
     * Tabs
     */

    pub fn new_tab(&mut self, view: V) {
        let group = self.group_mut(self.focused);
        group.tabs.insert(group.active + 1, Tab::new(view));
        group.active += 1;
    }

    /// Closes the active tab, then its group when it was the last one. False when it was the last tab of all.
    pub fn close_tab(&mut self) -> bool {
        let focused = self.focused;
        let group = self.group_mut(focused);

        if group.tabs.len() > 1 {
            group.tabs.remove(group.active);
            group.active = group.active.min(group.tabs.len() - 1);
            return true;
        }

        return self.close_group(focused);
    }

    pub fn cycle_tab(&mut self, forward: bool) {
        let group = self.group_mut(self.focused);
        let count = group.tabs.len();
        group.active = if forward { (group.active + 1) % count } else { (group.active + count - 1) % count };
    }

    /// Goes to the nth tab (1 based) of the group
    pub fn goto_tab(&mut self, n: usize) {
        let group = self.group_mut(self.focused);
        group.active = n.saturating_sub(1).min(group.tabs.len() - 1);
    }

    /*
     * Splits
     */

    /// Splits the focused group, the new group shows a view and gets the focus
    pub fn split(&mut self, dir: Dir, view: V) -> GroupId {
        let id = self.next;
        self.next += 1;

        self.root.split(self.focused, id, dir.side_by_side(), dir.before());
        self.groups.insert(id, Group { tabs: vec![Tab::new(view)], active: 0 });
        self.focus(id);

        return id;
    }

    /// Closes a group, false when it is the last one
    pub fn close_group(&mut self, group: GroupId) -> bool {
        if self.groups.len() == 1 {
            return false;
        }

        self.root.remove(group);
        self.groups.remove(&group);
        self.links.retain(|(a, b)| *a != group && *b != group);
        self.rects.remove(&group);

        if self.focused == group {
            self.focused = if self.groups.contains_key(&self.previous) { self.previous } else { self.root.first() };
        }

        return true;
    }

    /// Keeps the focused group only
    pub fn only(&mut self) {
        let focused = self.focused;

        for id in self.group_ids() {
            if id != focused {
                self.close_group(id);
            }
        }
    }

    /// Group next to the focused one in a direction, from the areas of the last render
    pub fn neighbor(&self, dir: Dir) -> Option<GroupId> {
        let current = self.rects.get(&self.focused)?;
        let (cx, cy) = (current.x as i32 + current.width as i32 / 2, current.y as i32 + current.height as i32 / 2);

        return self.rects.iter()
            .filter(|(id, _)| **id != self.focused)
            .filter_map(|(&id, r)| {
                let (x, y, w, h) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
                let (rx, ry) = (x + w / 2, y + h / 2);

                let (distance, overlaps) = match dir {
                    Dir::Left if x + w <= current.x as i32 => (current.x as i32 - (x + w), y < current.y as i32 + current.height as i32 && y + h > current.y as i32),
                    Dir::Right if x >= current.x as i32 + current.width as i32 => (x - (current.x as i32 + current.width as i32), y < current.y as i32 + current.height as i32 && y + h > current.y as i32),
                    Dir::Up if y + h <= current.y as i32 => (current.y as i32 - (y + h), x < current.x as i32 + current.width as i32 && x + w > current.x as i32),
                    Dir::Down if y >= current.y as i32 + current.height as i32 => (y - (current.y as i32 + current.height as i32), x < current.x as i32 + current.width as i32 && x + w > current.x as i32),
                    _ => return None,
                };

                let off_axis = if dir.side_by_side() { (ry - cy).abs() } else { (rx - cx).abs() };
                Some(((!overlaps, distance, off_axis), id))
            })
            .min()
            .map(|(_, id)| id);
    }

    pub fn focus_dir(&mut self, dir: Dir) -> bool {
        match self.neighbor(dir) {
            Some(id) => {
                self.focus(id);
                true
            }
            None => false,
        }
    }

    pub fn focus_previous(&mut self) {
        let previous = self.previous;
        self.focus(previous);
    }

    /// Next (or previous) group in reading order
    pub fn cycle_group(&mut self, forward: bool) {
        let ids = self.group_ids();
        let index = ids.iter().position(|&g| g == self.focused).unwrap_or(0);
        let next = if forward { (index + 1) % ids.len() } else { (index + ids.len() - 1) % ids.len() };
        self.focus(ids[next]);
    }

    /// Moves the active tab to the group in a direction, a new split when there is none
    pub fn move_tab(&mut self, dir: Dir) {
        let source = self.focused;
        let target = self.neighbor(dir);
        let group = self.group_mut(source);

        if group.tabs.len() == 1 && target.is_none() {
            return;
        }

        let tab = group.tabs.remove(group.active);
        group.active = group.active.min(group.tabs.len().saturating_sub(1));
        let empty = group.tabs.is_empty();

        match target {
            Some(target) => {
                let group = self.group_mut(target);
                group.tabs.push(tab);
                group.active = group.tabs.len() - 1;
                self.focus(target);
            }
            None => {
                let id = self.split(dir, tab.view.clone());
                self.group_mut(id).tabs[0] = tab;
            }
        }

        if empty {
            self.close_group(source);
        }
    }

    /// Resizes the focused group, false when no split is along that direction
    pub fn resize(&mut self, side_by_side: bool, delta: i32) -> bool {
        return self.root.resize(self.focused, side_by_side, delta);
    }

    pub fn equalize(&mut self) {
        self.root.equalize();
    }

    /// Areas of the groups in an area (remembered for the directional moves)
    pub fn layout(&mut self, area: Rect) -> Vec<(GroupId, Rect)> {
        let mut out = Vec::new();
        self.root.layout(area, &mut out);
        self.rects = out.iter().copied().collect();
        return out;
    }

    /*
     * Links
     */

    /// Links the focused group with the previous one (their cursors follow each other), or unlinks it
    pub fn toggle_link(&mut self) -> bool {
        let (a, b) = (self.focused, self.previous);

        if let Some(index) = self.links.iter().position(|&(x, y)| x == a || y == a) {
            self.links.remove(index);
            return false;
        }

        if a == b || !self.groups.contains_key(&b) {
            return false;
        }

        self.links.retain(|&(x, y)| x != b && y != b);
        self.links.push((a, b));
        return true;
    }

    pub fn linked(&self, group: GroupId) -> Option<GroupId> {
        return self.links.iter().find_map(|&(a, b)| if a == group { Some(b) } else if b == group { Some(a) } else { None });
    }

    /*
     * Sessions
     */

    pub fn save<R>(&self, describe: &dyn Fn(&V) -> R) -> Layout<R> {
        fn node<V, R>(workspace: &Workspace<V>, current: &Node, describe: &dyn Fn(&V) -> R) -> Layout<R> {
            match current {
                Node::Leaf(id) => {
                    let group = &workspace.groups[id];
                    Layout::Group { tabs: group.tabs.iter().map(|t| describe(&t.view)).collect(), active: group.active }
                }
                Node::Split { side_by_side, ratio, a, b } => Layout::Split {
                    side_by_side: *side_by_side,
                    ratio: *ratio,
                    a: Box::new(node(workspace, a, describe)),
                    b: Box::new(node(workspace, b, describe)),
                },
            }
        }

        return node(self, &self.root, describe);
    }

    pub fn restore<R>(layout: &Layout<R>, open: &mut dyn FnMut(&R) -> V) -> Self {
        fn node<V, R>(layout: &Layout<R>, groups: &mut HashMap<GroupId, Group<V>>, next: &mut GroupId, open: &mut dyn FnMut(&R) -> V) -> Node {
            match layout {
                Layout::Group { tabs, active } => {
                    let id = *next;
                    *next += 1;
                    let tabs: Vec<Tab<V>> = tabs.iter().map(|r| Tab::new(open(r))).collect();
                    let active = (*active).min(tabs.len().saturating_sub(1));
                    groups.insert(id, Group { tabs, active });
                    Node::Leaf(id)
                }
                Layout::Split { side_by_side, ratio, a, b } => Node::Split {
                    side_by_side: *side_by_side,
                    ratio: (*ratio).clamp(10, 90),
                    a: Box::new(node(a, groups, next, open)),
                    b: Box::new(node(b, groups, next, open)),
                },
            }
        }

        let mut groups = HashMap::new();
        let mut next = 0;
        let root = node(layout, &mut groups, &mut next, open);
        let first = root.first();

        return Workspace { root, groups, focused: first, previous: first, next, rects: HashMap::new(), links: Vec::new() };
    }
}

impl<V: Clone> Workspace<V> {
    /// A restored layout must have at least one tab in each group
    pub fn is_valid(&self) -> bool {
        return self.groups.values().all(|g| !g.tabs.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn titles(workspace: &Workspace<&'static str>) -> Vec<Vec<&'static str>> {
        return workspace.group_ids().iter().map(|id| workspace.group(*id).tabs.iter().map(|t| t.view).collect()).collect();
    }

    #[test]
    fn splits_and_tabs() {
        let mut workspace = Workspace::new("a");
        workspace.new_tab("b");
        assert_eq!(*workspace.view(), "b");
        workspace.cycle_tab(true);
        assert_eq!(*workspace.view(), "a");
        workspace.goto_tab(2);
        assert_eq!(*workspace.view(), "b");

        // Side by side: c on the right
        let c = workspace.split(Dir::Right, "c");
        workspace.layout(Rect::new(0, 0, 100, 40));
        assert_eq!(workspace.focused, c);
        assert!(workspace.focus_dir(Dir::Left));
        assert_eq!(*workspace.view(), "b");
        assert!(!workspace.focus_dir(Dir::Left));

        // d below b
        workspace.split(Dir::Down, "d");
        let rects = workspace.layout(Rect::new(0, 0, 100, 40));
        assert_eq!(rects.len(), 3);
        assert!(workspace.focus_dir(Dir::Up));
        assert_eq!(*workspace.view(), "b");
        assert!(workspace.focus_dir(Dir::Right));
        assert_eq!(*workspace.view(), "c");

        // b moves to the group of c
        workspace.focus_dir(Dir::Left);
        workspace.move_tab(Dir::Right);
        assert_eq!(titles(&workspace), vec![vec!["a"], vec!["d"], vec!["c", "b"]]);

        workspace.resize(true, 10);
        workspace.equalize();

        assert!(workspace.close_tab());
        assert!(workspace.close_tab());
        assert_eq!(titles(&workspace), vec![vec!["a"], vec!["d"]]);
        workspace.only();
        assert_eq!(workspace.group_count(), 1);
        assert!(!workspace.close_tab());
    }

    #[test]
    fn links_and_sessions() {
        let mut workspace = Workspace::new("a");
        workspace.split(Dir::Right, "b");
        assert!(workspace.toggle_link());
        assert_eq!(workspace.linked(workspace.focused), Some(0));
        assert!(!workspace.toggle_link());
        assert_eq!(workspace.linked(0), None);

        let layout = workspace.save(&|v: &&str| v.to_string());
        let text = toml::to_string(&SessionTest { layout: layout.clone() }).unwrap();
        let parsed: SessionTest = toml::from_str(&text).unwrap();
        assert_eq!(parsed.layout, layout);

        let restored = Workspace::restore(&parsed.layout, &mut |r: &String| if r == "a" { "a" } else { "b" });
        assert_eq!(titles(&restored), vec![vec!["a"], vec!["b"]]);
        assert!(restored.is_valid());
    }

    #[derive(Serialize, Deserialize)]
    struct SessionTest {
        layout: Layout<String>,
    }
}
