/*
 * Layered graph layout (Sugiyama style) for terminal rendering, with orthogonal edge routing
 *
 * 1. Cycle removal: back edges are found with a DFS from the roots
 * 2. Layer assignment: longest path from the roots
 * 3. Long edges are split with dummy nodes (one per crossed layer), back edges get a dummy column
 * 4. Crossing reduction: barycenter sweeps
 * 5. Horizontal placement: weighted isotonic regression (pool adjacent violators) towards the neighbors
 * 6. Edge routing: vertical segments go through the dummy columns, horizontal segments get their own
 *    track in the channel between two layers so they never overlap
 *
 * All the coordinates are in terminal cells.
 */

use std::collections::HashMap;

/// Horizontal space between two nodes of the same layer
const NODE_GAP: i32 = 4;
/// Horizontal space around dummy nodes (edge columns)
const DUMMY_GAP: i32 = 2;
/// Number of crossing reduction sweeps
const ORDERING_SWEEPS: usize = 12;
/// Number of horizontal placement sweeps
const PLACEMENT_SWEEPS: usize = 8;
/// Crossing counting is quadratic, skip it for very large layers
const MAX_CROSSING_COUNT_EDGES: usize = 4000;

#[derive(Clone, Debug, Default)]
pub struct GraphInput {
    /// (width, height) of each node, in cells
    pub sizes: Vec<(i32, i32)>,
    /// (from, to) node indices
    pub edges: Vec<(usize, usize)>,
    /// Preferred roots (entry points), placed at the top
    pub roots: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeLayout {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub layer: usize,
}

impl NodeLayout {
    pub fn center_x(&self) -> i32 {
        return self.x + self.w / 2;
    }

    pub fn center_y(&self) -> i32 {
        return self.y + self.h / 2;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EdgeRoute {
    /// Index of the edge in the input
    pub edge: usize,
    /// Orthogonal polyline, from the cell below the source node to the cell above the target node
    pub points: Vec<(i32, i32)>,
    /// Edge going up (loop)
    pub back: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Layout {
    pub nodes: Vec<NodeLayout>,
    pub edges: Vec<EdgeRoute>,
    pub width: i32,
    pub height: i32,
    /// Nodes in reading order (top to bottom, left to right)
    pub order: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LNodeKind {
    Real(usize),
    Dummy,
}

#[derive(Clone, Debug)]
struct LNode {
    kind: LNodeKind,
    layer: usize,
    width: i32,
    /// Neighbors in the layer above / below
    up: Vec<usize>,
    down: Vec<usize>,
    /// Real node of the same layer this dummy should stay next to (back edge columns)
    partner: Option<usize>,
    x: i32,
}

/// Chain of layered nodes for an input edge
#[derive(Clone, Debug)]
struct Chain {
    edge: usize,
    back: bool,
    /// Layered nodes crossed by the edge, from the source layer to the target layer (dummies only for back edges)
    dummies: Vec<usize>,
    from: usize,
    to: usize,
}

fn find_back_edges(n: usize, input: &GraphInput) -> Vec<bool> {
    let mut adjacency: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];

    for (i, &(from, to)) in input.edges.iter().enumerate() {
        adjacency[from].push((to, i));
    }

    let mut back = vec![false; input.edges.len()];
    // 0: unvisited, 1: on the stack, 2: done
    let mut state = vec![0u8; n];

    let mut starts: Vec<usize> = input.roots.iter().copied().filter(|&r| r < n).collect();
    starts.extend(0..n);

    for start in starts {
        if state[start] != 0 {
            continue;
        }

        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        state[start] = 1;

        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            if *next < adjacency[node].len() {
                let (to, edge) = adjacency[node][*next];
                *next += 1;

                match state[to] {
                    0 => {
                        state[to] = 1;
                        stack.push((to, 0));
                    }
                    1 => back[edge] = true,
                    _ => {}
                }
            } else {
                state[node] = 2;
                stack.pop();
            }
        }
    }

    return back;
}

fn assign_layers(n: usize, input: &GraphInput, back: &[bool]) -> Vec<usize> {
    let mut indegree = vec![0usize; n];
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, &(from, to)) in input.edges.iter().enumerate() {
        if !back[i] && from != to {
            adjacency[from].push(to);
            indegree[to] += 1;
        }
    }

    let mut layer = vec![0usize; n];
    let mut queue: Vec<usize> = (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut head = 0;

    while head < queue.len() {
        let node = queue[head];
        head += 1;

        for &to in adjacency[node].iter() {
            layer[to] = layer[to].max(layer[node] + 1);
            indegree[to] -= 1;

            if indegree[to] == 0 {
                queue.push(to);
            }
        }
    }

    return layer;
}

/// Weighted isotonic regression: minimizes sum(w * (y - target)^2) with y non decreasing
fn isotonic(targets: &[f64], weights: &[f64]) -> Vec<f64> {
    // Blocks of (value, weight, count)
    let mut blocks: Vec<(f64, f64, usize)> = Vec::with_capacity(targets.len());

    for (&t, &w) in targets.iter().zip(weights.iter()) {
        blocks.push((t, w, 1));

        while blocks.len() >= 2 && blocks[blocks.len() - 2].0 > blocks[blocks.len() - 1].0 {
            let (v2, w2, c2) = blocks.pop().unwrap();
            let (v1, w1, c1) = blocks.pop().unwrap();
            let w = w1 + w2;
            blocks.push(((v1 * w1 + v2 * w2) / w, w, c1 + c2));
        }
    }

    let mut res = Vec::with_capacity(targets.len());

    for (v, _, c) in blocks {
        res.extend(std::iter::repeat(v).take(c));
    }

    return res;
}

struct Layering {
    nodes: Vec<LNode>,
    layers: Vec<Vec<usize>>,
    chains: Vec<Chain>,
    /// Layered node of each real node
    real: Vec<usize>,
}

impl Layering {
    fn gap(&self, a: usize, b: usize) -> i32 {
        if self.nodes[a].kind == LNodeKind::Dummy || self.nodes[b].kind == LNodeKind::Dummy {
            return DUMMY_GAP;
        }

        return NODE_GAP;
    }

    fn build(input: &GraphInput, layer_of: &[usize], back: &[bool]) -> Self {
        let n = input.sizes.len();
        let num_layers = layer_of.iter().copied().max().map_or(0, |m| m + 1);

        let mut layering = Layering { nodes: Vec::new(), layers: vec![Vec::new(); num_layers], chains: Vec::new(), real: Vec::new() };

        for i in 0..n {
            let id = layering.nodes.len();
            layering.nodes.push(LNode { kind: LNodeKind::Real(i), layer: layer_of[i], width: input.sizes[i].0.max(1), up: Vec::new(), down: Vec::new(), partner: None, x: 0 });
            layering.real.push(id);
        }

        let add_dummy = |layering: &mut Layering, layer: usize, partner: Option<usize>| -> usize {
            let id = layering.nodes.len();
            layering.nodes.push(LNode { kind: LNodeKind::Dummy, layer, width: 1, up: Vec::new(), down: Vec::new(), partner, x: 0 });
            return id;
        };

        let link = |layering: &mut Layering, upper: usize, lower: usize| {
            layering.nodes[upper].down.push(lower);
            layering.nodes[lower].up.push(upper);
        };

        for (i, &(from, to)) in input.edges.iter().enumerate() {
            let (lf, lt) = (layer_of[from], layer_of[to]);
            let (rf, rt) = (layering.real[from], layering.real[to]);

            if !back[i] && from != to && lt > lf {
                let mut previous = rf;
                let mut dummies = Vec::new();

                for layer in lf + 1..lt {
                    let dummy = add_dummy(&mut layering, layer, None);
                    link(&mut layering, previous, dummy);
                    dummies.push(dummy);
                    previous = dummy;
                }

                link(&mut layering, previous, rt);
                layering.chains.push(Chain { edge: i, back: false, dummies, from, to });
            } else {
                // Back edge (or self loop): a column of dummies from the target layer to the source layer
                let (top, bottom) = (lt.min(lf), lt.max(lf));
                let mut dummies = Vec::new();

                for layer in top..=bottom {
                    let partner = if layer == lt { Some(rt) } else if layer == lf { Some(rf) } else { None };
                    let dummy = add_dummy(&mut layering, layer, partner);

                    if let Some(&previous) = dummies.last() {
                        link(&mut layering, previous, dummy);
                    }

                    dummies.push(dummy);
                }

                layering.chains.push(Chain { edge: i, back: true, dummies, from, to });
            }
        }

        return layering;
    }

    fn initial_order(&mut self, input: &GraphInput) {
        // DFS preorder from the roots, dummies follow the node they come from
        let mut visited = vec![false; self.nodes.len()];
        let mut starts: Vec<usize> = input.roots.iter().filter(|&&r| r < self.real.len()).map(|&r| self.real[r]).collect();
        starts.extend(self.real.iter().copied());

        let mut down_all: Vec<Vec<usize>> = self.nodes.iter().map(|n| n.down.clone()).collect();

        // Back edge columns hang next to their source
        for chain in self.chains.iter().filter(|c| c.back) {
            if let Some(&last) = chain.dummies.last() {
                down_all[self.real[chain.from]].push(last);
            }

            for &dummy in chain.dummies.iter() {
                if !down_all[self.real[chain.from]].contains(&dummy) {
                    down_all[self.real[chain.from]].push(dummy);
                }
            }
        }

        for start in starts {
            if visited[start] {
                continue;
            }

            let mut stack = vec![start];

            while let Some(node) = stack.pop() {
                if visited[node] {
                    continue;
                }

                visited[node] = true;
                self.layers[self.nodes[node].layer].push(node);

                for &next in down_all[node].iter().rev() {
                    if !visited[next] {
                        stack.push(next);
                    }
                }
            }
        }

        for (id, v) in visited.iter().enumerate() {
            if !v {
                self.layers[self.nodes[id].layer].push(id);
            }
        }

        for l in 0..self.layers.len() {
            self.attach_partners(l);
        }
    }

    fn positions(&self) -> Vec<usize> {
        let mut pos = vec![0usize; self.nodes.len()];

        for layer in self.layers.iter() {
            for (i, &node) in layer.iter().enumerate() {
                pos[node] = i;
            }
        }

        return pos;
    }

    fn count_crossings(&self, pos: &[usize]) -> usize {
        let mut total = 0;

        for layer in self.layers.iter() {
            let mut edges: Vec<(usize, usize)> = Vec::new();

            for &node in layer.iter() {
                for &lower in self.nodes[node].down.iter() {
                    edges.push((pos[node], pos[lower]));
                }
            }

            if edges.len() > MAX_CROSSING_COUNT_EDGES {
                continue;
            }

            for i in 0..edges.len() {
                for j in i + 1..edges.len() {
                    let (a, b) = (edges[i], edges[j]);

                    if (a.0 < b.0 && a.1 > b.1) || (a.0 > b.0 && a.1 < b.1) {
                        total += 1;
                    }
                }
            }
        }

        return total;
    }

    fn sweep(&mut self, downward: bool) {
        let num_layers = self.layers.len();
        let indices: Vec<usize> = if downward { (1..num_layers).collect() } else { (0..num_layers.saturating_sub(1)).rev().collect() };

        for l in indices {
            let pos = self.positions();

            let mut keys: Vec<(f64, usize)> = self.layers[l].iter().map(|&node| {
                let n = &self.nodes[node];
                let neighbors = if downward { &n.up } else { &n.down };

                let sum: f64 = neighbors.iter().map(|&m| pos[m] as f64).sum();
                let count = neighbors.len() as f64;

                let key = if count > 0.0 { sum / count } else { pos[node] as f64 };

                (key, node)
            }).collect();

            keys.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            self.layers[l] = keys.into_iter().map(|(_, node)| node).collect();
            self.attach_partners(l);
        }
    }

    /// Moves the back edge columns right after the node they belong to
    fn attach_partners(&mut self, l: usize) {
        let layer = std::mem::take(&mut self.layers[l]);
        let (attached, mut rest): (Vec<usize>, Vec<usize>) = layer.into_iter().partition(|&node| self.nodes[node].partner.is_some());

        for dummy in attached {
            let partner = self.nodes[dummy].partner.unwrap();

            // After the partner and the columns already attached to it
            let mut index = rest.iter().position(|&n| n == partner).map_or(rest.len(), |i| i + 1);

            while index < rest.len() && self.nodes[rest[index]].partner == Some(partner) {
                index += 1;
            }

            rest.insert(index, dummy);
        }

        self.layers[l] = rest;
    }

    fn reduce_crossings(&mut self) {
        let mut best = self.layers.clone();
        let mut best_crossings = self.count_crossings(&self.positions());

        for i in 0..ORDERING_SWEEPS {
            if best_crossings == 0 {
                break;
            }

            self.sweep(i % 2 == 0);

            let crossings = self.count_crossings(&self.positions());

            if crossings < best_crossings {
                best_crossings = crossings;
                best = self.layers.clone();
            }
        }

        self.layers = best;
    }

    fn place_layer(&mut self, l: usize, desired_centers: &[f64]) {
        let layer = &self.layers[l];

        let mut offsets = Vec::with_capacity(layer.len());
        let mut targets = Vec::with_capacity(layer.len());
        let mut weights = Vec::with_capacity(layer.len());
        let mut offset = 0i32;

        for (i, &node) in layer.iter().enumerate() {
            if i > 0 {
                offset += self.nodes[layer[i - 1]].width + self.gap(layer[i - 1], node);
            }

            let desired_left = desired_centers[i] - self.nodes[node].width as f64 / 2.0;

            offsets.push(offset);
            targets.push(desired_left - offset as f64);
            weights.push(if self.nodes[node].kind == LNodeKind::Dummy { 2.0 } else { 1.0 });
        }

        let solution = isotonic(&targets, &weights);

        for (i, &node) in layer.clone().iter().enumerate() {
            self.nodes[node].x = (solution[i] + offsets[i] as f64).round() as i32;
        }

        // Rounding can break the minimal separation, fix it left to right
        let layer = self.layers[l].clone();

        for i in 1..layer.len() {
            let min_x = self.nodes[layer[i - 1]].x + self.nodes[layer[i - 1]].width + self.gap(layer[i - 1], layer[i]);

            if self.nodes[layer[i]].x < min_x {
                self.nodes[layer[i]].x = min_x;
            }
        }
    }

    fn center(&self, node: usize) -> f64 {
        return self.nodes[node].x as f64 + self.nodes[node].width as f64 / 2.0;
    }

    fn assign_x(&mut self) {
        // Initial packing
        for l in 0..self.layers.len() {
            let layer = self.layers[l].clone();
            let mut x = 0;

            for (i, &node) in layer.iter().enumerate() {
                if i > 0 {
                    x += self.gap(layer[i - 1], node);
                }

                self.nodes[node].x = x;
                x += self.nodes[node].width;
            }
        }

        let num_layers = self.layers.len();

        for sweep in 0..PLACEMENT_SWEEPS {
            let downward = sweep % 2 == 0;
            let indices: Vec<usize> = if downward { (0..num_layers).collect() } else { (0..num_layers).rev().collect() };

            for l in indices {
                let desired: Vec<f64> = self.layers[l].iter().map(|&node| {
                    let n = &self.nodes[node];
                    let neighbors = if downward { &n.up } else { &n.down };

                    if let Some(partner) = n.partner {
                        let p = &self.nodes[partner];
                        return p.x as f64 + p.width as f64 + DUMMY_GAP as f64;
                    }

                    let mut centers: Vec<f64> = neighbors.iter().map(|&m| self.center(m)).collect();

                    // On the last sweeps, use both directions to balance the result
                    if sweep >= PLACEMENT_SWEEPS - 2 {
                        let other = if downward { &n.down } else { &n.up };
                        centers.extend(other.iter().map(|&m| self.center(m)));
                    }

                    if centers.is_empty() {
                        return self.center(node);
                    }

                    return centers.iter().sum::<f64>() / centers.len() as f64;
                }).collect();

                self.place_layer(l, &desired);
            }
        }

        let min_x = self.nodes.iter().map(|n| n.x).min().unwrap_or(0);

        for node in self.nodes.iter_mut() {
            node.x -= min_x;
        }
    }
}

/// Horizontal segment of an edge in a channel, before the track assignment
#[derive(Clone, Copy, Debug)]
struct Jog {
    chain: usize,
    channel: usize,
    x1: i32,
    x2: i32,
    track: usize,
}

fn assign_tracks(jogs: &mut [Jog], num_channels: usize) -> Vec<usize> {
    let mut tracks_per_channel = vec![0usize; num_channels];
    let mut by_channel: HashMap<usize, Vec<usize>> = HashMap::new();

    for (i, jog) in jogs.iter().enumerate() {
        by_channel.entry(jog.channel).or_default().push(i);
    }

    let overlaps = |a: &Jog, b: &Jog| -> bool {
        let (a_lo, a_hi) = (a.x1.min(a.x2), a.x1.max(a.x2));
        let (b_lo, b_hi) = (b.x1.min(b.x2), b.x1.max(b.x2));

        return a_lo <= b_hi + 1 && b_lo <= a_hi + 1;
    };

    for (channel, indices) in by_channel {
        // Staircase: a segment going left must be below the segments going left from a port on its left
        // (otherwise it crosses their vertical part), and the opposite for the segments going right
        let mut left: Vec<usize> = indices.iter().copied().filter(|&i| jogs[i].x2 < jogs[i].x1).collect();
        let mut right: Vec<usize> = indices.iter().copied().filter(|&i| jogs[i].x2 > jogs[i].x1).collect();

        left.sort_by_key(|&i| (jogs[i].x1, std::cmp::Reverse(jogs[i].x2)));
        right.sort_by_key(|&i| (std::cmp::Reverse(jogs[i].x1), jogs[i].x2));

        let mut assigned: Vec<usize> = Vec::new();
        let mut count = 0;

        for i in left.into_iter().chain(right) {
            let track = assigned.iter()
                .filter(|&&j| overlaps(&jogs[i], &jogs[j]))
                .map(|&j| jogs[j].track + 1)
                .max()
                .unwrap_or(0);

            jogs[i].track = track;
            count = count.max(track + 1);
            assigned.push(i);
        }

        tracks_per_channel[channel] = count;
    }

    return tracks_per_channel;
}

/// Spreads k ports along a node border
fn port_positions(x: i32, w: i32, k: usize) -> Vec<i32> {
    if k == 0 {
        return Vec::new();
    }

    let inner_start = x + 1;
    let inner_width = (w - 2).max(1);

    return (0..k).map(|i| inner_start + ((i as i32 * 2 + 1) * inner_width) / (k as i32 * 2)).collect();
}

pub fn layout(input: &GraphInput) -> Layout {
    let n = input.sizes.len();

    if n == 0 {
        return Layout::default();
    }

    let back = find_back_edges(n, input);
    let layer_of = assign_layers(n, input, &back);

    let mut layering = Layering::build(input, &layer_of, &back);
    layering.initial_order(input);
    layering.reduce_crossings();
    layering.assign_x();

    let num_layers = layering.layers.len();
    let real = layering.real.clone();

    // Ports: outgoing edges on the bottom border, incoming edges on the top border, sorted by the other end
    let first_step = |chain: &Chain| -> usize {
        if chain.back { *chain.dummies.last().unwrap() } else { chain.dummies.first().copied().unwrap_or(real[chain.to]) }
    };

    let last_step = |chain: &Chain| -> usize {
        if chain.back { *chain.dummies.first().unwrap() } else { chain.dummies.last().copied().unwrap_or(real[chain.from]) }
    };

    let mut out_port = vec![0i32; layering.chains.len()];
    let mut in_port = vec![0i32; layering.chains.len()];

    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut incoming: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, chain) in layering.chains.iter().enumerate() {
        outgoing[chain.from].push(i);
        incoming[chain.to].push(i);
    }

    for node in 0..n {
        let ln = &layering.nodes[real[node]];

        let center = |id: usize| layering.nodes[id].x * 2 + layering.nodes[id].width;

        outgoing[node].sort_by_key(|&c| center(first_step(&layering.chains[c])));
        incoming[node].sort_by_key(|&c| center(last_step(&layering.chains[c])));

        for (&chain, x) in outgoing[node].iter().zip(port_positions(ln.x, ln.width, outgoing[node].len())) {
            out_port[chain] = x;
        }

        for (&chain, x) in incoming[node].iter().zip(port_positions(ln.x, ln.width, incoming[node].len())) {
            in_port[chain] = x;
        }
    }

    // Channel c is above layer c, channel num_layers is below the last layer
    let num_channels = num_layers + 1;
    let mut jogs: Vec<Jog> = Vec::new();

    // Horizontal segments of each chain, in path order: (channel, from x, to x)
    let mut paths: Vec<Vec<(usize, i32, i32)>> = Vec::new();

    for (i, chain) in layering.chains.iter().enumerate() {
        let mut segments = Vec::new();
        let lf = layer_of[chain.from];
        let lt = layer_of[chain.to];

        if !chain.back {
            let mut xs = vec![out_port[i]];
            xs.extend(chain.dummies.iter().map(|&d| layering.nodes[d].x));
            xs.push(in_port[i]);

            for (step, pair) in xs.windows(2).enumerate() {
                segments.push((lf + step + 1, pair[0], pair[1]));
            }
        } else {
            // Down into the channel below the source, over to the column, up the column, over to the target
            let column: Vec<i32> = chain.dummies.iter().map(|&d| layering.nodes[d].x).collect();
            let (top, bottom) = (lt.min(lf), lt.max(lf));

            segments.push((bottom + 1, out_port[i], *column.last().unwrap()));

            for idx in (1..column.len()).rev() {
                segments.push((top + idx, column[idx], column[idx - 1]));
            }

            segments.push((top, column[0], in_port[i]));
        }

        for &(channel, x1, x2) in segments.iter() {
            if x1 != x2 {
                jogs.push(Jog { chain: i, channel, x1, x2, track: 0 });
            }
        }

        paths.push(segments);
    }

    let tracks = assign_tracks(&mut jogs, num_channels);

    let mut track_of: HashMap<(usize, usize), usize> = HashMap::new();

    for jog in jogs.iter() {
        track_of.insert((jog.chain, jog.channel), jog.track);
    }

    // Vertical coordinates
    let channel_height = |c: usize| -> i32 {
        let t = tracks[c] as i32;

        if c == 0 || c == num_layers {
            // Top and bottom channels are only used by back edges
            return if t > 0 { t + 2 } else if c == 0 { 0 } else { 1 };
        }

        return (t + 2).max(3);
    };

    let mut channel_top = vec![0i32; num_channels];
    let mut layer_top = vec![0i32; num_layers];
    let mut y = 0;

    for l in 0..num_layers {
        channel_top[l] = y;
        y += channel_height(l);
        layer_top[l] = y;

        let height = layering.layers[l].iter().filter_map(|&node| match layering.nodes[node].kind {
            LNodeKind::Real(i) => Some(input.sizes[i].1.max(1)),
            LNodeKind::Dummy => None,
        }).max().unwrap_or(1);

        y += height;
    }

    channel_top[num_layers] = y;
    y += channel_height(num_layers);

    let height = y;

    let nodes: Vec<NodeLayout> = (0..n).map(|i| {
        let ln = &layering.nodes[real[i]];
        NodeLayout { x: ln.x, y: layer_top[ln.layer], w: input.sizes[i].0.max(1), h: input.sizes[i].1.max(1), layer: ln.layer }
    }).collect();

    let track_y = |channel: usize, track: usize| -> i32 { channel_top[channel] + 1 + track as i32 };

    let mut edges = Vec::new();

    for (i, chain) in layering.chains.iter().enumerate() {
        let source = &nodes[chain.from];
        let target = &nodes[chain.to];

        let mut points = vec![(out_port[i], source.y + source.h)];

        for &(channel, x1, x2) in paths[i].iter() {
            if x1 == x2 {
                continue;
            }

            let ty = track_y(channel, track_of[&(i, channel)]);
            points.push((x1, ty));
            points.push((x2, ty));
        }

        points.push((in_port[i], target.y - 1));

        // Remove duplicated and collinear points
        points.dedup();

        let mut simplified: Vec<(i32, i32)> = Vec::with_capacity(points.len());

        for p in points {
            if simplified.len() >= 2 {
                let a = simplified[simplified.len() - 2];
                let b = simplified[simplified.len() - 1];

                if (a.0 == b.0 && b.0 == p.0) || (a.1 == b.1 && b.1 == p.1) {
                    simplified.pop();
                }
            }

            simplified.push(p);
        }

        edges.push(EdgeRoute { edge: chain.edge, points: simplified, back: chain.back });
    }

    edges.sort_by_key(|e| e.edge);

    let width = layering.nodes.iter().map(|n| n.x + n.width).max().unwrap_or(0) + 1;

    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (nodes[i].layer, nodes[i].x));

    return Layout { nodes, edges, width, height, order };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(input: &GraphInput, layout: &Layout) {
        // Nodes never overlap
        for (i, a) in layout.nodes.iter().enumerate() {
            for b in layout.nodes.iter().skip(i + 1) {
                let overlap = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
                assert!(!overlap, "{:?} overlaps {:?}", a, b);
            }
        }

        assert_eq!(layout.edges.len(), input.edges.len());

        for route in layout.edges.iter() {
            let (from, to) = input.edges[route.edge];
            let (source, target) = (&layout.nodes[from], &layout.nodes[to]);

            // Orthogonal polyline
            for pair in route.points.windows(2) {
                assert!(pair[0].0 == pair[1].0 || pair[0].1 == pair[1].1, "{:?}", route.points);
            }

            // Starts below the source and ends above the target
            let first = route.points[0];
            let last = *route.points.last().unwrap();

            assert_eq!(first.1, source.y + source.h);
            assert!(first.0 > source.x && first.0 < source.x + source.w - 1 || source.w <= 2);
            assert_eq!(last.1, target.y - 1);
            assert!(last.0 > target.x && last.0 < target.x + target.w - 1 || target.w <= 2);

            // Horizontal segments never go through a node
            for pair in route.points.windows(2) {
                if pair[0].1 == pair[1].1 {
                    let (lo, hi) = (pair[0].0.min(pair[1].0), pair[0].0.max(pair[1].0));

                    for node in layout.nodes.iter() {
                        let crosses = pair[0].1 >= node.y && pair[0].1 < node.y + node.h && lo < node.x + node.w && hi >= node.x;
                        assert!(!crosses, "segment {:?} crosses {:?}", pair, node);
                    }
                }
            }
        }
    }

    #[test]
    fn diamond() {
        let input = GraphInput {
            sizes: vec![(20, 5), (10, 3), (12, 4), (20, 3)],
            edges: vec![(0, 1), (0, 2), (1, 3), (2, 3)],
            roots: vec![0],
        };

        let layout = layout(&input);

        check(&input, &layout);

        assert_eq!(layout.nodes[0].layer, 0);
        assert_eq!(layout.nodes[1].layer, 1);
        assert_eq!(layout.nodes[2].layer, 1);
        assert_eq!(layout.nodes[3].layer, 2);
        assert_eq!(layout.order[0], 0);
        assert_eq!(*layout.order.last().unwrap(), 3);
        assert!(layout.edges.iter().all(|e| !e.back));
    }

    #[test]
    fn loop_and_self_loop() {
        let input = GraphInput {
            sizes: vec![(10, 3), (14, 6), (10, 3), (8, 3)],
            edges: vec![(0, 1), (1, 2), (2, 1), (1, 3), (3, 3)],
            roots: vec![0],
        };

        let layout = layout(&input);

        check(&input, &layout);

        assert!(layout.edges[2].back);
        assert!(layout.edges[4].back);
        assert!(!layout.edges[1].back);

        // The loop goes up: it must end above node 1 while starting below node 2
        let route = &layout.edges[2];
        assert!(route.points.last().unwrap().1 < route.points[0].1);
    }

    #[test]
    fn long_edges_and_disconnected() {
        let input = GraphInput {
            sizes: vec![(10, 3); 6],
            edges: vec![(0, 1), (1, 2), (2, 3), (0, 3), (0, 2)],
            roots: vec![0],
        };

        let layout = layout(&input);

        check(&input, &layout);

        assert_eq!(layout.nodes[3].layer, 3);
        assert_eq!(layout.order.len(), 6);
    }

    #[test]
    fn isotonic_regression() {
        let res = isotonic(&[1.0, 3.0, 2.0, 4.0], &[1.0, 1.0, 1.0, 1.0]);
        assert_eq!(res, vec![1.0, 2.5, 2.5, 4.0]);
    }

    #[test]
    fn many_nodes() {
        // Chain with branches, to make sure nothing is quadratic in a bad way
        let n = 400;
        let mut edges = Vec::new();

        for i in 0..n - 1 {
            edges.push((i, i + 1));

            if i % 3 == 0 && i + 5 < n {
                edges.push((i, i + 5));
            }

            if i % 7 == 0 && i > 10 {
                edges.push((i, i - 9));
            }
        }

        let input = GraphInput { sizes: vec![(16, 4); n], edges, roots: vec![0] };
        let layout = layout(&input);

        check(&input, &layout);
    }
}
