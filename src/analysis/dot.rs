/*
 * Graphviz (dot) export of the control flow graphs and of the call graph
 */

use crate::analysis::function::{CallTarget, EdgeKind, Function};
use crate::analysis::insn::Decoder;
use crate::analysis::Analysis;
use crate::program::Program;

use std::fmt::Write;

fn escape(text: &str) -> String {
    return text.replace('\\', "\\\\").replace('"', "\\\"");
}

pub fn edge_color(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::True => "#4ec94e",
        EdgeKind::False => "#e05252",
        EdgeKind::Jump => "#569cd6",
        EdgeKind::Fallthrough => "#808080",
        EdgeKind::Switch => "#c586c0",
    }
}

/// Control flow graphs of the given functions, one cluster per function
pub fn cfg_dot(program: &Program, analysis: &Analysis, decoder: &Decoder, functions: &[&Function]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "digraph cfg {{");
    let _ = writeln!(out, "    node [shape=box, fontname=\"monospace\", fontsize=10];");
    let _ = writeln!(out, "    edge [fontname=\"monospace\", fontsize=9];");

    for function in functions {
        let _ = writeln!(out, "    subgraph \"cluster_{:x}\" {{", function.addr);
        let _ = writeln!(out, "        label=\"{} ({:#x})\";", escape(&function.name), function.addr);

        for block in function.blocks.values() {
            let mut label = String::new();

            if block.start == function.addr {
                let _ = write!(label, "{}:\\l", escape(&function.name));
            }

            for insn in block.insns.iter() {
                let (mnemonic, operands, comment) = analysis.insn_text(program, decoder, insn);
                let comment = comment.map_or(String::new(), |c| format!("  ; {}", c));

                let _ = write!(label, "{:#x}  {} {}{}\\l", insn.addr, escape(&mnemonic), escape(&operands), escape(&comment));
            }

            let _ = writeln!(out, "        \"b_{:x}\" [label=\"{}\"];", block.start, label);
        }

        for block in function.blocks.values() {
            for edge in block.succs.iter() {
                let label = match edge.kind {
                    EdgeKind::True => "label=\"t\", ",
                    EdgeKind::False => "label=\"f\", ",
                    _ => "",
                };

                let _ = writeln!(out, "        \"b_{:x}\" -> \"b_{:x}\" [{}color=\"{}\"];", block.start, edge.to, label, edge_color(edge.kind));
            }
        }

        let _ = writeln!(out, "    }}");
    }

    let _ = writeln!(out, "}}");

    return out;
}

/// Call graph of all the functions, imports are drawn as separate nodes
pub fn callgraph_dot(analysis: &Analysis) -> String {
    let mut out = String::new();
    let mut imports = std::collections::BTreeSet::new();

    let _ = writeln!(out, "digraph callgraph {{");
    let _ = writeln!(out, "    node [shape=box, fontname=\"monospace\", fontsize=10];");

    for function in analysis.functions.values().filter(|f| f.thunk.is_none()) {
        let _ = writeln!(out, "    \"f_{:x}\" [label=\"{}\\n{:#x}\"];", function.addr, escape(&function.name), function.addr);
    }

    for function in analysis.functions.values().filter(|f| f.thunk.is_none()) {
        for (target, tail) in analysis.callees(function) {
            let style = if tail { " [style=dashed]" } else { "" };

            match &target {
                CallTarget::Function(addr) => {
                    let _ = writeln!(out, "    \"f_{:x}\" -> \"f_{:x}\"{};", function.addr, addr, style);
                }
                CallTarget::Import(name) => {
                    imports.insert(name.clone());
                    let _ = writeln!(out, "    \"f_{:x}\" -> \"imp_{}\"{};", function.addr, escape(name), style);
                }
                CallTarget::Indirect => {}
            }
        }
    }

    for import in imports {
        let name = analysis.call_target_name(&CallTarget::Import(import.clone()));
        let _ = writeln!(out, "    \"imp_{}\" [label=\"{}\", style=dashed, color=\"#808080\"];", escape(&import), escape(&name));
    }

    let _ = writeln!(out, "}}");

    return out;
}
