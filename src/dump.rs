use capstone::Insn;

pub fn dump_field(label: &str, value: impl std::fmt::Display, indent: usize, value_align: usize) {
    println!(
        "{:>width$}{label:<align$}: {}",
        "",
        value,
        width = indent,
        align = value_align
    );
}

pub fn dump_instruction(instruction: &Insn, indent: usize) {
    println!(
        "{:>width$}{}", "", instruction, width = indent
    );
}
