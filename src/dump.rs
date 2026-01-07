use std::time::{Duration, SystemTime};

use capstone::Insn;
use chrono::prelude::{DateTime, Utc};

pub fn dump_label(label: &str, indent: usize) {
    println!(
        "{:>width$}{}", "", label, width = indent,
    )
}

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

pub fn dump_u32_as_ctime(ctime: u32) -> String {
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(ctime as u64);
    let dt: DateTime<Utc> = time.into();

    return format!("{}", dt.format("%d/%m/%Y %H:%M"));
}
