use crate::dump::dump_label;
use crate::pe::parse_pe;
use crate::args::Args;

use clap::Parser;

use regex::Regex;

pub mod pe;
pub mod dump;
pub mod args;
pub mod disasm;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let pe = parse_pe(&args.file_path)?;

    if args.dos_header {
        pe.get_dos_header().dump(0, args.padding_size);
    }

    if args.nt_header {
        pe.get_nt_header().dump(0, args.padding_size);
    }

    if args.optional_header {
        pe.get_optional_header().dump(0, args.padding_size);
    }

    if args.sections {
        let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

        println!("Sections ({})", pe.get_number_of_sections());
        println!("");

        for (_, section) in pe.sections {
            if sections_filter_regex.is_match(section.header.name.as_str()) {
                section.dump(0, args.padding_size, &args);
            }
        }
    }

    if args.debug {
        if let Some(dd) = pe.debug_directory {
            dd.dump(0, args.padding_size);
        } else {
            dump_label("Debug", 0);
            dump_label("No debug information found in PE", args.padding_size);
        }
    }

    if args.exception {
        if let Some(et) = pe.exception_table {
            et.dump(0, args.padding_size);
        } else {
            dump_label("Exception", 0);
            dump_label("No exception information found in PE", args.padding_size);
        }

    }

    return Ok(());
}
