use crate::pe::parse_pe;
use crate::args::Args;

use clap::Parser;

use regex::Regex;

pub mod pe;
pub mod dump;
pub mod args;
pub mod disasm;
pub mod tui;
pub mod format;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let pe = parse_pe(&args.file_path)?;

    if args.tui {
        return tui::main(&args.file_path, pe);
    }

    if args.dos_header {
        pe.get_dos_header().dump().print(0, args.padding_size);
    }

    if args.nt_header {
        pe.get_nt_header().dump().print(0, args.padding_size);
    }

    if args.optional_header {
        pe.get_optional_header().dump().print(0, args.padding_size);
    }

    if args.sections {
        let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

        println!("Sections ({})", pe.get_number_of_sections());
        println!("");

        for (_, section) in pe.sections {
            if sections_filter_regex.is_match(section.header.name.as_str()) {
                section.dump(args.disasm).print(0, args.padding_size);
            }
        }
    }

    if args.import {
        if pe.import_directory_table.is_none() {
            println!("Import data");
            println!("No Import Data found in PE");
        } else {
            pe.import_directory_table.as_ref().unwrap().dump().print(0, args.padding_size);

            for ilt in pe.import_lookup_tables.as_ref().unwrap().iter() {
                ilt.dump().print(0, args.padding_size);
            }

            println!("");

            pe.hint_name_table.as_ref().unwrap().dump().print(0, args.padding_size);
        }
    }

    if args.import_directory_table {
        if let Some(ref idt) = pe.import_directory_table {
            idt.dump().print(0, args.padding_size);
        } else {
           println!("Import Directory Table");
           println!("No Import Directory Table found in PE");
        }
    }

    if args.hint_name_table {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump().print(0, args.padding_size);
        } else {
            println!("Hint/Name Table");
            println!("No Hint/Name Table found in PE");
        }
    }

    if args.dlls {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump_dlls().print(0, args.padding_size);
        } else {
            println!("DLLs");
            println!("No DLLs found in PE");
        }
    }

    if args.debug {
        if let Some(ref dd) = pe.debug_directory {
            dd.dump().print(0, args.padding_size);
        } else {
            println!("Debug");
            println!("No debug information found in PE");
        }
    }

    if args.exception {
        if let Some(ref et) = pe.exception_table {
            et.dump().print(0, args.padding_size);
        } else {
            println!("Exception");
            println!("No exception information found in PE");
        }

    }

    return Ok(());
}
