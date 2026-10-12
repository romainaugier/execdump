use execdump_core::elf::ELF;
use execdump_core::exec::Exec;
use execdump_core::macho::MachO;
use crate::args::{Args, DecompileOutput};
use execdump_decompiler::analysis::analyze;
use execdump_decompiler::analysis::dot::{callgraph_dot, cfg_dot};
use execdump_decompiler::analysis::function::Function;
use execdump_decompiler::analysis::insn::Decoder;
use execdump_decompiler::Decompiler;
use execdump_core::program::programs_from_exec;
use execdump_core::pe::PE;

use regex::Regex;


pub fn dump_pe(pe: &PE, args: &Args) {
    if args.pe_headers {
        pe.get_dos_header().dump().print(0, args.padding_size);
        pe.get_nt_header().dump().print(0, args.padding_size);
        pe.get_optional_header().dump().print(0, args.padding_size);
    }

    if args.pe_dos_header {
        pe.get_dos_header().dump().print(0, args.padding_size);
    }

    if args.pe_nt_header {
        pe.get_nt_header().dump().print(0, args.padding_size);
    }

    if args.pe_optional_header {
        pe.get_optional_header().dump().print(0, args.padding_size);
    }

    if args.sections {
        let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

        println!("Sections ({})", pe.get_number_of_sections());
        println!("");

        for (_, section) in pe.sections.iter() {
            if sections_filter_regex.is_match(section.header.name.as_str()) {
                section.dump(pe, args.sections_data, args.disasm).print(0, args.padding_size);
            }
        }
    }

    if args.pe_import {
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

    if args.pe_import_directory_table {
        if let Some(ref idt) = pe.import_directory_table {
            idt.dump().print(0, args.padding_size);
        } else {
           println!("Import Directory Table");
           println!("No Import Directory Table found in PE");
        }
    }

    if args.pe_hint_name_table {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump().print(0, args.padding_size);
        } else {
            println!("Hint/Name Table");
            println!("No Hint/Name Table found in PE");
        }
    }

    if args.pe_dlls {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump_dlls().print(0, args.padding_size);
        } else {
            println!("DLLs");
            println!("No DLLs found in PE");
        }
    }

    if args.pe_export {
        if let Some(ref export_data) = pe.export_data {
            export_data.dump().print(0, args.padding_size);
        } else {
            println!("Export Data");
            println!("No export data found in PE");
        }
    }

    if args.pe_debug_directory {
        if let Some(ref dd) = pe.debug_directory {
            dd.dump().print(0, args.padding_size);
        } else {
            println!("Debug");
            println!("No debug information found in PE");
        }
    }

    if args.pe_exc_table {
        if let Some(ref et) = pe.exception_table {
            et.dump().print(0, args.padding_size);
        } else {
            println!("Exception");
            println!("No exception information found in PE");
        }

    }
}

pub fn dump_elf(elf: &ELF, args: &Args) {
    if args.elf_header {
        elf.headers.elf_header.dump().print(0, args.padding_size);
    }

    if args.elf_program_headers {
        elf.dump_program_headers().print(0, args.padding_size);
    }

    if args.sections {
        let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

        println!("Sections ({})", elf.sections.len());
        println!("");

        for (_, section) in elf.sections.iter() {
            if sections_filter_regex.is_match(section.name.as_str()) {
                section.dump(elf, args.sections_data, args.disasm).print(0, args.padding_size);
                println!("");
            }
        }
    }

    if args.elf_headers {
        elf.headers.elf_header.dump().print(0, args.padding_size);
        elf.dump_program_headers().print(0, args.padding_size);
    }

    if args.elf_symbols {
        if elf.symbol_tables.is_empty() {
            println!("Symbol Tables");
            println!("No symbol table found in ELF");
        }

        for table in elf.symbol_tables.iter() {
            table.dump().print(0, args.padding_size);
        }
    }

    if args.elf_dynamic {
        if let Some(ref dynamic) = elf.dynamic {
            dynamic.dump().print(0, args.padding_size);
        } else {
            println!("Dynamic Section");
            println!("No dynamic section found in ELF");
        }
    }

    if args.elf_relocations {
        if elf.relocation_tables.is_empty() {
            println!("Relocation Tables");
            println!("No relocation table found in ELF");
        }

        for table in elf.relocation_tables.iter() {
            table.dump().print(0, args.padding_size);
        }
    }

    if args.elf_imports {
        elf.dump_imports().print(0, args.padding_size);
    }

    if args.elf_notes {
        elf.dump_notes().print(0, args.padding_size);
    }
}

pub fn dump_macho(macho: &MachO, args: &Args) {
    if args.macho_fat_header {
        if let Some(ref fat_header) = macho.fat_header {
            fat_header.dump().print(0, args.padding_size);
        } else {
            println!("Fat Header");
            println!("No fat header found in Mach-O");
            println!("");
        }
    }

    for binary in macho.binaries.iter() {
        if args.macho_header {
            binary.header.dump().print(0, args.padding_size);
        }

        if args.macho_load_commands {
            binary.dump_load_commands().print(0, args.padding_size);
        }

        if args.sections {
            let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

            println!("Sections ({}, {})", binary.cpu_name(), binary.sections.len());
            println!("");

            for (name, section) in binary.sections.iter() {
                if sections_filter_regex.is_match(name.as_str()) {
                    section.dump(binary, args.sections_data, args.disasm).print(0, args.padding_size);
                    println!("");
                }
            }
        }

        if args.macho_symbols {
            binary.dump_symbols().print(0, args.padding_size);
        }

        if args.macho_imports {
            binary.dump_dylibs().print(0, args.padding_size);
        }
    }
}

pub fn dump_decompile(exec: &Exec, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let filter = Regex::new(&args.functions_filter)?;

    for program in programs_from_exec(exec) {
        let analysis = analyze(&program, None)?;
        let decoder = Decoder::new(program.architecture())?;

        let functions: Vec<&Function> = analysis.functions.values()
            .filter(|f| filter.is_match(&f.name) || filter.is_match(&format!("{:x}", f.addr)))
            .collect();

        for output in args.decompile.iter() {
            match output {
                DecompileOutput::Functions => {
                    println!("Functions ({}, {})", program.name, functions.len());
                    println!("");
                    println!("{:<18} {:>8} {:>6} {:>6} {:<16} {}", "Address", "Size", "Blocks", "Insns", "Source", "Name");

                    for function in functions.iter() {
                        let mut flags = Vec::new();

                        if function.thunk.is_some() {
                            flags.push("thunk");
                        }

                        if function.noreturn {
                            flags.push("noreturn");
                        }

                        if function.unresolved_jumps > 0 {
                            flags.push("unresolved jumps");
                        }

                        println!(
                            "{:#018x} {:>8} {:>6} {:>6} {:<16} {}{}",
                            function.addr,
                            function.size(),
                            function.blocks.len(),
                            function.num_insns(),
                            function.source.name(),
                            function.name,
                            if flags.is_empty() { String::new() } else { format!(" ({})", flags.join(", ")) },
                        );
                    }

                    println!("");
                }
                DecompileOutput::Cfg => print!("{}", cfg_dot(&program, &analysis, &decoder, &functions)),
                DecompileOutput::Callgraph => print!("{}", callgraph_dot(&analysis)),
                DecompileOutput::C => {
                    let decompiler = Decompiler::new(&program, &analysis)?;

                    for function in functions.iter().filter(|f| f.thunk.is_none()) {
                        match decompiler.c_code(function.addr) {
                            Ok(code) => println!("// {:#x}\n{}", function.addr, code),
                            Err(error) => println!("// {} ({:#x}): {}\n", function.name, function.addr, error),
                        }
                    }
                }
                DecompileOutput::Llvm => {
                    let decompiler = Decompiler::new(&program, &analysis)?;

                    for function in functions.iter().filter(|f| f.thunk.is_none()) {
                        match decompiler.llvm_ir(function.addr) {
                            Ok(ir) => println!("; {} ({:#x})\n{}", function.name, function.addr, ir),
                            Err(error) => println!("; {} ({:#x}): {}\n", function.name, function.addr, error),
                        }
                    }
                }
            }
        }
    }

    return Ok(());
}

pub fn dump_exec(exec: &Exec, args: &Args) {
    match exec {
        Exec::PE(pe) => dump_pe(pe, args),
        Exec::ELF(elf) => dump_elf(elf, args),
        Exec::MachO(macho) => dump_macho(macho, args),
    }

    if !args.decompile.is_empty() {
        if let Err(error) = dump_decompile(exec, args) {
            eprintln!("Decompilation failed: {}", error);
        }
    }
}
