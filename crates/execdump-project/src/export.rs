/*
 * Export of the C code as a source tree: one file per module in src/, its header in include/ with
 * the prototypes of its functions, plus headers for the imported functions and the globals.
 * The tree is meant to be read and built upon, it does not always compile as it is.
 */

use crate::project::Project;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

const COMMON: &str = "execdump.h";
const IMPORTS: &str = "execdump_imports.h";
const GLOBALS: &str = "execdump_globals.h";

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub dir: PathBuf,
    pub files: usize,
    pub functions: usize,
    /// Functions exported with unresolved conflicts
    pub conflicts: Vec<String>,
}

/// Header of a module: net/socket.c -> net/socket.h
pub fn header_of(module: &str) -> String {
    let stem = module.rsplit_once('.').filter(|(_, ext)| !ext.contains('/')).map_or(module, |(stem, _)| stem);
    return format!("{}.h", stem);
}

/// Name of the function of a prototype line
fn prototype_name(signature: &str) -> Option<&str> {
    let open = signature.find('(')?;
    let before = signature[..open].trim_end();
    let start = before.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |i| i + 1);

    return Some(&before[start..]).filter(|n| !n.is_empty());
}

fn write(dir: &Path, path: &str, text: &str, files: &mut usize) -> Result<(), String> {
    let path = dir.join(path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {}", parent.display(), e))?;
    }

    std::fs::write(&path, text).map_err(|e| format!("{}: {}", path.display(), e))?;
    *files += 1;

    return Ok(());
}

pub fn export(project: &mut Project, dir: &Path) -> Result<Report, String> {
    let missing = project.missing();

    if !missing.is_empty() {
        return Err(format!("{} functions are not decompiled yet", missing.len()));
    }

    let mut report = Report { dir: dir.to_path_buf(), ..Report::default() };
    let modules: Vec<String> = project.modules.names().cloned().collect();

    // Module of each function, by C name
    let mut module_of: HashMap<String, String> = HashMap::new();
    let mut texts: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let mut globals: BTreeMap<String, u64> = BTreeMap::new();
    let mut calls: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for module in modules.iter() {
        for addr in project.modules.functions(module).to_vec() {
            let Some(rendered) = project.export_text(addr) else {
                continue;
            };

            let conflict = crate::store::has_conflicts(&rendered.text);

            if conflict {
                report.conflicts.push(project.function_name(addr));
            }

            if let Some(name) = prototype_name(&rendered.meta.signature) {
                module_of.insert(name.to_string(), module.clone());
            }

            imports.extend(rendered.meta.decls.iter().cloned());
            globals.extend(rendered.meta.globals.iter().cloned());
            calls.entry(module.clone()).or_default().extend(rendered.meta.calls.iter().chain(rendered.meta.others.iter()).cloned());
            texts.entry(module.clone()).or_default().push((rendered.meta.signature.clone(), rendered.text.clone(), rendered.ok));
            report.functions += 1;
        }
    }

    // The functions of the program are declared by their module header, not as imports
    imports.retain(|decl| prototype_name(decl).is_none_or(|n| !module_of.contains_key(n)));

    let mut common = String::from("#pragma once\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n");
    common.push_str("typedef uint8_t undefined;\ntypedef uint8_t undefined1;\ntypedef uint16_t undefined2;\ntypedef uint32_t undefined4;\ntypedef uint64_t undefined8;\n");
    common.push_str("typedef struct { uint8_t bytes[16]; } undefined16;\n\n");
    common.push_str(&format!("#include \"{}\"\n#include \"{}\"\n", IMPORTS, GLOBALS));
    write(dir, &format!("include/{}", COMMON), &common, &mut report.files)?;

    let mut text = String::from("#pragma once\n\n");
    imports.iter().for_each(|d| text.push_str(&format!("{}\n", d)));
    write(dir, &format!("include/{}", IMPORTS), &text, &mut report.files)?;

    let mut text = String::from("#pragma once\n\n");
    globals.iter().for_each(|(name, addr)| text.push_str(&format!("extern undefined {}[]; /* {:#x} */\n", name, addr)));
    write(dir, &format!("include/{}", GLOBALS), &text, &mut report.files)?;

    for (module, functions) in texts.iter() {
        let header = header_of(module);

        let mut text = format!("#pragma once\n\n#include \"{}\"\n\n", COMMON);
        let tags: BTreeSet<String> = functions.iter().filter(|(_, _, ok)| *ok).flat_map(|(signature, _, _)| execdump_decompiler::c::ast::struct_tags(signature)).collect();
        tags.iter().for_each(|tag| text.push_str(&format!("struct {};\n", tag)));
        functions.iter().filter(|(_, _, ok)| *ok).for_each(|(signature, _, _)| text.push_str(&format!("{};\n", signature)));
        write(dir, &format!("include/{}", header), &text, &mut report.files)?;

        let others: BTreeSet<String> = calls.get(module).into_iter().flatten().filter_map(|name| module_of.get(name)).filter(|m| *m != module).map(|m| header_of(m)).collect();

        let mut text = format!("#include \"{}\"\n#include \"{}\"\n", COMMON, header);
        others.iter().for_each(|h| text.push_str(&format!("#include \"{}\"\n", h)));

        for (_, body, _) in functions.iter() {
            text.push('\n');
            text.push_str(body);
        }

        write(dir, &format!("src/{}", module), &text, &mut report.files)?;
    }

    return Ok(report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::tests::{open, temporary};

    #[test]
    fn names() {
        assert_eq!(header_of("net/socket.c"), "net/socket.h");
        assert_eq!(header_of("Socket.cpp"), "Socket.h");
        assert_eq!(header_of("v1.2/noext"), "v1.2/noext.h");
        assert_eq!(prototype_name("int f(int a)"), Some("f"));
        assert_eq!(prototype_name("char *next_word(const char *s)"), Some("next_word"));
    }

    #[test]
    fn source_tree() {
        let location = temporary("export-project");
        let out = temporary("export-tree");
        let mut project = open(&location);
        project.wait_idle();

        let classify = project.resolve("classify").unwrap();
        project.move_function(classify, "lib/classes.c").unwrap();

        let report = project.export(&out).unwrap();
        assert!(report.functions >= 4);
        assert!(report.conflicts.is_empty());

        let main = std::fs::read_to_string(out.join("src/analysis.c")).unwrap();
        assert!(main.starts_with("#include \"execdump.h\"\n#include \"analysis.h\"\n#include \"lib/classes.h\"\n"), "{}", main);
        assert!(main.contains("int main("), "{}", main);

        let header = std::fs::read_to_string(out.join("include/lib/classes.h")).unwrap();
        assert!(header.contains("int classify(int a1);"), "{}", header);

        let imports = std::fs::read_to_string(out.join("include/execdump_imports.h")).unwrap();
        assert!(imports.contains("lib_add("), "{}", imports);
        assert!(!imports.contains("classify("), "{}", imports);

        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&location);
    }
}
