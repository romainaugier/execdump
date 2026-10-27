/*
 * Shared libraries a program needs, found where the system loader would look for them:
 * - ELF: the RPATH (without RUNPATH), LD_LIBRARY_PATH, the RUNPATH, /etc/ld.so.conf, then the default
 *   directories; only the libraries of the same class and machine are taken
 * - PE: the directory of the binary, then the PATH
 * - Mach-O: absolute paths, @executable_path, @loader_path and @rpath (LC_RPATH)
 */

use crate::exec::Exec;
use crate::macho::LoadCommandData;

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Needed {
    /// As the binary names it (DT_NEEDED, DLL name, install name)
    pub name: String,
    pub path: Option<PathBuf>,
}

pub fn needed_libraries(exec: &Exec, binary: &Path) -> Vec<Needed> {
    let dir = binary.parent().map(Path::to_path_buf).unwrap_or_default();

    return match exec {
        Exec::ELF(elf) => {
            let Some(dynamic) = elf.dynamic.as_ref() else {
                return Vec::new();
            };

            let strings = |tag| dynamic.entries.iter().filter(|e| e.tag() == Some(tag)).filter_map(|e| e.string.clone()).collect::<Vec<String>>();
            let expand = |paths: Vec<String>| -> Vec<PathBuf> {
                paths.iter().flat_map(|p| p.split(':').map(|p| PathBuf::from(p.replace("$ORIGIN", &dir.to_string_lossy()).replace("${ORIGIN}", &dir.to_string_lossy())))).collect()
            };

            let rpath = expand(strings(crate::elf::DynamicTag::DtRpath));
            let runpath = expand(strings(crate::elf::DynamicTag::DtRunpath));
            let environment: Vec<PathBuf> = std::env::var("LD_LIBRARY_PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
            let identity = elf_identity(binary);

            let mut search: Vec<PathBuf> = Vec::new();

            if runpath.is_empty() {
                search.extend(rpath);
            }

            search.extend(environment);
            search.extend(runpath);
            search.extend(ld_so_conf(Path::new("/etc/ld.so.conf")));
            search.extend(default_directories(identity));

            dynamic
                .needed_libraries()
                .into_iter()
                .map(|name| {
                    let path = if name.contains('/') {
                        Some(dir.join(name)).filter(|p| p.is_file())
                    } else {
                        search.iter().map(|d| d.join(name)).find(|p| p.is_file() && (identity.is_none() || elf_identity(p) == identity))
                    };

                    Needed { name: name.to_string(), path }
                })
                .collect()
        }
        Exec::PE(pe) => {
            let names: Vec<String> = pe.hint_name_table.as_ref().map(|t| t.entries.iter().map(|e| e.dll_name.clone()).collect()).unwrap_or_default();
            let mut search = vec![dir.clone()];
            search.extend(std::env::var("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default());

            names.into_iter().map(|name| Needed { path: search.iter().find_map(|d| find_insensitive(d, &name)), name }).collect()
        }
        Exec::MachO(macho) => {
            let Some(first) = macho.binaries.first() else {
                return Vec::new();
            };

            let expand = |path: &str| PathBuf::from(path.replace("@executable_path", &dir.to_string_lossy()).replace("@loader_path", &dir.to_string_lossy()));
            let rpaths: Vec<PathBuf> = first.load_commands.iter().filter_map(|c| match &c.data { LoadCommandData::Rpath { path } => Some(expand(path)), _ => None }).collect();

            first
                .dylibs()
                .iter()
                .filter_map(|c| match &c.data { LoadCommandData::Dylib { name, .. } => Some(name.clone()), _ => None })
                .map(|name| {
                    let path = match name.strip_prefix("@rpath/") {
                        Some(rest) => rpaths.iter().map(|r| r.join(rest)).find(|p| p.is_file()),
                        None => Some(expand(&name)).filter(|p| p.is_file()),
                    };

                    Needed { name, path }
                })
                .collect()
        }
    };
}

/// Class and machine of an ELF file
fn elf_identity(path: &Path) -> Option<(u8, u16)> {
    use std::io::Read;

    let mut header = [0u8; 20];
    std::fs::File::open(path).ok()?.read_exact(&mut header).ok()?;

    if &header[..4] != b"\x7fELF" {
        return None;
    }

    let machine = if header[5] == 2 { u16::from_be_bytes([header[18], header[19]]) } else { u16::from_le_bytes([header[18], header[19]]) };
    return Some((header[4], machine));
}

/// Directories of /etc/ld.so.conf, with its includes
fn ld_so_conf(path: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut dirs = Vec::new();

    for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty()) {
        let Some(pattern) = line.strip_prefix("include").map(str::trim) else {
            dirs.push(PathBuf::from(line));
            continue;
        };

        let pattern = if Path::new(pattern).is_absolute() { PathBuf::from(pattern) } else { path.parent().unwrap_or(Path::new("/")).join(pattern) };

        // The patterns have a * in their file name only (ld.so.conf.d/*.conf)
        let (Some(parent), Some(name)) = (pattern.parent(), pattern.file_name().and_then(|n| n.to_str())) else {
            continue;
        };

        let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
        let Ok(entries) = std::fs::read_dir(parent) else {
            continue;
        };

        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix) && (name.contains('*') || n == name)))
            .collect();

        files.sort();
        files.iter().for_each(|f| dirs.extend(ld_so_conf(f)));
    }

    return dirs;
}

fn default_directories(identity: Option<(u8, u16)>) -> Vec<PathBuf> {
    // Debian multiarch directories of the machine (x86_64, aarch64, i386)
    let multiarch = match identity {
        Some((2, 62)) => Some("x86_64-linux-gnu"),
        Some((2, 183)) => Some("aarch64-linux-gnu"),
        Some((1, 3)) => Some("i386-linux-gnu"),
        _ => None,
    };

    let mut dirs = Vec::new();

    if let Some(multiarch) = multiarch {
        dirs.push(PathBuf::from("/lib").join(multiarch));
        dirs.push(PathBuf::from("/usr/lib").join(multiarch));
    }

    if identity.is_some_and(|(class, _)| class == 2) {
        dirs.extend(["/lib64", "/usr/lib64"].map(PathBuf::from));
    } else {
        dirs.extend(["/lib32", "/usr/lib32"].map(PathBuf::from));
    }

    dirs.extend(["/lib", "/usr/lib", "/usr/local/lib"].map(PathBuf::from));
    return dirs;
}

/// File of a directory by name, ignoring the case (Windows file names)
fn find_insensitive(dir: &Path, name: &str) -> Option<PathBuf> {
    let exact = dir.join(name);

    if exact.is_file() {
        return Some(exact);
    }

    return std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.eq_ignore_ascii_case(name)));
}

/// Name of a symbol without its ELF version (name@@VERSION)
pub fn unversioned(name: &str) -> &str {
    return name.split('@').next().unwrap_or(name);
}

#[cfg(all(test, target_arch="x86_64", target_family="unix"))]
mod tests {
    use super::*;
    use crate::elf::parse_elf;

    #[test]
    fn system_libraries() {
        // ls needs the C library, which the loader finds in a default directory
        let path = PathBuf::from("/bin/ls");

        if !path.exists() {
            return;
        }

        let exec = Exec::ELF(parse_elf(&path).unwrap());
        let needed = needed_libraries(&exec, &path);
        let libc = needed.iter().find(|n| n.name.starts_with("libc.so")).unwrap();

        assert!(libc.path.as_ref().is_some_and(|p| p.is_file()), "{:?}", needed);
        assert_eq!(elf_identity(libc.path.as_ref().unwrap()), elf_identity(&path));
    }

    #[test]
    fn fixture_without_libraries() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/elf_x86_64_dyn");
        let exec = Exec::ELF(parse_elf(&path).unwrap());
        let needed = needed_libraries(&exec, &path);

        assert_eq!(needed.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), vec!["libfoo.so"]);
        assert_eq!(needed[0].path, None);
        assert_eq!(unversioned("printf@GLIBC_2.2.5"), "printf");
    }
}
