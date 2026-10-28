// SPDX-License-Identifier: Apache-2.0
/*
 * --specs: the build, the machine and the platform daedale runs on, to paste in bug reports.
 *
 * The machine is read from the system directly (procfs and uname on Linux, sysctl on macOS, the registry and Win32
 * on Windows). The paths under the home directory start with ~ so that a report does not give the user name.
 */

use crate::config::Config;

use anyhow::Result;

use daedale_debugger::Kind;
use daedale_tui::DebuggerConfig;

use std::io::Write;
use std::process::{Command, Stdio};

pub fn print() -> Result<()> {
    let (config, config_status) = config();
    let (llvm_major, llvm_minor, llvm_patch) = inkwell::support::get_llvm_version();
    let (capstone_major, capstone_minor) = capstone::Capstone::lib_version();

    let mut specs: Vec<(&str, String)> = vec![
        ("commit", env!("DAEDALE_COMMIT").to_string()),
        ("build", format!("{}, {}, {}", env!("DAEDALE_PROFILE"), env!("DAEDALE_TARGET"), env!("DAEDALE_RUSTC"))),
        ("llvm", format!("{}.{}.{}", llvm_major, llvm_minor, llvm_patch)),
        ("capstone", format!("{}.{}", capstone_major, capstone_minor)),
        ("os", system::os().unwrap_or_else(|| std::env::consts::OS.to_string())),
    ];

    if let Some(kernel) = system::kernel() {
        specs.push(("kernel", kernel));
    }

    specs.push(("arch", arch()));
    specs.push(("cpu", cpu()));
    specs.push(("memory", system::memory().map(gib).unwrap_or_else(|| "unknown".to_string())));
    specs.push(("terminal", terminal()));
    specs.push(("debugger", debugger(&config.debugger)));
    specs.push(("config", config_status));

    let mut out = std::io::stdout().lock();

    writeln!(out, "daedale {}", env!("CARGO_PKG_VERSION"))?;

    for (key, value) in specs {
        writeln!(out, "{:<10}{}", key, value)?;
    }

    return Ok(());
}

fn config() -> (Config, String) {
    let path = Config::path().filter(|path| path.is_file()).map(|path| tilde(&path.display().to_string()));

    return match (Config::load(), path) {
        (Ok(config), Some(path)) => (config, path),
        (Ok(config), None) => (config, "none".to_string()),
        (Err(error), path) => {
            let path = path.unwrap_or_else(|| "~/.daedalerc".to_string());
            (Config::default(), format!("{} is invalid: {}", path, one_line(&error.root_cause().to_string())))
        }
    };
}

/// The first and last lines of a message: TOML errors put the source and a caret between the position and the reason
fn one_line(message: &str) -> String {
    let mut lines = message.lines().map(str::trim).filter(|line| !line.is_empty());
    let first = lines.next().unwrap_or_default();

    return match lines.last() {
        Some(last) => format!("{}: {}", first, last),
        None => first.to_string(),
    };
}

fn arch() -> String {
    let arch = std::env::consts::ARCH;

    return match system::native_arch() {
        Some(native) if native != arch => format!("{} (emulated on {})", arch, native),
        _ => arch.to_string(),
    };
}

fn cpu() -> String {
    let name = system::cpu().unwrap_or_else(|| "unknown".to_string());

    return match std::thread::available_parallelism() {
        Ok(threads) => format!("{} ({} threads)", name, threads),
        Err(_) => name,
    };
}

fn gib(bytes: u64) -> String {
    return format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64);
}

fn terminal() -> String {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let mut parts: Vec<String> = Vec::with_capacity(4);

    if let Some(program) = var("TERM_PROGRAM") {
        parts.push(match var("TERM_PROGRAM_VERSION") {
            Some(version) => format!("{} {}", program, version),
            None => program,
        });
    } else if var("WT_SESSION").is_some() {
        parts.push("Windows Terminal".to_string());
    }

    parts.extend(var("TERM"));
    parts.extend(var("COLORTERM"));

    if let Ok((columns, rows)) = crossterm::terminal::size() {
        parts.push(format!("{}x{}", columns, rows));
    }

    return if parts.is_empty() { "unknown".to_string() } else { parts.join(", ") };
}

/// The debugger the TUI would run, with the first line of its --version
fn debugger(config: &DebuggerConfig) -> String {
    let kind = config.backend.as_deref().and_then(Kind::from_name);

    let Some((kind, path)) = daedale_debugger::find(kind, config.path.as_deref()) else {
        return "none found".to_string();
    };

    let version = Command::new(&path)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|output| String::from_utf8_lossy(&output.stdout).lines().next().map(|line| line.trim().to_string()))
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "version unknown".to_string());

    return format!("{} at {}, {}", kind.name(), tilde(&path.display().to_string()), version);
}

fn tilde(text: &str) -> String {
    return match dirs::home_dir() {
        Some(home) if !home.as_os_str().is_empty() => text.replace(&*home.to_string_lossy(), "~"),
        _ => text.to_string(),
    };
}

#[cfg(unix)]
fn uname() -> Option<String> {
    use std::ffi::CStr;

    let mut name: libc::utsname = unsafe { std::mem::zeroed() };

    if unsafe { libc::uname(&mut name) } != 0 {
        return None;
    }

    let field = |chars: &[libc::c_char]| unsafe { CStr::from_ptr(chars.as_ptr()) }.to_string_lossy().into_owned();

    return Some(format!("{} {}", field(&name.sysname), field(&name.release)));
}

#[cfg(target_os = "linux")]
mod system {
    pub fn os() -> Option<String> {
        let release = std::fs::read_to_string("/etc/os-release").ok()?;
        let name = release.lines().find_map(|line| line.strip_prefix("PRETTY_NAME="))?;

        return Some(name.trim_matches('"').to_string());
    }

    pub fn kernel() -> Option<String> {
        return super::uname();
    }

    /// x86 kernels give the model name, arm64 ones only the ids of the core: the board then, or the ids
    pub fn cpu() -> Option<String> {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let field = |name: &str| {
            cpuinfo.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                return (key.trim() == name).then(|| value.trim().to_string());
            })
        };

        if let Some(model) = field("model name") {
            return Some(model);
        }

        if let Ok(model) = std::fs::read_to_string("/proc/device-tree/model") {
            return Some(model.trim_end_matches('\0').trim().to_string());
        }

        return Some(format!("implementer {}, part {}", field("CPU implementer")?, field("CPU part")?));
    }

    pub fn memory() -> Option<u64> {
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };

        if unsafe { libc::sysinfo(&mut info) } != 0 {
            return None;
        }

        return Some(info.totalram as u64 * info.mem_unit as u64);
    }

    pub fn native_arch() -> Option<&'static str> {
        return None;
    }
}

#[cfg(target_os = "macos")]
mod system {
    use std::ffi::CStr;
    use std::ptr::null_mut;

    fn sysctl_string(name: &CStr) -> Option<String> {
        let mut size: libc::size_t = 0;

        if unsafe { libc::sysctlbyname(name.as_ptr(), null_mut(), &mut size, null_mut(), 0) } != 0 || size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size];

        if unsafe { libc::sysctlbyname(name.as_ptr(), buffer.as_mut_ptr().cast(), &mut size, null_mut(), 0) } != 0 {
            return None;
        }

        buffer.truncate(size);

        return Some(CStr::from_bytes_until_nul(&buffer).ok()?.to_string_lossy().into_owned());
    }

    fn sysctl_value<T: Copy + Default>(name: &CStr) -> Option<T> {
        let mut value = T::default();
        let mut size = std::mem::size_of::<T>();

        if unsafe { libc::sysctlbyname(name.as_ptr(), (&raw mut value).cast(), &mut size, null_mut(), 0) } != 0 {
            return None;
        }

        return (size == std::mem::size_of::<T>()).then_some(value);
    }

    pub fn os() -> Option<String> {
        let version = sysctl_string(c"kern.osproductversion")?;

        return Some(match sysctl_string(c"kern.osversion") {
            Some(build) => format!("macOS {} ({})", version, build),
            None => format!("macOS {}", version),
        });
    }

    pub fn kernel() -> Option<String> {
        return super::uname();
    }

    pub fn cpu() -> Option<String> {
        return sysctl_string(c"machdep.cpu.brand_string");
    }

    pub fn memory() -> Option<u64> {
        return sysctl_value::<u64>(c"hw.memsize");
    }

    /// An x86_64 build runs translated by Rosetta on Apple silicon
    pub fn native_arch() -> Option<&'static str> {
        return (sysctl_value::<i32>(c"sysctl.proc_translated") == Some(1)).then_some("aarch64");
    }
}

#[cfg(windows)]
mod system {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW};
    use windows_sys::Win32::System::SystemInformation::{
        GlobalMemoryStatusEx, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386, MEMORYSTATUSEX,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};

    use std::ffi::c_void;
    use std::ptr::null_mut;

    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const PROCESSOR: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

    fn wide(text: &str) -> Vec<u16> {
        return text.encode_utf16().chain(Some(0)).collect();
    }

    fn registry(key: &str, value: &str, flags: REG_ROUTINE_FLAGS, data: *mut c_void, size: &mut u32) -> bool {
        let (key, value) = (wide(key), wide(value));

        return unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), flags, null_mut(), data, size) } == ERROR_SUCCESS;
    }

    fn registry_string(key: &str, value: &str) -> Option<String> {
        let mut buffer = [0u16; 256];
        let mut size = std::mem::size_of_val(&buffer) as u32;

        if !registry(key, value, RRF_RT_REG_SZ, buffer.as_mut_ptr().cast(), &mut size) {
            return None;
        }

        let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());

        return Some(String::from_utf16_lossy(&buffer[..length]).trim().to_string());
    }

    fn registry_dword(key: &str, value: &str) -> Option<u32> {
        let mut data: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;

        return registry(key, value, RRF_RT_REG_DWORD, (&raw mut data).cast(), &mut size).then_some(data);
    }

    /// ProductName stays "Windows 10" on Windows 11, whose builds start at 22000
    pub fn os() -> Option<String> {
        let build: u32 = registry_string(CURRENT_VERSION, "CurrentBuildNumber")?.parse().ok()?;
        let mut name = registry_string(CURRENT_VERSION, "ProductName")?;

        if build >= 22000 {
            name = name.replace("Windows 10", "Windows 11");
        }

        if let Some(display_version) = registry_string(CURRENT_VERSION, "DisplayVersion") {
            name = format!("{} {}", name, display_version);
        }

        return Some(match registry_dword(CURRENT_VERSION, "UBR") {
            Some(revision) => format!("{} (build {}.{})", name, build, revision),
            None => format!("{} (build {})", name, build),
        });
    }

    pub fn kernel() -> Option<String> {
        return None;
    }

    pub fn cpu() -> Option<String> {
        return registry_string(PROCESSOR, "ProcessorNameString");
    }

    pub fn memory() -> Option<u64> {
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

        if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
            return None;
        }

        return Some(status.ullTotalPhys);
    }

    /// The machine of Windows itself: an x64 build runs emulated on Windows on ARM
    pub fn native_arch() -> Option<&'static str> {
        let (mut process, mut native) = (0u16, 0u16);

        if unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } == 0 {
            return None;
        }

        return match native {
            IMAGE_FILE_MACHINE_AMD64 => Some("x86_64"),
            IMAGE_FILE_MACHINE_ARM64 => Some("aarch64"),
            IMAGE_FILE_MACHINE_I386 => Some("x86"),
            _ => None,
        };
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod system {
    pub fn os() -> Option<String> {
        return None;
    }

    pub fn kernel() -> Option<String> {
        return super::uname();
    }

    pub fn cpu() -> Option<String> {
        return None;
    }

    pub fn memory() -> Option<u64> {
        return None;
    }

    pub fn native_arch() -> Option<&'static str> {
        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::args::Args;

    use clap::Parser;

    #[test]
    fn arguments() {
        assert!(Args::try_parse_from(["daedale", "--specs"]).unwrap().specs);
        assert!(Args::try_parse_from(["daedale"]).is_err());
        assert!(Args::try_parse_from(["daedale", "a.out"]).unwrap().file_path.is_some());
    }

    #[test]
    fn formatting() {
        assert_eq!(gib(8 << 30), "8.0 GiB");
        assert_eq!(gib(3 << 29), "1.5 GiB");
        assert_eq!(one_line("read error"), "read error");
        assert_eq!(one_line("TOML parse error at line 1, column 14\n  |\n1 | a = [\n  |      ^\nunclosed array\n"), "TOML parse error at line 1, column 14: unclosed array");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn machine() {
        assert!(system::cpu().is_some_and(|cpu| !cpu.is_empty()));
        assert!(system::memory().is_some_and(|bytes| bytes > 0));
        assert!(!env!("DAEDALE_TARGET").is_empty());
    }
}
