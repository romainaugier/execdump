// SPDX-License-Identifier: Apache-2.0
/*
 * Build information printed by --specs: the commit, the profile, the target and the compiler
 */

use std::path::Path;
use std::process::Command;

fn command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();

    return if text.is_empty() { None } else { Some(text.to_string()) };
}

/// Builds again when the commit changes: checkout (HEAD), new commit on the branch (refs/heads), gc (packed-refs).
/// A path that does not exist would rerun the script on every build, so only the existing ones are watched.
fn watch_git() {
    for name in ["HEAD", "refs/heads", "packed-refs"] {
        if let Some(path) = command("git", &["rev-parse", "--git-path", name]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={}", path);
            }
        }
    }
}

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let commit = command("git", &["rev-parse", "--short=12", "HEAD"]);

    if commit.is_some() {
        watch_git();
    }

    println!("cargo:rustc-env=EXECDUMP_COMMIT={}", commit.as_deref().unwrap_or("unknown"));
    println!("cargo:rustc-env=EXECDUMP_RUSTC={}", command(&rustc, &["-V"]).as_deref().unwrap_or("unknown"));
    println!("cargo:rustc-env=EXECDUMP_PROFILE={}", std::env::var("PROFILE").unwrap_or_default());
    println!("cargo:rustc-env=EXECDUMP_TARGET={}", std::env::var("TARGET").unwrap_or_default());
}
