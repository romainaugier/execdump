// SPDX-License-Identifier: Apache-2.0
/*
 * Global configuration, loaded from ~/.daedalerc (TOML), one section per feature
 */

use anyhow::{Context, Result};

use daedale_decompiler::llm::LlmConfig;
use daedale_tui::{DebuggerConfig, KeyBindings};

use serde::Deserialize;

use std::path::PathBuf;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub keys: KeyBindings,
    pub llm: LlmConfig,
    pub debugger: DebuggerConfig,
}

impl Config {
    /// ~/.daedalerc, or the ~/.execdumprc of execdump when only it exists
    pub fn path() -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        let path = home.join(".daedalerc");
        let legacy = home.join(".execdumprc");

        return Some(if !path.exists() && legacy.is_file() { legacy } else { path });
    }

    pub fn load() -> Result<Self> {
        let Some(path) = Config::path() else {
            return Ok(Config::default());
        };

        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = std::fs::read_to_string(&path).with_context(|| path.display().to_string())?;

        return toml::from_str(&contents).with_context(|| path.display().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections() {
        let config: Config = toml::from_str("[keys]\ncall_graph = 'G'\n").unwrap();
        assert_eq!(config.keys.call_graph, 'G');
        assert_eq!(config.keys.quit, 'q');

        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.keys.call_graph, 'C');
        assert!(!config.llm.is_enabled());

        let config: Config = toml::from_str("[llm]\nbackend = 'ollama'\nmodel = 'qwen'\nbase_url = 'http://localhost:11434'\n").unwrap();
        assert!(config.llm.is_enabled());
        assert_eq!(config.llm.max_tokens, 2048);
    }
}
