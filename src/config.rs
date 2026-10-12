/*
 * Global configuration, loaded from ~/.execdumprc (TOML), one section per feature
 */

use execdump_decompiler::llm::LlmConfig;
use execdump_tui::KeyBindings;

use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub keys: KeyBindings,
    pub llm: LlmConfig,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let Some(path) = dirs::home_dir().map(|h| h.join(".execdumprc")) else {
            return Ok(Config::default());
        };

        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = std::fs::read_to_string(&path)?;

        return toml::from_str(&contents).map_err(|e| format!("{}: {}", path.display(), e).into());
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
