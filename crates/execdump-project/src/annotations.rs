// SPDX-License-Identifier: Apache-2.0
/*
 * What the user (or the LLM, once accepted) says about the program: names, prototypes, summaries,
 * variables and modules of the functions, names of the globals. One small TOML file per annotated
 * function or global, so that the history stays readable and merges well.
 */

use anyhow::Result;

use execdump_decompiler::notes::VarNote;

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct VarNotes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
}

impl VarNotes {
    pub fn is_empty(&self) -> bool {
        return self.name.is_none() && self.ty.is_none();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FunctionNotes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Module (source file) the function belongs to, instead of the one found automatically
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Prototype typed by the user, "int parse(const char *text)"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Variables, by the name the decompiler gives them
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, VarNotes>,
}

impl FunctionNotes {
    pub fn is_empty(&self) -> bool {
        return self.name.is_none() && self.module.is_none() && self.prototype.is_none() && self.summary.is_none() && self.vars.values().all(|v| v.is_empty());
    }

    pub fn to_toml(&self) -> String {
        return toml::to_string(self).unwrap_or_default();
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        return Ok(toml::from_str(text)?);
    }

    /// The notes of the decompiler for the variables
    pub fn var_notes(&self) -> BTreeMap<String, VarNote> {
        return self.vars.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), VarNote { name: v.name.clone(), ty: v.ty.clone() })).collect();
    }

    /// The fields set in another set of notes replace these ones
    pub fn overlay(&mut self, other: &FunctionNotes) {
        if other.name.is_some() {
            self.name = other.name.clone();
        }

        if other.module.is_some() {
            self.module = other.module.clone();
        }

        if other.prototype.is_some() {
            self.prototype = other.prototype.clone();
        }

        if other.summary.is_some() {
            self.summary = other.summary.clone();
        }

        for (var, notes) in other.vars.iter() {
            let entry = self.vars.entry(var.clone()).or_default();

            if notes.name.is_some() {
                entry.name = notes.name.clone();
            }

            if notes.ty.is_some() {
                entry.ty = notes.ty.clone();
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalNotes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl GlobalNotes {
    pub fn is_empty(&self) -> bool {
        return self.name.is_none();
    }
}

/// Modules created by the user (they exist even when they hold no function yet)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModuleList {
    pub modules: Vec<String>,
}

/// Valid module path: relative, made of C-friendly file names
pub fn valid_module(path: &str) -> bool {
    return !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+')));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_round_trip() {
        let mut notes = FunctionNotes { name: Some("parse".to_string()), module: Some("net/socket.c".to_string()), ..Default::default() };
        notes.vars.insert("a1".to_string(), VarNotes { name: Some("text".to_string()), ty: Some("const char *".to_string()) });

        let text = notes.to_toml();
        assert!(text.contains("name = \"parse\""), "{}", text);
        assert_eq!(FunctionNotes::from_toml(&text).unwrap(), notes);
        assert!(FunctionNotes::default().is_empty());

        let mut other = FunctionNotes { summary: Some("Parses.".to_string()), ..Default::default() };
        other.vars.insert("a1".to_string(), VarNotes { name: Some("input".to_string()), ty: None });
        notes.overlay(&other);
        assert_eq!(notes.vars["a1"], VarNotes { name: Some("input".to_string()), ty: Some("const char *".to_string()) });
        assert_eq!(notes.summary.as_deref(), Some("Parses."));
    }

    #[test]
    fn module_paths() {
        assert!(valid_module("net/socket.c"));
        assert!(!valid_module("../x.c"));
        assert!(!valid_module("/abs.c"));
        assert!(!valid_module("a b.c"));
    }
}
