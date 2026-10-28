// SPDX-License-Identifier: Apache-2.0
/*
 * Projects: the whole program decompiled in the background, organized in modules, annotated and
 * edited by the user (and the LLM), kept in a git repository and exported as a source tree
 */

pub mod annotations;
pub mod cache;
pub mod export;
pub mod hash;
pub mod modules;
pub mod project;
pub mod service;
pub mod store;

pub use project::{default_location, default_workers, Project, Proposal, Shown};
pub use service::Priority;
