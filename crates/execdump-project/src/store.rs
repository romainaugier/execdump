/*
 * History of a project, in a bare git repository (libgit2), following the vendor branch pattern:
 * - generated: the C code as the decompiler renders it, only for the functions the user edited
 * - main: the work of the user (annotations, modules, edited functions)
 * - llm/<id>: proposals of the LLM, reviewed before being merged into main
 * Trees are built in memory (no worktree), so the repository only holds what was touched.
 */

use git2::{FileFavor, MergeFileInput, MergeFileOptions, ObjectType, Oid, Patch, Repository, Signature, Tree};

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const MAIN: &str = "main";
pub const GENERATED: &str = "generated";
pub const PROPOSALS: &str = "llm/";

pub struct Store {
    repo: Repository,
}

fn error(e: git2::Error) -> String {
    return e.message().to_string();
}

impl Store {
    pub fn open_or_init(path: &Path) -> Result<Self, String> {
        let repo = match Repository::open_bare(path) {
            Ok(repo) => repo,
            Err(_) => {
                std::fs::create_dir_all(path).map_err(|e| format!("{}: {}", path.display(), e))?;
                let repo = Repository::init_bare(path).map_err(error)?;
                repo.set_head(&format!("refs/heads/{}", MAIN)).map_err(error)?;
                repo
            }
        };

        return Ok(Store { repo });
    }

    pub fn path(&self) -> &Path {
        return self.repo.path();
    }

    pub fn tip(&self, branch: &str) -> Option<Oid> {
        return self.repo.refname_to_id(&format!("refs/heads/{}", branch)).ok();
    }

    fn tree(&self, branch: &str) -> Option<Tree<'_>> {
        return self.tip(branch).and_then(|oid| self.repo.find_commit(oid).ok()).and_then(|c| c.tree().ok());
    }

    pub fn read(&self, branch: &str, path: &str) -> Option<Vec<u8>> {
        let tree = self.tree(branch)?;
        let entry = tree.get_path(Path::new(path)).ok()?;

        return self.repo.find_blob(entry.id()).ok().map(|b| b.content().to_vec());
    }

    /// Every file under a directory of a branch, by path relative to the directory
    pub fn files(&self, branch: &str, dir: &str) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();

        let Some(tree) = self.tree(branch) else {
            return files;
        };

        let dir = dir.trim_end_matches('/');

        let subtree = if dir.is_empty() {
            Some(tree)
        } else {
            tree.get_path(Path::new(dir)).ok().and_then(|e| self.repo.find_tree(e.id()).ok())
        };

        if let Some(subtree) = subtree {
            let _ = subtree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
                if entry.kind() == Some(ObjectType::Blob) {
                    if let (Ok(name), Ok(blob)) = (entry.name(), self.repo.find_blob(entry.id())) {
                        files.insert(format!("{}{}", root, name), blob.content().to_vec());
                    }
                }

                git2::TreeWalkResult::Ok
            });
        }

        return files;
    }

    /// Commits changes (path, new content or None to delete) on a branch, with extra parents
    /// (merged branches). Returns None when nothing changed.
    pub fn commit(&self, branch: &str, changes: &[(String, Option<Vec<u8>>)], message: &str, extra_parents: &[Oid]) -> Result<Option<Oid>, String> {
        let parent = self.tip(branch).map(|oid| self.repo.find_commit(oid)).transpose().map_err(error)?;
        let base = parent.as_ref().map(|c| c.tree()).transpose().map_err(error)?;

        let changes: Vec<(Vec<&str>, Option<&[u8]>)> = changes.iter().map(|(p, c)| (p.split('/').filter(|s| !s.is_empty()).collect(), c.as_deref())).collect();
        let tree = self.write_tree(base.as_ref(), &changes)?;
        let tree = match tree {
            Some(oid) => oid,
            None => self.repo.treebuilder(None).and_then(|b| b.write()).map_err(error)?,
        };

        if base.as_ref().is_some_and(|b| b.id() == tree) && extra_parents.is_empty() {
            return Ok(None);
        }

        let tree = self.repo.find_tree(tree).map_err(error)?;
        let signature = self.signature();
        let mut parents = Vec::new();

        if let Some(parent) = parent {
            parents.push(parent);
        }

        for &oid in extra_parents {
            if let Ok(commit) = self.repo.find_commit(oid) {
                if !parents.iter().any(|p| p.id() == oid) {
                    parents.push(commit);
                }
            }
        }

        let parents: Vec<&git2::Commit> = parents.iter().collect();
        let oid = self.repo.commit(Some(&format!("refs/heads/{}", branch)), &signature, &signature, message, &tree, &parents).map_err(error)?;

        return Ok(Some(oid));
    }

    /// Creates a branch at the tip of another one (replaced if it exists)
    pub fn branch_from(&self, name: &str, from: &str) -> Result<(), String> {
        match self.tip(from) {
            Some(oid) => {
                let commit = self.repo.find_commit(oid).map_err(error)?;
                self.repo.branch(name, &commit, true).map_err(error)?;
            }
            None => {
                let _ = self.repo.find_reference(&format!("refs/heads/{}", name)).and_then(|mut r| r.delete());
            }
        }

        return Ok(());
    }

    pub fn branches(&self, prefix: &str) -> Vec<String> {
        let Ok(branches) = self.repo.branches(Some(git2::BranchType::Local)) else {
            return Vec::new();
        };

        let mut names: Vec<String> = branches.flatten().filter_map(|(b, _)| b.name().ok().flatten().map(|n| n.to_string())).filter(|n| n.starts_with(prefix)).collect();
        names.sort();

        return names;
    }

    pub fn delete_branch(&self, name: &str) {
        if let Ok(mut branch) = self.repo.find_branch(name, git2::BranchType::Local) {
            let _ = branch.delete();
        }
    }

    fn signature(&self) -> Signature<'static> {
        let config = self.repo.config().ok();
        let get = |key: &str| config.as_ref().and_then(|c| c.get_string(key).ok());

        let name = get("user.name").unwrap_or_else(|| std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "execdump".to_string()));
        let email = get("user.email").unwrap_or_else(|| "execdump@localhost".to_string());

        return Signature::now(&name, &email).unwrap_or_else(|_| Signature::now("execdump", "execdump@localhost").unwrap());
    }

    /// Writes a tree with the changes applied to a base tree, None when it ends up empty
    fn write_tree(&self, base: Option<&Tree>, changes: &[(Vec<&str>, Option<&[u8]>)]) -> Result<Option<Oid>, String> {
        let mut builder = self.repo.treebuilder(base).map_err(error)?;
        let mut subdirs: BTreeMap<&str, Vec<(Vec<&str>, Option<&[u8]>)>> = BTreeMap::new();

        for (path, content) in changes {
            match path.as_slice() {
                [] => {}
                [name] => match content {
                    Some(content) => {
                        let blob = self.repo.blob(content).map_err(error)?;
                        builder.insert(name, blob, 0o100644).map_err(error)?;
                    }
                    None => {
                        if builder.get(name).map_err(error)?.is_some() {
                            builder.remove(name).map_err(error)?;
                        }
                    }
                },
                [dir, rest @ ..] => subdirs.entry(dir).or_default().push((rest.to_vec(), *content)),
            }
        }

        for (dir, changes) in subdirs {
            let existing = builder.get(dir).map_err(error)?.filter(|e| e.kind() == Some(ObjectType::Tree)).map(|e| e.id());
            let subtree = existing.map(|oid| self.repo.find_tree(oid)).transpose().map_err(error)?;

            match self.write_tree(subtree.as_ref(), &changes)? {
                Some(oid) => {
                    builder.insert(dir, oid, 0o040000).map_err(error)?;
                }
                None => {
                    if builder.get(dir).map_err(error)?.is_some() {
                        builder.remove(dir).map_err(error)?;
                    }
                }
            }
        }

        if builder.len() == 0 {
            return Ok(None);
        }

        return builder.write().map(Some).map_err(error);
    }
}

/*
 * Text helpers (libgit2's diff and merge on buffers, no repository needed)
 */

pub const CONFLICT_START: &str = "<<<<<<< edited";
pub const CONFLICT_MIDDLE: &str = "=======";
pub const CONFLICT_END: &str = ">>>>>>> decompiled";

/// Merges the edits of a text (ours, made on base) with a new version of the base (theirs).
/// Returns the merged text and whether it has conflicts (marked as in git).
pub fn merge_text(base: &str, ours: &str, theirs: &str) -> (String, bool) {
    let mut ancestor = MergeFileInput::new();
    ancestor.content(base.as_bytes());
    let mut edited = MergeFileInput::new();
    edited.content(ours.as_bytes());
    let mut decompiled = MergeFileInput::new();
    decompiled.content(theirs.as_bytes());

    let mut options = MergeFileOptions::new();
    options.our_label("edited").their_label("decompiled").favor(FileFavor::Normal);

    match git2::merge_file(&ancestor, &edited, &decompiled, Some(&mut options)) {
        Ok(result) => (String::from_utf8_lossy(result.content()).into_owned(), !result.is_automergeable()),
        Err(_) => (ours.to_string(), true),
    }
}

/// Merges the edits of a text into a new version of its base. When the new version only renames
/// identifiers (the most common change: a function or a variable was named), the renames are applied
/// to the edited text, otherwise the texts are merged by lines.
pub fn rebase_text(base: &str, ours: &str, theirs: &str) -> (String, bool) {
    if let Some(renames) = renames(base, theirs) {
        return (rename_identifiers(ours, &renames), false);
    }

    let (merged, conflict) = merge_text(base, ours, theirs);

    // libgit2 can report a conflict without marking it: the whole function is the conflict then
    if conflict && !has_conflicts(&merged) {
        return (format!("{}\n{}{}\n{}{}\n", CONFLICT_START, ours, CONFLICT_MIDDLE, theirs, CONFLICT_END), true);
    }

    return (merged, conflict);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Ident(&'a str),
    Other(&'a str),
}

/// C tokens of a text, without the comments and the white space (strings are single tokens)
fn tokens(text: &str) -> Vec<(usize, Token<'_>)> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        let start = i;

        if c.is_ascii_whitespace() {
            i += 1;
        } else if text[i..].starts_with("//") {
            i = text[i..].find('\n').map_or(bytes.len(), |n| i + n);
        } else if text[i..].starts_with("/*") {
            i = text[i + 2..].find("*/").map_or(bytes.len(), |n| i + n + 4);
        } else if c == b'"' || c == b'\'' {
            i += 1;

            while i < bytes.len() && bytes[i] != c && bytes[i] != b'\n' {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }

            i = (i + 1).min(bytes.len());
            tokens.push((start, Token::Other(&text[start..i])));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }

            tokens.push((start, Token::Ident(&text[start..i])));
        } else {
            i += text[i..].chars().next().map_or(1, |c| c.len_utf8());

            // Numbers are single tokens
            if c.is_ascii_digit() {
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'.') {
                    i += 1;
                }
            }

            tokens.push((start, Token::Other(&text[start..i])));
        }
    }

    return tokens;
}

/// The identifiers renamed between two texts, when it is the only difference
fn renames(old: &str, new: &str) -> Option<HashMap<String, String>> {
    let (old, new) = (tokens(old), tokens(new));

    if old.len() != new.len() {
        return None;
    }

    let mut renames: HashMap<String, String> = HashMap::new();

    for ((_, a), (_, b)) in old.iter().zip(new.iter()) {
        match (a, b) {
            (Token::Ident(a), Token::Ident(b)) if a != b => {
                if renames.insert(a.to_string(), b.to_string()).is_some_and(|previous| previous != *b) {
                    return None;
                }
            }
            (Token::Ident(a), Token::Ident(_)) => {
                // An identifier both kept and renamed is not a rename
                if renames.get(*a).is_some_and(|r| r != a) {
                    return None;
                }

                renames.insert(a.to_string(), a.to_string());
            }
            (a, b) if a == b => {}
            _ => return None,
        }
    }

    renames.retain(|a, b| a != b);
    return Some(renames);
}

fn rename_identifiers(text: &str, renames: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;

    for (start, token) in tokens(text) {
        if let Token::Ident(name) = token {
            if let Some(new) = renames.get(name) {
                out.push_str(&text[last..start]);
                out.push_str(new);
                last = start + name.len();
            }
        }
    }

    out.push_str(&text[last..]);
    return out;
}

pub fn has_conflicts(text: &str) -> bool {
    return text.lines().any(|l| l.starts_with(CONFLICT_START));
}

/// Unified diff of two texts (empty when they are equal)
pub fn diff_text(old: &str, new: &str, path: &str) -> String {
    let patch = Patch::from_buffers(old.as_bytes(), Some(Path::new(path)), new.as_bytes(), Some(Path::new(path)), None);

    return patch.and_then(|mut p| p.to_buf()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
}

/// Address of the lines of an edited text: the unchanged lines keep the address of their line in the base
pub fn map_lines(base: &str, base_lines: &[Option<u64>], text: &str) -> Vec<Option<u64>> {
    let count = text.lines().count();
    let mut lines = vec![None; count];

    let Ok(patch) = Patch::from_buffers(base.as_bytes(), None, text.as_bytes(), None, None) else {
        return lines;
    };

    // Lines between the hunks are unchanged: walk both texts in step, skipping the hunks
    let (mut old, mut new) = (0usize, 0usize);

    for h in 0..patch.num_hunks() {
        let Ok((hunk, _)) = patch.hunk(h) else {
            continue;
        };

        let (old_start, new_start) = ((hunk.old_start() as usize).saturating_sub(1), (hunk.new_start() as usize).saturating_sub(1));

        while new < new_start.min(count) {
            lines[new] = base_lines.get(old).copied().flatten();
            old += 1;
            new += 1;
        }

        // Context lines inside the hunk are unchanged too
        if let Ok(line_count) = patch.num_lines_in_hunk(h) {
            for l in 0..line_count {
                let Ok(line) = patch.line_in_hunk(h, l) else {
                    continue;
                };

                match (line.old_lineno(), line.new_lineno()) {
                    (Some(o), Some(n)) if (n as usize) <= count => lines[n as usize - 1] = base_lines.get(o as usize - 1).copied().flatten(),
                    _ => {}
                }
            }
        }

        old = old_start + hunk.old_lines() as usize;
        new = new_start + hunk.new_lines() as usize;
    }

    while new < count {
        lines[new] = base_lines.get(old).copied().flatten();
        old += 1;
        new += 1;
    }

    return lines;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_and_files() {
        let dir = std::env::temp_dir().join(format!("execdump-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_or_init(&dir).unwrap();

        let first = store.commit(MAIN, &[("fn/1000.toml".to_string(), Some(b"name = \"f\"\n".to_vec())), ("modules.toml".to_string(), Some(b"modules = []\n".to_vec()))], "first", &[]).unwrap();
        assert!(first.is_some());

        // Nothing changed: no commit
        assert_eq!(store.commit(MAIN, &[("modules.toml".to_string(), Some(b"modules = []\n".to_vec()))], "same", &[]).unwrap(), None);

        store.branch_from("llm/1", MAIN).unwrap();
        store.commit("llm/1", &[("fn/2000.toml".to_string(), Some(b"name = \"g\"\n".to_vec()))], "proposal", &[]).unwrap();
        assert_eq!(store.branches(PROPOSALS), ["llm/1"]);

        let tip = store.tip("llm/1").unwrap();
        store.commit(MAIN, &[("fn/1000.toml".to_string(), None), ("fn/2000.toml".to_string(), Some(b"name = \"g\"\n".to_vec()))], "accept", &[tip]).unwrap();
        store.delete_branch("llm/1");

        let files = store.files(MAIN, "fn");
        assert_eq!(files.keys().collect::<Vec<_>>(), ["2000.toml"]);
        assert_eq!(store.read(MAIN, "modules.toml").unwrap(), b"modules = []\n");
        assert!(store.branches(PROPOSALS).is_empty());

        // Reopening finds everything back
        drop(store);
        let store = Store::open_or_init(&dir).unwrap();
        assert_eq!(store.read(MAIN, "fn/2000.toml").unwrap(), b"name = \"g\"\n");
        assert!(store.read(GENERATED, "fn/2000.c").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merges() {
        let base = "int f(int a1)\n{\n    int v1;\n\n    v1 = g(a1);\n    return v1;\n}\n";
        let ours = "int f(int a1)\n{\n    int v1;\n\n    // the result of g\n    v1 = g(a1);\n    return v1;\n}\n";
        let theirs = "int f(int a1)\n{\n    int count;\n\n    count = g(a1);\n    return count;\n}\n";

        // Renames are applied to the edited text, comments and strings are left alone
        let (merged, conflict) = rebase_text(base, ours, theirs);
        assert!(!conflict, "{}", merged);
        assert_eq!(merged, "int f(int a1)\n{\n    int count;\n\n    // the result of g\n    count = g(a1);\n    return count;\n}\n");

        let (merged, _) = rebase_text("f(v1, \"v1\");\n", "f(v1, \"v1\"); // v1\n", "f(n, \"v1\");\n");
        assert_eq!(merged, "f(n, \"v1\"); // v1\n");

        let ours = "int f(int a1)\n{\n    int v1;\n\n    v1 = h(a1);\n    return v1;\n}\n";
        let (merged, conflict) = rebase_text(base, ours, theirs);
        assert!(!conflict);
        assert_eq!(merged, "int f(int a1)\n{\n    int count;\n\n    count = h(a1);\n    return count;\n}\n");

        // Other changes are merged by lines
        let theirs = "int f(int a1)\n{\n    int v1;\n\n    v1 = g(a1 + 1);\n    return v1;\n}\n";
        let (merged, conflict) = rebase_text(base, ours, theirs);
        assert!(conflict);
        assert!(has_conflicts(&merged), "{}", merged);
        assert!(merged.contains(CONFLICT_END), "{}", merged);

        let theirs = "int f(int a1)\n{\n    int v1;\n\n    v1 = g(a1);\n    v1 += 1;\n    return v1;\n}\n";
        let ours = "// comment\nint f(int a1)\n{\n    int v1;\n\n    v1 = g(a1);\n    return v1;\n}\n";
        let (merged, conflict) = rebase_text(base, ours, theirs);
        assert!(!conflict);
        assert_eq!(merged, "// comment\nint f(int a1)\n{\n    int v1;\n\n    v1 = g(a1);\n    v1 += 1;\n    return v1;\n}\n");

        let renamed = "int f(int a1)\n{\n    int count;\n\n    count = g(a1);\n    return count;\n}\n";
        let diff = diff_text(base, renamed, "fn/1000.c");
        assert!(diff.contains("-    int v1;\n+    int count;"), "{}", diff);
        assert!(diff_text(base, base, "x").is_empty());
    }

    #[test]
    fn line_addresses() {
        let base = "a\nb\nc\nd\n";
        let lines = [Some(1), Some(2), None, Some(4)];

        assert_eq!(map_lines(base, &lines, "a\nnew\nb\nc\nd\n"), [Some(1), None, Some(2), None, Some(4)]);
        assert_eq!(map_lines(base, &lines, "a\nc\nd\n"), [Some(1), None, Some(4)]);
        assert_eq!(map_lines(base, &lines, base), lines);
    }
}
