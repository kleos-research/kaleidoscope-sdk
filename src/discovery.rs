//! Vault discovery for `kaleidoscope init`.
//!
//! Before this module existed, `init --root <an existing vault>` returned rc=0
//! and `"status":"initialized"` while FORKING the vault: `init-profile` on a
//! root that already holds a workspace does not fail, it succeeds and adds a
//! second one. Measured 2026-08-26 on a real engine:
//!
//! the vault held ONE workspace before, and TWO after -- the original plus a
//! second one the manager never asked for. (The real coordinates are not
//! reproduced here: `scripts/poison_scan.py` refuses a raw vault identity in
//! any source file, and it refused this comment.)
//!
//! And the fork removes the recovery path: `kscope profile import` then refuses
//! with "vault has 2 workspaces; select an explicit workspace instead of
//! importing" (rc=2). The engine's own adopt path does the right thing on the
//! same vault -- `profile import` reuses the existing workspace and leaves the
//! count at 1 -- the manager simply never called it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::Result;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const ROOT_MANIFEST_SCHEMA: &str = "filesystem.root-manifest";

/// What one candidate directory is, as far as a read-only probe can tell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Candidate {
    NotAVault,
    Vault { root: PathBuf, workspaces: usize },
}

/// Which discovery rule produced a candidate. Carried into the refusal so an
/// ambiguous result can say WHERE each vault came from, not merely that there
/// were several.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryRule {
    ExplicitRoot,
    RegisteredProfile,
    DefaultRoot,
    ProjectLocal,
    UserVaultDirectory,
}

impl DiscoveryRule {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitRoot => "--root",
            Self::RegisteredProfile => "registered profile",
            Self::DefaultRoot => "default root",
            Self::ProjectLocal => "<project>/.kaleidoscope",
            Self::UserVaultDirectory => "user vault directory",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundVault {
    pub rule: DiscoveryRule,
    pub detail: Option<String>,
    pub root: PathBuf,
    pub workspaces: usize,
}

/// This probe DISCOVERS. It never DECIDES.
///
/// It answers one question -- "is this directory worth offering to the engine"
/// -- and its `workspaces` count is for the operator's eyes, so a refusal can
/// name the number. The identity decision is `kscope profile import`, which
/// refuses "profile root is not a Kaleidoscope vault" (rc=2, nothing written)
/// and "vault has 2 workspaces; select an explicit workspace instead of
/// importing" (rc=2). If this probe and the engine ever disagree, the ENGINE is
/// right and this function is wrong: report the engine's message verbatim and
/// never fall back to creating.
///
/// `kscope vault-preview` is not usable here: it requires the directory to be
/// named exactly `.kaleidoscope` and refuses anything else with
/// "whole-vault lifecycle commands require an exact .kaleidoscope directory".
#[must_use]
pub fn probe(root: &Path) -> Candidate {
    if !root.is_absolute() {
        return Candidate::NotAVault;
    }
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Candidate::NotAVault,
    }
    let manifest = root.join("manifest.json");
    match fs::symlink_metadata(&manifest) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_MANIFEST_BYTES => {}
        _ => return Candidate::NotAVault,
    }
    let Ok(bytes) = fs::read(&manifest) else {
        return Candidate::NotAVault;
    };
    let Ok(document) = serde_json::from_slice::<Value>(&bytes) else {
        return Candidate::NotAVault;
    };
    if document["schema_name"] != ROOT_MANIFEST_SCHEMA {
        return Candidate::NotAVault;
    }
    Candidate::Vault {
        root: root.to_path_buf(),
        workspaces: count_workspaces(root),
    }
}

fn count_workspaces(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root.join("workspaces")) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with("wsp_")
                && entry.file_type().is_ok_and(|kind| kind.is_dir())
        })
        .count()
}

/// De-duplicating collector: candidates are keyed by canonicalised absolute
/// path, so the same vault reached by two rules is one candidate, reported
/// under the first rule that found it.
#[derive(Debug, Default)]
pub struct CandidateSet {
    seen: BTreeSet<PathBuf>,
    found: Vec<FoundVault>,
}

impl CandidateSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn offer(&mut self, rule: DiscoveryRule, detail: Option<String>, root: &Path) {
        let key = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if self.seen.contains(&key) {
            return;
        }
        if let Candidate::Vault { root, workspaces } = probe(&key) {
            self.seen.insert(key);
            self.found.push(FoundVault {
                rule,
                detail,
                root,
                workspaces,
            });
        } else {
            // Remember the miss too, so a non-vault path is not re-probed by a
            // later rule that names the same directory.
            self.seen.insert(key);
        }
    }

    #[must_use]
    pub fn into_found(self) -> Vec<FoundVault> {
        self.found
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.found.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.found.is_empty()
    }
}

/// Immediate child directories of `directory`, sorted, bounded. Used by the
/// user-vault-directory rule.
pub fn child_directories(directory: &Path) -> Result<Vec<PathBuf>> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(Vec::new());
    };
    let mut children = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    children.sort();
    Ok(children)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn write_manifest(root: &Path, schema: &str) {
        fs::create_dir_all(root.join("workspaces")).unwrap();
        fs::write(
            root.join("manifest.json"),
            format!("{{\"schema_name\":\"{schema}\",\"schema_version\":1}}"),
        )
        .unwrap();
    }

    /// T-B8: four distinct negatives, so a probe that returned `NotAVault`
    /// unconditionally could not also satisfy `probe_counts_workspaces`.
    #[test]
    fn the_probe_classifies_a_non_vault_correctly() {
        let temp = TempDir::new().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();

        let empty = base.join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert_eq!(probe(&empty), Candidate::NotAVault, "empty directory");

        let wrong = base.join("wrong-schema");
        write_manifest(&wrong, "filesystem.something-else");
        assert_eq!(probe(&wrong), Candidate::NotAVault, "wrong schema_name");

        let directory_manifest = base.join("manifest-is-a-directory");
        fs::create_dir_all(directory_manifest.join("manifest.json")).unwrap();
        assert_eq!(
            probe(&directory_manifest),
            Candidate::NotAVault,
            "manifest.json is a directory"
        );

        let real = base.join("real");
        write_manifest(&real, ROOT_MANIFEST_SCHEMA);
        let linked = base.join("linked");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        #[cfg(unix)]
        assert_eq!(probe(&linked), Candidate::NotAVault, "symlinked directory");

        let relative = Path::new("relative/path");
        assert_eq!(probe(relative), Candidate::NotAVault, "relative path");
    }

    #[test]
    fn probe_counts_workspaces_and_ignores_other_entries() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("vault");
        write_manifest(&root, ROOT_MANIFEST_SCHEMA);
        fs::create_dir_all(root.join("workspaces/wsp_one")).unwrap();
        fs::create_dir_all(root.join("workspaces/wsp_two")).unwrap();
        fs::create_dir_all(root.join("workspaces/not-a-workspace")).unwrap();
        fs::write(root.join("workspaces/wsp_a_file"), "x").unwrap();
        assert_eq!(
            probe(&root),
            Candidate::Vault {
                root: root.clone(),
                workspaces: 2
            }
        );
    }

    #[test]
    fn the_candidate_set_deduplicates_by_canonical_path() {
        let temp = TempDir::new().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("vault");
        write_manifest(&root, ROOT_MANIFEST_SCHEMA);
        fs::create_dir_all(root.join("workspaces/wsp_one")).unwrap();

        let mut set = CandidateSet::new();
        set.offer(DiscoveryRule::ExplicitRoot, None, &root);
        set.offer(DiscoveryRule::DefaultRoot, None, &root);
        assert_eq!(set.len(), 1);
        let found = set.into_found();
        assert_eq!(found[0].rule, DiscoveryRule::ExplicitRoot);
        assert_eq!(found[0].workspaces, 1);
    }
}
