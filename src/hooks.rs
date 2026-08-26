//! The Claude Code `SessionStart` hook.
//!
//! WHAT THIS HOOK DELIBERATELY IS NOT
//!
//! It does not call `search`, `remember`, or any gated engine command. Three
//! reasons, all of which have to survive the next reader:
//!
//!  1. `search` writes an exposure row on every call -- `ledger` defaults true
//!     and `ledger: false` is REFUSED rather than silently upgraded. A hook
//!     that fires on every session start, resume, clear and compact would write
//!     to the user's vault on each, without the user having asked for a read.
//!  2. At `SessionStart` there is no user prompt yet, so there is no query to
//!     rank against. A generic project-scoped search is retrieval with nothing
//!     to retrieve for.
//!  3. A gated call can refuse for entitlement reasons, and a hook that fails
//!     is a hook the harness reports as broken at the top of every session.
//!
//! Automatic retrieval on `UserPromptSubmit` is a SEPARATE decision that needs
//! a measurement -- latency per prompt, exposure-row volume, retrieval quality
//! with no top-k tuning -- and is explicitly out of scope for v1. It is written
//! down here so the next reader does not re-derive the three reasons above.
//!
//! WHY A HOOK AT ALL, GIVEN CLAUDE.md
//!
//! `CLAUDE.md` is read once at session start. A `SessionStart` hook fires on
//! `startup`, `resume`, `clear` AND `compact` -- so the instruction survives
//! compaction. That is the whole justification.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{project_root, user_home};
use crate::engine::Engine;
use crate::error::{ManagerError, Result};
use crate::fs_safe::{
    FileLock, Snapshot, assert_unchanged, atomic_remove, atomic_write, digest_bytes, read_snapshot,
    prune_empty_managed_directories, restore_snapshot, sibling_path, write_bounded_backup,
};
use crate::host::Scope;
use crate::instructions::RestoreTier;
use crate::model::validate_profile_name;

const OWNER: &str = "kaleidoscope-manager-v1";
const RECEIPT_VERSION: u32 = 1;
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const EVENT: &str = "SessionStart";
const MATCHER: &str = "startup|resume|clear|compact";
const HOOK_TIMEOUT_SECONDS: u64 = 10;
/// The hook bounds its own stdout. A hook that floods the session context is a
/// hook the user turns off.
const MAX_HOOK_OUTPUT_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    Add,
    Update,
    Remove,
    AlreadyInstalled,
    AlreadyRemoved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookReceipt {
    version: u32,
    owner: String,
    scope: Scope,
    profile: String,
    /// The exact array element the manager added. Removal matches on canonical
    /// JSON equality against this -- `settings.json` is JSON, so there is no
    /// comment marker to own bytes with.
    owned: Value,
    owned_sha256: String,
    pre_sha256: String,
    post_sha256: String,
    file_created: bool,
}

impl HookReceipt {
    fn validate(&self, scope: Scope) -> Result<()> {
        if self.version != RECEIPT_VERSION
            || self.owner != OWNER
            || self.scope != scope
            || validate_profile_name(&self.profile).is_err()
            || !self.owned.is_object()
            || self.owned_sha256 != canonical_digest(&self.owned)?
        {
            return Err(ManagerError::InvalidOwnerReceipt);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| ManagerError::InvalidOwnerReceipt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct HookPlan {
    pub scope: Scope,
    pub action: HookAction,
    pub target: PathBuf,
    pub receipt_path: PathBuf,
    pub backup_path: PathBuf,
    pub restore: Option<RestoreTier>,
    preview: String,
    original: Snapshot,
    receipt_original: Snapshot,
    updated: Option<Vec<u8>>,
    receipt_after: Option<HookReceipt>,
    remove_backup: bool,
}

impl HookPlan {
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }

    #[must_use]
    pub const fn is_noop(&self) -> bool {
        matches!(
            self.action,
            HookAction::AlreadyInstalled | HookAction::AlreadyRemoved
        )
    }

    pub fn apply(&self) -> Result<()> {
        if self.is_noop() {
            return Ok(());
        }
        // Named, not `_lock`: it is dropped explicitly below so the prune can
        // see an empty directory, and clippy rejects using an underscore binding.
        let lock = FileLock::acquire(&self.target)?;
        assert_unchanged(
            &self.target,
            &self.original,
            MAX_SETTINGS_BYTES,
            "harness settings",
        )?;
        assert_unchanged(
            &self.receipt_path,
            &self.receipt_original,
            MAX_RECEIPT_BYTES,
            "hook owner receipt",
        )?;
        // NOT written on a removal, and that is the fix for two defects at
        // once.
        //
        // `self.restore.is_some()` is exactly "this plan is undoing an install".
        // On that branch `self.original` is the file AS THE MANAGER LEFT IT, so
        // writing a backup here OVERWROTE the pre-install backup with
        // post-install content -- destroying the user's only copy of their
        // original file, while `remove_backup`'s comment two screens down still
        // asserted the backup was that copy. And on the branch where the
        // manager CREATED the file, no backup existed at install time (there
        // were no bytes to save), so this call MINTED one during teardown and
        // nothing ever deleted it: a stray dotfile naming the profile and the
        // engine path, left in the user's project by the command whose whole
        // job is to leave nothing.
        //
        // Nothing depends on a backup during removal. `atomic_write` is
        // temp-file-plus-rename and `atomic_remove` is a single unlink, so
        // neither can leave a half-written file, and the error path restores
        // from `self.original` in memory rather than from disk.
        if self.restore.is_none() {
            write_bounded_backup(&self.target, &self.original)?;
        }
        match self.updated.as_deref() {
            Some(bytes) => {
                atomic_write(&self.target, bytes, self.original.unix_mode.or(Some(0o600)))?;
            }
            None => atomic_remove(&self.target)?,
        }
        let receipt_result = match &self.receipt_after {
            Some(receipt) => atomic_write(&self.receipt_path, &receipt.encode()?, Some(0o600)),
            None => atomic_remove(&self.receipt_path),
        };
        if let Err(error) = receipt_result {
            restore_snapshot(&self.target, &self.original)?;
            return Err(error);
        }
        if self.remove_backup {
            atomic_remove(&self.backup_path)?;
        }
        // Remove a directory the manager created and has just emptied.
        //
        // The lock must go FIRST: `FileLock` lives beside the target as
        // `<file>.kaleidoscope-lock` and is only unlinked on drop, so pruning
        // while it is held finds a directory that is never empty.
        drop(lock);
        if self.updated.is_none() {
            prune_empty_managed_directories(&self.target);
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self, dry_run: bool) -> Value {
        let mut value = json!({
            "version": 1,
            "status": if dry_run { "dry_run" } else if self.is_noop() { "unchanged" } else { "applied" },
            "action": self.action,
            "event": EVENT,
            "scope": self.scope,
            "target": self.target,
            "owner_receipt": self.receipt_path,
            "backup": self.backup_path,
        });
        if let Some(restore) = self.restore {
            value["restore"] = json!(restore);
        }
        value
    }
}

/// `.claude/settings.json` (project) or `~/.claude/settings.json` (user).
///
/// NOT `.claude/settings.local.json`. The local file is the personal,
/// gitignored one; a hook the manager installs on behalf of a project belongs
/// in the shareable `settings.json`, and `--scope user` covers the personal
/// case. (MCP *approval* does live in `settings.local.json` -- that is a
/// different key in a different file and does not apply here.)
pub fn settings_path(scope: Scope, explicit_project: Option<&Path>) -> Result<PathBuf> {
    Ok(match scope {
        Scope::User => user_home()?.join(".claude").join("settings.json"),
        Scope::Project => project_root(explicit_project)?
            .join(".claude")
            .join("settings.json"),
    })
}

#[must_use]
pub fn owned_entry(manager: &Path, profile: &str) -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": format!("{} hook session-start --profile {profile}", manager.display()),
            "timeout": HOOK_TIMEOUT_SECONDS,
        }],
    })
}

pub fn plan_install(
    scope: Scope,
    manager: &Path,
    profile: &str,
    explicit_project: Option<&Path>,
) -> Result<HookPlan> {
    plan_install_at(scope, manager, profile, &settings_path(scope, explicit_project)?)
}

pub fn plan_remove(scope: Scope, explicit_project: Option<&Path>, force: bool) -> Result<HookPlan> {
    plan_remove_at(scope, &settings_path(scope, explicit_project)?, force)
}

pub fn plan_install_at(
    scope: Scope,
    manager: &Path,
    profile: &str,
    target: &Path,
) -> Result<HookPlan> {
    validate_profile_name(profile)?;
    let receipt_path = sibling_path(target, ".kaleidoscope-owner.json")?;
    let backup_path = sibling_path(target, ".kaleidoscope-backup")?;
    let original = read_snapshot(target, MAX_SETTINGS_BYTES, "harness settings")?;
    let receipt_original = read_snapshot(&receipt_path, MAX_RECEIPT_BYTES, "hook owner receipt")?;
    let receipt = decode_receipt(&receipt_original, scope)?;
    let mut document = parse_settings(&original)?;
    let desired = owned_entry(manager, profile);

    let matches = matching_indices(&document, receipt.as_ref().map(|r| &r.owned))?;
    let resembling = resembling_indices(&document, &desired)?;

    let action = match (matches.len(), resembling.len()) {
        (0, 0) => HookAction::Add,
        (1, _) => {
            if entry_at(&document, matches[0])? == desired {
                return Ok(noop_plan(
                    scope,
                    HookAction::AlreadyInstalled,
                    target.to_path_buf(),
                    receipt_path,
                    backup_path,
                    original,
                    receipt_original,
                ));
            }
            HookAction::Update
        }
        // Zero exact matches but an element carries our exact command with
        // different surrounding fields: a user-edited copy. Refuse, name it.
        (0, _) => {
            return Err(ManagerError::HostConflict(format!(
                "{} already carries a SessionStart entry running this manager with different surrounding fields; remove it by hand or re-run with --force",
                target.display()
            )));
        }
        // More than one exact match. Never remove "the first one".
        _ => {
            return Err(ManagerError::HostConflict(format!(
                "{} carries {} identical manager-owned SessionStart entries; refusing to guess which one is ours",
                target.display(),
                matches.len()
            )));
        }
    };

    match action {
        HookAction::Add => push_entry(&mut document, desired.clone())?,
        HookAction::Update => replace_entry(&mut document, matches[0], desired.clone())?,
        _ => unreachable!("only Add and Update reach here"),
    }
    let updated = encode_settings(&document)?;
    let pre_sha256 = receipt
        .as_ref()
        .map_or_else(|| original.sha256.clone(), |r| r.pre_sha256.clone());
    let file_created = receipt
        .as_ref()
        .map_or(original.bytes.is_none(), |r| r.file_created);
    Ok(HookPlan {
        scope,
        action,
        preview: format!(
            "Install the Kaleidoscope {EVENT} hook in {}\nEntry:\n{}",
            target.display(),
            serde_json::to_string_pretty(&desired).unwrap_or_default()
        ),
        target: target.to_path_buf(),
        receipt_path,
        backup_path,
        restore: None,
        original,
        receipt_original,
        updated: Some(updated.clone()),
        receipt_after: Some(HookReceipt {
            version: RECEIPT_VERSION,
            owner: OWNER.to_owned(),
            scope,
            profile: profile.to_owned(),
            owned_sha256: canonical_digest(&desired)?,
            owned: desired,
            pre_sha256,
            post_sha256: digest_bytes(&updated),
            file_created,
        }),
        remove_backup: false,
    })
}

pub fn plan_remove_at(scope: Scope, target: &Path, force: bool) -> Result<HookPlan> {
    let receipt_path = sibling_path(target, ".kaleidoscope-owner.json")?;
    let backup_path = sibling_path(target, ".kaleidoscope-backup")?;
    let original = read_snapshot(target, MAX_SETTINGS_BYTES, "harness settings")?;
    let receipt_original = read_snapshot(&receipt_path, MAX_RECEIPT_BYTES, "hook owner receipt")?;
    let Some(receipt) = decode_receipt(&receipt_original, scope)? else {
        return Ok(noop_plan(
            scope,
            HookAction::AlreadyRemoved,
            target.to_path_buf(),
            receipt_path,
            backup_path,
            original,
            receipt_original,
        ));
    };
    let mut document = parse_settings(&original)?;
    let matches = matching_indices(&document, Some(&receipt.owned))?;
    match matches.len() {
        0 => {
            let resembling = resembling_indices(&document, &receipt.owned)?;
            if resembling.is_empty() {
                return Ok(noop_plan(
                    scope,
                    HookAction::AlreadyRemoved,
                    target.to_path_buf(),
                    receipt_path,
                    backup_path,
                    original,
                    receipt_original,
                ));
            }
            if !force {
                return Err(ManagerError::HostConflict(format!(
                    "the {EVENT} entry in {} has been hand-edited and no longer matches its owner receipt; re-run with --force to remove it",
                    target.display()
                )));
            }
            remove_entry(&mut document, resembling[0])?;
        }
        1 => remove_entry(&mut document, matches[0])?,
        count => {
            return Err(ManagerError::HostConflict(format!(
                "{} carries {count} identical manager-owned {EVENT} entries; refusing to remove the first one",
                target.display()
            )));
        }
    }

    // Tier 1: the file is byte-for-byte what the manager wrote, and either the
    // manager created it or the backup holds exactly the pre-install bytes.
    let backup = read_snapshot(&backup_path, MAX_SETTINGS_BYTES, "settings backup")?;
    let file_is_ours = original.sha256 == receipt.post_sha256;
    let backup_is_pre = backup.bytes.is_some() && backup.sha256 == receipt.pre_sha256;
    if file_is_ours && (receipt.file_created || backup_is_pre) {
        let (updated, remove_backup) = if receipt.file_created {
            // The manager created this file, so the pre-install state is
            // ABSENCE. Any backup here holds manager-written bytes, never the
            // user's -- including the one `apply` writes on its way out.
            (None, true)
        } else {
            (backup.bytes.clone(), true)
        };
        return Ok(HookPlan {
            scope,
            action: HookAction::Remove,
            preview: format!(
                "Remove the Kaleidoscope {EVENT} hook from {} (exact restore)",
                target.display()
            ),
            target: target.to_path_buf(),
            receipt_path,
            backup_path,
            restore: Some(RestoreTier::ByteIdentical),
            original,
            receipt_original,
            updated,
            receipt_after: None,
            remove_backup,
        });
    }

    let updated = if receipt.file_created && is_empty_shell(&document) {
        None
    } else {
        Some(encode_settings(&document)?)
    };
    Ok(HookPlan {
        scope,
        action: HookAction::Remove,
        preview: format!(
            "Remove the Kaleidoscope {EVENT} hook from {} (structural restore; formatting normalized)",
            target.display()
        ),
        target: target.to_path_buf(),
        receipt_path,
        backup_path,
        restore: Some(RestoreTier::Structural),
        original,
        receipt_original,
        updated,
        receipt_after: None,
        remove_backup: false,
    })
}

/// The hook body. Runs `kscope profile launch NAME`, which is UNGATED, and
/// emits the reminder. Exits 0 always: a hook that exits non-zero is a hook the
/// user turns off, and a broken memory configuration should be VISIBLE, not
/// fatal.
#[must_use]
pub fn session_start_output(
    engine: std::result::Result<&Engine, &ManagerError>,
    profile: &str,
) -> String {
    let context = match engine {
        Ok(engine) => match engine.profile_launch(profile) {
            Ok(_) => format!(
                "Kaleidoscope memory is connected (profile: {profile}). For nontrivial tasks, read and follow .claude/skills/use-kaleidoscope/SKILL.md before using it. Use only the public `search` and `remember` tools."
            ),
            Err(error) => format!(
                "Kaleidoscope memory is configured but not usable (profile: {profile}): {error}. Run `kaleidoscope doctor --json`."
            ),
        },
        // The REASON travels. This arm took an `Option` and printed only "the
        // engine could not be resolved", which reads as "not installed" -- and
        // the case that produced it most often was an engine that WAS found and
        // then rejected, so the hook pointed the user at the wrong problem. The
        // sibling arm one screen up has always interpolated its error; this one
        // threw its away because `main.rs` called `Engine::resolve(..).ok()`.
        Err(error) => format!(
            "Kaleidoscope memory is configured but the engine could not be resolved (profile: {profile}): {error}. Run `kaleidoscope doctor --json`."
        ),
    };
    let mut line = serde_json::to_string(&json!({
        "hookSpecificOutput": {
            "hookEventName": EVENT,
            "additionalContext": context,
        }
    }))
    .unwrap_or_default();
    if line.len() > MAX_HOOK_OUTPUT_BYTES {
        line = serde_json::to_string(&json!({
            "hookSpecificOutput": {
                "hookEventName": EVENT,
                "additionalContext": format!(
                    "Kaleidoscope memory: profile {profile} could not be validated. Run `kaleidoscope doctor --json`."
                ),
            }
        }))
        .unwrap_or_default();
    }
    line
}

fn decode_receipt(snapshot: &Snapshot, scope: Scope) -> Result<Option<HookReceipt>> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(None);
    };
    let receipt: HookReceipt =
        serde_json::from_slice(bytes).map_err(|_| ManagerError::InvalidOwnerReceipt)?;
    receipt.validate(scope)?;
    Ok(Some(receipt))
}

fn parse_settings(snapshot: &Snapshot) -> Result<Value> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(json!({}));
    };
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|_| ManagerError::InvalidHostConfig("settings.json is not valid JSON".to_owned()))?;
    if !document.is_object() {
        return Err(ManagerError::InvalidHostConfig(
            "settings.json is not a JSON object".to_owned(),
        ));
    }
    Ok(document)
}

fn encode_settings(document: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|_| ManagerError::InvalidHostConfig("cannot encode settings.json".to_owned()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_digest(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ManagerError::InvalidHostConfig("cannot canonicalise entry".to_owned()))?;
    Ok(digest_bytes(&bytes))
}

fn event_array(document: &Value) -> Option<&Vec<Value>> {
    document.get("hooks")?.get(EVENT)?.as_array()
}

fn matching_indices(document: &Value, owned: Option<&Value>) -> Result<Vec<usize>> {
    let Some(owned) = owned else {
        return Ok(Vec::new());
    };
    Ok(event_array(document).map_or_else(Vec::new, |entries| {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| *entry == owned)
            .map(|(index, _)| index)
            .collect()
    }))
}

/// Elements carrying our exact `command` string but not equal to the owned
/// entry -- a user-edited copy.
fn resembling_indices(document: &Value, owned: &Value) -> Result<Vec<usize>> {
    let command = owned
        .get("hooks")
        .and_then(|hooks| hooks.get(0))
        .and_then(|hook| hook.get("command"))
        .and_then(Value::as_str);
    let Some(command) = command else {
        return Ok(Vec::new());
    };
    Ok(event_array(document).map_or_else(Vec::new, |entries| {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                *entry != owned
                    && entry
                        .get("hooks")
                        .and_then(Value::as_array)
                        .is_some_and(|hooks| {
                            hooks.iter().any(|hook| {
                                hook.get("command").and_then(Value::as_str) == Some(command)
                            })
                        })
            })
            .map(|(index, _)| index)
            .collect()
    }))
}

fn entry_at(document: &Value, index: usize) -> Result<Value> {
    event_array(document)
        .and_then(|entries| entries.get(index).cloned())
        .ok_or(ManagerError::InvalidOwnerReceipt)
}

fn push_entry(document: &mut Value, entry: Value) -> Result<()> {
    let object = document
        .as_object_mut()
        .ok_or_else(|| ManagerError::InvalidHostConfig("settings.json is not an object".to_owned()))?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| ManagerError::InvalidHostConfig("hooks is not an object".to_owned()))?;
    let array = hooks
        .entry(EVENT)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            ManagerError::InvalidHostConfig(format!("hooks.{EVENT} is not an array"))
        })?;
    array.push(entry);
    Ok(())
}

fn replace_entry(document: &mut Value, index: usize, entry: Value) -> Result<()> {
    let array = document
        .get_mut("hooks")
        .and_then(|hooks| hooks.get_mut(EVENT))
        .and_then(Value::as_array_mut)
        .ok_or(ManagerError::InvalidOwnerReceipt)?;
    *array.get_mut(index).ok_or(ManagerError::InvalidOwnerReceipt)? = entry;
    Ok(())
}

/// Remove the element, then the key if the array is empty, then `hooks` if it
/// is empty. Leaving `"hooks": {"SessionStart": []}` behind is not reversal.
fn remove_entry(document: &mut Value, index: usize) -> Result<()> {
    let hooks = document
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or(ManagerError::InvalidOwnerReceipt)?;
    let array = hooks
        .get_mut(EVENT)
        .and_then(Value::as_array_mut)
        .ok_or(ManagerError::InvalidOwnerReceipt)?;
    if index >= array.len() {
        return Err(ManagerError::InvalidOwnerReceipt);
    }
    array.remove(index);
    if array.is_empty() {
        hooks.remove(EVENT);
    }
    if hooks.is_empty() {
        document
            .as_object_mut()
            .ok_or(ManagerError::InvalidOwnerReceipt)?
            .remove("hooks");
    }
    Ok(())
}

fn is_empty_shell(document: &Value) -> bool {
    document.as_object().is_some_and(serde_json::Map::is_empty)
}

#[allow(clippy::too_many_arguments)]
fn noop_plan(
    scope: Scope,
    action: HookAction,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
) -> HookPlan {
    HookPlan {
        scope,
        action,
        preview: format!(
            "the {EVENT} hook is already {} at {}",
            if action == HookAction::AlreadyInstalled {
                "installed"
            } else {
                "absent"
            },
            target.display()
        ),
        target,
        receipt_path,
        backup_path,
        restore: None,
        original,
        receipt_original,
        updated: None,
        receipt_after: None,
        remove_backup: false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn settings(temp: &TempDir) -> PathBuf {
        let directory = fs::canonicalize(temp.path()).unwrap().join(".claude");
        fs::create_dir_all(&directory).unwrap();
        directory.join("settings.json")
    }

    fn manager() -> PathBuf {
        PathBuf::from("/opt/kaleidoscope/bin/kaleidoscope")
    }

    /// T-B22 half one: the entry the manager writes is the shape Claude Code's
    /// settings schema accepts, checked field by field rather than by eyeball.
    #[test]
    fn the_installed_entry_matches_the_documented_hook_shape() {
        let entry = owned_entry(&manager(), "default");
        assert_eq!(entry["matcher"], json!(MATCHER));
        let hooks = entry["hooks"].as_array().expect("hooks is an array");
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["type"], json!("command"));
        assert_eq!(hooks[0]["timeout"], json!(HOOK_TIMEOUT_SECONDS));
        let command = hooks[0]["command"].as_str().unwrap();
        assert!(command.starts_with("/opt/kaleidoscope/bin/kaleidoscope "));
        assert!(command.ends_with("hook session-start --profile default"));
    }

    /// T-B22 half two: the hook's own stdout parses as the documented output
    /// contract and is bounded. Asserted on the parsed fields, not on "it did
    /// not error".
    #[test]
    fn the_hook_emits_the_documented_output_contract_and_is_bounded() {
        let line = session_start_output(Err(&ManagerError::EngineNotFound), "default");
        assert!(
            line.len() <= MAX_HOOK_OUTPUT_BYTES,
            "hook output is {} bytes",
            line.len()
        );
        let parsed: Value = serde_json::from_str(&line).expect("hook output must be JSON");
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], json!(EVENT));
        let context = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("additionalContext must be a string");
        assert!(!context.is_empty(), "additionalContext must not be empty");
        // T-B23: an unusable profile is REPORTED, not swallowed. Both halves --
        // an empty-output implementation fails this, an exit-1 implementation
        // fails the CLI-level assertion in tests/manager_cli.rs.
        assert!(
            context.contains("doctor"),
            "a broken configuration must name the recovery command: {context}"
        );
    }

    #[test]
    fn install_then_remove_restores_a_preexisting_file_byte_identically() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        let seed = "{\n    \"theme\": \"dark\",\n    \"alwaysThinkingEnabled\": true\n}\n";
        fs::write(&target, seed).unwrap();
        let before = fs::read(&target).unwrap();

        let install = plan_install_at(Scope::Project, &manager(), "default", &target).unwrap();
        install.apply().unwrap();
        let installed: Value =
            serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(installed["theme"], json!("dark"));
        assert_eq!(
            installed["hooks"][EVENT].as_array().unwrap().len(),
            1,
            "exactly one entry must be added"
        );

        let remove = plan_remove_at(Scope::Project, &target, false).unwrap();
        assert_eq!(remove.restore, Some(RestoreTier::ByteIdentical));
        remove.apply().unwrap();
        assert_eq!(
            fs::read(&target).unwrap(),
            before,
            "settings.json was not restored byte-identically"
        );
        assert!(!remove.backup_path.exists(), "Tier 1 left a backup behind");
    }

    #[test]
    fn a_file_the_manager_created_is_removed_entirely() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        plan_install_at(Scope::Project, &manager(), "default", &target)
            .unwrap()
            .apply()
            .unwrap();
        assert!(target.exists());
        let remove = plan_remove_at(Scope::Project, &target, false).unwrap();
        remove.apply().unwrap();
        assert!(!target.exists(), "a manager-created settings.json survived");
        assert!(!remove.receipt_path.exists());
    }

    /// T-B27: a user-edited copy of our entry refuses, and --force removes it.
    #[test]
    fn a_user_edited_hook_entry_refuses_and_force_removes_it() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        fs::write(&target, "{}\n").unwrap();
        plan_install_at(Scope::Project, &manager(), "default", &target)
            .unwrap()
            .apply()
            .unwrap();
        let mut document: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        document["hooks"][EVENT][0]["hooks"][0]["timeout"] = json!(99);
        fs::write(&target, encode_settings(&document).unwrap()).unwrap();

        let refused = plan_remove_at(Scope::Project, &target, false)
            .expect_err("a hand-edited entry must refuse");
        assert!(
            matches!(refused, ManagerError::HostConflict(_)),
            "expected HostConflict, got {refused:?}"
        );
        assert!(refused.to_string().contains("--force"));

        let forced = plan_remove_at(Scope::Project, &target, true).unwrap();
        forced.apply().unwrap();
        let after: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert!(after.get("hooks").is_none(), "the entry survived: {after}");
    }

    /// T-B28: two identical entries refuse, and NEITHER is removed. An
    /// implementation that removed "the first one" fails the second assertion.
    #[test]
    fn two_identical_hook_entries_refuse_and_remove_neither() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        fs::write(&target, "{}\n").unwrap();
        plan_install_at(Scope::Project, &manager(), "default", &target)
            .unwrap()
            .apply()
            .unwrap();
        let mut document: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        let duplicate = document["hooks"][EVENT][0].clone();
        document["hooks"][EVENT]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        fs::write(&target, encode_settings(&document).unwrap()).unwrap();

        let refused = plan_remove_at(Scope::Project, &target, false)
            .expect_err("duplicated entries must refuse");
        assert!(matches!(refused, ManagerError::HostConflict(_)));
        let after: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(
            after["hooks"][EVENT].as_array().unwrap().len(),
            2,
            "a refusal must not remove anything"
        );
    }

    #[test]
    fn reinstall_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        plan_install_at(Scope::Project, &manager(), "default", &target)
            .unwrap()
            .apply()
            .unwrap();
        let repeated = plan_install_at(Scope::Project, &manager(), "default", &target).unwrap();
        assert_eq!(repeated.action, HookAction::AlreadyInstalled);
    }
}
