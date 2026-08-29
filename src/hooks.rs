//! The Claude Code `SessionStart` hook.
//!
//! WHAT THIS HOOK EMITS, AND WHY IT CHANGED
//!
//! It used to print one unconditional sentence -- "Kaleidoscope memory is
//! connected (profile: default)" -- whenever `kscope profile launch` returned a
//! valid descriptor. That sentence asserted a state it never checked. A profile
//! launching is not the same claim as "the two MCP tools are in the model's
//! tool list", and on 2026-08-27 the two came apart for an entire session:
//! the profile launched, the server started, `claude mcp list` said
//!
//! ```text
//! kaleidoscope: ... Connected - tools fetch failed - Invalid result for
//! tools/list: [ttlMs expected number, received undefined;
//!              cacheScope invalid_value expected "public"|"private"]
//! ```
//!
//! and NEITHER tool reached the model. The hook said "connected" the whole
//! time. So the rule now is: probe, then report what was found, and publish the
//! finding in a form a later session can be audited against rather than
//! believed. The first line of the emitted context is a one-line JSON object
//! carrying `tools_visible` and every rung the verdict was computed from.
//!
//! WHAT THE PROBE CAN AND CANNOT SEE
//!
//! It runs the command the HOST is registered to run -- read out of
//! `.mcp.json` / `~/.claude.json`, not assumed -- speaks MCP to it over stdio,
//! and reads `tools/list` back. That proves the server publishes `search` and
//! `remember`. It then applies the one client-side check whose failure was
//! observed first-hand (`ttlMs` / `cacheScope`, see `client_contract`).
//!
//! It CANNOT see the model's actual tool list; no hook can. So the emitted text
//! says so, and says which direction to trust if the two disagree. A probe that
//! overstated its reach is the defect this file exists to stop repeating.
//!
//! WHAT IT NOW CARRIES: CONTENT, NOT ADVICE
//!
//! The old body was ~230 characters of instruction and zero memories -- a
//! reminder to go and get context, spent from the same budget the context
//! itself would have cost. It now retrieves a handful of memories for the
//! project the session is standing in and injects them directly.
//!
//! It describes them off what came BACK, not off what was asked. A scoped
//! request is not evidence of a scoped answer: a memory whose `project` axis is
//! null is excluded by no scope filter, so a vault of unlabelled memories
//! answers every `{"scope":{"project":X}}` the same way for every X. The header
//! only says "recorded for {label}" when every served hit actually carries that
//! label, and `labelled_for_project` publishes the count either way. Writing
//! that sentence off "a filter was sent" would have been this file's own defect
//! committed a second time, one section further down the same output.
//!
//! That reverses a decision recorded here, and the reversal is deliberate:
//!
//!  1. `search` writes an exposure row, and `ledger: false` is REFUSED rather
//!     than silently upgraded. So retrieving at all means one exposure row per
//!     session start. That is now an accepted cost, bounded by `top_k` and by
//!     `maximum_context_bytes`, and it is opt-out-able without turning the hook
//!     off: `--no-memories`, or `KALEIDOSCOPE_HOOK_MEMORIES=0`.
//!  2. "There is no query at `SessionStart`" was true of a general search and
//!     false of this one. The project the session opened in IS the query, and
//!     the engine resolves it (`where --root-only`, which redirects a linked
//!     worktree to its main checkout) rather than the manager guessing.
//!  3. "A gated call can refuse" stays true, and is handled by degrading:
//!     a refusal, an empty vault, a missing engine and a slow query all produce
//!     a fast, quiet, still-useful output. None of them changes the exit code.
//!
//! BUDGETS, BOTH OF THEM
//!
//! Bytes: the whole JSON line is capped at `MAX_HOOK_OUTPUT_BYTES`, the context
//! inside it at `MAX_CONTEXT_BYTES`, and the memory section at
//! `MAX_MEMORY_SECTION_BYTES`. The emitted JSON says what the budget was, so a
//! reader can tell a short answer from a truncated one.
//!
//! Time: every subprocess runs through `engine::run_bounded`, under a per-stage
//! timeout AND a shared `TOTAL_TIME_BUDGET` deadline. The settings entry allows
//! `HOOK_TIMEOUT_SECONDS`; this aims an order of magnitude below it.
//!
//! EXIT CODE
//!
//! Always 0, on every path, including every failure path. A hook that exits
//! non-zero is a hook the user turns off, and a broken memory configuration
//! should be VISIBLE, not fatal. Nothing above may change that; the CLI-level
//! test `the_hook_exits_zero_when_every_stage_fails` pins it.
//!
//! WHY A HOOK AT ALL, GIVEN CLAUDE.md
//!
//! `CLAUDE.md` is read once at session start. A `SessionStart` hook fires on
//! `startup`, `resume`, `clear` AND `compact` -- so the context survives
//! compaction. That is the whole justification.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{project_root, user_home};
use crate::engine::{BoundedOutput, Engine, run_bounded};
use crate::error::{ManagerError, Result};
use crate::fs_safe::{
    FileLock, Snapshot, TargetWrite, assert_unchanged, atomic_remove, atomic_write, digest_bytes,
    prune_empty_managed_directories, read_snapshot, restore_snapshot, sibling_path,
    write_bounded_backup,
};
use crate::host::{Host, Scope, host_config_path};
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
/// The budget for `additionalContext` itself, inside that line. Lower than
/// `MAX_HOOK_OUTPUT_BYTES` because JSON escaping is not free: every newline in
/// a multi-line context costs two bytes on the wire, and this context is
/// deliberately multi-line.
const MAX_CONTEXT_BYTES: usize = 2600;
/// Of that context, the share the retrieved memories may take. The rest is the
/// status block, which is small and must never be the thing that gets dropped.
const MAX_MEMORY_SECTION_BYTES: usize = 1500;
/// How many memories to ask for, and the engine-side byte bound on the served
/// set. Both are published `search` controls, so an evaluation can reproduce
/// exactly what a session start retrieved.
const MEMORY_TOP_K: u64 = 4;
const MEMORY_CONTEXT_BYTES: u64 = 2048;

/// The whole hook, wall clock, across every subprocess. The settings entry
/// allows `HOOK_TIMEOUT_SECONDS`; this is the budget the hook holds ITSELF to,
/// and the measured typical run is roughly a twentieth of it.
const TOTAL_TIME_BUDGET: Duration = Duration::from_secs(6);
/// Per-stage ceilings. They deliberately SUM to more than the total: the shared
/// deadline is what bounds the hook, and a stage that runs cold is allowed to
/// spend its own headroom at the cost of the stages after it, which then
/// degrade to "skipped: the hook's time budget was spent" rather than pushing
/// the whole hook past the harness's limit.
///
/// THESE ARE CEILINGS, NOT EXPECTATIONS. Measured end to end against the real
/// engine and a 179-memory vault: 100-170 ms warm, which is 2-3% of the total
/// budget. The ceilings are set for the pathological case, and the pathological
/// case is not hypothetical -- a first spawn of a freshly written executable on
/// macOS measured 620 ms with the machine idle and exceeded 2,000 ms under
/// parallel load, which a tighter ceiling reported as "timed out" for an engine
/// that was working perfectly. A hook that misattributes contention as a broken
/// engine is the same defect as one that asserts "connected" without looking.
///
/// The whole budget still sits below `HOOK_TIMEOUT_SECONDS`, on purpose: 6 s
/// with a diagnosis beats 10 s and a harness kill with no output at all.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(3);
const WHERE_TIMEOUT: Duration = Duration::from_millis(1_200);
const PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);
const SEARCH_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait for the harness's own hook input on stdin before giving up
/// and falling back to the working directory. Short on purpose: run by hand
/// from a terminal, stdin is a tty and nothing is ever coming.
const STDIN_TIMEOUT: Duration = Duration::from_millis(200);

/// The MCP protocol version the probe negotiates.
///
/// Not a guess and not the newest thing in the spec: it is the version Claude
/// Code itself negotiated with this server, read out of its own connection log
/// (`negotiatedProtocolVersion":"2026-07-28"`). The probe must speak the same
/// version as the client it is reporting on, because the server's `tools/list`
/// result DIFFERS between versions -- at `2025-06-18` it omits `resultType` and
/// the per-tool `annotations` that appear at `2026-07-28`. A probe on the older
/// version validates a payload the client never sees.
const PROBE_PROTOCOL_VERSION: &str = "2026-07-28";
/// The two tools the product publishes, and the only two.
const PUBLIC_TOOLS: [&str; 2] = ["remember", "search"];
/// The MCP server key the manager registers under, in every host that takes a
/// JSON entry. Same string `host::json_entry_path` writes.
const SERVER_KEY: &str = "kaleidoscope";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    Add,
    /// An entry byte-identical to ours was already there with no receipt. Take
    /// ownership by writing the receipt; change no bytes.
    Adopt,
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
    /// See `host::OwnershipReceipt::adopted`.
    #[serde(default)]
    adopted: bool,
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
    pub adopted: bool,
    /// A structural restore that nonetheless returned every byte it did not
    /// own. See `json_span`.
    pub formatting_preserved: bool,
    preview: String,
    original: Snapshot,
    receipt_original: Snapshot,
    write: TargetWrite,
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
        // `Leave` is excluded: an adoption writes nothing to the target.
        if self.restore.is_none() && !self.write.is_leave() {
            write_bounded_backup(&self.target, &self.original)?;
        }
        match &self.write {
            TargetWrite::Write(bytes) => {
                atomic_write(&self.target, bytes, self.original.unix_mode.or(Some(0o600)))?;
            }
            TargetWrite::Remove => atomic_remove(&self.target)?,
            TargetWrite::Leave => {}
        }
        let receipt_result = match &self.receipt_after {
            Some(receipt) => atomic_write(&self.receipt_path, &receipt.encode()?, Some(0o600)),
            None => atomic_remove(&self.receipt_path),
        };
        if let Err(error) = receipt_result {
            // NOT on a `Leave` plan: `self.original` IS the file, and rewriting
            // it would touch bytes an adoption promised not to touch.
            if !self.write.is_leave() {
                restore_snapshot(&self.target, &self.original)?;
            }
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
        if self.write.is_remove() {
            prune_empty_managed_directories(&self.target);
        }
        Ok(())
    }

    #[must_use]
    /// The backup path IF a backup will be there when this returns, else `None`.
    ///
    /// It used to be `self.backup_path` unconditionally -- a path the plan
    /// merely KNOWS, printed whether or not a file exists at it. On an adopt
    /// run all three steps named a `.kaleidoscope-backup` that was never
    /// created (adoption writes nothing to the target, so there are no
    /// pre-modification bytes for a backup to hold), and a caller could not
    /// tell "restorable from a backup" from "not restorable".
    ///
    /// A real run reports the filesystem, because `summary` is called after
    /// `apply`. A dry run reports the PREDICTION, because the file the flag is
    /// asking about has not been written yet.
    fn backup_after(&self, dry_run: bool) -> Option<&std::path::Path> {
        if dry_run && self.restore.is_none() && !self.write.is_leave() {
            return Some(self.backup_path.as_path());
        }
        if dry_run && self.remove_backup {
            return None;
        }
        self.backup_path
            .exists()
            .then_some(self.backup_path.as_path())
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
            "backup": self.backup_after(dry_run),
        });
        if let Some(restore) = self.restore {
            value["restore"] = json!(restore);
            if restore == RestoreTier::Structural {
                value["formatting"] = json!(if self.formatting_preserved {
                    "preserved"
                } else {
                    "normalized"
                });
            }
        }
        if self.adopted {
            value["adopted"] = json!(true);
        }
        if self.action == HookAction::Adopt {
            value["detail"] = json!(
                "existing content is byte-identical to the manager's; the owner receipt was written and no bytes were changed"
            );
        }
        value
    }

    #[must_use]
    pub const fn writes_nothing(&self) -> bool {
        self.write.is_leave()
    }

    #[must_use]
    pub const fn target(&self) -> &PathBuf {
        &self.target
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
    plan_install_at(
        scope,
        manager,
        profile,
        &settings_path(scope, explicit_project)?,
    )
}

pub fn plan_remove(scope: Scope, explicit_project: Option<&Path>, force: bool) -> Result<HookPlan> {
    plan_remove_at(scope, &settings_path(scope, explicit_project)?, force)
}

#[allow(clippy::too_many_lines)]
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
    let identical = identical_indices(&document, &desired)?;
    let resembling = resembling_indices(&document, &desired)?;

    // THE MEASURED rc=0 DEFECT. `matching_indices` keys on `receipt.owned` and
    // returns EMPTY when the receipt is absent, so an entry byte-identical to
    // ours but carrying no receipt fell through to `Add` and the manager
    // APPENDED A SECOND IDENTICAL ENTRY -- reporting success. After that,
    // `teardown` refuses with `count > 1` and `--force` refuses too: the user
    // is wedged by a command that said it worked. Adoption is the fix, and it
    // belongs here rather than in the exit-code work, because the wrong exit
    // code was a symptom of doing the wrong thing, not of reporting it wrongly.
    let action = match (matches.len(), identical.len(), resembling.len()) {
        (0, 0, 0) => HookAction::Add,
        (0, 1, _) if receipt.is_none() => HookAction::Adopt,
        (0, count, _) if receipt.is_none() && count > 1 => {
            return Err(ManagerError::HostConflict(format!(
                "{} carries {count} identical Kaleidoscope {EVENT} entries; refusing to guess which one is ours. Remove all but one from \"hooks.{EVENT}\" in that file, then re-run.",
                target.display()
            )));
        }
        (1, _, _) => {
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
        //
        // The message used to end "or re-run with --force" -- a flag `run_init`
        // does not parse and `plan_install_at` does not take. A named remedy
        // that cannot be invoked is worse than none: it sends the user to look
        // for something that is not there.
        (0, _, _) => {
            return Err(ManagerError::HostConflict(format!(
                "{} already carries a {EVENT} entry that runs this manager with different surrounding fields. Nothing was changed.\nWays forward:\n  wire everything except the hook\n      kaleidoscope init --host claude-code --no-hooks\n  remove that entry from \"hooks.{EVENT}\" in {} by hand, then re-run.",
                target.display(),
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

    let (write, post_sha256) = match action {
        HookAction::Adopt => (TargetWrite::Leave, original.sha256.clone()),
        HookAction::Add | HookAction::Update => {
            if action == HookAction::Add {
                push_entry(&mut document, desired.clone())?;
            } else {
                replace_entry(&mut document, matches[0], desired.clone())?;
            }
            let encoded = encode_settings(&document)?;
            let digest = digest_bytes(&encoded);
            (TargetWrite::Write(encoded), digest)
        }
        _ => unreachable!("only Add, Adopt and Update reach here"),
    };
    let adopted = action == HookAction::Adopt || receipt.as_ref().is_some_and(|r| r.adopted);
    let pre_sha256 = if action == HookAction::Adopt {
        original.sha256.clone()
    } else {
        receipt
            .as_ref()
            .map_or_else(|| original.sha256.clone(), |r| r.pre_sha256.clone())
    };
    let file_created = action != HookAction::Adopt
        && receipt
            .as_ref()
            .map_or(original.bytes.is_none(), |r| r.file_created);
    Ok(HookPlan {
        scope,
        action,
        adopted,
        formatting_preserved: false,
        preview: if action == HookAction::Adopt {
            format!(
                "Adopt the existing Kaleidoscope {EVENT} entry in {} (byte-identical to this manager's; nothing will be written to the file)\nEntry:\n{}",
                target.display(),
                serde_json::to_string_pretty(&desired).unwrap_or_default()
            )
        } else {
            format!(
                "Install the Kaleidoscope {EVENT} hook in {}\nEntry:\n{}",
                target.display(),
                serde_json::to_string_pretty(&desired).unwrap_or_default()
            )
        },
        target: target.to_path_buf(),
        receipt_path,
        backup_path,
        restore: None,
        original,
        receipt_original,
        write,
        receipt_after: Some(HookReceipt {
            version: RECEIPT_VERSION,
            owner: OWNER.to_owned(),
            scope,
            profile: profile.to_owned(),
            owned_sha256: canonical_digest(&desired)?,
            owned: desired,
            pre_sha256,
            post_sha256,
            file_created,
            adopted,
        }),
        remove_backup: false,
    })
}

#[allow(clippy::too_many_lines)]
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
    let before = document.clone();
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
    // ADOPTION BYPASSES TIER 1. An adopted ENTRY is removed -- an entry is not
    // a file, removing it destroys nothing the user authored in any meaningful
    // sense (by the adoption test itself it is byte-identical to what
    // `owned_entry` regenerates from the profile and the engine path, so
    // `kaleidoscope connect` puts it back byte-for-byte), and everything around
    // it survives. Leaving it would report `status: "removed"` while the
    // harness still launches `kscope` on every session: a refusal spelled as an
    // answer, and exactly the state a user runs `teardown` to escape.
    if !receipt.adopted && file_is_ours && (receipt.file_created || backup_is_pre) {
        let (write, remove_backup) = if receipt.file_created {
            // The manager created this file, so the pre-install state is
            // ABSENCE. Any backup here holds manager-written bytes, never the
            // user's -- including the one `apply` writes on its way out.
            (TargetWrite::Remove, true)
        } else {
            (
                backup
                    .bytes
                    .clone()
                    .map_or(TargetWrite::Remove, TargetWrite::Write),
                true,
            )
        };
        return Ok(HookPlan {
            scope,
            action: HookAction::Remove,
            adopted: receipt.adopted,
            formatting_preserved: false,
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
            write,
            receipt_after: None,
            remove_backup,
        });
    }

    // `file_created` is false for every adoption, so a settings.json the user
    // wrote is never deleted, even when removing our entry empties it.
    let mut formatting_preserved = false;
    let write = if receipt.file_created && is_empty_shell(&document) {
        TargetWrite::Remove
    } else {
        // See `json_span`. `encode_settings` re-encodes the whole document,
        // which on an ADOPTED settings.json reformats the user's
        // `permissions.allow` and any hook of their own -- content the manager
        // has never written a byte of. Cut our entry's own bytes out instead,
        // and only re-encode if that cannot be proved equivalent.
        let excised = original
            .bytes
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| crate::json_span::excise(text, &before, &document));
        match excised {
            Some(text) => {
                formatting_preserved = true;
                TargetWrite::Write(text.into_bytes())
            }
            None => TargetWrite::Write(encode_settings(&document)?),
        }
    };
    Ok(HookPlan {
        scope,
        action: HookAction::Remove,
        adopted: receipt.adopted,
        formatting_preserved,
        preview: format!(
            "Remove the Kaleidoscope {EVENT} hook from {} ({})",
            target.display(),
            if formatting_preserved {
                "structural restore; every byte outside the entry preserved"
            } else {
                "structural restore; formatting normalized"
            }
        ),
        target: target.to_path_buf(),
        receipt_path,
        backup_path,
        restore: Some(RestoreTier::Structural),
        original,
        receipt_original,
        write,
        receipt_after: None,
        remove_backup: false,
    })
}

/// What this invocation of the hook was asked to do.
///
/// A struct rather than four positional parameters because `cwd` is the one
/// that is easiest to get wrong and hardest to notice: the harness passes the
/// SESSION's working directory on stdin, and taking the hook process's own
/// working directory instead silently retrieves for the wrong project.
#[derive(Clone, Debug)]
pub struct SessionStartOptions {
    pub profile: String,
    pub cwd: PathBuf,
    /// Retrieve and inject memories. `--no-memories` or
    /// `KALEIDOSCOPE_HOOK_MEMORIES=0` turns this off without turning the hook
    /// off -- the point being that a user who does not want an exposure row per
    /// session start still gets the reachability report.
    pub retrieval: bool,
}

/// One shared wall-clock deadline for every stage.
///
/// Per-stage timeouts alone do not bound a hook: four stages of two seconds is
/// an eight-second hook. `slice` hands out the SMALLER of the stage's own
/// timeout and what is left of the total, and `None` once the total is spent --
/// which is how a slow first stage silently cancels the later ones instead of
/// pushing the hook past the harness's limit.
struct Deadline {
    started: Instant,
    end: Instant,
}

impl Deadline {
    fn new(budget: Duration) -> Self {
        let started = Instant::now();
        Self {
            started,
            end: started + budget,
        }
    }

    fn slice(&self, stage: Duration) -> Option<Duration> {
        let remaining = self.end.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        Some(stage.min(remaining))
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// The MCP server entry the HOST is registered to launch.
///
/// Read, never assumed. The probe's whole value is that it runs the command
/// Claude Code runs; a probe that ran `Engine::path` instead would come back
/// green for a registration that points somewhere else, which is one of the
/// two ways "connected" was asserted without being checked.
struct Registration {
    scope: &'static str,
    source: PathBuf,
    command: String,
    args: Vec<String>,
}

impl Registration {
    fn display_command(&self) -> String {
        if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        }
    }
}

/// Claude Code's own MCP entry for this session's project, project scope first.
///
/// Project scope first because that is the order Claude Code resolves in, and
/// reporting the user-scope entry while a project-scope one shadows it would be
/// a true statement about the wrong file.
fn find_registration(cwd: &Path) -> Option<Registration> {
    let home = user_home().ok()?;
    let project = project_root(Some(cwd)).ok()?;
    for scope in [Scope::Project, Scope::User] {
        let Ok(path) = host_config_path(Host::ClaudeCode, scope, &home, &project) else {
            continue;
        };
        let Ok(snapshot) = read_snapshot(&path, MAX_HOST_CONFIG_PROBE_BYTES, "host configuration")
        else {
            continue;
        };
        let Some(bytes) = snapshot.bytes.as_deref() else {
            continue;
        };
        let Ok(document) = serde_json::from_slice::<Value>(bytes) else {
            continue;
        };
        let entry = &document["mcpServers"][SERVER_KEY];
        let Some(command) = entry["command"].as_str() else {
            continue;
        };
        let args = entry["args"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return Some(Registration {
            scope: scope.as_str(),
            source: path,
            command: command.to_owned(),
            args,
        });
    }
    None
}

/// `~/.claude.json` is Claude Code's live configuration and grows; measured at
/// 152 KB here. The cap is generous because a truncated read would be reported
/// as "no registration", which is the wrong finding.
const MAX_HOST_CONFIG_PROBE_BYTES: u64 = 4 * 1024 * 1024;

/// The marker the engine appends to every entitlement refusal, and the two
/// identifiers behind it that are **self-healing**.
///
/// Both strings are fixed by `reference/entitlement-contract-v1.json`
/// (`refusal_marker_prefix`, `refusal_identifiers`), the public contract both
/// SDKs already assert. The Python client classifies on it; until now this
/// manager did not, which is the whole defect this pair of functions closes.
const ENTITLEMENT_REFUSAL_MARKER: &str = "kscope-entitlement-refusal: ";

/// `E_UNVERIFIED` and `E_GRACE_EXPIRED` are the two refusals the *next call
/// fixes by itself*: each one starts a revalidation, and the engine's own text
/// for both ends in "run any gated command again". Every other identifier in
/// the contract needs a human -- a key that was never set, revoked, expired,
/// malformed, or a clock to correct -- and stays a relay.
///
/// The distinction matters because this hook writes into a model's system
/// prompt. Reporting a self-healing refusal as a settled fact about the whole
/// session is how an agent stops calling Kaleidoscope after one transient
/// network gap, and it is not recoverable inside that session: nothing re-probes.
const SELF_HEALING_REFUSALS: [&str; 2] = ["E_UNVERIFIED", "E_GRACE_EXPIRED"];

/// Pull the entitlement identifier out of captured engine output.
///
/// Scans from the END, because the engine appends its marker last and
/// `run_bounded` may have truncated a noisy stderr from the front -- the
/// contract's own bounding test pins the marker as the final line.
fn entitlement_refusal(detail: &str) -> Option<&str> {
    detail.lines().rev().find_map(|line| {
        line.trim()
            .strip_prefix(ENTITLEMENT_REFUSAL_MARKER)
            .map(str::trim)
            .filter(|identifier| !identifier.is_empty())
    })
}

/// True when the refusal will clear on its own, so the right instruction to a
/// model is "call the tools anyway" rather than "the tools do not work".
fn refusal_is_self_healing(identifier: &str) -> bool {
    SELF_HEALING_REFUSALS.contains(&identifier)
}

/// What the MCP probe found. Every arm is reportable; none is an error.
enum Probe {
    /// No `mcpServers.kaleidoscope` entry applies to this project at all, so
    /// Claude Code has nothing to start. This is a finding, not a failure.
    Unregistered,
    /// A registration exists but the command it names is not something the
    /// manager will execute -- missing, not a regular file, not executable.
    Unusable { detail: String },
    /// The command was run and did not answer usably.
    NoAnswer { detail: String },
    Answered {
        protocol: Option<String>,
        server: Option<String>,
        tools: Vec<String>,
        /// `None` when the `tools/list` result satisfies the client-side
        /// contract; otherwise why the client will reject it.
        contract: Option<&'static str>,
        elapsed: Duration,
    },
}

impl Probe {
    fn tools(&self) -> &[String] {
        match self {
            Self::Answered { tools, .. } => tools,
            _ => &[],
        }
    }

    fn publishes_both(&self) -> bool {
        PUBLIC_TOOLS
            .iter()
            .all(|wanted| self.tools().iter().any(|found| found == wanted))
    }
}

/// The one client-side check whose failure was observed first-hand.
///
/// `claude mcp list` against this exact server, 2026-08-27, reproducible 3/3:
///
/// ```text
/// tools fetch failed - Invalid result for tools/list:
/// [ { "path": ["ttlMs"],      "message": "expected number, received undefined" },
///   { "path": ["cacheScope"], "message": "expected one of \"public\"|\"private\"" } ]
/// ```
///
/// The `path` on both entries is a single element, so these are TOP-LEVEL
/// fields of the `tools/list` result, not per-tool ones -- which is why this
/// looks at `result` and not at `result.tools[]`. rmcp 3.1.0 emits
/// `{resultType, tools}` and neither field, so the client discards every tool
/// the server published and no `mcp__kaleidoscope__*` name reaches the model.
///
/// KNOWN DIRECTION OF ERROR: if a future client stops requiring these, this
/// reports `tools_visible: false` for tools that are in fact present. That is
/// the safe direction -- it points at a working fallback rather than at a tool
/// that is not there -- and the emitted text says explicitly which way to trust
/// a disagreement. It is not the safe direction to guess `true`.
fn client_contract(result: &Value) -> Option<&'static str> {
    let ttl = result.get("ttlMs").is_some_and(Value::is_number);
    let scope = result
        .get("cacheScope")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "public" || value == "private");
    if ttl && scope {
        return None;
    }
    Some(
        "the server's tools/list result omits the top-level `ttlMs` (number) and `cacheScope` (\"public\"|\"private\") fields this Claude Code build requires, so the client rejects the whole result and drops both tools",
    )
}

/// Speak MCP to the registered command and read `tools/list` back.
///
/// Three messages in one write, then EOF: `initialize`, the `initialized`
/// notification the spec requires before any request, and `tools/list`. Closing
/// stdin is what makes the server exit, so the whole exchange is one bounded
/// process and there is nothing to clean up.
fn probe_mcp(registration: Option<&Registration>, timeout: Option<Duration>) -> Probe {
    let Some(registration) = registration else {
        return Probe::Unregistered;
    };
    let Some(timeout) = timeout else {
        return Probe::NoAnswer {
            detail: "skipped: the hook's time budget was already spent".to_owned(),
        };
    };
    // Validated through `Engine::new`, which canonicalises first and then
    // checks what will actually be executed. The path comes out of a
    // configuration file, so "it is there" is not the same as "it is a regular
    // executable file", and the probe must not be the thing that runs whatever
    // a rewritten `.mcp.json` names.
    let executable = match Engine::new(Path::new(&registration.command)) {
        Ok(engine) => engine.path().to_path_buf(),
        Err(error) => {
            return Probe::Unusable {
                detail: format!("{}: {error}", registration.command),
            };
        }
    };
    let payload = format!(
        concat!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{version}","capabilities":{{}},"clientInfo":{{"name":"kaleidoscope-session-start-probe","version":"1"}}}}}}"#,
            "\n",
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#,
            "\n",
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#,
            "\n",
        ),
        version = PROBE_PROTOCOL_VERSION,
    );
    let arguments: Vec<&str> = registration.args.iter().map(String::as_str).collect();
    let output = match run_bounded(
        &executable,
        &arguments,
        None,
        Some(payload.as_bytes()),
        timeout,
    ) {
        Ok(output) => output,
        Err(failure) => {
            return Probe::NoAnswer {
                detail: failure.to_string(),
            };
        }
    };
    read_probe_answer(&output)
}

fn read_probe_answer(output: &BoundedOutput) -> Probe {
    let text = String::from_utf8_lossy(&output.stdout);
    let mut initialize = None;
    let mut listing = None;
    for line in text.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match message.get("id").and_then(Value::as_u64) {
            Some(1) => initialize = message.get("result").cloned(),
            Some(2) => listing = message.get("result").cloned(),
            _ => {}
        }
    }
    let Some(listing) = listing else {
        let detail = if output.stderr.is_empty() {
            format!(
                "the server returned no tools/list result{}",
                if output.success {
                    String::new()
                } else {
                    " and exited non-zero".to_owned()
                }
            )
        } else {
            output.stderr.clone()
        };
        return Probe::NoAnswer { detail };
    };
    let tools = listing["tools"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Probe::Answered {
        protocol: initialize
            .as_ref()
            .and_then(|value| value["protocolVersion"].as_str())
            .map(str::to_owned),
        server: initialize.as_ref().and_then(|value| {
            let name = value["serverInfo"]["name"].as_str()?;
            let version = value["serverInfo"]["version"].as_str().unwrap_or("?");
            Some(format!("{name} {version}"))
        }),
        contract: client_contract(&listing),
        tools,
        elapsed: output.elapsed,
    }
}

/// The project this session opened in, asked of the ENGINE.
///
/// `where --root-only` and not `cwd.file_name()`: a linked worktree's directory
/// is named after the branch, so the basename of this session's cwd here is
/// `kscope-promotion-benchmarks-df7441` and the project is `kaleidoscope`.
/// Querying with the former retrieves nothing and reports an empty vault.
fn resolve_project(
    engine: &Engine,
    cwd: &Path,
    timeout: Option<Duration>,
) -> Option<(String, PathBuf)> {
    let output = engine
        .run_bounded_in(Some(cwd), &["where", "--root-only"], None, timeout?)
        .ok()?;
    if !output.success {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let directory = value["repository"]
        .as_str()
        .or_else(|| value["project"].as_str())
        .map(PathBuf::from)?;
    let label = directory.file_name()?.to_str()?.to_owned();
    Some((label, directory))
}

/// What retrieval produced. `Skipped` and `Empty` are not failures and must not
/// read as ones: an empty vault is the normal state of a new install.
enum Memories {
    Skipped(&'static str),
    Unavailable(String),
    Empty,
    Found {
        entries: Vec<String>,
        /// Whether the request that produced these hits CARRIED a scope
        /// filter. Not whether the filter discriminated -- see `labelled`.
        scope_requested: bool,
        /// How many of the served hits actually carry `scope.project == label`.
        ///
        /// This exists because a scoped request is not evidence of a scoped
        /// answer. A memory whose `project` axis is null is not excluded by any
        /// scope filter, so a vault of unlabelled memories answers every
        /// `{"scope":{"project":X}}` identically for every X. Measured
        /// 2026-08-27: `{"project":"fakeproj"}` against a scratch directory
        /// created seconds earlier returned three memories, and
        /// `{"project":"zzz-definitely-not-a-project-9999"}` returned those
        /// same three. The header used to read "N memories already recorded
        /// for {label}" off `scope_requested` alone, which restated the
        /// unconditional-claim defect this hook exists to fix, one section
        /// further down the same output.
        labelled: usize,
        elapsed: Duration,
    },
}

/// Retrieve for the project, scoped first and unscoped only if that was empty.
///
/// Scoped first because a vault can hold several projects and a session start
/// wants this one. Unscoped second because a scope filter that matches nothing
/// returns nothing, and "no memories" is a worse answer than "these ranked
/// highest" when the only thing wrong was a label the writer spelled
/// differently.
fn retrieve_memories(
    engine: &Engine,
    profile: &str,
    label: Option<&str>,
    cwd: &Path,
    deadline: &Deadline,
) -> Memories {
    let Some(label) = label else {
        return Memories::Unavailable("the project could not be resolved".to_owned());
    };
    let started = Instant::now();
    let mut last_error = None;
    for scope_requested in [true, false] {
        let Some(timeout) = deadline.slice(SEARCH_TIMEOUT) else {
            return last_error.map_or(
                Memories::Skipped("the hook's time budget was spent before retrieval"),
                Memories::Unavailable,
            );
        };
        let mut request = json!({
            "query": label,
            "top_k": MEMORY_TOP_K,
            "maximum_context_bytes": MEMORY_CONTEXT_BYTES,
        });
        if scope_requested {
            request["scope"] = json!({ "project": label });
        }
        let payload = request.to_string();
        let output = match engine.run_bounded_in(
            Some(cwd),
            &["call", "--profile", profile, "search"],
            Some(payload.as_bytes()),
            timeout,
        ) {
            Ok(output) => output,
            Err(failure) => return Memories::Unavailable(failure.to_string()),
        };
        if !output.success {
            last_error = Some(if output.stderr.is_empty() {
                "the engine refused the search".to_owned()
            } else {
                output.stderr.clone()
            });
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
            last_error = Some("the engine's search result did not parse".to_owned());
            continue;
        };
        let (entries, labelled) = render_hits(&value, label);
        if !entries.is_empty() {
            return Memories::Found {
                entries,
                scope_requested,
                labelled,
                elapsed: started.elapsed(),
            };
        }
    }
    last_error.map_or(Memories::Empty, Memories::Unavailable)
}

/// One line per memory: type, title, the opening of the body, and the id.
///
/// The id travels because it is the handle for the follow-up -- `search` by
/// `memory_id` returns the exact current record and writes no exposure row --
/// and because a memory quoted without it cannot be corrected.
/// Returns the rendered lines and, of the lines RENDERED, how many carry
/// `scope.project == label`. Counted over the rendered set and not over every
/// hit, so the count always describes the text the model is shown.
fn render_hits(value: &Value, label: &str) -> (Vec<String>, usize) {
    let Some(hits) = value["selected_hits"].as_array() else {
        return (Vec::new(), 0);
    };
    let mut entries = Vec::new();
    let mut labelled = 0_usize;
    let mut spent = 0_usize;
    for hit in hits {
        let content = hit["content_md"].as_str().unwrap_or_default();
        let mut lines = content.lines().filter(|line| !line.trim().is_empty());
        let title = lines
            .next()
            .unwrap_or("(untitled)")
            .trim_start_matches('#')
            .trim();
        let body = lines.next().unwrap_or_default().trim();
        let kind = hit["memory_type"].as_str().unwrap_or("memory");
        let id = hit["memory_id"].as_str().unwrap_or("mem_?");
        let entry = format!(
            "- [{kind}] {title} — {} ({id})",
            clip(body, 160.min(MAX_MEMORY_SECTION_BYTES))
        );
        if spent + entry.len() + 1 > MAX_MEMORY_SECTION_BYTES {
            break;
        }
        spent += entry.len() + 1;
        entries.push(entry);
        if hit["scope"]["project"].as_str() == Some(label) {
            labelled += 1;
        }
    }
    (entries, labelled)
}

/// Truncate to a BYTE budget on a CHARACTER boundary.
///
/// Two ways to get this wrong and both are live here. Byte-slicing a UTF-8
/// string mid-character panics, and a hook that panics is a hook that exits
/// non-zero. And the marker costs bytes: the first version of this took
/// `budget - 1` characters and then pushed a three-byte ellipsis, which
/// overran every budget it was given -- caught by
/// `clipping_never_splits_a_character` rather than by review.
fn clip(text: &str, budget: usize) -> String {
    const MARKER: &str = "\u{2026}";
    if text.len() <= budget {
        return text.to_owned();
    }
    let room = budget.saturating_sub(MARKER.len());
    let mut end = room.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut clipped = text[..end].to_owned();
    if budget >= MARKER.len() {
        clipped.push_str(MARKER);
    }
    clipped
}

/// The hook body: probe, retrieve, report. Exits 0 always -- see the module
/// documentation, and `the_hook_exits_zero_when_every_stage_fails`.
#[must_use]
pub fn session_start_output(
    engine: std::result::Result<&Engine, &ManagerError>,
    options: &SessionStartOptions,
) -> String {
    let deadline = Deadline::new(TOTAL_TIME_BUDGET);
    let registration = find_registration(&options.cwd);
    let probe = probe_mcp(registration.as_ref(), deadline.slice(PROBE_TIMEOUT));

    // The profile rung. UNGATED, and kept even though the probe supersedes it
    // for reachability: it is the only thing that separates "the memory
    // configuration is broken" from "the configuration is fine and the client
    // rejected the tool list", and those have different remedies.
    let (launch, engine_path) = match engine {
        Ok(engine) => {
            let outcome = match deadline.slice(LAUNCH_TIMEOUT) {
                Some(timeout) => match engine.run_bounded_in(
                    None,
                    &["profile", "launch", &options.profile],
                    None,
                    timeout,
                ) {
                    Ok(output) if output.success => Ok(()),
                    Ok(output) => Err(if output.stderr.is_empty() {
                        "the engine refused the profile".to_owned()
                    } else {
                        output.stderr
                    }),
                    Err(failure) => Err(failure.to_string()),
                },
                None => Err("skipped: the hook's time budget was already spent".to_owned()),
            };
            (outcome, Some(engine.path().to_path_buf()))
        }
        Err(error) => (Err(error.to_string()), None),
    };

    let project = match (engine, launch.is_ok()) {
        (Ok(engine), true) => resolve_project(engine, &options.cwd, deadline.slice(WHERE_TIMEOUT)),
        _ => None,
    };
    let label = project.as_ref().map(|(label, _)| label.clone());
    let memories = match (engine, options.retrieval, launch.is_ok()) {
        (_, false, _) => {
            Memories::Skipped("retrieval is off (--no-memories or KALEIDOSCOPE_HOOK_MEMORIES=0)")
        }
        (Ok(engine), true, true) => retrieve_memories(
            engine,
            &options.profile,
            label.as_deref(),
            &options.cwd,
            &deadline,
        ),
        (_, true, _) => Memories::Skipped("the profile did not launch, so nothing was retrieved"),
    };

    let tools_visible = registration.is_some()
        && probe.publishes_both()
        && matches!(&probe, Probe::Answered { contract: None, .. });

    let facts = probe_facts(
        options,
        registration.as_ref(),
        &probe,
        &launch,
        engine_path.as_deref(),
        project.as_ref(),
        &memories,
        tools_visible,
        &deadline,
    );
    let context = render_context(
        options,
        registration.as_ref(),
        &probe,
        &launch,
        project.as_ref(),
        &memories,
        tools_visible,
        &facts,
    );
    encode_hook_line(&context, &facts)
}

/// The machine-readable half. One line, one object, every rung the verdict was
/// computed from -- so a later session can be AUDITED rather than believed,
/// which is the whole reason the old unconditional sentence was a defect.
#[allow(clippy::too_many_arguments)]
fn probe_facts(
    options: &SessionStartOptions,
    registration: Option<&Registration>,
    probe: &Probe,
    launch: &std::result::Result<(), String>,
    engine_path: Option<&Path>,
    project: Option<&(String, PathBuf)>,
    memories: &Memories,
    tools_visible: bool,
    deadline: &Deadline,
) -> Value {
    let probe_value = match probe {
        Probe::Unregistered => json!({"outcome": "unregistered"}),
        Probe::Unusable { detail } => json!({"outcome": "unusable", "detail": detail}),
        Probe::NoAnswer { detail } => {
            // The identifier rides alongside the raw detail rather than
            // replacing it: the detail is what a person debugs with, the
            // identifier is what a program branches on.
            match entitlement_refusal(detail) {
                Some(identifier) => json!({
                    "outcome": "no_answer",
                    "detail": detail,
                    "entitlement_refusal": identifier,
                    "self_healing": refusal_is_self_healing(identifier),
                }),
                None => json!({"outcome": "no_answer", "detail": detail}),
            }
        }
        Probe::Answered {
            protocol,
            server,
            tools,
            contract,
            elapsed,
        } => json!({
            "outcome": "answered",
            "protocol": protocol,
            "server": server,
            "tools": tools,
            "client_contract_ok": contract.is_none(),
            "ms": elapsed.as_millis(),
        }),
    };
    let memories_value = match memories {
        Memories::Skipped(reason) => json!({"outcome": "skipped", "detail": reason}),
        Memories::Unavailable(detail) => json!({"outcome": "unavailable", "detail": detail}),
        Memories::Empty => json!({"outcome": "empty", "count": 0}),
        Memories::Found {
            entries,
            scope_requested,
            labelled,
            elapsed,
        } => json!({
            "outcome": "found",
            "count": entries.len(),
            // Deliberately two fields and not one. `scope_requested` is what
            // was ASKED; `labelled` is what came back carrying the project.
            // The old single `scoped` conflated them and read as the second
            // while only ever measuring the first.
            "scope_requested": scope_requested,
            "labelled_for_project": labelled,
            "ms": elapsed.as_millis(),
        }),
    };
    json!({
        "kaleidoscope_session_start": 1,
        "tools_visible": tools_visible,
        "reason": verdict_reason(registration, probe, tools_visible),
        "profile": options.profile,
        "engine": engine_path.map(|path| path.display().to_string()),
        "profile_launch": match launch {
            Ok(()) => json!("ok"),
            Err(detail) => json!(detail),
        },
        "registration": registration.map(|entry| json!({
            "scope": entry.scope,
            "source": entry.source.display().to_string(),
            "command": entry.display_command(),
        })),
        "probe": probe_value,
        "project": project.map(|(label, directory)| json!({
            "label": label,
            "directory": directory.display().to_string(),
        })),
        "memories": memories_value,
        "budget_bytes": MAX_CONTEXT_BYTES,
        "total_ms": deadline.elapsed().as_millis(),
    })
}

fn verdict_reason(
    registration: Option<&Registration>,
    probe: &Probe,
    tools_visible: bool,
) -> &'static str {
    if tools_visible {
        return "server publishes both tools and the tools/list result satisfies the client contract";
    }
    match probe {
        Probe::Unregistered => {
            if registration.is_none() {
                "no mcpServers.kaleidoscope entry applies to this project"
            } else {
                "unregistered"
            }
        }
        Probe::Unusable { .. } => "the registered command is not an executable file",
        Probe::NoAnswer { .. } => "the registered command did not answer tools/list",
        Probe::Answered { contract, .. } => {
            if contract.is_some() {
                "client_tools_list_contract"
            } else {
                "the server did not publish both search and remember"
            }
        }
    }
}

/// The half a model reads. Status first, because a memory quoted under a false
/// claim about how to reach more of them is worse than no memory at all.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn render_context(
    options: &SessionStartOptions,
    registration: Option<&Registration>,
    probe: &Probe,
    launch: &std::result::Result<(), String>,
    project: Option<&(String, PathBuf)>,
    memories: &Memories,
    tools_visible: bool,
    facts: &Value,
) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "{facts}");
    if tools_visible {
        let _ = writeln!(
            text,
            "Kaleidoscope MCP tools ARE reachable: mcp__{SERVER_KEY}__search and mcp__{SERVER_KEY}__remember. Probed by speaking MCP to {}, not assumed.",
            registration.map_or_else(
                || "the registered server".to_owned(),
                Registration::display_command
            )
        );
    } else if let Some(identifier) = match probe {
        Probe::NoAnswer { detail } => entitlement_refusal(detail),
        _ => None,
    }
    .filter(|identifier| refusal_is_self_healing(identifier))
    {
        // The self-healing case, and it must come FIRST in the paragraph.
        // The old text opened "NOT usable in this session" and only hedged
        // four lines later; a model reads the first sentence, believes it,
        // and never reaches the hedge. Front-loading is the entire fix --
        // the hedge was already there and did not work.
        let _ = writeln!(
            text,
            "Kaleidoscope's tools are probably fine — CALL THEM. This probe was refused by a \
             TRANSIENT entitlement check ({identifier}), which clears itself: the next gated \
             call starts a fresh revalidation. If mcp__{SERVER_KEY}__search and \
             mcp__{SERVER_KEY}__remember are in your tool list, use them normally and only \
             fall back if a call actually fails. Nothing re-probes after this line, so treating \
             it as a settled fact about the session is the one wrong move."
        );
        let _ = writeln!(
            text,
            "If a call does fail, the CLI is unaffected:\n  echo '{{\"query\":\"...\",\"top_k\":5}}' | kscope call --profile {} search",
            options.profile
        );
    } else {
        let _ = writeln!(
            text,
            "Kaleidoscope MCP tools are NOT usable in this session. {}",
            unreachable_detail(registration, probe)
        );
        // The profile rung goes BEFORE the fallback when it failed, because
        // then the fallback is not yet available either and "run this command"
        // above "that command cannot run" is advice in the wrong order.
        if let Err(detail) = launch {
            let _ = writeln!(
                text,
                "The engine itself is also unhealthy — profile `{}` did not launch: {detail}. Run `kaleidoscope doctor --json` first; until it passes, the CLI below cannot run either.",
                options.profile
            );
        }
        let _ = writeln!(
            text,
            "The CLI is the fallback — it is unaffected by the MCP fault, and that orthogonality is the point:\n  echo '{{\"query\":\"...\",\"top_k\":5}}' | kscope call --profile {} search\n  kscope schema search   # every accepted field, including memory_id lookups, which write no exposure row",
            options.profile
        );
        let _ = writeln!(
            text,
            "This probe watched the SERVER, not your tool list; no hook can see your tool list. If mcp__{SERVER_KEY}__search and mcp__{SERVER_KEY}__remember are in fact present, prefer them — those two are the whole tool surface."
        );
    }
    if tools_visible {
        if let Err(detail) = launch {
            let _ = writeln!(
                text,
                "Profile `{}` did not launch: {detail}. Run `kaleidoscope doctor --json`.",
                options.profile
            );
        }
    }
    match memories {
        Memories::Found {
            entries, labelled, ..
        } => {
            let label = project.map_or("this project", |(label, _)| label.as_str());
            // Phrased off `labelled`, never off "a scope filter was sent".
            // Three states, because they are three different claims and only
            // the first one licenses "recorded for {label}".
            let provenance = if *labelled == entries.len() {
                format!("recorded for {label}")
            } else if *labelled == 0 {
                format!(
                    "ranked for {label}, none of them carrying a project label — a memory with no project axis is not excluded by a scope filter, so these may belong to any project in this vault"
                )
            } else {
                format!(
                    "ranked for {label}; {labelled} of {} carry that project label and the rest carry none",
                    entries.len()
                )
            };
            let _ = writeln!(
                text,
                "\n{} memories {provenance} (budget {MAX_MEMORY_SECTION_BYTES} B; there are more — search for the rest):",
                entries.len(),
            );
            for entry in entries {
                let _ = writeln!(text, "{entry}");
            }
        }
        Memories::Empty => {
            let _ = writeln!(
                text,
                "\nThe vault holds no memories for this project yet. Record durable decisions as they are made."
            );
        }
        Memories::Unavailable(detail) => {
            let _ = writeln!(text, "\nNo memories were retrieved: {detail}.");
        }
        Memories::Skipped(reason) => {
            let _ = writeln!(text, "\nNo memories were retrieved: {reason}.");
        }
    }
    text
}

fn unreachable_detail(registration: Option<&Registration>, probe: &Probe) -> String {
    match probe {
        Probe::Unregistered => format!(
            "No `mcpServers.{SERVER_KEY}` entry applies to this project, so the harness starts no server. Run `kaleidoscope connect --host claude-code`."
        ),
        Probe::Unusable { detail } => format!(
            "The registered command cannot be run ({detail}). Run `kaleidoscope doctor --json`."
        ),
        Probe::NoAnswer { detail } => format!(
            "The registered command `{}` did not answer tools/list ({detail}).",
            registration.map_or_else(|| "?".to_owned(), Registration::display_command)
        ),
        Probe::Answered {
            contract, tools, ..
        } => match contract {
            Some(reason) => format!(
                "The server starts and publishes {}, but {reason}. No mcp__{SERVER_KEY}__* name will appear in your tool list.",
                if tools.is_empty() {
                    "nothing".to_owned()
                } else {
                    tools.join(" and ")
                }
            ),
            None => format!(
                "The server answered but published {} rather than search and remember.",
                if tools.is_empty() {
                    "no tools".to_owned()
                } else {
                    tools.join(", ")
                }
            ),
        },
    }
}

/// The documented `SessionStart` output contract, bounded.
///
/// Shape confirmed against the official hooks reference
/// (code.claude.com/docs/en/hooks): `hookSpecificOutput.hookEventName` plus a
/// STRING `additionalContext`, applied only when the hook exits 0, and
/// concatenated across multiple `SessionStart` hooks.
///
/// Bounded by shrinking the context and re-encoding, never by discarding it:
/// the previous implementation replaced an over-long context with a generic
/// "could not be validated" line, which threw away the entire finding to save
/// bytes. The memory section goes first because the status block is the part
/// that must survive.
fn encode_hook_line(context: &str, facts: &Value) -> String {
    let mut candidate = clip_context(context);
    let mut line = wrap_hook_line(&candidate);
    if line.len() <= MAX_HOOK_OUTPUT_BYTES {
        return line;
    }
    candidate = clip_context(context.split("\n\n").next().unwrap_or(context));
    line = wrap_hook_line(&candidate);
    if line.len() <= MAX_HOOK_OUTPUT_BYTES {
        return line;
    }
    // Last resort: the machine-readable line alone. It is one line, it carries
    // `tools_visible`, and it is what an audit needs.
    wrap_hook_line(&clip(&facts.to_string(), MAX_CONTEXT_BYTES))
}

fn clip_context(context: &str) -> String {
    clip(context, MAX_CONTEXT_BYTES)
}

fn wrap_hook_line(context: &str) -> String {
    serde_json::to_string(&json!({
        "hookSpecificOutput": {
            "hookEventName": EVENT,
            "additionalContext": context,
        }
    }))
    .unwrap_or_default()
}

/// The harness's own hook input, read from stdin under a short timeout.
///
/// `cwd` is the field that matters: it is the SESSION's working directory, and
/// the hook process's own is not guaranteed to be it. Read on a thread with a
/// `recv_timeout` because run by hand from a terminal stdin is a tty and the
/// read never returns -- and a hook that blocks on a tty is a hook that hangs
/// every session start of anyone who tries it manually.
#[must_use]
pub fn read_hook_input() -> Option<Value> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let read = std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut text);
        let _ = sender.send(read.ok().map(|_| text));
    });
    let text = receiver.recv_timeout(STDIN_TIMEOUT).ok()??;
    serde_json::from_str(&text).ok()
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
    let document: Value = serde_json::from_slice(bytes).map_err(|_| {
        ManagerError::InvalidHostConfig("settings.json is not valid JSON".to_owned())
    })?;
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

// THREE PROBES, ONE SIGNATURE, deliberately.
//
// None of them can fail today, and clippy is right that the `Result` is
// unnecessary in isolation. They are kept identical because they are read as a
// family and the decision below matches on all three at once -- and the
// duplicate-entry defect was caused precisely by two of them being conflated.
// A signature that differs between them is an invitation to conflate them
// again; a wrapper that costs nothing is not.
#[allow(clippy::unnecessary_wraps)]
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

/// Elements exactly equal to the entry this manager would write, REGARDLESS of
/// any receipt.
///
/// Deliberately separate from the two probes beside it, because they answer
/// three different questions: `matching_indices` asks "is this the entry the
/// RECEIPT names", this asks "is this the entry we WOULD write", and
/// `resembling_indices` asks "does this carry our command but differ". Folding
/// the first two together is what made a receipt-less identical entry invisible
/// and got a second copy appended.
#[allow(clippy::unnecessary_wraps)]
fn identical_indices(document: &Value, desired: &Value) -> Result<Vec<usize>> {
    Ok(event_array(document).map_or_else(Vec::new, |entries| {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| *entry == desired)
            .map(|(index, _)| index)
            .collect()
    }))
}

/// Elements carrying our exact `command` string but not equal to the owned
/// entry -- a user-edited copy.
#[allow(clippy::unnecessary_wraps)]
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
    let object = document.as_object_mut().ok_or_else(|| {
        ManagerError::InvalidHostConfig("settings.json is not an object".to_owned())
    })?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| ManagerError::InvalidHostConfig("hooks is not an object".to_owned()))?;
    let array = hooks
        .entry(EVENT)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| ManagerError::InvalidHostConfig(format!("hooks.{EVENT} is not an array")))?;
    array.push(entry);
    Ok(())
}

fn replace_entry(document: &mut Value, index: usize, entry: Value) -> Result<()> {
    let array = document
        .get_mut("hooks")
        .and_then(|hooks| hooks.get_mut(EVENT))
        .and_then(Value::as_array_mut)
        .ok_or(ManagerError::InvalidOwnerReceipt)?;
    *array
        .get_mut(index)
        .ok_or(ManagerError::InvalidOwnerReceipt)? = entry;
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
        adopted: false,
        formatting_preserved: false,
        original,
        receipt_original,
        // NOT `Remove`: a no-op plan must not hold a value that would delete
        // the user's settings file.
        write: TargetWrite::Leave,
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

    fn options() -> SessionStartOptions {
        SessionStartOptions {
            profile: "default".to_owned(),
            cwd: std::env::temp_dir(),
            retrieval: false,
        }
    }

    /// T-B22 half two: the hook's own stdout parses as the documented output
    /// contract and is bounded. Asserted on the parsed fields, not on "it did
    /// not error".
    #[test]
    fn the_hook_emits_the_documented_output_contract_and_is_bounded() {
        let line = session_start_output(Err(&ManagerError::EngineNotFound), &options());
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
        // T-B23: an unusable configuration is REPORTED, not swallowed. Both
        // halves -- an empty-output implementation fails this, an exit-1
        // implementation fails the CLI-level assertion in tests/manager_cli.rs.
        assert!(
            context.contains("doctor") || context.contains("kaleidoscope connect"),
            "a broken configuration must name the recovery command: {context}"
        );
    }

    /// ITEM 3, the defect this change exists for. The hook must never again
    /// emit a bare success string: the FIRST line of the context is a
    /// machine-readable object carrying `tools_visible` and the rungs it was
    /// computed from, so a later session can be audited rather than believed.
    ///
    /// Driven through the real entry point with no engine at all, which is the
    /// path that used to print "could not be resolved" and nothing else.
    #[test]
    fn the_hook_publishes_a_machine_readable_verdict_and_never_a_bare_success_string() {
        let line = session_start_output(Err(&ManagerError::EngineNotFound), &options());
        let parsed: Value = serde_json::from_str(&line).unwrap();
        let context = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        let first = context
            .lines()
            .next()
            .expect("the context must have a line");
        let facts: Value = serde_json::from_str(first)
            .unwrap_or_else(|error| panic!("first line must be JSON ({error}): {first}"));
        assert_eq!(facts["kaleidoscope_session_start"], json!(1));
        assert!(
            facts["tools_visible"].is_boolean(),
            "tools_visible must be a boolean, not absent or a string: {facts}"
        );
        assert!(
            facts["probe"]["outcome"].is_string(),
            "the verdict must say what was probed: {facts}"
        );
        assert!(
            facts["total_ms"].is_number(),
            "the hook must publish its own wall time: {facts}"
        );
        // The bare-success string that stood here for a whole session.
        assert!(
            !context.contains("Kaleidoscope memory is connected"),
            "the hook re-asserted a state it never checked: {context}"
        );
    }

    /// ITEM 3's other half: when the tools are NOT visible, the hook must give
    /// the working fallback rather than only naming the fault. The CLI works
    /// when MCP does not, and that orthogonality is the whole point.
    ///
    /// Driven through `render_context` and not through `session_start_output`.
    /// The end-to-end version asserted `tools_visible == false` "because a temp
    /// directory has no Kaleidoscope MCP registration" -- which stopped being
    /// true the moment the USER-scope registration landed, since a user-scope
    /// `mcpServers.kaleidoscope` applies to every directory on the machine
    /// including a temp one. That is the registration working as designed, so
    /// the test was reading the developer's own `~/.claude.json`: green on a
    /// machine that had never run `kaleidoscope connect` and red on every
    /// machine that had. It failed here for exactly that reason, and pinning it
    /// with a `KALEIDOSCOPE_USER_HOME` override would have traded a
    /// machine-dependent test for a process-global env write racing the other
    /// two tests that call `session_start_output`.
    ///
    /// Every unreachable arm is covered, because the fallback is only useful if
    /// it appears on the arm the user actually hit.
    #[test]
    fn an_unreachable_tool_surface_carries_the_cli_fallback() {
        let unreachable = [
            Probe::Unregistered,
            Probe::Unusable {
                detail: "/nonexistent/kscope: canonicalize engine failed (NotFound)".to_owned(),
            },
            Probe::NoAnswer {
                detail: "the server returned no tools/list result".to_owned(),
            },
            // The 2026-08-27 arm: the server is up and publishes both tools,
            // and the client still drops them.
            Probe::Answered {
                protocol: Some("2026-07-28".to_owned()),
                server: Some("rmcp 3.1.0".to_owned()),
                tools: vec!["remember".to_owned(), "search".to_owned()],
                contract: client_contract(&json!({"tools": []})),
                elapsed: Duration::from_millis(40),
            },
        ];
        for probe in &unreachable {
            let text = render_context(
                &options(),
                None,
                probe,
                &Ok(()),
                None,
                &Memories::Empty,
                false,
                &json!({}),
            );
            assert!(
                text.contains("kscope call --profile default search"),
                "the fallback must be a command that can be run: {text}"
            );
            assert!(
                text.contains("NOT usable"),
                "the fault must be stated plainly: {text}"
            );
        }
    }

    /// Realistic captured stderr: the engine writes its prose, then
    /// `AGENT_REMEDIATION`, then the marker as the final line.
    fn refusal_stderr(identifier: &str) -> String {
        format!(
            "kscope: the alpha key in KALEIDOSCOPE_API_KEY could not be revalidated within the\n\
             grace window.\n\
             Reconnect to the network and run any gated command again.\n\
             kscope-entitlement-refusal: {identifier}\n"
        )
    }

    #[test]
    fn the_marker_is_read_from_the_end_of_captured_output() {
        assert_eq!(
            entitlement_refusal(&refusal_stderr("E_GRACE_EXPIRED")),
            Some("E_GRACE_EXPIRED")
        );
        // A stderr truncated from the FRONT still ends in the marker, which is
        // why the scan runs backwards.
        let flooded = format!("{}{}", "noise\n".repeat(500), refusal_stderr("E_REVOKED"));
        assert_eq!(entitlement_refusal(&flooded), Some("E_REVOKED"));
        // Output with no marker at all must not be mistaken for a refusal.
        assert_eq!(
            entitlement_refusal("the server returned no tools/list result"),
            None
        );
        assert_eq!(entitlement_refusal("kscope-entitlement-refusal: "), None);
    }

    #[test]
    fn only_the_two_recoverable_identifiers_are_self_healing() {
        assert!(refusal_is_self_healing("E_UNVERIFIED"));
        assert!(refusal_is_self_healing("E_GRACE_EXPIRED"));
        for permanent in [
            "E_NO_KEY",
            "E_KEY_FILE_UNUSABLE",
            "E_MALFORMED_KEY",
            "E_UNKNOWN_KEY",
            "E_REVOKED",
            "E_KEY_EXPIRED",
            "E_CLOCK_BACKWARDS",
            "E_UNKNOWN",
        ] {
            assert!(
                !refusal_is_self_healing(permanent),
                "{permanent} needs a human and must stay a relay"
            );
        }
    }

    /// The defect this whole change exists for, asserted as a property of the
    /// rendered text rather than of the classifier: a transient refusal must
    /// not be reported as a settled fact about the session.
    #[test]
    fn a_self_healing_refusal_tells_the_model_to_call_the_tools() {
        for identifier in ["E_UNVERIFIED", "E_GRACE_EXPIRED"] {
            let text = render_context(
                &options(),
                None,
                &Probe::NoAnswer {
                    detail: refusal_stderr(identifier),
                },
                &Ok(()),
                None,
                &Memories::Empty,
                false,
                &json!({}),
            );
            assert!(
                !text.contains("NOT usable"),
                "{identifier} is recoverable and must not be reported as a settled fault: {text}"
            );
            assert!(
                text.contains("CALL THEM"),
                "{identifier} must instruct the model to try the tools: {text}"
            );
            assert!(
                text.contains(identifier),
                "the identifier itself must survive into the text: {text}"
            );
            // The lead sentence is the fix. A hedge further down is what the
            // old text already had, and it did not work.
            let lead = text
                .lines()
                .find(|line| line.contains("Kaleidoscope"))
                .unwrap_or("");
            assert!(
                lead.contains("CALL THEM"),
                "the instruction must be in the FIRST sentence about Kaleidoscope, not below it: {lead}"
            );
            assert!(
                text.contains("kscope call --profile default search"),
                "the fallback must still be reachable: {text}"
            );
        }
    }

    #[test]
    fn a_permanent_refusal_is_still_reported_as_a_fault() {
        let text = render_context(
            &options(),
            None,
            &Probe::NoAnswer {
                detail: refusal_stderr("E_REVOKED"),
            },
            &Ok(()),
            None,
            &Memories::Empty,
            false,
            &json!({}),
        );
        assert!(
            text.contains("NOT usable"),
            "a revoked key is not self-healing and must stay plain: {text}"
        );
    }

    /// Binds both constants to the published cross-repo contract, so a code
    /// added or renamed on the engine side cannot silently stop being
    /// classified here. This is the check whose absence let the manager ship
    /// knowing none of these identifiers while the Python client asserted all
    /// of them.
    #[test]
    fn the_classifier_matches_the_published_entitlement_contract() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("reference/entitlement-contract-v1.json");
        let contract: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("contract is readable"))
                .expect("contract is JSON");
        assert_eq!(
            contract["refusal_marker_prefix"].as_str(),
            Some(ENTITLEMENT_REFUSAL_MARKER),
            "the marker this hook scans for is fixed by the contract"
        );
        let published: Vec<&str> = contract["refusal_identifiers"]
            .as_array()
            .expect("refusal_identifiers is an array")
            .iter()
            .chain(
                contract["sdk_only_identifiers"]
                    .as_array()
                    .map(|values| values.iter())
                    .unwrap_or_default(),
            )
            .map(|value| value.as_str().expect("identifier is a string"))
            .collect();
        for identifier in SELF_HEALING_REFUSALS {
            assert!(
                published.contains(&identifier),
                "{identifier} is classified here but is not in the contract"
            );
        }
        // Every published identifier must be classified deliberately, so a new
        // one fails this test rather than defaulting into the permanent bucket
        // without anybody deciding it belongs there.
        let decided: Vec<&str> = [
            "E_NO_KEY",
            "E_KEY_FILE_UNUSABLE",
            "E_MALFORMED_KEY",
            "E_UNVERIFIED",
            "E_UNKNOWN_KEY",
            "E_REVOKED",
            "E_KEY_EXPIRED",
            "E_GRACE_EXPIRED",
            "E_CLOCK_BACKWARDS",
            "E_UNKNOWN",
        ]
        .to_vec();
        for identifier in &published {
            assert!(
                decided.contains(identifier),
                "{identifier} is published but this hook has never decided whether it is \
                 self-healing -- add it to the list above with a reason"
            );
        }
    }

    /// The end-to-end half, asserting only what holds on ANY machine: whatever
    /// the ambient registration is, the two must agree. A `tools_visible: true`
    /// that carried no tool names, or a `false` that carried no fallback, is
    /// the failure either way.
    #[test]
    fn the_verdict_and_the_prose_agree_whatever_this_machine_is_registered_for() {
        let line = session_start_output(Err(&ManagerError::EngineNotFound), &options());
        let parsed: Value = serde_json::from_str(&line).unwrap();
        let context = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        let facts: Value = serde_json::from_str(context.lines().next().unwrap()).unwrap();
        let visible = facts["tools_visible"]
            .as_bool()
            .expect("tools_visible must be a boolean");
        if visible {
            assert!(
                context.contains("ARE reachable"),
                "a true verdict must name the reachable tools: {context}"
            );
        } else {
            assert!(
                context.contains("kscope call --profile default search"),
                "a false verdict must carry the working fallback: {context}"
            );
        }
    }

    /// A scoped REQUEST must never be rendered as a scoped ANSWER.
    ///
    /// Live on 2026-08-27: `{"scope":{"project":"fakeproj"}}` against a scratch
    /// directory created seconds earlier served three memories, every one of
    /// them carrying `project: null`, and the header read "3 memories already
    /// recorded for fakeproj". The identical query with
    /// `{"project":"zzz-definitely-not-a-project-9999"}` served the same three,
    /// which is what proves the filter never discriminated. Driven through
    /// `render_hits` -- the function that actually decides the count -- rather
    /// than by hand-building the counter it feeds.
    #[test]
    fn unlabelled_hits_are_not_reported_as_recorded_for_the_project() {
        let served = json!({"selected_hits": [
            {"memory_id": "mem_a", "memory_type": "procedure",
             "content_md": "# One\nbody one", "scope": {"project": Value::Null}},
            {"memory_id": "mem_b", "memory_type": "architecture",
             "content_md": "# Two\nbody two", "scope": {"project": "fakeproj"}},
        ]});
        let (entries, labelled) = render_hits(&served, "fakeproj");
        assert_eq!(entries.len(), 2, "both hits are within the byte budget");
        assert_eq!(
            labelled, 1,
            "exactly one hit carries the project axis; a null axis must not count"
        );

        // All-null is the case that produced the false sentence.
        let all_null = json!({"selected_hits": [
            {"memory_id": "mem_a", "memory_type": "procedure",
             "content_md": "# One\nbody one", "scope": {"project": Value::Null}},
        ]});
        let (entries, labelled) = render_hits(&all_null, "fakeproj");
        assert_eq!(entries.len(), 1);
        assert_eq!(labelled, 0);

        let text = render_context(
            &options(),
            None,
            &Probe::Unregistered,
            &Ok(()),
            Some(&("fakeproj".to_owned(), PathBuf::from("/tmp/fakeproj"))),
            &Memories::Found {
                entries,
                // The request DID carry a scope filter. That must not be
                // enough to earn the "recorded for" phrasing.
                scope_requested: true,
                labelled,
                elapsed: Duration::from_millis(1),
            },
            false,
            &json!({}),
        );
        assert!(
            !text.contains("recorded for fakeproj"),
            "a scoped request with zero labelled hits must not claim ownership: {text}"
        );
        assert!(
            text.contains("not excluded by a scope filter"),
            "the reader must be told why these may belong to another project: {text}"
        );
    }

    /// The client-side contract check is the difference between "the server
    /// starts" and "the tools reach the model", and it was the whole 2026-08-27
    /// failure. Both directions, because a check that only ever returns `Some`
    /// would pass a one-sided test while pinning `tools_visible` at false.
    #[test]
    fn the_client_contract_check_sees_both_the_shipped_result_and_a_conforming_one() {
        // What rmcp 3.1.0 actually returns at protocol 2026-07-28, verbatim.
        let shipped = json!({"resultType": "complete", "tools": [{"name": "remember"}]});
        assert!(
            client_contract(&shipped).is_some(),
            "the shipped result must be recognised as the one the client rejects"
        );
        let conforming = json!({
            "resultType": "complete",
            "tools": [{"name": "remember"}],
            "ttlMs": 60_000,
            "cacheScope": "private",
        });
        assert!(
            client_contract(&conforming).is_none(),
            "a result carrying both fields must pass, or the check can only ever say no"
        );
        // A present-but-wrong `cacheScope` is the client's second complaint and
        // must not be accepted just because the key exists.
        let wrong = json!({"ttlMs": 1, "cacheScope": "everyone"});
        assert!(client_contract(&wrong).is_some());
    }

    /// The byte budget is enforced by SHRINKING, not by discarding. The old
    /// implementation replaced an over-long context with a generic sentence,
    /// which threw the finding away to save bytes.
    #[test]
    fn an_oversized_context_is_clipped_rather_than_replaced() {
        let facts = json!({"kaleidoscope_session_start": 1, "tools_visible": false});
        let context = format!(
            "{facts}
head line

{}",
            "x".repeat(64 * 1024)
        );
        let line = encode_hook_line(&context, &facts);
        assert!(
            line.len() <= MAX_HOOK_OUTPUT_BYTES,
            "hook output is {} bytes",
            line.len()
        );
        let parsed: Value = serde_json::from_str(&line).unwrap();
        let emitted = parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(
            emitted.contains("\"tools_visible\":false") || emitted.contains("tools_visible"),
            "the verdict was discarded to make room: {emitted}"
        );
        assert!(
            emitted.contains("head line"),
            "the status block must survive clipping: {emitted}"
        );
    }

    /// `clip` slices UTF-8, and a hook that panics is a hook that exits
    /// non-zero. Driven with a budget that lands inside a multi-byte character.
    #[test]
    fn clipping_never_splits_a_character() {
        let text = "\u{e9}".repeat(64);
        for budget in 1..text.len() {
            let clipped = clip(&text, budget);
            assert!(clipped.len() <= budget, "clip({budget}) overran its budget");
        }
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
        let installed: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
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

#[cfg(test)]
mod adoption_tests {
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

    fn entries(target: &Path) -> Vec<Value> {
        let document: Value = serde_json::from_slice(&fs::read(target).unwrap()).unwrap();
        document["hooks"][EVENT]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    /// THE MEASURED rc=0 DEFECT: an identical entry with no receipt used to be
    /// APPENDED A SECOND TIME, at rc=0, wedging teardown afterwards.
    ///
    /// Asserted on the ARRAY LENGTH and on the subsequent teardown succeeding.
    /// The failure mode before the fix is a count, not an error string, so no
    /// message assertion could have caught it.
    #[test]
    fn an_identical_hook_entry_is_adopted_not_duplicated() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        let desired = owned_entry(&manager(), "default");
        fs::write(
            &target,
            serde_json::to_vec_pretty(&json!({"hooks": {EVENT: [desired.clone()]}})).unwrap(),
        )
        .unwrap();
        let before = digest_bytes(&fs::read(&target).unwrap());

        let plan = plan_install_at(Scope::Project, &manager(), "default", &target).unwrap();
        assert_eq!(plan.action, HookAction::Adopt);
        assert_eq!(plan.write, TargetWrite::Leave);
        plan.apply().unwrap();

        assert_eq!(
            entries(&target).len(),
            1,
            "a second identical entry was appended"
        );
        assert_eq!(
            digest_bytes(&fs::read(&target).unwrap()),
            before,
            "adoption must not touch the file"
        );
        assert!(
            !sibling_path(&target, ".kaleidoscope-backup")
                .unwrap()
                .exists(),
            "adoption writes no backup"
        );

        // The wedge the duplicate produced: teardown refused with count > 1.
        let removal = plan_remove_at(Scope::Project, &target, false).unwrap();
        removal.apply().unwrap();
        assert!(
            entries(&target).is_empty(),
            "an adopted ENTRY is removed by teardown -- it is reproducible from the profile"
        );
        assert!(target.exists(), "the file itself is not deleted");
    }

    /// Two identical entries and no receipt is ambiguous, and it refuses rather
    /// than picking one. The message must name the manual step.
    #[test]
    fn two_identical_hook_entries_without_a_receipt_refuse() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        let desired = owned_entry(&manager(), "default");
        fs::write(
            &target,
            serde_json::to_vec_pretty(&json!({"hooks": {EVENT: [desired.clone(), desired]}}))
                .unwrap(),
        )
        .unwrap();
        let rendered = plan_install_at(Scope::Project, &manager(), "default", &target)
            .expect_err("two identical entries must refuse")
            .to_string();
        assert!(rendered.contains("2 identical"), "{rendered}");
        assert!(rendered.contains("Remove all but one"), "{rendered}");
    }

    /// A RESEMBLING entry still refuses, and the message must not name a flag
    /// that cannot be invoked.
    ///
    /// It used to end "or re-run with --force" -- a flag `run_init` does not
    /// parse and `plan_install_at` does not take. Both halves are asserted:
    /// the flag that works is present, the one that never existed is absent.
    #[test]
    fn a_resembling_hook_entry_refuses_and_names_no_hooks_not_force() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        let mut resembling = owned_entry(&manager(), "default");
        resembling["hooks"][0]["timeout"] = json!(99);
        fs::write(
            &target,
            serde_json::to_vec_pretty(&json!({"hooks": {EVENT: [resembling]}})).unwrap(),
        )
        .unwrap();
        let rendered = plan_install_at(Scope::Project, &manager(), "default", &target)
            .expect_err("a resembling entry must refuse")
            .to_string();
        assert!(rendered.contains("--no-hooks"), "{rendered}");
        assert!(
            !rendered.contains("--force"),
            "the message names a flag this command cannot accept: {rendered}"
        );
    }

    /// Removing an adopted entry keeps every other key in the file.
    ///
    /// "the entry is gone" alone would pass for an implementation that deleted
    /// the file, so the surrounding keys are compared explicitly.
    #[test]
    fn teardown_of_an_adopted_entry_keeps_the_rest_of_the_file() {
        let temp = TempDir::new().unwrap();
        let target = settings(&temp);
        let desired = owned_entry(&manager(), "default");
        fs::write(
            &target,
            serde_json::to_vec_pretty(&json!({
                "hooks": {EVENT: [desired]},
                "permissions": {"allow": ["Bash(ls:*)"]},
                "model": "opus",
            }))
            .unwrap(),
        )
        .unwrap();
        plan_install_at(Scope::Project, &manager(), "default", &target)
            .unwrap()
            .apply()
            .unwrap();
        let plan = plan_remove_at(Scope::Project, &target, false).unwrap();
        assert_eq!(plan.restore, Some(RestoreTier::Structural));
        plan.apply().unwrap();

        let after: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert!(
            after.get("hooks").is_none(),
            "the entry and its container go"
        );
        assert_eq!(after["model"], json!("opus"), "other keys must survive");
        assert_eq!(after["permissions"]["allow"][0], json!("Bash(ls:*)"));
        assert!(
            !sibling_path(&target, ".kaleidoscope-owner.json")
                .unwrap()
                .exists()
        );
    }
}
