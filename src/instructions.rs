use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::project_root;
use crate::error::{ManagerError, Result};
use crate::fs_safe::{
    FileLock, Snapshot, assert_unchanged, atomic_remove, atomic_write, digest_bytes, read_snapshot,
    prune_empty_managed_directories, restore_snapshot, sibling_path, write_bounded_backup,
};
use crate::host::Host;

const OWNER: &str = "kaleidoscope-manager-v1";
const RECEIPT_VERSION: u32 = 2;
const MAX_INSTRUCTION_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstructionTarget {
    Skill,
    Agents,
    Claude,
    Cursor,
}

impl InstructionTarget {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Agents => "agents",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
        }
    }

    /// `skill` is the one target whose location depends on the harness, so it
    /// is the one target that refuses to guess. Defaulting is what put the file
    /// in `.agents/skills/` for Claude Code, which does not read that path.
    #[must_use]
    pub const fn requires_host(self) -> bool {
        matches!(self, Self::Skill)
    }
}

impl FromStr for InstructionTarget {
    type Err = ManagerError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "skill" | "skill.md" => Ok(Self::Skill),
            "agents" | "agents.md" => Ok(Self::Agents),
            "claude" | "claude.md" => Ok(Self::Claude),
            "cursor" | "cursor-rule" => Ok(Self::Cursor),
            _ => Err(ManagerError::Usage(
                "instruction target must be skill, agents, claude, or cursor".to_owned(),
            )),
        }
    }
}

/// How the manager owns bytes in the target file.
///
/// `MarkerBlock` is a delimited span inside a file the user also owns.
/// `WholeFile` is a file the manager wrote in full, whose ownership is carried
/// entirely by the receipt digest -- no marker inside the content.
///
/// The skill file moved to `WholeFile` because the marker used to be injected
/// INSIDE the YAML frontmatter:
///
/// ```text
/// ---
/// # >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=skill
/// name: use-kaleidoscope
/// ```
///
/// It parses (`#` is a YAML comment), but it means the shipped SKILL.md and the
/// installed one are different files, and any strict frontmatter reader is a
/// risk. Cursor keeps `MarkerBlock`: its frontmatter is Cursor's own and there
/// is no reported symptom, so changing it would be an untested change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedShape {
    MarkerBlock,
    WholeFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionAction {
    Add,
    Update,
    Remove,
    AlreadyInstalled,
    AlreadyRemoved,
}

/// Which restore tier a removal achieved. Reporting this is the mechanism, not
/// decoration: a claim of reversibility that cannot say which of the two it
/// achieved is a claim nothing can check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreTier {
    /// The file was byte-identical to what the manager wrote, so the pre-write
    /// bytes were put back verbatim (or the manager-created file was deleted).
    ByteIdentical,
    /// The user edited the file after install. Byte-identity to the pre-install
    /// state is not merely hard, it is WRONG -- their edit must survive. The
    /// owned span is parsed out and the rest re-encoded.
    Structural,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstructionReceipt {
    version: u32,
    owner: String,
    target: InstructionTarget,
    shape: OwnedShape,
    owned_sha256: String,
    owned_block: String,
    /// Digest of the file BEFORE the manager first wrote it.
    /// `digest_bytes(b"<absent>")` when the manager created the file, which is
    /// exactly what `Snapshot::absent()` produces.
    pre_sha256: String,
    /// Digest of the bytes the manager wrote. Tier 1 fires iff the file still
    /// matches this.
    post_sha256: String,
    /// The exact separator inserted between the user's text and the owned
    /// block. Two heuristics that must agree become one recorded fact: the old
    /// code chose the separator by inspecting the text in `install_block` and
    /// removed it by a different rule in `remove_block`, which is why a file
    /// with no trailing newline came back with one.
    separator: String,
    file_created: bool,
}

impl InstructionReceipt {
    /// The receipt carries NO host.
    ///
    /// `--host` selects the PATH and nothing else, and two harnesses can share
    /// one path: codex and opencode both read `.agents/skills/`, exactly as they
    /// both read `AGENTS.md`. A receipt that recorded the installing host would
    /// make the second harness's install refuse its own file with
    /// `InvalidOwnerReceipt`, which is what happened the first time this was
    /// written. The receipt sits beside the file it owns, so the path already
    /// identifies it.
    fn validate(&self, target: InstructionTarget) -> Result<()> {
        if self.version != RECEIPT_VERSION
            || self.owner != OWNER
            || self.target != target
            || self.owned_sha256 != digest_bytes(self.owned_block.as_bytes())
        {
            return Err(ManagerError::InvalidOwnerReceipt);
        }
        // A `WholeFile` receipt validates on its digest alone -- there is no
        // marker in the content to check, which is the whole point.
        if self.shape == OwnedShape::MarkerBlock {
            let start = marker_start(target);
            let end = format!("{}\n", marker_end(target));
            if !self.owned_block.starts_with(start) || !self.owned_block.ends_with(&end) {
                return Err(ManagerError::InvalidOwnerReceipt);
            }
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
pub struct InstructionPlan {
    pub target_kind: InstructionTarget,
    pub host: Option<Host>,
    pub action: InstructionAction,
    pub target: PathBuf,
    pub receipt_path: PathBuf,
    pub backup_path: PathBuf,
    pub restore: Option<RestoreTier>,
    /// Set only on a forced removal: the bytes that will be discarded, so the
    /// user can see what they lose before it is gone.
    pub discarded: Option<String>,
    preview: String,
    original: Snapshot,
    receipt_original: Snapshot,
    updated: Option<Vec<u8>>,
    receipt_after: Option<InstructionReceipt>,
    /// True when the backup is provably redundant after a Tier-1 restore --
    /// the file now equals what the backup held. Never true on Tier 2, where
    /// the backup is the user's only copy of the pre-edit state.
    remove_backup: bool,
}

impl InstructionPlan {
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }

    #[must_use]
    pub const fn is_noop(&self) -> bool {
        matches!(
            self.action,
            InstructionAction::AlreadyInstalled | InstructionAction::AlreadyRemoved
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
            MAX_INSTRUCTION_BYTES,
            "agent instruction file",
        )?;
        assert_unchanged(
            &self.receipt_path,
            &self.receipt_original,
            MAX_RECEIPT_BYTES,
            "instruction owner receipt",
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
            if assert_unchanged(
                &self.target,
                &snapshot_after(self.updated.as_deref(), self.original.unix_mode),
                MAX_INSTRUCTION_BYTES,
                "agent instruction file",
            )
            .is_ok()
            {
                restore_snapshot(&self.target, &self.original)?;
            }
            return Err(error);
        }
        if self.remove_backup {
            // Provably redundant: the file now equals what the backup held.
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
            "instruction": self.target_kind,
            "host": self.host,
            "target": self.target,
            "owner_receipt": self.receipt_path,
            "backup": self.backup_path,
        });
        if let Some(restore) = self.restore {
            value["restore"] = json!(restore);
            if restore == RestoreTier::Structural {
                value["formatting"] = json!("normalized");
            }
        }
        if let Some(discarded) = &self.discarded {
            value["ownership"] = json!("forced");
            value["discarded_user_edits"] = json!(true);
            value["discarded_sha256"] = json!(digest_bytes(discarded.as_bytes()));
        }
        value
    }
}

pub fn plan_install(
    target_kind: InstructionTarget,
    host: Option<Host>,
    explicit_project: Option<&Path>,
    force: bool,
) -> Result<InstructionPlan> {
    plan_install_at(target_kind, host, &project_root(explicit_project)?, force)
}

pub fn plan_remove(
    target_kind: InstructionTarget,
    host: Option<Host>,
    explicit_project: Option<&Path>,
    force: bool,
) -> Result<InstructionPlan> {
    plan_remove_at(target_kind, host, &project_root(explicit_project)?, force)
}

/// The skill's absolute path, per harness.
///
/// Claude Code reads `.claude/skills/<name>/SKILL.md` (project) and
/// `~/.claude/skills/` (user); it does not read `.agents/skills/`. The engine
/// repository itself carries `.claude/skills/use-kaleidoscope/SKILL.md`, and
/// its sessions load it. Until this change the one harness whose instruction
/// block said "read and follow `.agents/skills/use-kaleidoscope/SKILL.md`" was
/// the harness that would not find it there -- and would not auto-load it as a
/// skill either way, because a skill outside `.claude/skills/` is just a
/// markdown file.
pub fn instruction_path(
    target_kind: InstructionTarget,
    host: Option<Host>,
    project: &Path,
) -> Result<PathBuf> {
    if !project.is_absolute() {
        return Err(ManagerError::UnsafePath {
            target: "project directory",
            reason: "path must be absolute",
        });
    }
    Ok(match target_kind {
        InstructionTarget::Skill => {
            let host = host.ok_or_else(|| {
                ManagerError::Usage(
                    "instructions install skill requires --host: the skill directory differs per harness (claude-code reads .claude/skills/, codex and opencode read .agents/skills/, cursor has none). Pass --host codex|claude-code|cursor|opencode."
                        .to_owned(),
                )
            })?;
            match host {
                Host::ClaudeCode => project.join(".claude/skills/use-kaleidoscope/SKILL.md"),
                Host::Codex | Host::OpenCode => {
                    project.join(".agents/skills/use-kaleidoscope/SKILL.md")
                }
                Host::Cursor => {
                    return Err(ManagerError::Usage(
                        "Cursor has no skill directory; install the cursor rule instead (kaleidoscope instructions install cursor)"
                            .to_owned(),
                    ));
                }
            }
        }
        InstructionTarget::Agents => project.join("AGENTS.md"),
        InstructionTarget::Claude => project.join("CLAUDE.md"),
        InstructionTarget::Cursor => project.join(".cursor/rules/kaleidoscope.mdc"),
    })
}

#[must_use]
pub const fn owned_shape(target: InstructionTarget) -> OwnedShape {
    match target {
        InstructionTarget::Skill => OwnedShape::WholeFile,
        InstructionTarget::Agents | InstructionTarget::Claude | InstructionTarget::Cursor => {
            OwnedShape::MarkerBlock
        }
    }
}

pub fn plan_install_at(
    target_kind: InstructionTarget,
    host: Option<Host>,
    project: &Path,
    force: bool,
) -> Result<InstructionPlan> {
    let target = instruction_path(target_kind, host, project)?;
    let receipt_path = sibling_path(&target, ".kaleidoscope-instruction-owner.json")?;
    let backup_path = sibling_path(&target, ".kaleidoscope-backup")?;
    let original = read_snapshot(&target, MAX_INSTRUCTION_BYTES, "agent instruction file")?;
    let receipt_original = read_snapshot(
        &receipt_path,
        MAX_RECEIPT_BYTES,
        "instruction owner receipt",
    )?;
    let old_receipt = decode_receipt(&receipt_original, target_kind)?;
    let text = snapshot_text(&original)?;
    let shape = owned_shape(target_kind);
    let desired = canonical_block(target_kind);

    let current = current_owned(&text, target_kind, old_receipt.as_ref(), shape, force)?;

    if matches!(
        target_kind,
        InstructionTarget::Skill | InstructionTarget::Cursor
    ) && old_receipt.is_none()
        && current.is_none()
        && !text.trim().is_empty()
    {
        return Err(ManagerError::HostConflict(format!(
            "{} already contains unmanaged content",
            target.display()
        )));
    }

    let mut discarded = None;
    if !force {
        validate_ownership(old_receipt.as_ref(), current.as_deref(), target_kind)?;
    } else if let Some(current) = current.as_deref() {
        let owned_matches = old_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.owned_block == current);
        if !owned_matches {
            discarded = Some(current.to_owned());
        }
    }

    if current.as_deref() == Some(desired.as_str())
        && old_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.owned_block == desired)
    {
        return Ok(noop_plan(
            target_kind,
            host,
            InstructionAction::AlreadyInstalled,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
        ));
    }
    let action = if current.is_some() {
        InstructionAction::Update
    } else {
        InstructionAction::Add
    };
    let (updated, separator) = install_block(&text, current.as_deref(), &desired, shape)?;
    let file_created = old_receipt
        .as_ref()
        .map_or(original.bytes.is_none(), |receipt| receipt.file_created);
    let pre_sha256 = old_receipt.as_ref().map_or_else(
        || original.sha256.clone(),
        |receipt| receipt.pre_sha256.clone(),
    );
    let receipt = InstructionReceipt {
        version: RECEIPT_VERSION,
        owner: OWNER.to_owned(),
        target: target_kind,
        shape,
        owned_sha256: digest_bytes(desired.as_bytes()),
        owned_block: desired.clone(),
        pre_sha256,
        post_sha256: digest_bytes(updated.as_bytes()),
        separator,
        file_created,
    };
    Ok(InstructionPlan {
        target_kind,
        host,
        action,
        preview: format!(
            "{} manager-owned {} instructions at {}\nOwned block:\n{}{}",
            if action == InstructionAction::Add {
                "Add"
            } else {
                "Update"
            },
            target_kind.as_str(),
            target.display(),
            desired,
            discarded.as_ref().map_or_else(String::new, |bytes| format!(
                "\n\nFORCED: these bytes will be DISCARDED:\n{bytes}"
            )),
        ),
        target,
        receipt_path,
        backup_path,
        restore: None,
        discarded,
        original,
        receipt_original,
        updated: Some(updated.into_bytes()),
        receipt_after: Some(receipt),
        remove_backup: false,
    })
}

pub fn plan_remove_at(
    target_kind: InstructionTarget,
    host: Option<Host>,
    project: &Path,
    force: bool,
) -> Result<InstructionPlan> {
    let target = instruction_path(target_kind, host, project)?;
    let receipt_path = sibling_path(&target, ".kaleidoscope-instruction-owner.json")?;
    let backup_path = sibling_path(&target, ".kaleidoscope-backup")?;
    let original = read_snapshot(&target, MAX_INSTRUCTION_BYTES, "agent instruction file")?;
    let receipt_original = read_snapshot(
        &receipt_path,
        MAX_RECEIPT_BYTES,
        "instruction owner receipt",
    )?;
    let receipt = decode_receipt(&receipt_original, target_kind)?;
    let text = snapshot_text(&original)?;
    let shape = owned_shape(target_kind);
    let current = current_owned(&text, target_kind, receipt.as_ref(), shape, force)?;

    let Some(receipt) = receipt else {
        if current.is_some() {
            return Err(ManagerError::HostConflict(format!(
                "the instruction marker at {} has no manager owner receipt; re-run with --force to remove it and disclose the discarded bytes",
                target.display()
            )));
        }
        return Ok(noop_plan(
            target_kind,
            host,
            InstructionAction::AlreadyRemoved,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
        ));
    };

    let mut discarded = None;
    if force {
        if let Some(current) = current.as_deref() {
            if receipt.owned_block != current {
                discarded = Some(current.to_owned());
            }
        }
    } else {
        validate_ownership(Some(&receipt), current.as_deref(), target_kind)?;
    }
    // A receipt, and no marker of any kind left in the file: BOTH markers were
    // edited or deleted by hand, so there is nothing `--force` can identify --
    // `forced_owned_span` matches markers and there are none. This used to fall
    // out as `InvalidOwnerReceipt`, whose rendering says "connection owner
    // receipt is invalid or does not match the managed entry": the wrong noun
    // for an agent instruction file, and no way forward. Name the state and the
    // two files instead.
    let Some(current) = current else {
        return Err(ManagerError::InvalidHostConfig(format!(
            "{} carries a manager owner receipt but no manager marker at all -- both markers were edited or removed by hand, so nothing here identifies the block, and --force cannot either. Delete the manager block from {} by hand, then delete {}.",
            target.display(),
            target.display(),
            receipt_path.display(),
        )));
    };

    // ---- TIER 1, EXACT ------------------------------------------------------
    //
    // If the file is still byte-for-byte what the manager wrote, and either the
    // manager created it or the backup holds exactly the pre-install bytes,
    // then the pre-install state is recoverable EXACTLY -- independent of key
    // ordering, indentation and trailing newlines, i.e. the whole class of
    // defect that made `…newline` come back as `…newline\n`.
    let backup = read_snapshot(&backup_path, MAX_INSTRUCTION_BYTES, "instruction backup")?;
    let file_is_ours = original.sha256 == receipt.post_sha256;
    let backup_is_pre = backup
        .bytes
        .as_deref()
        .is_some_and(|_| backup.sha256 == receipt.pre_sha256);
    if file_is_ours && (receipt.file_created || backup_is_pre) {
        let (updated, remove_backup) = if receipt.file_created {
            // The manager created this file, so the pre-install state is
            // ABSENCE and any backup of it holds manager-written bytes, never
            // the user's. (`apply` no longer mints one on the way out either --
            // see the `self.restore.is_none()` guard there.)
            (None, true)
        } else {
            (backup.bytes.clone(), true)
        };
        return Ok(InstructionPlan {
            target_kind,
            host,
            action: InstructionAction::Remove,
            preview: format!(
                "Remove manager-owned {} instructions from {} (exact restore)\nOwned block:\n{current}",
                target_kind.as_str(),
                target.display(),
            ),
            target,
            receipt_path,
            backup_path,
            restore: Some(RestoreTier::ByteIdentical),
            discarded,
            original,
            receipt_original,
            updated,
            receipt_after: None,
            remove_backup,
        });
    }

    // ---- TIER 2, STRUCTURAL -------------------------------------------------
    //
    // The user edited the file since install. Byte-identity to the pre-install
    // state is not merely hard, it is WRONG -- their edit must survive. Remove
    // exactly the recorded separator plus the owned span and keep everything
    // else. The backup is KEPT: it is the user's only copy of the pre-edit
    // state, and a backup whose digest does not match `pre_sha256` is never
    // deleted.
    let removed = remove_block(&text, &current, &receipt.separator, shape)?;
    let updated = if receipt.file_created && removed.trim().is_empty() {
        None
    } else {
        Some(removed.into_bytes())
    };
    Ok(InstructionPlan {
        target_kind,
        host,
        action: InstructionAction::Remove,
        preview: format!(
            "Remove manager-owned {} instructions from {} (structural restore; formatting normalized)\nOwned block:\n{current}{}",
            target_kind.as_str(),
            target.display(),
            discarded.as_ref().map_or_else(String::new, |bytes| format!(
                "\n\nFORCED: these bytes will be DISCARDED:\n{bytes}"
            )),
        ),
        target,
        receipt_path,
        backup_path,
        restore: Some(RestoreTier::Structural),
        discarded,
        original,
        receipt_original,
        updated,
        receipt_after: None,
        remove_backup: false,
    })
}

/// The manager-owned bytes currently present, whatever the shape.
///
/// For `WholeFile` there is no marker to find, so ownership is the receipt's
/// digest against the file's whole content -- and when the file is present but
/// does not match, the whole content IS the divergent owned region, which is
/// what makes a `--force` disclosure possible.
fn current_owned(
    text: &str,
    target: InstructionTarget,
    receipt: Option<&InstructionReceipt>,
    shape: OwnedShape,
    force: bool,
) -> Result<Option<String>> {
    match shape {
        // `--force` is the documented escape hatch for a hand-edited owned
        // block, and until this branch existed it could not run: `?` on
        // `find_owned_block` fired HERE, several statements before `force` was
        // ever consulted. So a duplicated block, a retyped marker or a deleted
        // closing marker refused `instructions remove`, `instructions remove
        // --force` AND `instructions install --force` alike, with rc=2 and
        // `doctor` reporting only "local validation failed" -- and the block
        // stayed in the user's CLAUDE.md permanently. The comment on
        // `validate_ownership` already said a guarantee a single character can
        // void permanently is not a guarantee; this is that comment's branch.
        OwnedShape::MarkerBlock => match find_owned_block(text, target) {
            // `find_owned_block` only errs when markers ARE present in a
            // configuration it cannot read, so the span below is never empty on
            // this branch; `None` would report "already removed", and that
            // would be a refusal spelled as an answer.
            Err(_) if force => match forced_owned_span(text, target) {
                Some(span) => Ok(Some(span)),
                None => find_owned_block(text, target),
            },
            other => other,
        },
        OwnedShape::WholeFile => {
            if text.is_empty() {
                Ok(None)
            } else if receipt.is_some() {
                Ok(Some(text.to_owned()))
            } else {
                Ok(None)
            }
        }
    }
}

fn canonical_block(target: InstructionTarget) -> String {
    match target {
        InstructionTarget::Skill => include_str!("../skills/use-kaleidoscope/SKILL.md").to_owned(),
        InstructionTarget::Agents => include_str!("../snippets/AGENTS.md").to_owned(),
        InstructionTarget::Claude => include_str!("../snippets/CLAUDE.md").to_owned(),
        InstructionTarget::Cursor => include_str!("../snippets/cursor-kaleidoscope.mdc").to_owned(),
    }
}

fn marker_start(target: InstructionTarget) -> &'static str {
    match target {
        // `Skill` is `WholeFile` and has no marker. This arm is unreachable
        // from `validate`, which only consults markers for `MarkerBlock`, and
        // is kept total rather than panicking.
        InstructionTarget::Skill => "",
        InstructionTarget::Agents => {
            "<!-- >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=agents -->"
        }
        InstructionTarget::Claude => {
            "<!-- >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=claude -->"
        }
        InstructionTarget::Cursor => {
            "---\n# >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=cursor"
        }
    }
}

fn marker_end(target: InstructionTarget) -> &'static str {
    match target {
        InstructionTarget::Skill => "",
        InstructionTarget::Agents => {
            "<!-- <<< kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=agents -->"
        }
        InstructionTarget::Claude => {
            "<!-- <<< kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=claude -->"
        }
        InstructionTarget::Cursor => {
            "# <<< kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=cursor"
        }
    }
}

fn decode_receipt(
    snapshot: &Snapshot,
    target: InstructionTarget,
) -> Result<Option<InstructionReceipt>> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(None);
    };
    let receipt: InstructionReceipt =
        serde_json::from_slice(bytes).map_err(|_| ManagerError::InvalidOwnerReceipt)?;
    receipt.validate(target)?;
    Ok(Some(receipt))
}

fn snapshot_text(snapshot: &Snapshot) -> Result<String> {
    String::from_utf8(snapshot.bytes.clone().unwrap_or_default()).map_err(|_| {
        ManagerError::InvalidHostConfig("agent instruction file is not UTF-8".to_owned())
    })
}

fn find_owned_block(text: &str, target: InstructionTarget) -> Result<Option<String>> {
    let start_marker = marker_start(target);
    let end_marker = marker_end(target);
    let starts = text.match_indices(start_marker).collect::<Vec<_>>();
    let ends = text.match_indices(end_marker).collect::<Vec<_>>();
    match (starts.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([(start, _)], [(end, _)]) if start < end => {
            let mut after = end + end_marker.len();
            if text.as_bytes().get(after) == Some(&b'\n') {
                after += 1;
            }
            Ok(Some(text[*start..after].to_owned()))
        }
        _ => Err(ManagerError::InvalidHostConfig(
            "instruction owner marker is duplicated or incomplete".to_owned(),
        )),
    }
}

/// The marker text up to and including `kaleidoscope-manager`.
///
/// Used by `--force` only. The exact marker carries `owner=` and
/// `instruction=`, and retyping one character of either makes the exact match
/// fail -- which is precisely the state `--force` exists to get a user out of,
/// so matching on it would defeat the purpose.
fn relaxed_marker(full: &str) -> &str {
    const OWNER_NEEDLE: &str = "kaleidoscope-manager";
    match full.find(OWNER_NEEDLE) {
        Some(at) => &full[..at + OWNER_NEEDLE.len()],
        None => full,
    }
}

/// The smallest contiguous region of `text` bounded by manager markers.
///
/// `--force` ONLY. From the first relaxed marker occurrence to the end of the
/// line carrying the last one, so a block that appears twice, a block whose
/// start marker was retyped, and a block whose closing marker was deleted all
/// yield ONE literal span that `remove_block` can take out. Whatever the span
/// contains is removed and is disclosed verbatim as `discarded_sha256` plus the
/// preview's `FORCED: these bytes will be DISCARDED` section -- including any
/// text of the user's that sits between two duplicated blocks.
///
/// It is not a repair. When only one side of the pair survives -- a deleted
/// closing marker -- the span is that one marker line, so `--force` removes the
/// marker and leaves the prose as ordinary text the user can delete. That is a
/// worse outcome than an exact removal and a much better one than a file
/// nothing can ever edit again, and after it there are no markers left, so the
/// normal paths work on the next run.
fn forced_owned_span(text: &str, target: InstructionTarget) -> Option<String> {
    let start = relaxed_marker(marker_start(target));
    let end = relaxed_marker(marker_end(target));
    if start.is_empty() || end.is_empty() {
        return None;
    }
    let mut lowest: Option<usize> = None;
    let mut highest = 0usize;
    for (at, hit) in text
        .match_indices(start)
        .chain(text.match_indices(end))
    {
        lowest = Some(lowest.map_or(at, |current: usize| current.min(at)));
        highest = highest.max(at + hit.len());
    }
    let lowest = lowest?;
    let after = text[highest..]
        .find('\n')
        .map_or(text.len(), |offset| highest + offset + 1);
    Some(text[lowest..after].to_owned())
}

fn validate_ownership(
    receipt: Option<&InstructionReceipt>,
    current: Option<&str>,
    target: InstructionTarget,
) -> Result<()> {
    match (receipt, current) {
        (None, None) => Ok(()),
        (Some(receipt), Some(current))
            if receipt.target == target
                && receipt.owned_block == current
                && receipt.owned_sha256 == digest_bytes(current.as_bytes()) =>
        {
            Ok(())
        }
        (None, Some(_)) => Err(ManagerError::HostConflict(
            "the instruction marker has no manager owner receipt; re-run with --force to remove it and disclose the discarded bytes"
                .to_owned(),
        )),
        // The wedge: a hand-edited owned block. Until `--force` existed this
        // refused every path -- remove, re-install and receipt deletion alike --
        // and the block stayed in the user's file permanently. The refusals were
        // honest, but a reversibility guarantee that a single character can void
        // permanently is not a guarantee. The message must now name what works.
        _ => Err(ManagerError::HostConflict(
            "the manager-owned instruction block has been hand-edited and no longer matches its owner receipt; re-run with --force to overwrite or remove it (the discarded bytes are printed in full first)"
                .to_owned(),
        )),
    }
}

/// Returns the new text and the exact separator that was inserted, so removal
/// removes a recorded fact rather than re-deriving it from a second heuristic.
fn install_block(
    text: &str,
    current: Option<&str>,
    desired: &str,
    shape: OwnedShape,
) -> Result<(String, String)> {
    if let Some(current) = current {
        if shape == OwnedShape::WholeFile {
            return Ok((desired.to_owned(), String::new()));
        }
        if text.matches(current).count() != 1 {
            return Err(ManagerError::InvalidHostConfig(
                "owned instruction block is ambiguous".to_owned(),
            ));
        }
        return Ok((text.replacen(current, desired, 1), String::new()));
    }
    if shape == OwnedShape::WholeFile {
        return Ok((desired.to_owned(), String::new()));
    }
    let separator = if text.is_empty() || text.ends_with("\n\n") {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    Ok((
        format!("{text}{separator}{desired}"),
        separator.to_owned(),
    ))
}

fn remove_block(
    text: &str,
    block: &str,
    separator: &str,
    shape: OwnedShape,
) -> Result<String> {
    if shape == OwnedShape::WholeFile {
        return Ok(String::new());
    }
    let Some(start) = text.find(block) else {
        return Err(ManagerError::InvalidOwnerReceipt);
    };
    if text[start + block.len()..].contains(block) {
        return Err(ManagerError::InvalidOwnerReceipt);
    }
    // Remove exactly the separator that was recorded at install time, and only
    // if it is still immediately before the block.
    let mut removal_start = start;
    if !separator.is_empty() && start >= separator.len() {
        let before = &text[start - separator.len()..start];
        if before == separator {
            removal_start = start - separator.len();
        }
    }
    Ok(format!(
        "{}{}",
        &text[..removal_start],
        &text[start + block.len()..]
    ))
}

/// After removing a manager-created file, remove the directories the manager
/// created for it and has now emptied. Bounded to the two directory shapes the
/// manager ever creates for instructions, and it never removes a non-empty one.
#[allow(clippy::too_many_arguments)]
fn noop_plan(
    target_kind: InstructionTarget,
    host: Option<Host>,
    action: InstructionAction,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
) -> InstructionPlan {
    InstructionPlan {
        target_kind,
        host,
        action,
        preview: format!(
            "{} instructions are already {} at {}",
            target_kind.as_str(),
            if action == InstructionAction::AlreadyInstalled {
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
        discarded: None,
        original,
        receipt_original,
        updated: None,
        receipt_after: None,
        remove_backup: false,
    }
}

fn snapshot_after(bytes: Option<&[u8]>, unix_mode: Option<u32>) -> Snapshot {
    match bytes {
        Some(bytes) => Snapshot {
            bytes: Some(bytes.to_vec()),
            sha256: digest_bytes(bytes),
            unix_mode,
        },
        None => Snapshot::absent(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn project(temp: &TempDir) -> PathBuf {
        let project = temp.path().join("project with spaces 🪞");
        fs::create_dir_all(&project).unwrap();
        fs::canonicalize(project).unwrap()
    }

    fn cases() -> Vec<(InstructionTarget, Option<Host>)> {
        vec![
            (InstructionTarget::Skill, Some(Host::ClaudeCode)),
            (InstructionTarget::Skill, Some(Host::Codex)),
            (InstructionTarget::Skill, Some(Host::OpenCode)),
            (InstructionTarget::Agents, None),
            (InstructionTarget::Claude, None),
            (InstructionTarget::Cursor, None),
        ]
    }

    #[test]
    fn all_instruction_targets_install_idempotently_and_remove_reversibly() {
        for (target_kind, host) in cases() {
            let temp = TempDir::new().unwrap();
            let project = project(&temp);
            let target = instruction_path(target_kind, host, &project).unwrap();
            if matches!(
                target_kind,
                InstructionTarget::Agents | InstructionTarget::Claude
            ) {
                fs::write(&target, "# Existing\n\nKeep this.\n").unwrap();
            }
            let before = fs::read(&target).ok();
            let install = plan_install_at(target_kind, host, &project, false).unwrap();
            install.apply().unwrap();
            assert!(target.exists(), "{target_kind:?} {host:?} was not installed");
            let backup_before = fs::read(&install.backup_path).ok();
            let repeated = plan_install_at(target_kind, host, &project, false).unwrap();
            assert_eq!(repeated.action, InstructionAction::AlreadyInstalled);
            repeated.apply().unwrap();
            assert_eq!(fs::read(&install.backup_path).ok(), backup_before);
            let remove = plan_remove_at(target_kind, host, &project, false).unwrap();
            assert_eq!(
                remove.restore,
                Some(RestoreTier::ByteIdentical),
                "{target_kind:?} {host:?} did not take the exact-restore tier"
            );
            remove.apply().unwrap();
            assert_eq!(
                fs::read(&target).ok(),
                before,
                "{target_kind:?} {host:?} did not round-trip byte-identically"
            );
        }
    }

    /// T-B10, the cell that is red without the two-tier restore: a file with no
    /// trailing newline came back with one, because `install_block` chose the
    /// separator by inspecting the text and `remove_block` removed it by a
    /// different rule.
    #[test]
    fn instructions_round_trip_is_byte_identical_over_five_file_shapes() {
        let shapes: [(&str, Option<&str>); 5] = [
            ("absent", None),
            ("lf-trailing-newline", Some("# Notes\n\nKeep this.\n")),
            ("crlf", Some("# Notes\r\n\r\nKeep this.\r\n")),
            ("no-trailing-newline", Some("# Notes\n\nKeep this.")),
            ("empty", Some("")),
        ];
        for (target_kind, host) in [
            (InstructionTarget::Claude, None),
            (InstructionTarget::Agents, None),
        ] {
            for (label, seed) in shapes {
                let temp = TempDir::new().unwrap();
                let project = project(&temp);
                let target = instruction_path(target_kind, host, &project).unwrap();
                if let Some(seed) = seed {
                    fs::write(&target, seed).unwrap();
                }
                let before = fs::read(&target).ok();
                plan_install_at(target_kind, host, &project, false)
                    .unwrap()
                    .apply()
                    .unwrap();
                let remove = plan_remove_at(target_kind, host, &project, false).unwrap();
                assert_eq!(
                    remove.restore,
                    Some(RestoreTier::ByteIdentical),
                    "{label}: expected the exact tier"
                );
                remove.apply().unwrap();
                assert_eq!(
                    fs::read(&target).ok(),
                    before,
                    "{target_kind:?}/{label} was not restored byte-identically"
                );
            }
        }
    }

    /// T-B11: the user's bytes must be there, and the tier must be Structural.
    /// An implementation that silently used Tier 1 would destroy the edit and
    /// still pass a "removal succeeded" test.
    #[test]
    fn a_user_edit_around_the_block_survives_removal() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target = instruction_path(InstructionTarget::Claude, None, &project).unwrap();
        fs::write(&target, "# Existing\n").unwrap();
        plan_install_at(InstructionTarget::Claude, None, &project, false)
            .unwrap()
            .apply()
            .unwrap();
        let text = fs::read_to_string(&target).unwrap();
        fs::write(&target, format!("PREPENDED\n{text}\nAPPENDED\n")).unwrap();

        let remove = plan_remove_at(InstructionTarget::Claude, None, &project, false).unwrap();
        assert_eq!(remove.restore, Some(RestoreTier::Structural));
        remove.apply().unwrap();
        let after = fs::read_to_string(&target).unwrap();
        assert!(after.contains("PREPENDED"), "user prefix lost: {after:?}");
        assert!(after.contains("APPENDED"), "user suffix lost: {after:?}");
        assert!(after.contains("# Existing"), "seed lost: {after:?}");
        assert!(!after.contains(OWNER), "owned block survived: {after:?}");
        // Tier 2 keeps the backup: it is the user's only copy of the pre-edit
        // state.
        assert!(remove.backup_path.exists(), "Tier 2 deleted the backup");
    }

    /// T-B14, the other half: a Tier-1 restore deletes the backup, because the
    /// file now provably equals what the backup held.
    #[test]
    fn backups_are_cleaned_up_after_an_exact_restore() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target = instruction_path(InstructionTarget::Claude, None, &project).unwrap();
        fs::write(&target, "# Existing\n").unwrap();
        let install = plan_install_at(InstructionTarget::Claude, None, &project, false).unwrap();
        install.apply().unwrap();
        assert!(install.backup_path.exists(), "no backup was written");
        let remove = plan_remove_at(InstructionTarget::Claude, None, &project, false).unwrap();
        remove.apply().unwrap();
        assert!(
            !remove.backup_path.exists(),
            "Tier 1 left a redundant backup behind"
        );
    }

    /// T-B12 and T-B13: the wedge refuses and names `--force`, and `--force`
    /// discloses what it drops.
    #[test]
    fn a_hand_edited_block_refuses_without_force_and_force_discloses() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target = instruction_path(InstructionTarget::Agents, None, &project).unwrap();
        fs::write(&target, "# Keep me\n").unwrap();
        plan_install_at(InstructionTarget::Agents, None, &project, false)
            .unwrap()
            .apply()
            .unwrap();
        let wedged = fs::read_to_string(&target)
            .unwrap()
            .replace("persist only verified", "persist every");
        fs::write(&target, &wedged).unwrap();

        for force in [false] {
            let error = plan_remove_at(InstructionTarget::Agents, None, &project, force)
                .expect_err("a hand-edited block must refuse");
            let message = error.to_string();
            assert!(
                message.contains("--force"),
                "the refusal does not name --force: {message}"
            );
            let error = plan_install_at(InstructionTarget::Agents, None, &project, force)
                .expect_err("a hand-edited block must refuse re-install too");
            assert!(error.to_string().contains("--force"));
        }

        let forced = plan_remove_at(InstructionTarget::Agents, None, &project, true).unwrap();
        let discarded = forced
            .discarded
            .clone()
            .expect("--force must disclose the discarded bytes");
        assert!(discarded.contains("persist every"));
        assert!(forced.preview().contains("persist every"));
        forced.apply().unwrap();
        let after = fs::read_to_string(&target).unwrap();
        assert!(after.contains("# Keep me"), "user text lost: {after:?}");
        assert!(!after.contains(OWNER), "owned block survived: {after:?}");
        let summary = forced.summary(false);
        assert_eq!(summary["discarded_user_edits"], json!(true));
        assert_eq!(summary["ownership"], json!("forced"));
    }

    /// T-B17 half one, and T-B18. The installed skill must be byte-identical to
    /// the shipped one -- today's injected frontmatter marker made them two
    /// different files.
    #[test]
    fn the_skill_lands_where_the_harness_reads_it_and_is_byte_identical() {
        let shipped = include_str!("../skills/use-kaleidoscope/SKILL.md");
        let expected: [(Host, &str); 3] = [
            (Host::ClaudeCode, ".claude/skills/use-kaleidoscope/SKILL.md"),
            (Host::Codex, ".agents/skills/use-kaleidoscope/SKILL.md"),
            (Host::OpenCode, ".agents/skills/use-kaleidoscope/SKILL.md"),
        ];
        for (host, suffix) in expected {
            let temp = TempDir::new().unwrap();
            let project = project(&temp);
            let path = instruction_path(InstructionTarget::Skill, Some(host), &project).unwrap();
            assert_eq!(path, project.join(suffix), "{host:?} skill path");
            plan_install_at(InstructionTarget::Skill, Some(host), &project, false)
                .unwrap()
                .apply()
                .unwrap();
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                shipped,
                "{host:?}: the installed skill is not byte-identical to the shipped one"
            );
        }
    }

    /// T-B20: a refusal, not a silent skip. And omitting --host refuses too,
    /// because defaulting is what put the file in the wrong place.
    #[test]
    fn skill_refuses_for_cursor_and_refuses_without_a_host() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let cursor = instruction_path(InstructionTarget::Skill, Some(Host::Cursor), &project)
            .expect_err("cursor has no skill directory");
        assert!(
            cursor.to_string().contains("cursor rule"),
            "the refusal must point at the cursor rule: {cursor}"
        );
        let missing = instruction_path(InstructionTarget::Skill, None, &project)
            .expect_err("skill without --host must refuse");
        assert!(missing.to_string().contains("--host"));
    }

    /// T-B19: parse the frontmatter with a strict reader rather than asserting
    /// the absence of a marker.
    #[test]
    fn the_shipped_skill_has_frontmatter_a_strict_parser_accepts() {
        let shipped = include_str!("../skills/use-kaleidoscope/SKILL.md");
        let rest = shipped
            .strip_prefix("---\n")
            .expect("SKILL.md must open with a YAML frontmatter fence");
        let (frontmatter, _) = rest
            .split_once("\n---\n")
            .expect("SKILL.md frontmatter must be closed");
        let mut keys = Vec::new();
        for line in frontmatter.lines() {
            assert!(
                !line.trim_start().starts_with('#'),
                "the frontmatter still carries an injected comment: {line}"
            );
            let (key, value) = line
                .split_once(": ")
                .unwrap_or_else(|| panic!("not a scalar mapping entry: {line}"));
            assert!(!value.trim().is_empty(), "empty value for {key}");
            keys.push(key.trim().to_owned());
        }
        assert!(keys.contains(&"name".to_owned()), "keys: {keys:?}");
        assert!(keys.contains(&"description".to_owned()), "keys: {keys:?}");
    }

    #[test]
    fn dry_plan_is_effect_free_and_concurrent_edit_refuses() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let plan = plan_install_at(InstructionTarget::Agents, None, &project, false).unwrap();
        assert!(!plan.target.exists());
        let _ = plan.summary(true);
        assert!(!plan.target.exists());
        fs::write(&plan.target, "concurrent\n").unwrap();
        assert!(matches!(plan.apply(), Err(ManagerError::ConcurrentEdit)));
    }

    #[test]
    fn tampered_receipt_refuses() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let install = plan_install_at(InstructionTarget::Agents, None, &project, false).unwrap();
        install.apply().unwrap();
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&install.receipt_path).unwrap()).unwrap();
        receipt["owner"] = json!("hostile-owner");
        fs::write(
            &install.receipt_path,
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            plan_install_at(InstructionTarget::Agents, None, &project, false),
            Err(ManagerError::InvalidOwnerReceipt)
        ));
    }

    #[test]
    fn removal_refuses_unrelated_concurrent_edit() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        fs::write(project.join("CLAUDE.md"), "# Keep\n").unwrap();
        let install = plan_install_at(InstructionTarget::Claude, None, &project, false).unwrap();
        install.apply().unwrap();
        let remove = plan_remove_at(InstructionTarget::Claude, None, &project, false).unwrap();
        let mut text = fs::read_to_string(&remove.target).unwrap();
        text.insert_str(0, "unrelated\n");
        fs::write(&remove.target, text).unwrap();
        assert!(matches!(remove.apply(), Err(ManagerError::ConcurrentEdit)));
    }

    #[test]
    fn invalid_and_unmanaged_preexisting_files_refuse_safely() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        fs::create_dir_all(project.join(".cursor/rules")).unwrap();
        fs::write(project.join(".cursor/rules/kaleidoscope.mdc"), "unmanaged").unwrap();
        assert!(matches!(
            plan_install_at(InstructionTarget::Cursor, None, &project, false),
            Err(ManagerError::HostConflict(_))
        ));
        fs::write(
            project.join("AGENTS.md"),
            format!("{}\nincomplete", marker_start(InstructionTarget::Agents)),
        )
        .unwrap();
        assert!(matches!(
            plan_install_at(InstructionTarget::Agents, None, &project, false),
            Err(ManagerError::InvalidHostConfig(_))
        ));
    }

    /// T-B17 half two: the snippet installed for a host must name the same path
    /// the skill lands at for that host. Cross-checks two artefacts against each
    /// other -- they disagreed for claude-code, which is exactly the defect.
    #[test]
    fn every_snippet_names_the_skill_path_its_own_harness_reads() {
        let claude = canonical_block(InstructionTarget::Claude);
        assert!(
            claude.contains(".claude/skills/use-kaleidoscope/SKILL.md"),
            "the CLAUDE.md snippet must name the path Claude Code reads"
        );
        assert!(
            !claude.contains(".agents/skills/"),
            "the CLAUDE.md snippet still names a path Claude Code does not read"
        );
        for target in [InstructionTarget::Agents, InstructionTarget::Cursor] {
            let snippet = canonical_block(target);
            assert!(
                snippet.contains(".agents/skills/use-kaleidoscope/SKILL.md"),
                "{target:?} must name the .agents skill path"
            );
        }
    }

    #[test]
    fn canonical_skill_keeps_the_public_boundary_and_privacy_rules() {
        let skill = include_str!("../skills/use-kaleidoscope/SKILL.md");
        for required in [
            "`search`",
            "`remember`",
            "live write schema",
            "Do not store tentative brainstorming, secrets, credentials, tokens, transcripts",
            "Do not construct direct vault-coordinate commands",
            "exposure",
            "repository evidence map",
            "one create batch",
        ] {
            assert!(
                skill.contains(required),
                "missing canonical rule: {required}"
            );
        }
        for forbidden in [
            "`recall`",
            "`compile`",
            "`ingest_memory`",
            "`feedback`",
            "workspace_id",
            "principal_id",
            "journal:",
        ] {
            assert!(
                !skill.contains(forbidden),
                "forbidden skill surface: {forbidden}"
            );
        }
    }
}
