use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::project_root;
use crate::error::{ManagerError, Result};
use crate::fs_safe::{
    FileLock, Snapshot, TargetWrite, assert_unchanged, atomic_remove, atomic_write, digest_bytes,
    prune_empty_managed_directories, read_snapshot, restore_snapshot, sibling_path,
    write_bounded_backup,
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
    /// The content already present is byte-identical to what this manager would
    /// write, so the manager took ownership by writing the receipt ALONE.
    ///
    /// NOT a no-op: `is_noop` stays false for it, because a receipt is written
    /// and the step has to be counted as applied. What it does not do is touch
    /// the target.
    Adopt,
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
    /// The manager never wrote these bytes -- it ADOPTED content that was
    /// already there, because the content was byte-identical to what it would
    /// have written. Teardown removed its receipt and left the file exactly as
    /// it found it.
    ///
    /// Reported so that "reversible" can be CHECKED rather than asserted: a
    /// file reported as left in place must still be on disk afterwards, with
    /// its original digest. A tier that could not distinguish this from a
    /// byte-identical restore would let "the file survived" and "the file was
    /// deleted and rewritten" wear the same label.
    AdoptedLeftInPlace,
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
    /// True when the manager took ownership of content it did NOT write.
    ///
    /// See `host::OwnershipReceipt::adopted` for the reasoning about stickiness
    /// and about NOT bumping `RECEIPT_VERSION`; the two receipts are the same
    /// decision made twice because they are separate files.
    #[serde(default)]
    adopted: bool,
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
    /// True when the receipt this plan writes -- or the one it is undoing --
    /// records that the manager took ownership of content it did not write.
    pub adopted: bool,
    preview: String,
    original: Snapshot,
    receipt_original: Snapshot,
    write: TargetWrite,
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

    /// `Adopt` is DELIBERATELY NOT a no-op: it writes a receipt, so it is an
    /// applied step that a confirmation prompt should cover and a summary
    /// should count.
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
        // `Leave` is excluded: an adoption writes nothing to the target, so
        // there are no pre-modification bytes for a backup to hold.
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
            if assert_unchanged(
                &self.target,
                &snapshot_after(&self.write, &self.original),
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
        // Only on a REMOVE. A `Leave` plan must never prune: the whole point of
        // leaving an adopted `SKILL.md` in place is undone if
        // `use-kaleidoscope/` and `skills/` go with it.
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
            "instruction": self.target_kind,
            "host": self.host,
            "target": self.target,
            "owner_receipt": self.receipt_path,
            "backup": self.backup_after(dry_run),
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
        if self.adopted {
            value["adopted"] = json!(true);
        }
        if self.action == InstructionAction::Adopt {
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
/// Does this project still carry a manager-owned instruction file or skill?
///
/// The question a teardown standing somewhere ELSE has to answer before it
/// removes machine-wide wiring: "is anybody still using this". Answered from
/// the manager's own path rules and its own receipt sidecars rather than from
/// a remembered file list, so a user who deleted the directory, or removed the
/// files by hand, simply stops counting -- no stale registry entry can hold
/// the shared entry hostage.
///
/// Cheap on purpose: existence of the receipt beside the target, no parsing,
/// no locks. It is a "should I warn" predicate, never an ownership decision.
#[must_use]
pub fn project_carries_instructions(project: &Path) -> bool {
    let mut targets: Vec<(InstructionTarget, Option<Host>)> = vec![
        (InstructionTarget::Agents, None),
        (InstructionTarget::Claude, None),
        (InstructionTarget::Cursor, None),
    ];
    for host in [Host::ClaudeCode, Host::Codex, Host::OpenCode] {
        targets.push((InstructionTarget::Skill, Some(host)));
    }
    targets.into_iter().any(|(target, host)| {
        instruction_path(target, host, project)
            .and_then(|path| sibling_path(&path, ".kaleidoscope-instruction-owner.json"))
            .is_ok_and(|receipt| receipt.exists())
    })
}

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

#[allow(clippy::too_many_lines)]
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

    // ---- ADOPTION -------------------------------------------------------
    //
    // THE RULE, STATED ONCE: the receipt remains the SOLE authority for
    // MODIFYING content. Content equality is authority only for ADOPTING it,
    // and adoption writes nothing to the target.
    //
    // That distinction is the whole safety argument. If it collapses into
    // "content is the discriminator", the next change is "the content is close
    // enough, overwrite it" -- and nothing here would then stop the manager
    // destroying a file it did not write.
    //
    // Identity is EXACT: no trailing-newline tolerance, no CRLF folding, no
    // whitespace trimming. A normalising comparison would call bytes
    // "identical" that it would then have to rewrite, and rewriting is
    // precisely what adoption promises not to do.
    let adopt_now = match shape {
        OwnedShape::WholeFile => old_receipt.is_none() && !text.is_empty() && text == desired,
        OwnedShape::MarkerBlock => {
            old_receipt.is_none() && current.as_deref() == Some(desired.as_str())
        }
    };
    if adopt_now {
        return Ok(adopt_plan(
            target_kind,
            host,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            desired,
            shape,
        ));
    }

    // Non-empty content that is NOT ours, in a file whose owned region would be
    // the whole file (the skill) or that carries no marker to delimit ours (the
    // Cursor rule).
    let mut discarded = None;
    if matches!(
        target_kind,
        InstructionTarget::Skill | InstructionTarget::Cursor
    ) && old_receipt.is_none()
        && current.is_none()
        && !text.trim().is_empty()
    {
        if shape == OwnedShape::MarkerBlock {
            // Cursor. `--force` cannot help: it identifies a span by MARKERS
            // and there are none here, so there is nothing for it to discard
            // that is provably the manager's. Name what does work.
            return Err(ManagerError::HostConflict(format!(
                "{} already exists and carries no Kaleidoscope marker block, so the manager cannot tell where its own text would end and yours begins. Nothing was changed.\nWays forward:\n  keep your file and wire everything else\n      kaleidoscope init --host cursor --no-instructions\n  delete {} by hand and re-run, or make it byte-identical to the manager's rule, which a re-run will adopt in place.",
                target.display(),
                target.display()
            )));
        }
        if !force {
            return Err(ManagerError::HostConflict(whole_file_conflict_message(
                &target,
                host,
                &original.sha256,
                original.bytes.as_deref().map_or(0, <[u8]>::len),
                &desired,
            )));
        }
        // `--force` over unmanaged whole-file content used to be UNREACHABLE:
        // the guard above returned before `force` was consulted, so the
        // documented escape hatch did not exist for this shape at all. The
        // whole file is the divergent owned region, so disclose it.
        discarded = Some(text.clone());
    }

    if !force {
        validate_ownership(old_receipt.as_ref(), current.as_deref(), target_kind, host)?;
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
    // Sticky. An Update over an adopted target stays adopted: "did the
    // pre-manager state already include this content?" is a fact about the past
    // that a later write cannot change, and it is what lets the teardown of an
    // updated-over-adoption restore the user's own original file (the backup
    // written at update time holds exactly those bytes).
    let adopted = old_receipt.as_ref().is_some_and(|receipt| receipt.adopted);
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
        adopted,
    };
    Ok(InstructionPlan {
        target_kind,
        host,
        action,
        adopted,
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
        write: TargetWrite::Write(updated.into_bytes()),
        receipt_after: Some(receipt),
        remove_backup: false,
    })
}

#[allow(clippy::too_many_lines)]
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

    // ---- WHOLE FILE THE MANAGER DID NOT CREATE ---------------------------
    //
    // ONE RULE, and it subsumes adoption while closing a latent destructive
    // bug. TEARDOWN LEAVES AN ADOPTED WHOLE FILE IN PLACE.
    //
    // The asymmetry with an adopted ENTRY (which teardown removes) is not an
    // inconsistency; it tracks exactly one thing -- whether the manager's owned
    // region is the whole file or a span inside a file the user owns. The file
    // existed before `init` ran, the user created it (by following the
    // documentation, most likely), and deleting it is visible, surprising and
    // irreversible from their side. Against that, the cost of leaving it is an
    // inert markdown file: it is documentation, not wiring, and it does nothing
    // once the MCP entry is gone.
    //
    // OWNERSHIP VALIDATION IS SKIPPED HERE ON PURPOSE. There is nothing for a
    // refusal to protect: the manager will not write to the file under either
    // branch, so no user edit can be destroyed -- and refusing would strand the
    // receipt permanently, which is exactly the wedge `current_owned`'s comment
    // describes. An adopted file the user has since edited is simply RELEASED.
    //
    // The bug this also closes: Tier 2 below computed `removed` as
    // `String::new()` for a `WholeFile` target and then wrote
    // `Some(b"")` -- an atomic write of an EMPTY FILE over the user's content
    // -- whenever `file_created` was false. That combination was unreachable
    // only because `plan_install_at` refused every non-empty unmanaged
    // whole-file target; adoption makes it reachable on day one.
    if shape == OwnedShape::WholeFile && !receipt.file_created {
        let backup = read_snapshot(&backup_path, MAX_INSTRUCTION_BYTES, "instruction backup")?;
        let file_is_ours = original.sha256 == receipt.post_sha256;
        let backup_is_pre = backup.bytes.is_some() && backup.sha256 == receipt.pre_sha256;
        let (write, restore, remove_backup) = if file_is_ours && backup_is_pre {
            // The manager updated content it had adopted, so the backup holds
            // the user's original file. Put it back verbatim.
            (
                backup
                    .bytes
                    .clone()
                    .map_or(TargetWrite::Leave, TargetWrite::Write),
                RestoreTier::ByteIdentical,
                true,
            )
        } else {
            (TargetWrite::Leave, RestoreTier::AdoptedLeftInPlace, false)
        };
        return Ok(InstructionPlan {
            target_kind,
            host,
            action: InstructionAction::Remove,
            adopted: receipt.adopted,
            preview: format!(
                "Release {} at {} ({})",
                target_kind.as_str(),
                target.display(),
                if restore == RestoreTier::ByteIdentical {
                    "restoring the file the manager adopted, exactly"
                } else {
                    "the manager adopted this file rather than creating it, so it is LEFT IN PLACE; only the owner receipt is removed"
                }
            ),
            target,
            receipt_path,
            backup_path,
            restore: Some(restore),
            discarded: None,
            original,
            receipt_original,
            write,
            receipt_after: None,
            remove_backup,
        });
    }

    let mut discarded = None;
    if force {
        if let Some(current) = current.as_deref() {
            if receipt.owned_block != current {
                discarded = Some(current.to_owned());
            }
        }
    } else {
        validate_ownership(Some(&receipt), current.as_deref(), target_kind, host)?;
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
    // ADOPTION BYPASSES TIER 1, and it must. For an adopted marker block
    // `pre == post == the untouched file`, so both conditions hold and Tier 1
    // would restore a backup that CONTAINS the block. Byte-exact restore is
    // impossible here by construction: the desired end state -- the file minus
    // a block it always had -- has never existed on disk.
    if !receipt.adopted && file_is_ours && (receipt.file_created || backup_is_pre) {
        let (write, remove_backup) = if receipt.file_created {
            // The manager created this file, so the pre-install state is
            // ABSENCE and any backup of it holds manager-written bytes, never
            // the user's. (`apply` no longer mints one on the way out either --
            // see the `self.restore.is_none()` guard there.)
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
        return Ok(InstructionPlan {
            target_kind,
            host,
            action: InstructionAction::Remove,
            adopted: receipt.adopted,
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
            write,
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
    // `file_created` is REQUIRED for the delete branch. Without it a
    // `WholeFile` target -- whose `removed` is always the empty string -- fell
    // through to `Some(b"")` and truncated the user's file to zero bytes.
    // The whole-file rule above now returns before this point for exactly the
    // `file_created == false` case, so this is belt and braces; it is written
    // as a positive condition anyway, because the failure mode of getting it
    // wrong is silent data loss.
    let write = if receipt.file_created && removed.trim().is_empty() {
        TargetWrite::Remove
    } else if shape == OwnedShape::WholeFile && !receipt.file_created {
        TargetWrite::Leave
    } else {
        TargetWrite::Write(removed.into_bytes())
    };
    Ok(InstructionPlan {
        target_kind,
        host,
        action: InstructionAction::Remove,
        adopted: receipt.adopted,
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
        write,
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

/// A plan that takes ownership of content already on disk, writing ONLY the
/// receipt.
///
/// `pre == post == original.sha256` is not a fudge. The file before the manager
/// touched it and the file after are the same file, because the manager wrote
/// nothing to it -- and that identity is what makes the later update path work
/// with no special case: if a manager upgrade genuinely changes the canonical
/// content, `apply` writes the backup AT THAT MOMENT, and the backup then holds
/// exactly these bytes, which are the pre-manager bytes.
///
/// `separator` is `""`, which is the literal truth: the manager inserted no
/// separator. `remove_block` already handles an empty separator by removing
/// exactly the block and nothing around it.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn adopt_plan(
    target_kind: InstructionTarget,
    host: Option<Host>,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    desired: String,
    shape: OwnedShape,
) -> InstructionPlan {
    let receipt = InstructionReceipt {
        version: RECEIPT_VERSION,
        owner: OWNER.to_owned(),
        target: target_kind,
        shape,
        owned_sha256: digest_bytes(desired.as_bytes()),
        owned_block: desired.clone(),
        pre_sha256: original.sha256.clone(),
        post_sha256: original.sha256.clone(),
        separator: String::new(),
        file_created: false,
        adopted: true,
    };
    InstructionPlan {
        target_kind,
        host,
        action: InstructionAction::Adopt,
        adopted: true,
        preview: format!(
            "Adopt the existing {} content at {} (byte-identical to this manager's; nothing will be written to the file, only the owner receipt beside it)\nOwned block:\n{desired}",
            target_kind.as_str(),
            target.display(),
        ),
        target,
        receipt_path,
        backup_path,
        restore: None,
        discarded: None,
        original,
        receipt_original,
        write: TargetWrite::Leave,
        receipt_after: Some(receipt),
        remove_backup: false,
    }
}

/// The refusal when a whole-file target exists and its content is NOT ours.
///
/// A refusal that does not say what to do next is where this failed for a real
/// user: they followed the documentation, placed the skill by hand, and got a
/// hard stop -- while a user who had done nothing at all sailed through. Both
/// digests are shown so "make it byte-identical" is an instruction a person can
/// actually carry out.
/// The `--host` fragment for a remedy line, never the literal word `HOST`.
///
/// A refusal that prints `kaleidoscope init --host HOST --no-instructions` and
/// exits 2 hands the user a command that exits 2 as well: `host must be codex,
/// claude-code, cursor, or opencode`. The inconsistency was visible INSIDE one
/// message -- the second remedy line interpolated the target correctly while
/// the first did not -- because the function that built it took no `host`
/// parameter at all. One helper, so the two call sites cannot drift again.
///
/// `claude-code` is the fallback when the caller genuinely has no host (the
/// `instructions` verbs accept a bare target): it is the majority harness, and
/// a remedy naming the wrong host is at least runnable and self-correcting,
/// where `HOST` is neither.
fn host_flag(host: Option<Host>) -> String {
    host.map_or_else(
        || "--host claude-code".to_owned(),
        |host| format!("--host {}", host.as_str()),
    )
}

fn whole_file_conflict_message(
    target: &Path,
    host: Option<Host>,
    yours: &str,
    your_bytes: usize,
    desired: &str,
) -> String {
    let host_flag = host_flag(host);
    format!(
        "{} already exists and its contents differ from the skill this manager installs, so nothing was changed.\n  yours:   sha256:{}   ({your_bytes} bytes)\n  manager: sha256:{}   ({} bytes)\nWays forward:\n  keep your file and wire everything else\n      kaleidoscope init {host_flag} --no-skill\n  replace it (the discarded bytes are printed in full first, and a {}.kaleidoscope-backup is kept)\n      kaleidoscope instructions install skill {host_flag} --force\nIf you make the file byte-identical to the manager's, a re-run will adopt it in place and write only the owner receipt.",
        target.display(),
        &yours[..yours.len().min(8)],
        &digest_bytes(desired.as_bytes())[..8],
        desired.len(),
        target.display(),
    )
}

fn canonical_block(target: InstructionTarget) -> String {
    match target {
        InstructionTarget::Skill => include_str!("../skills/use-kaleidoscope/SKILL.md").to_owned(),
        InstructionTarget::Agents => include_str!("../snippets/AGENTS.md").to_owned(),
        InstructionTarget::Claude => include_str!("../snippets/CLAUDE.md").to_owned(),
        InstructionTarget::Cursor => include_str!("../snippets/cursor-kaleidoscope.mdc").to_owned(),
    }
}

/// The file a target lives in, named for a message. The path is not available
/// at `validate_ownership`, so this names the file the user will recognise.
fn marker_label(target: InstructionTarget) -> &'static str {
    match target {
        InstructionTarget::Skill => "SKILL.md",
        InstructionTarget::Agents => "AGENTS.md",
        InstructionTarget::Claude => "CLAUDE.md",
        InstructionTarget::Cursor => ".cursor/rules/kaleidoscope.mdc",
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
    for (at, hit) in text.match_indices(start).chain(text.match_indices(end)) {
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
    host: Option<Host>,
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
        // Reached only when the block DIFFERS from the canonical one -- an
        // identical block is intercepted by adoption before this is called.
        (None, Some(_)) => Err(ManagerError::HostConflict(format!(
            "{} contains a Kaleidoscope block that differs from this version's, and it carries no manager owner receipt. Nothing was changed.\nWays forward:\n  keep your block and wire everything else\n      kaleidoscope init {host_flag} --no-instructions\n  replace it (the discarded bytes are printed in full first)\n      kaleidoscope instructions install {} --force",
            marker_label(target),
            target.as_str(),
            host_flag = host_flag(host),
        ))),
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
    Ok((format!("{text}{separator}{desired}"), separator.to_owned()))
}

fn remove_block(text: &str, block: &str, separator: &str, shape: OwnedShape) -> Result<String> {
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
        adopted: false,
        discarded: None,
        original,
        receipt_original,
        // NOT `Remove`: a value that would delete the user's file has no
        // business sitting in a no-op plan, guarded only by an early return.
        write: TargetWrite::Leave,
        receipt_after: None,
        remove_backup: false,
    }
}

fn snapshot_after(write: &TargetWrite, original: &Snapshot) -> Snapshot {
    match write {
        TargetWrite::Write(bytes) => Snapshot {
            bytes: Some(bytes.clone()),
            sha256: digest_bytes(bytes),
            unix_mode: original.unix_mode,
        },
        TargetWrite::Remove => Snapshot::absent(),
        // An adoption's "after" state IS its "before" state.
        TargetWrite::Leave => original.clone(),
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
            assert!(
                target.exists(),
                "{target_kind:?} {host:?} was not installed"
            );
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
            // Tamper on the heading, not on a sentence. Keying this to a phrase
            // in the shipped body made the test silently stop testing when the
            // body was reworded: the replace became a no-op, the block stayed
            // byte-identical, and "a hand-edited block refuses" passed by never
            // hand-editing anything. The heading is structural and is what the
            // sibling tests below already tamper with.
            .replace(
                "## Kaleidoscope memory",
                "## Kaleidoscope memory\nUSER TAMPERED",
            );
        fs::write(&target, &wedged).unwrap();

        {
            let force = false;
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
        assert!(discarded.contains("USER TAMPERED"));
        assert!(forced.preview().contains("USER TAMPERED"));
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
        // Each entry is a short token standing for a RULE, not a sentence the
        // skill has to keep word for word.
        //
        // This list used to pin phrases instead: `live write schema`, a
        // twelve-word privacy sentence quoted exactly, `exposure`, and
        // `repository evidence map`. That made the skill unrewritable without
        // failing a test named for its rules -- and it froze in place exactly
        // the internal vocabulary the skill is meant to keep OUT of a reader's
        // way. `exposure` and `repository evidence map` are gone deliberately:
        // both named an internal mechanism the reader cannot act on, and the
        // rules they were standing in for are checked below by what they
        // actually require.
        for (rule, token) in [
            ("the read tool is named", "`search`"),
            ("the write tool is named", "`remember`"),
            ("the live schema is the authority", "kscope schema remember"),
            ("a profile, never raw vault coordinates", "--profile"),
            ("secrets are never stored", "secrets"),
            ("credentials are never stored", "credentials"),
            ("transcripts are never stored", "transcripts"),
            ("every entity carries a matcher gloss", "`is`"),
            ("a revision corrects rather than duplicates", "corrections"),
            // The skill's whole job is teaching a write, and it shipped for
            // months without a single worked example. This is the guard that
            // it never does so again.
            ("a worked write example is present", "\"mode\": \"create\""),
        ] {
            assert!(
                skill.contains(token),
                "the skill no longer says {rule} (looked for {token})"
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

#[cfg(test)]
mod adoption_tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn project(temp: &TempDir) -> PathBuf {
        let project = temp.path().join("adopt project ü");
        fs::create_dir_all(&project).unwrap();
        fs::canonicalize(project).unwrap()
    }

    fn plant(target: &Path, bytes: &str) {
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }

    fn digest_of(path: &Path) -> String {
        digest_bytes(&fs::read(path).unwrap())
    }

    /// A byte-identical `SKILL.md` placed by hand is ADOPTED, and adoption
    /// writes nothing to the file.
    ///
    /// The digest and the backup-absence assertions are what make this
    /// non-vacuous: any implementation that rewrites the identical bytes still
    /// produces a file with the right content, and fails both of them.
    #[test]
    fn adopts_byte_identical_skill() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        plant(&target, &canonical_block(InstructionTarget::Skill));
        let before = digest_of(&target);

        let plan = plan_install_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap();
        assert_eq!(plan.action, InstructionAction::Adopt);
        assert_eq!(plan.write, TargetWrite::Leave);
        assert!(
            !plan.is_noop(),
            "an adoption writes a receipt; it is applied"
        );
        let receipt = plan
            .receipt_after
            .clone()
            .expect("adoption writes a receipt");
        assert!(receipt.adopted);
        assert!(!receipt.file_created);
        assert_eq!(receipt.pre_sha256, receipt.post_sha256);
        assert_eq!(receipt.pre_sha256, before);

        plan.apply().unwrap();
        assert_eq!(digest_of(&target), before, "adoption must not touch bytes");
        assert!(
            !sibling_path(&target, ".kaleidoscope-backup")
                .unwrap()
                .exists(),
            "adoption writes no backup: there are no pre-modification bytes to hold"
        );
        assert!(
            sibling_path(&target, ".kaleidoscope-instruction-owner.json")
                .unwrap()
                .exists()
        );
    }

    /// ONE BYTE of difference is not identity.
    ///
    /// The direct control on "no normalisation": a trailing-newline-tolerant or
    /// whitespace-trimming comparison passes the adoption test above and fails
    /// this one. The message assertion is the second half -- a refusal that
    /// does not say what to do next is where this failed for a real user.
    #[test]
    fn refuses_a_skill_that_differs_by_one_byte_and_names_no_skill() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        let mut content = canonical_block(InstructionTarget::Skill);
        content.push('\n');
        plant(&target, &content);
        let before = digest_of(&target);

        let error = plan_install_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .expect_err("one byte of difference must still refuse");
        let rendered = error.to_string();
        assert!(rendered.contains("--no-skill"), "{rendered}");
        assert!(rendered.contains("adopt it in place"), "{rendered}");
        assert_eq!(digest_of(&target), before, "a refusal changes nothing");
    }

    #[test]
    fn adopts_an_identical_marker_block() {
        for target_kind in [InstructionTarget::Claude, InstructionTarget::Agents] {
            let temp = TempDir::new().unwrap();
            let project = project(&temp);
            let target = instruction_path(target_kind, None, &project).unwrap();
            plant(
                &target,
                &format!("# Mine\n\n{}", canonical_block(target_kind)),
            );
            let before = digest_of(&target);
            let plan = plan_install_at(target_kind, None, &project, false).unwrap();
            assert_eq!(plan.action, InstructionAction::Adopt, "{target_kind:?}");
            plan.apply().unwrap();
            assert_eq!(digest_of(&target), before, "{target_kind:?}");
            let receipt = plan.receipt_after.clone().unwrap();
            assert!(receipt.adopted);
            assert_eq!(receipt.separator, "", "the manager inserted no separator");
        }
    }

    /// `adopted` survives an Update, and `pre_sha256` is NOT recomputed.
    ///
    /// Driven through a REAL caller -- adopt, hand-edit inside the block,
    /// re-install with `--force` -- rather than by forging a receipt on disk.
    /// A hand-built input would certify whatever the implementation happens to
    /// do with it; this asserts the property against the door a user comes
    /// through.
    ///
    /// `pre_sha256` staying put is the load-bearing half: it is what a later
    /// Tier-1 restore compares the backup against, and an implementation that
    /// recomputes it passes every other adoption test.
    #[test]
    fn adopted_is_sticky_across_an_update() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target = instruction_path(InstructionTarget::Claude, None, &project).unwrap();
        plant(
            &target,
            &format!("# Mine\n\n{}", canonical_block(InstructionTarget::Claude)),
        );
        let adopted_digest = digest_of(&target);

        let first = plan_install_at(InstructionTarget::Claude, None, &project, false).unwrap();
        assert_eq!(first.action, InstructionAction::Adopt);
        first.apply().unwrap();

        // The user edits INSIDE the manager's block. `--force` is the
        // documented way back, and it takes the Update branch.
        let text = fs::read_to_string(&target).unwrap();
        let edited = text.replace(
            "## Kaleidoscope memory",
            "## Kaleidoscope memory\nUSER TAMPERED",
        );
        assert_ne!(
            edited, text,
            "the fixture edit must actually change the block"
        );
        fs::write(&target, &edited).unwrap();

        let second = plan_install_at(InstructionTarget::Claude, None, &project, true).unwrap();
        assert_eq!(second.action, InstructionAction::Update);
        let receipt = second.receipt_after.clone().unwrap();
        assert!(
            receipt.adopted,
            "adoption is a fact about the past that a later write cannot change"
        );
        assert!(!receipt.file_created);
        assert_eq!(
            receipt.pre_sha256, adopted_digest,
            "pre_sha256 must be carried forward, not recomputed"
        );
    }

    /// adopt -> user edit -> forced update -> teardown, end to end.
    ///
    /// The user's own text outside the block survives byte-for-byte and the
    /// block is gone. This is the reversibility claim that matters for an
    /// adopted marker block, and it is the only test that exercises `adopted`,
    /// `file_created`, `pre_sha256` and the backup together.
    #[test]
    fn adopt_update_teardown_keeps_the_users_own_text() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target = instruction_path(InstructionTarget::Claude, None, &project).unwrap();
        let mine = "# Mine\n\nkeep every byte of this\n\n";
        plant(
            &target,
            &format!("{mine}{}", canonical_block(InstructionTarget::Claude)),
        );

        plan_install_at(InstructionTarget::Claude, None, &project, false)
            .unwrap()
            .apply()
            .unwrap();
        let text = fs::read_to_string(&target).unwrap();
        fs::write(
            &target,
            text.replace(
                "## Kaleidoscope memory",
                "## Kaleidoscope memory\nUSER TAMPERED",
            ),
        )
        .unwrap();
        let update = plan_install_at(InstructionTarget::Claude, None, &project, true).unwrap();
        update.apply().unwrap();
        let backup = sibling_path(&target, ".kaleidoscope-backup").unwrap();
        assert!(
            backup.exists(),
            "an update over an adoption writes the backup at THAT moment -- it is the only copy of the pre-update file"
        );

        let removal = plan_remove_at(InstructionTarget::Claude, None, &project, false).unwrap();
        assert_eq!(
            removal.restore,
            Some(RestoreTier::Structural),
            "an adopted block bypasses Tier 1: the desired end state never existed on disk"
        );
        removal.apply().unwrap();
        let after = fs::read_to_string(&target).unwrap();
        assert!(
            after.starts_with(mine),
            "the user's own text must survive byte-for-byte: {after:?}"
        );
        assert!(
            !after.contains("kaleidoscope-manager"),
            "the block must be gone: {after:?}"
        );
    }

    /// TEARDOWN LEAVES AN ADOPTED WHOLE FILE IN PLACE.
    ///
    /// Asserted on the file's presence, its digest, the reported tier AND the
    /// containing directory -- the last of which catches
    /// `prune_empty_managed_directories` firing on a `Leave` plan and taking
    /// `use-kaleidoscope/` with it.
    #[test]
    fn teardown_leaves_an_adopted_whole_file() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        plant(&target, &canonical_block(InstructionTarget::Skill));
        let before = digest_of(&target);
        plan_install_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap()
        .apply()
        .unwrap();

        let plan = plan_remove_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap();
        assert_eq!(plan.restore, Some(RestoreTier::AdoptedLeftInPlace));
        assert_eq!(plan.write, TargetWrite::Leave);
        plan.apply().unwrap();

        assert!(target.exists(), "the user's file must survive teardown");
        assert_eq!(digest_of(&target), before);
        assert!(
            target.parent().unwrap().is_dir(),
            "the containing directory must not be pruned around a file left in place"
        );
        assert!(
            !sibling_path(&target, ".kaleidoscope-instruction-owner.json")
                .unwrap()
                .exists(),
            "the receipt is removed even though the file is not"
        );
        let strays: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter_map(|entry| {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                name.contains(".kaleidoscope-").then_some(name)
            })
            .collect();
        assert!(strays.is_empty(), "left behind: {strays:?}");
    }

    /// An adopted file the user has SINCE EDITED is released, not refused.
    ///
    /// Before this the path refused: `validate_ownership` saw a hand-edited
    /// owned block and stranded the receipt permanently. rc is asserted, not
    /// just the absence of damage.
    #[test]
    fn teardown_of_an_adopted_whole_file_after_a_user_edit_releases_it() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        plant(&target, &canonical_block(InstructionTarget::Skill));
        plan_install_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap()
        .apply()
        .unwrap();
        fs::write(&target, "the user rewrote this entirely\n").unwrap();
        let edited = digest_of(&target);

        let plan = plan_remove_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .expect("an adopted file the user edited is released, not refused");
        assert_eq!(plan.restore, Some(RestoreTier::AdoptedLeftInPlace));
        plan.apply().unwrap();
        assert_eq!(digest_of(&target), edited, "the user's edit must survive");
        assert!(
            !sibling_path(&target, ".kaleidoscope-instruction-owner.json")
                .unwrap()
                .exists()
        );
    }

    /// A whole-file removal NEVER writes a zero-byte file.
    ///
    /// The latent destructive bug adoption made reachable: `remove_block`
    /// returns `""` for a whole-file target, and with `file_created == false`
    /// that became `Some(b"")` -- an atomic write of an empty file over the
    /// user's content. Asserted on a BYTE LENGTH, which no status field can
    /// fake.
    #[test]
    fn whole_file_teardown_never_writes_an_empty_file() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);
        let target =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        plant(&target, &canonical_block(InstructionTarget::Skill));
        plan_install_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap()
        .apply()
        .unwrap();
        // Force the state that used to truncate: file_created false, and the
        // file no longer matching post_sha256 so Tier 1 cannot fire.
        fs::write(&target, "user content that must not be destroyed\n").unwrap();
        let plan = plan_remove_at(
            InstructionTarget::Skill,
            Some(Host::ClaudeCode),
            &project,
            false,
        )
        .unwrap();
        plan.apply().unwrap();
        let length = fs::metadata(&target).map_or(0, |meta| meta.len());
        assert!(length > 0, "the target was truncated to {length} bytes");
    }

    /// Every conflict message names a way forward.
    ///
    /// Asserted against the RENDERED error, not against a constant, so a
    /// message that stops naming a flag fails even if the constant survives.
    #[test]
    fn every_instruction_conflict_message_names_a_way_forward() {
        let temp = TempDir::new().unwrap();
        let project = project(&temp);

        let skill =
            instruction_path(InstructionTarget::Skill, Some(Host::ClaudeCode), &project).unwrap();
        plant(&skill, "hand written skill\n");
        let cursor = instruction_path(InstructionTarget::Cursor, None, &project).unwrap();
        plant(&cursor, "my own cursor rule\n");
        let claude = instruction_path(InstructionTarget::Claude, None, &project).unwrap();
        plant(
            &claude,
            &format!(
                "{}\nHAND EDITED\n{}\n",
                marker_start(InstructionTarget::Claude),
                marker_end(InstructionTarget::Claude)
            ),
        );

        for (target_kind, host) in [
            (InstructionTarget::Skill, Some(Host::ClaudeCode)),
            (InstructionTarget::Cursor, None),
            (InstructionTarget::Claude, None),
        ] {
            let rendered = plan_install_at(target_kind, host, &project, false)
                .expect_err("differing content must refuse")
                .to_string();
            assert!(
                [
                    "--no-skill",
                    "--no-instructions",
                    "--no-connect",
                    "--no-hooks"
                ]
                .iter()
                .any(|flag| rendered.contains(flag))
                    || rendered.contains("by hand"),
                "{target_kind:?} refusal names no way forward: {rendered}"
            );
        }
    }
}
