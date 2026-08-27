use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::{claude_config_dir, codex_home, project_root, user_home, xdg_config_home};
use crate::error::{ManagerError, Result};
use crate::fs_safe::{
    FileLock, Snapshot, TargetWrite, assert_unchanged, atomic_remove, atomic_write, digest_bytes,
    prune_empty_managed_directories, read_snapshot, restore_snapshot, sibling_path,
    write_bounded_backup,
};
use crate::instructions::RestoreTier;
use crate::model::{LaunchDescriptor, validate_profile_name};

const OWNER: &str = "kaleidoscope-manager-v1";
const OWNER_RECEIPT_VERSION: u32 = 1;
const MAX_HOST_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MARKER_START: &str = "# >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 host=codex";
const MARKER_END: &str = "# <<< kaleidoscope-manager owner=kaleidoscope-manager-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Host {
    Codex,
    ClaudeCode,
    Cursor,
    OpenCode,
}

impl Host {
    pub const ALL: [Self; 4] = [Self::Codex, Self::ClaudeCode, Self::Cursor, Self::OpenCode];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::OpenCode => "opencode",
        }
    }
}

impl FromStr for Host {
    type Err = ManagerError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude" | "claude-code" => Ok(Self::ClaudeCode),
            "cursor" => Ok(Self::Cursor),
            "opencode" => Ok(Self::OpenCode),
            _ => Err(ManagerError::Usage(
                "host must be codex, claude-code, cursor, or opencode".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Project,
}

impl Scope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

impl FromStr for Scope {
    type Err = ManagerError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "project" => Ok(Self::Project),
            _ => Err(ManagerError::Usage(
                "scope must be user or project".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    Add,
    Adopt,
    Update,
    Remove,
    AlreadyConnected,
    AlreadyDisconnected,
}

/// `OpenCode` has two simultaneously documented configuration contracts.
/// Stable v1 is the default; v2 remains an explicit beta surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpenCodeVersion {
    StableV1,
    BetaV2,
}

impl FromStr for OpenCodeVersion {
    type Err = ManagerError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "stable" | "stable-v1" | "v1" => Ok(Self::StableV1),
            "beta" | "beta-v2" | "v2" => Ok(Self::BetaV2),
            _ => Err(ManagerError::Usage(
                "OpenCode version must be stable-v1 or beta-v2".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedFormat {
    JsonEntry,
    CodexMarkerBlock,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipReceipt {
    version: u32,
    owner: String,
    host: Host,
    scope: Scope,
    profile: String,
    format: OwnedFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    open_code_version: Option<OpenCodeVersion>,
    owned_sha256: String,
    owned: Value,
    /// Digest of the file BEFORE the manager first wrote it, and of the bytes
    /// the manager wrote. Together they are what lets removal restore the
    /// pre-connect bytes EXACTLY instead of reserialising -- which is the whole
    /// fix for the JSON hosts, where `serde_json` alphabetised the user's keys
    /// and `to_vec_pretty` discarded their indentation. `serde(default)` so a
    /// receipt written before this field existed still decodes; it simply takes
    /// the structural tier, which is what it got before.
    #[serde(default)]
    pre_sha256: String,
    #[serde(default)]
    post_sha256: String,
    config_created: bool,
    /// True when the manager took ownership of content it did NOT write,
    /// because that content was byte-identical to what it would have written.
    ///
    /// Sticky: an `Update` over an adopted target carries it forward, exactly
    /// as `config_created` is carried forward, because the question it answers
    /// -- "did the pre-manager state already include this entry?" -- is a fact
    /// about the past that a later write cannot change.
    ///
    /// `serde(default)` and NO version bump. A new binary reads every receipt
    /// already on disk correctly, because `adopted: false` ("the manager wrote
    /// it") is true of every receipt written to date; bumping
    /// `OWNER_RECEIPT_VERSION` would refuse all of them and wedge existing
    /// installs behind a manual `rm`. The cost, stated so it is not discovered:
    /// an OLDER binary reading a NEW receipt hits `deny_unknown_fields` and
    /// reports `InvalidOwnerReceipt`, so downgrading the manager over an
    /// existing install needs the two sidecars deleted by hand. That is what
    /// `InvalidOwnerReceipt`'s message already tells the user to do -- and
    /// after adoption it is a SAFE remedy for the first time, because the
    /// re-run adopts the unchanged content instead of refusing it.
    #[serde(default)]
    adopted: bool,
}

impl OwnershipReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: Host,
        scope: Scope,
        profile: &str,
        format: OwnedFormat,
        owned: Value,
        config_created: bool,
        open_code_version: Option<OpenCodeVersion>,
        pre_sha256: String,
        post_sha256: String,
        adopted: bool,
    ) -> Result<Self> {
        validate_profile_name(profile)?;
        let owned_sha256 = owned_digest(format, &owned)?;
        Ok(Self {
            version: OWNER_RECEIPT_VERSION,
            owner: OWNER.to_owned(),
            host,
            scope,
            profile: profile.to_owned(),
            format,
            open_code_version,
            owned_sha256,
            owned,
            pre_sha256,
            post_sha256,
            config_created,
            adopted,
        })
    }

    fn validate(&self, host: Host, scope: Scope) -> Result<()> {
        if self.version != OWNER_RECEIPT_VERSION
            || self.owner != OWNER
            || self.host != host
            || self.scope != scope
            || validate_profile_name(&self.profile).is_err()
            || self.owned_sha256 != owned_digest(self.format, &self.owned)?
            || (self.host == Host::OpenCode) != self.open_code_version.is_some()
        {
            return Err(ManagerError::InvalidOwnerReceipt);
        }
        match self.format {
            OwnedFormat::JsonEntry if !self.owned.is_object() => {
                Err(ManagerError::InvalidOwnerReceipt)
            }
            OwnedFormat::CodexMarkerBlock
                if self
                    .owned
                    .as_str()
                    .is_none_or(|block| !block.starts_with(MARKER_START)) =>
            {
                Err(ManagerError::InvalidOwnerReceipt)
            }
            _ => Ok(()),
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| ManagerError::InvalidOwnerReceipt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionPlan {
    pub host: Host,
    pub scope: Scope,
    pub action: ChangeAction,
    pub profile: Option<String>,
    pub target: PathBuf,
    pub receipt_path: PathBuf,
    pub backup_path: PathBuf,
    /// Which restore tier a removal achieved. `None` on connect. Reporting it
    /// is the mechanism, not decoration: a reversibility claim that cannot say
    /// which of the two tiers it achieved is a claim nothing can check.
    pub restore: Option<RestoreTier>,
    /// True when the receipt this plan writes -- or the receipt it is undoing
    /// -- records that the manager took ownership of content it did not write.
    pub adopted: bool,
    /// A structural restore that nonetheless returned every byte it did not
    /// own. See `json_span`.
    pub formatting_preserved: bool,
    preview: String,
    original: Snapshot,
    receipt_original: Snapshot,
    write: TargetWrite,
    receipt_after: Option<OwnershipReceipt>,
    remove_backup: bool,
}

impl ConnectionPlan {
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }

    #[must_use]
    pub const fn is_noop(&self) -> bool {
        matches!(
            self.action,
            ChangeAction::AlreadyConnected | ChangeAction::AlreadyDisconnected
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
            MAX_HOST_CONFIG_BYTES,
            "host configuration",
        )?;
        assert_unchanged(
            &self.receipt_path,
            &self.receipt_original,
            MAX_RECEIPT_BYTES,
            "connection owner receipt",
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
        // `TargetWrite::Leave` is excluded for a reason that is not merely an
        // optimisation: an adoption writes NOTHING to the target, so there are
        // no pre-modification bytes for a backup to hold. Minting one would
        // leave a stray copy of the user's own file beside it, named after the
        // manager, for a command that changed nothing.
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
            let expected = snapshot_for_write(&self.write, &self.original);
            if assert_unchanged(
                &self.target,
                &expected,
                MAX_HOST_CONFIG_BYTES,
                "host configuration",
            )
            .is_ok()
            {
                restore_snapshot(&self.target, &self.original)?;
            }
            return Err(error);
        }
        if self.remove_backup {
            // Provably redundant: the file now equals what the backup held.
            // Never reached on Tier 2, where the backup is the user's only copy
            // of the pre-edit state.
            atomic_remove(&self.backup_path)?;
        }
        // Remove a directory the manager created and has just emptied.
        //
        // The lock must go FIRST: `FileLock` lives beside the target as
        // `<file>.kaleidoscope-lock` and is only unlinked on drop, so pruning
        // while it is held finds a directory that is never empty.
        drop(lock);
        // Only on a REMOVE. `Leave` must never reach here: pruning after an
        // adoption teardown would delete `use-kaleidoscope/` and possibly
        // `skills/` around a file the manager deliberately left in place.
        if self.write.is_remove() {
            prune_empty_managed_directories(&self.target);
        }
        Ok(())
    }

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
            "host": self.host,
            "scope": self.scope,
            "profile": self.profile,
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
        if self.action == ChangeAction::Adopt {
            value["detail"] = json!(
                "existing content is byte-identical to the manager's; the owner receipt was written and no bytes were changed"
            );
        }
        value
    }

    /// The bytes this plan will leave on the target, for the pre-flight check.
    #[must_use]
    pub const fn writes_nothing(&self) -> bool {
        self.write.is_leave()
    }

    #[must_use]
    pub const fn target(&self) -> &PathBuf {
        &self.target
    }
}

pub fn host_config_path(host: Host, scope: Scope, home: &Path, project: &Path) -> Result<PathBuf> {
    if !home.is_absolute() || !project.is_absolute() {
        return Err(ManagerError::UnsafePath {
            target: "host configuration",
            reason: "home and project roots must be absolute",
        });
    }
    // The USER-scope arms honour each harness's own configuration-directory
    // override. Project-scope arms deliberately do not: a project's files live
    // in the project, and an environment variable that moved them would put
    // shared, version-controlled configuration outside the checkout.
    Ok(match (host, scope) {
        (Host::Codex, Scope::User) => codex_home(home)?.join("config.toml"),
        (Host::Codex, Scope::Project) => project.join(".codex").join("config.toml"),
        (Host::ClaudeCode, Scope::User) => claude_config_dir(home)?.join(".claude.json"),
        (Host::ClaudeCode, Scope::Project) => project.join(".mcp.json"),
        (Host::Cursor, Scope::User) => home.join(".cursor").join("mcp.json"),
        (Host::Cursor, Scope::Project) => project.join(".cursor").join("mcp.json"),
        (Host::OpenCode, Scope::User) => xdg_config_home(home)?
            .join("opencode")
            .join("opencode.json"),
        (Host::OpenCode, Scope::Project) => project.join("opencode.json"),
    })
}

/// `read_snapshot` for a host configuration, with a message a person can act on.
///
/// The generic refusal is `unsafe host configuration path: not a bounded
/// regular file`, which conflates "too big" with "not a regular file" and names
/// neither the size nor a way forward. That was tolerable while user scope was
/// opt-in. It is not tolerable now that `~/.claude.json` -- Claude Code's own
/// live configuration, measured at 152,109 bytes here and growing, against a
/// 1 MiB cap -- is the default target.
fn read_host_config(path: &Path, host: Host, scope: Scope) -> Result<Snapshot> {
    match read_snapshot(path, MAX_HOST_CONFIG_BYTES, "host configuration") {
        Err(ManagerError::UnsafePath {
            reason: "not a bounded regular file",
            ..
        }) => {
            let size = std::fs::symlink_metadata(path).map(|meta| meta.len()).ok();
            Err(match size {
                Some(size) if size > MAX_HOST_CONFIG_BYTES => {
                    // The remedy names the host the caller actually asked for.
                    // It used to say `--host HOST`, which exits 2 with "host
                    // must be codex, claude-code, cursor, or opencode" when
                    // copied -- a refusal handing out a dead end, which is the
                    // exact failure mode adoption was introduced to remove.
                    //
                    // `--scope project` is only a way forward when the caller
                    // was in user scope; in project scope the oversized file IS
                    // the project one, so the only move is to trim it.
                    let alternative = if scope == Scope::User {
                        format!(
                            "\nWays forward:\n  put the entry in the project instead\n      kaleidoscope init --host {} --scope project\n  or trim the file by hand and re-run.",
                            host.as_str()
                        )
                    } else {
                        "\nWay forward:\n  trim the file by hand and re-run.".to_owned()
                    };
                    ManagerError::HostConfigTooLarge(format!(
                        "{} is {size} bytes, over the {MAX_HOST_CONFIG_BYTES}-byte limit this manager will read and rewrite whole, so nothing was changed. The limit exists because every edit re-encodes the entire document, and a partial write of a harness's live configuration is not recoverable.{alternative}",
                        path.display()
                    ))
                }
                _ => ManagerError::UnsafePath {
                    target: "host configuration",
                    reason: "not a bounded regular file",
                },
            })
        }
        other => other,
    }
}

pub fn plan_connect(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    explicit_project: Option<&Path>,
) -> Result<ConnectionPlan> {
    plan_connect_version(host, scope, profile, descriptor, explicit_project, None)
}

pub fn plan_connect_version(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    explicit_project: Option<&Path>,
    open_code_version: Option<OpenCodeVersion>,
) -> Result<ConnectionPlan> {
    let home = user_home()?;
    let project = project_root(explicit_project)?;
    plan_connect_at_version(
        host,
        scope,
        profile,
        descriptor,
        &home,
        &project,
        open_code_version,
    )
}

pub fn plan_connect_at(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    home: &Path,
    project: &Path,
) -> Result<ConnectionPlan> {
    plan_connect_at_version(host, scope, profile, descriptor, home, project, None)
}

pub fn plan_connect_at_version(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    home: &Path,
    project: &Path,
    open_code_version: Option<OpenCodeVersion>,
) -> Result<ConnectionPlan> {
    if host != Host::OpenCode && open_code_version.is_some() {
        return Err(ManagerError::Usage(
            "--opencode-version is valid only for the opencode host".to_owned(),
        ));
    }
    validate_profile_name(profile)?;
    let target = host_config_path(host, scope, home, project)?;
    let receipt_path = sibling_path(&target, ".kaleidoscope-owner.json")?;
    let backup_path = sibling_path(&target, ".kaleidoscope-backup")?;
    let original = read_host_config(&target, host, scope)?;
    let receipt_original =
        read_snapshot(&receipt_path, MAX_RECEIPT_BYTES, "connection owner receipt")?;
    let old_receipt = decode_receipt(&receipt_original, host, scope)?;

    if host == Host::Codex {
        plan_codex_connect(
            host,
            scope,
            profile,
            descriptor,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            old_receipt,
        )
    } else {
        plan_json_connect(
            host,
            scope,
            profile,
            descriptor,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            old_receipt,
            open_code_version,
        )
    }
}

pub fn plan_disconnect(
    host: Host,
    scope: Scope,
    explicit_project: Option<&Path>,
) -> Result<ConnectionPlan> {
    let home = user_home()?;
    let project = project_root(explicit_project)?;
    plan_disconnect_at(host, scope, &home, &project)
}

pub fn plan_disconnect_at(
    host: Host,
    scope: Scope,
    home: &Path,
    project: &Path,
) -> Result<ConnectionPlan> {
    let target = host_config_path(host, scope, home, project)?;
    let receipt_path = sibling_path(&target, ".kaleidoscope-owner.json")?;
    let backup_path = sibling_path(&target, ".kaleidoscope-backup")?;
    let original = read_host_config(&target, host, scope)?;
    let receipt_original =
        read_snapshot(&receipt_path, MAX_RECEIPT_BYTES, "connection owner receipt")?;
    let receipt = decode_receipt(&receipt_original, host, scope)?;

    if host == Host::Codex {
        plan_codex_disconnect(
            host,
            scope,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            receipt,
        )
    } else {
        plan_json_disconnect(
            host,
            scope,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            receipt,
        )
    }
}

pub fn inspect_owned_connection(
    host: Host,
    scope: Scope,
    explicit_project: Option<&Path>,
) -> Result<Option<String>> {
    let plan = plan_disconnect(host, scope, explicit_project)?;
    match plan.action {
        ChangeAction::AlreadyDisconnected => Ok(None),
        ChangeAction::Remove => Ok(plan.profile),
        _ => Err(ManagerError::InvalidOwnerReceipt),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
fn plan_codex_connect(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    old_receipt: Option<OwnershipReceipt>,
) -> Result<ConnectionPlan> {
    let text = snapshot_text(&original)?;
    validate_codex_document(&text)?;
    let current_block = find_codex_block(&text)?;
    // NEVER ADOPTABLE, and it keeps refusing. Adoption requires a delimited
    // region the manager can later remove exactly; an undelimited TOML table
    // is not one, so there is no span a teardown could take back out. Only the
    // message changes: it now says what to do next.
    if current_block.is_none() && contains_unmanaged_codex_table(&text) {
        return Err(ManagerError::HostConflict(format!(
            "{} contains an [mcp_servers.kaleidoscope] table that is not inside a manager marker block, so the manager cannot tell where its own text would end and yours begins. Nothing was changed.\nWays forward:\n  wire everything except the MCP entry\n      kaleidoscope init --host codex --no-connect\n  delete the [mcp_servers.kaleidoscope] table from {} by hand, then re-run.",
            target.display(),
            target.display()
        )));
    }
    // `desired` is computed BEFORE the ownership check, which is the only
    // reordering adoption needs here: the check refuses the no-receipt case,
    // and adoption has to be able to look at the content first.
    let desired = codex_block(descriptor, profile)?;
    // ADOPTION. The marker block already in the file is exactly the one this
    // manager writes. Take ownership by writing the receipt; touch no bytes.
    if old_receipt.is_none() && current_block.as_deref() == Some(desired.as_str()) {
        let receipt = OwnershipReceipt::new(
            host,
            scope,
            profile,
            OwnedFormat::CodexMarkerBlock,
            Value::String(desired.clone()),
            false,
            None,
            original.sha256.clone(),
            original.sha256.clone(),
            true,
        )?;
        return Ok(ConnectionPlan {
            host,
            scope,
            action: ChangeAction::Adopt,
            profile: Some(profile.to_owned()),
            preview: format!(
                "Adopt the existing {} marker block at {} (byte-identical to this manager's; nothing will be written to the file)\nOwned marker block:\n{}",
                host.as_str(),
                target.display(),
                desired
            ),
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            restore: None,
            adopted: true,
            formatting_preserved: false,
            write: TargetWrite::Leave,
            receipt_after: Some(receipt),
            remove_backup: false,
        });
    }
    // A marker block with NO receipt that is not byte-identical to `desired`.
    //
    // Without this arm the call below lands in `validate_current_ownership`'s
    // `(None, Some(current))` catch-all and reports `InvalidOwnerReceipt`,
    // whose message tells the user to "delete the Kaleidoscope entry and its
    // `*.kaleidoscope-owner.json` receipt beside it by hand" -- naming a
    // receipt that, in this state, does not exist. Measured: a user who
    // hand-edits inside the block and then follows that remedy by deleting the
    // receipt gets the IDENTICAL message back, now naming a file they have
    // already removed. The message is a fixed point: following it can never
    // satisfy it, because the blocker is the block, not the receipt.
    //
    // The two sibling paths already do this correctly -- `instructions.rs`
    // refuses a receiptless differing block by naming `--no-instructions`, and
    // the JSON hosts refuse through `unmanaged_json_entry_message`, which names
    // `--no-connect`. This is the same refusal for the one shape that lacked
    // it. It stays a REFUSAL: the content differs, so adoption must not take
    // it. Only the remedy becomes true and reachable.
    //
    // `--force` deliberately does not appear here. The block is delimited by
    // the manager's own markers, so a forced overwrite would be provably
    // bounded -- but `run_init` parses no such flag for the connect step, and
    // naming a flag the command cannot accept is the very defect being fixed.
    if old_receipt.is_none() && current_block.is_some() {
        return Err(ManagerError::HostConflict(format!(
            "{} contains a Kaleidoscope marker block that differs from this version's, and it carries no manager owner receipt. Nothing was changed.\nWays forward:\n  keep your block and wire everything else\n      kaleidoscope init --host {} --no-connect\n  delete the marker block (from the `>>> kaleidoscope-manager` line to the `<<< kaleidoscope-manager` line) from {} by hand, then re-run.\nIf you make the block byte-identical to this manager's, a re-run will adopt it in place and write only the owner receipt.",
            target.display(),
            host.as_str(),
            target.display()
        )));
    }
    validate_current_ownership(
        old_receipt.as_ref(),
        current_block
            .as_deref()
            .map(|block| Value::String(block.to_owned())),
        OwnedFormat::CodexMarkerBlock,
    )?;
    if current_block.as_deref() == Some(desired.as_str()) {
        return no_change_plan(
            host,
            scope,
            ChangeAction::AlreadyConnected,
            Some(profile),
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            desired,
            old_receipt.as_ref().is_some_and(|receipt| receipt.adopted),
        );
    }
    let action = if current_block.is_some() {
        ChangeAction::Update
    } else {
        ChangeAction::Add
    };
    let updated_text = install_codex_block(&text, current_block.as_deref(), &desired)?;
    validate_codex_document(&updated_text)?;
    let config_created = old_receipt
        .as_ref()
        .map_or(original.bytes.is_none(), |receipt| receipt.config_created);
    let updated_bytes = updated_text.into_bytes();
    let pre_sha256 = old_receipt.as_ref().map_or_else(
        || original.sha256.clone(),
        |receipt| {
            if receipt.pre_sha256.is_empty() {
                original.sha256.clone()
            } else {
                receipt.pre_sha256.clone()
            }
        },
    );
    let adopted = old_receipt.as_ref().is_some_and(|receipt| receipt.adopted);
    let receipt = OwnershipReceipt::new(
        host,
        scope,
        profile,
        OwnedFormat::CodexMarkerBlock,
        Value::String(desired.clone()),
        config_created,
        None,
        pre_sha256,
        digest_bytes(&updated_bytes),
        adopted,
    )?;
    Ok(ConnectionPlan {
        host,
        scope,
        action,
        profile: Some(profile.to_owned()),
        preview: format!(
            "{} {} configuration at {}\nOwned marker block:\n{}",
            action_word(action),
            host.as_str(),
            target.display(),
            desired
        ),
        target,
        receipt_path,
        backup_path,
        original,
        receipt_original,
        restore: None,
        adopted,
        formatting_preserved: false,
        write: TargetWrite::Write(updated_bytes),
        receipt_after: Some(receipt),
        remove_backup: false,
    })
}

/// How the preview describes the restore it is about to perform.
///
/// Three outcomes, not two: byte-identical, structural-but-byte-preserving
/// (the entry's own bytes were cut out and nothing else moved), and
/// structural-and-normalized (the whole document was re-encoded). The middle
/// one used to be reported as the third, which understated it -- and the third
/// is the one a user with a hand-formatted file needs to see coming.
const fn restore_words(restore: RestoreTier, formatting_preserved: bool) -> &'static str {
    match (restore, formatting_preserved) {
        (RestoreTier::ByteIdentical, _) => "exact restore",
        (_, true) => "structural restore; every byte outside the entry preserved",
        (_, false) => "structural restore; formatting normalized",
    }
}

/// The two- (now three-) tier restore, shared by both disconnect planners.
///
/// TIER 1, EXACT. The target is still byte-for-byte what the manager wrote, and
/// either the manager created it or the backup holds exactly the pre-connect
/// bytes. Then the pre-connect state is recoverable EXACTLY: put the backup
/// back verbatim, or delete a file we created. This is independent of key
/// ordering, indentation and trailing newlines -- i.e. the entire class of
/// defect that made a user's `.mcp.json` come back alphabetised and re-indented
/// after connect then disconnect.
///
/// TIER 2, STRUCTURAL. Otherwise the user edited the file since connect, and
/// byte-identity to the pre-connect state is not merely hard, it is WRONG --
/// their edit must survive. Fall back to the parse-remove-re-encode path and
/// SAY SO: `restore: "structural", formatting: "normalized"`. Reporting the
/// tier is what makes the guarantee checkable; a Tier-2 result where Tier 1 was
/// expected is a failure even when the bytes happen to match.
fn resolve_restore(
    target: &Path,
    backup_path: &Path,
    original: &Snapshot,
    receipt: &OwnershipReceipt,
    structural: TargetWrite,
) -> Result<(RestoreTier, TargetWrite, bool)> {
    let _ = target;
    // ADOPTION BYPASSES TIER 1, and it must.
    //
    // For an adopted entry `post_sha256` is the untouched file, so `file_is_
    // ours` holds and `config_created` is false while `backup_is_pre` holds
    // too (pre == post) -- Tier 1 would fire and restore "the pre-connect
    // bytes", which for an adoption are the bytes WITH the entry still in
    // them. Byte-exact restore is not merely wrong here, it is impossible: the
    // desired end state, the file minus an entry it always had, has never
    // existed on disk. Take the structural path and say so.
    if receipt.adopted {
        return Ok((RestoreTier::Structural, structural, false));
    }
    let backup = read_snapshot(
        backup_path,
        MAX_HOST_CONFIG_BYTES,
        "host configuration backup",
    )?;
    let file_is_ours = !receipt.post_sha256.is_empty() && original.sha256 == receipt.post_sha256;
    let backup_is_pre = backup.bytes.is_some()
        && !receipt.pre_sha256.is_empty()
        && backup.sha256 == receipt.pre_sha256;
    if file_is_ours && (receipt.config_created || backup_is_pre) {
        return Ok(if receipt.config_created {
            // `remove_backup` is UNCONDITIONALLY true here, matching
            // `hooks.rs` and `instructions.rs`. It used to be
            // `backup.bytes.is_some()`, sampled at PLAN time -- before `apply`
            // had written the backup it then failed to remove. The manager
            // created this file and is about to delete it outright, so any
            // backup of it holds manager-written bytes by construction and is
            // redundant whether or not one exists at this instant. Measured on
            // all four hosts: `.mcp.json.kaleidoscope-backup`,
            // `.codex/config.toml.kaleidoscope-backup`,
            // `.cursor/mcp.json.kaleidoscope-backup` and
            // `opencode.json.kaleidoscope-backup` all survived a teardown that
            // reported `restore: byte_identical`, each naming the profile and
            // the absolute engine path.
            (RestoreTier::ByteIdentical, TargetWrite::Remove, true)
        } else {
            (
                RestoreTier::ByteIdentical,
                backup.bytes.map_or(TargetWrite::Remove, TargetWrite::Write),
                true,
            )
        });
    }
    Ok((RestoreTier::Structural, structural, false))
}

#[allow(clippy::too_many_arguments)]
fn plan_codex_disconnect(
    host: Host,
    scope: Scope,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    receipt: Option<OwnershipReceipt>,
) -> Result<ConnectionPlan> {
    let text = snapshot_text(&original)?;
    validate_codex_document(&text)?;
    let current = find_codex_block(&text)?;
    let Some(receipt) = receipt else {
        if current.is_some() || contains_unmanaged_codex_table(&text) {
            return Err(ManagerError::HostConflict(
                "the Kaleidoscope Codex entry has no manager owner receipt".to_owned(),
            ));
        }
        return no_change_plan(
            host,
            scope,
            ChangeAction::AlreadyDisconnected,
            None,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            String::new(),
            false,
        );
    };
    validate_current_ownership(
        Some(&receipt),
        current.clone().map(Value::String),
        OwnedFormat::CodexMarkerBlock,
    )?;
    let owned = current.ok_or(ManagerError::InvalidOwnerReceipt)?;
    let removed = remove_codex_block(&text, &owned, !receipt.adopted)?;
    // A file the manager did not create is never deleted, even when removing
    // the block empties it.
    let structural = if receipt.config_created && removed.trim().is_empty() {
        TargetWrite::Remove
    } else {
        TargetWrite::Write(removed.into_bytes())
    };
    let adopted = receipt.adopted;
    let (restore, write, remove_backup) =
        resolve_restore(&target, &backup_path, &original, &receipt, structural)?;
    Ok(ConnectionPlan {
        host,
        scope,
        action: ChangeAction::Remove,
        profile: Some(receipt.profile),
        preview: format!(
            "Remove the manager-owned {} block from {} ({})\nOwned marker block:\n{}",
            host.as_str(),
            target.display(),
            restore_words(restore, true),
            owned
        ),
        target,
        receipt_path,
        backup_path,
        restore: Some(restore),
        adopted,
        // `remove_codex_block` is a textual cut from the original document, so
        // the Codex structural tier has ALWAYS been byte-preserving outside the
        // marker block. It reported "formatting normalized" anyway, which
        // understated it in the one place the manager was already doing the
        // right thing.
        formatting_preserved: true,
        original,
        receipt_original,
        write,
        receipt_after: None,
        remove_backup,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
fn plan_json_connect(
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &LaunchDescriptor,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    old_receipt: Option<OwnershipReceipt>,
    requested_open_code_version: Option<OpenCodeVersion>,
) -> Result<ConnectionPlan> {
    let mut document = parse_json_document(&original)?;
    let open_code_version = if host == Host::OpenCode {
        Some(select_opencode_version(
            &document,
            old_receipt.as_ref(),
            requested_open_code_version,
        )?)
    } else {
        None
    };
    let desired = desired_json_entry(host, descriptor, open_code_version);
    let path = json_entry_path(host, open_code_version);
    let current = get_json_path(&document, path).cloned();
    let mut action = if current.is_some() {
        ChangeAction::Update
    } else {
        ChangeAction::Add
    };

    if let Some(receipt) = old_receipt.as_ref() {
        validate_current_ownership(Some(receipt), current.clone(), OwnedFormat::JsonEntry)?;
    } else if current.as_ref() == Some(&desired) {
        // ADOPTION. The entry already in the file is exactly the one this
        // manager writes, so doing nothing already produces the desired state
        // and the only thing missing is the receipt.
        //
        // The `host == Host::OpenCode &&` qualifier that used to guard this was
        // never a property of OpenCode; it was where the idea got written down
        // first. The discriminator for MODIFYING content stays the receipt --
        // content equality unlocks ADOPTION only, and adoption writes nothing.
        action = ChangeAction::Adopt;
    } else if current.is_some() {
        return Err(ManagerError::HostConflict(unmanaged_json_entry_message(
            host, &target, path, &desired,
        )));
    }

    if current.as_ref() == Some(&desired) && old_receipt.is_some() {
        return no_change_plan(
            host,
            scope,
            ChangeAction::AlreadyConnected,
            Some(profile),
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            serde_json::to_string_pretty(&desired).unwrap_or_default(),
            old_receipt.as_ref().is_some_and(|receipt| receipt.adopted),
        );
    }

    let (write, post_sha256) = if action == ChangeAction::Adopt {
        // NOT `TargetWrite::Write(original.bytes)`. Rewriting identical bytes
        // touches mtime, and on the `~/.claude.json` default path it would
        // re-serialise 152 KB of Claude Code's live state -- losing its
        // indentation -- for a command that changed nothing.
        if original.bytes.is_none() {
            return Err(ManagerError::HostConflict(
                "cannot adopt an absent entry".to_owned(),
            ));
        }
        (TargetWrite::Leave, original.sha256.clone())
    } else {
        set_json_path(&mut document, path, desired.clone())?;
        let encoded = encode_json_document(&document)?;
        let digest = digest_bytes(&encoded);
        (TargetWrite::Write(encoded), digest)
    };
    let config_created = action != ChangeAction::Adopt
        && old_receipt
            .as_ref()
            .map_or(original.bytes.is_none(), |receipt| receipt.config_created);
    let pre_sha256 = old_receipt.as_ref().map_or_else(
        || original.sha256.clone(),
        |receipt| {
            if receipt.pre_sha256.is_empty() {
                original.sha256.clone()
            } else {
                receipt.pre_sha256.clone()
            }
        },
    );
    // Sticky, exactly as `config_created` is: an Update over an adopted entry
    // stays adopted, because the pre-manager state DID already include it.
    let adopted = action == ChangeAction::Adopt
        || old_receipt.as_ref().is_some_and(|receipt| receipt.adopted);
    let receipt = OwnershipReceipt::new(
        host,
        scope,
        profile,
        OwnedFormat::JsonEntry,
        desired.clone(),
        config_created,
        open_code_version,
        pre_sha256,
        post_sha256,
        adopted,
    )?;
    Ok(ConnectionPlan {
        host,
        scope,
        action,
        profile: Some(profile.to_owned()),
        preview: if action == ChangeAction::Adopt {
            format!(
                "Adopt the existing {} entry at {} (byte-identical to this manager's; nothing will be written to the file)\nOwned structured entry:\n{}",
                host.as_str(),
                target.display(),
                serde_json::to_string_pretty(&desired).unwrap_or_default()
            )
        } else {
            format!(
                "{} {} configuration at {}\nOwned structured entry:\n{}",
                action_word(action),
                host.as_str(),
                target.display(),
                serde_json::to_string_pretty(&desired).unwrap_or_default()
            )
        },
        target,
        receipt_path,
        backup_path,
        original,
        receipt_original,
        restore: None,
        adopted,
        formatting_preserved: false,
        write,
        receipt_after: Some(receipt),
        remove_backup: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan_json_disconnect(
    host: Host,
    scope: Scope,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    receipt: Option<OwnershipReceipt>,
) -> Result<ConnectionPlan> {
    let mut document = parse_json_document(&original)?;
    let Some(receipt) = receipt else {
        let has_entry = if host == Host::OpenCode {
            opencode_shape_state(&document)?.has_any_entry()
        } else {
            get_json_path(&document, json_entry_path(host, None)).is_some()
        };
        if has_entry {
            return Err(ManagerError::HostConflict(format!(
                "the {} Kaleidoscope entry has no manager owner receipt",
                host.as_str()
            )));
        }
        return no_change_plan(
            host,
            scope,
            ChangeAction::AlreadyDisconnected,
            None,
            target,
            receipt_path,
            backup_path,
            original,
            receipt_original,
            String::new(),
            false,
        );
    };
    let path = json_entry_path(host, receipt.open_code_version);
    let current = get_json_path(&document, path).cloned();
    if host == Host::OpenCode {
        let state = opencode_shape_state(&document)?;
        if state.conflicts_with(
            receipt
                .open_code_version
                .expect("validated OpenCode receipt"),
        ) {
            return Err(ManagerError::HostConflict(
                "both stable-v1 and beta-v2 OpenCode Kaleidoscope entries exist; manual review is required"
                    .to_owned(),
            ));
        }
    }
    validate_current_ownership(Some(&receipt), current.clone(), OwnedFormat::JsonEntry)?;
    let owned = current.ok_or(ManagerError::InvalidOwnerReceipt)?;
    let before = document.clone();
    remove_json_path(&mut document, path)?;
    // `config_created` is false for every adoption, so removing the entry from
    // a hand-written file that held only ours leaves `{"mcpServers": {}}`
    // rather than deleting the file. Untidy; never destructive.
    let mut formatting_preserved = false;
    let structural = if receipt.config_created
        && json_document_is_empty_shell(host, receipt.open_code_version, &document)
    {
        TargetWrite::Remove
    } else {
        // BYTE-PRESERVING FIRST, RE-ENCODE ONLY AS A FALLBACK.
        //
        // `encode_json_document` rewrites the whole file in the manager's own
        // pretty form. On a file the manager wrote that is a no-op; on an
        // ADOPTED one -- the entry was hand-written, so the manager has never
        // touched a byte of it -- it reformats entries the manager does not
        // own and never did. `json_span::excise` cuts the entry's exact bytes
        // out instead and PROVES the result by re-parsing it against the
        // document this function just computed, so the fallback is the old
        // behaviour rather than a risk.
        let excised = snapshot_text(&original)
            .ok()
            .and_then(|text| crate::json_span::excise(&text, &before, &document));
        match excised {
            Some(text) => {
                formatting_preserved = true;
                TargetWrite::Write(text.into_bytes())
            }
            None => TargetWrite::Write(encode_json_document(&document)?),
        }
    };
    let adopted = receipt.adopted;
    let (restore, write, remove_backup) =
        resolve_restore(&target, &backup_path, &original, &receipt, structural)?;
    Ok(ConnectionPlan {
        host,
        scope,
        action: ChangeAction::Remove,
        profile: Some(receipt.profile),
        preview: format!(
            "Remove the manager-owned {} entry from {} ({})\nOwned structured entry:\n{}",
            host.as_str(),
            target.display(),
            restore_words(restore, formatting_preserved),
            serde_json::to_string_pretty(&owned).unwrap_or_default()
        ),
        target,
        receipt_path,
        backup_path,
        restore: Some(restore),
        adopted,
        formatting_preserved,
        original,
        receipt_original,
        write,
        receipt_after: None,
        remove_backup,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
fn no_change_plan(
    host: Host,
    scope: Scope,
    action: ChangeAction,
    profile: Option<&str>,
    target: PathBuf,
    receipt_path: PathBuf,
    backup_path: PathBuf,
    original: Snapshot,
    receipt_original: Snapshot,
    preview_owned: String,
    adopted: bool,
) -> Result<ConnectionPlan> {
    // A DEFENSIVE ASSERT WITH NO REACHABLE TRIGGER, kept deliberately.
    //
    // "A matching entry with no receipt" is exactly the state the `Adopt`
    // branches in `plan_json_connect` and `plan_codex_connect` now intercept,
    // so no caller can arrive here in it. It stays because the invariant it
    // states -- `AlreadyConnected` implies a receipt -- is what makes the rest
    // of this module's reasoning about ownership sound, and an assertion that
    // cannot fire is cheaper than a comment saying it cannot.
    if action == ChangeAction::AlreadyConnected && receipt_original.bytes.is_none() {
        return Err(ManagerError::HostConflict(
            "a matching entry exists but has no manager owner receipt".to_owned(),
        ));
    }
    Ok(ConnectionPlan {
        host,
        scope,
        action,
        profile: profile.map(str::to_owned),
        preview: if preview_owned.is_empty() {
            format!(
                "No manager-owned {} entry exists at {}",
                host.as_str(),
                target.display()
            )
        } else {
            format!(
                "{} is already connected at {}\nOwned entry:\n{}",
                host.as_str(),
                target.display(),
                preview_owned
            )
        },
        target,
        receipt_path,
        backup_path,
        restore: None,
        adopted,
        formatting_preserved: false,
        original,
        receipt_original,
        // NOT `Remove`. This plan is a no-op and `apply` returns before it is
        // read, but a value that would DELETE the user's configuration is the
        // wrong thing to leave sitting in a struct field guarded only by an
        // early return somewhere else.
        write: TargetWrite::Leave,
        receipt_after: None,
        remove_backup: false,
    })
}

fn decode_receipt(
    snapshot: &Snapshot,
    host: Host,
    scope: Scope,
) -> Result<Option<OwnershipReceipt>> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(None);
    };
    let receipt: OwnershipReceipt =
        serde_json::from_slice(bytes).map_err(|_| ManagerError::InvalidOwnerReceipt)?;
    receipt.validate(host, scope)?;
    Ok(Some(receipt))
}

fn validate_current_ownership(
    receipt: Option<&OwnershipReceipt>,
    current: Option<Value>,
    format: OwnedFormat,
) -> Result<()> {
    match (receipt, current) {
        (None, None) => Ok(()),
        // The digest is taken over `receipt.owned`, NOT over `current`.
        //
        // These are two checks with two jobs. `receipt.owned == current` asks
        // whether the entry in the user's file is still the one the manager
        // wrote, and `serde_json`'s map comparison answers that
        // order-insensitively -- correctly, because `{"type":…,"command":…}`
        // and `{"command":…,"type":…}` are the same entry. `owned_sha256` asks
        // whether the RECEIPT is internally consistent, which is a question
        // about the receipt and has nothing to do with the user's file.
        //
        // Digesting `current` conflated them, and because `Cargo.toml` builds
        // `serde_json` with `preserve_order`, the second check was
        // order-SENSITIVE while the first was not. Reordering the three keys of
        // the manager's own `.mcp.json` entry -- which is what any formatter
        // with sort-keys does, and what a user tidying the file does by hand --
        // then made the connection PERMANENTLY unremovable: `teardown`,
        // `teardown --force` and `disconnect` all returned rc=2 "connection
        // owner receipt is invalid or does not match the managed entry", and
        // restoring the original key order was the only way out. Measured on
        // claude-code and opencode.
        //
        // Backwards compatible by construction: `receipt.owned` is serialised
        // and re-read with the same order-preserving map, so an existing
        // receipt's stored digest still matches.
        (Some(receipt), Some(current))
            if receipt.format == format
                && receipt.owned == current
                && receipt.owned_sha256 == owned_digest(format, &receipt.owned)? =>
        {
            Ok(())
        }
        _ => Err(ManagerError::InvalidOwnerReceipt),
    }
}

/// The refusal a user sees when a foreign Kaleidoscope entry is in the way.
///
/// NO `--force` IS ADDED TO THE HOST-CONFIG PLANNERS, and that is a decision
/// rather than an omission. An instruction block is delimited by the manager's
/// own markers, so forcing there discards bytes that are provably inside its
/// own region, and they are disclosed and backed up first. A foreign
/// `mcpServers.kaleidoscope` entry has no such proof -- it may be another
/// tool's, or a hand-tuned command line -- and discarding it is unrecoverable.
/// The manual remedy is one action, is reversible by the user, and is spelled
/// out here with the exact path and key.
fn unmanaged_json_entry_message(
    host: Host,
    target: &Path,
    path: &[&str],
    desired: &Value,
) -> String {
    let full = path.join(".");
    let parent = path
        .split_last()
        .map_or_else(String::new, |(_, parents)| parents.join("."));
    let rendered = serde_json::to_string_pretty(desired)
        .unwrap_or_default()
        .lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{} already contains a \"{full}\" entry that is not the one this manager writes, and it carries no manager owner receipt. The manager will not edit an entry it cannot prove it wrote. Nothing was changed.\nWays forward:\n  wire everything except the MCP entry\n      kaleidoscope init --host {} --no-connect\n  hand the entry over: delete the \"kaleidoscope\" key under \"{parent}\" in {}, then re-run -- or make it byte-identical to this, which a re-run will adopt in place:\n{rendered}",
        target.display(),
        host.as_str(),
        target.display(),
    )
}

fn owned_digest(format: OwnedFormat, owned: &Value) -> Result<String> {
    let bytes = match format {
        OwnedFormat::JsonEntry => {
            serde_json::to_vec(owned).map_err(|_| ManagerError::InvalidOwnerReceipt)?
        }
        OwnedFormat::CodexMarkerBlock => owned
            .as_str()
            .ok_or(ManagerError::InvalidOwnerReceipt)?
            .as_bytes()
            .to_vec(),
    };
    Ok(digest_bytes(&bytes))
}

fn desired_json_entry(
    host: Host,
    descriptor: &LaunchDescriptor,
    open_code_version: Option<OpenCodeVersion>,
) -> Value {
    let command = descriptor.command.to_string_lossy().into_owned();
    match host {
        Host::ClaudeCode => json!({
            "type": "stdio",
            "command": command,
            "args": descriptor.args,
        }),
        Host::Cursor => json!({
            "command": command,
            "args": descriptor.args,
        }),
        Host::OpenCode => {
            let mut launch = vec![command];
            launch.extend(descriptor.args.clone());
            match open_code_version.expect("OpenCode version is selected before rendering") {
                OpenCodeVersion::StableV1 => json!({
                    "type": "local",
                    "command": launch,
                    "enabled": true,
                }),
                OpenCodeVersion::BetaV2 => json!({
                    "type": "local",
                    "command": launch,
                    "codemode": false,
                }),
            }
        }
        Host::Codex => unreachable!("Codex uses a marker-delimited TOML transform"),
    }
}

fn json_entry_path(
    host: Host,
    open_code_version: Option<OpenCodeVersion>,
) -> &'static [&'static str] {
    match host {
        Host::ClaudeCode | Host::Cursor => &["mcpServers", "kaleidoscope"],
        Host::OpenCode => match open_code_version.expect("OpenCode receipt records its version") {
            OpenCodeVersion::StableV1 => &["mcp", "kaleidoscope"],
            OpenCodeVersion::BetaV2 => &["mcp", "servers", "kaleidoscope"],
        },
        Host::Codex => &[],
    }
}

#[derive(Clone, Copy, Debug)]
struct OpenCodeShapeState {
    stable_entry: bool,
    beta_container: bool,
    beta_entry: bool,
}

impl OpenCodeShapeState {
    const fn has_any_entry(self) -> bool {
        self.stable_entry || self.beta_entry
    }

    const fn conflicts_with(self, version: OpenCodeVersion) -> bool {
        match version {
            OpenCodeVersion::StableV1 => self.beta_container,
            OpenCodeVersion::BetaV2 => self.stable_entry,
        }
    }
}

fn opencode_shape_state(document: &Value) -> Result<OpenCodeShapeState> {
    let Some(mcp) = document.get("mcp") else {
        return Ok(OpenCodeShapeState {
            stable_entry: false,
            beta_container: false,
            beta_entry: false,
        });
    };
    let mcp = mcp.as_object().ok_or_else(|| {
        ManagerError::InvalidHostConfig("OpenCode mcp must be an object".to_owned())
    })?;
    let stable_entry = mcp.contains_key("kaleidoscope");
    let (beta_container, beta_entry) = match mcp.get("servers") {
        None => (false, false),
        Some(servers) => {
            let servers = servers.as_object().ok_or_else(|| {
                ManagerError::InvalidHostConfig(
                    "OpenCode mcp.servers must be an object for beta-v2".to_owned(),
                )
            })?;
            (true, servers.contains_key("kaleidoscope"))
        }
    };
    Ok(OpenCodeShapeState {
        stable_entry,
        beta_container,
        beta_entry,
    })
}

fn select_opencode_version(
    document: &Value,
    receipt: Option<&OwnershipReceipt>,
    requested: Option<OpenCodeVersion>,
) -> Result<OpenCodeVersion> {
    let state = opencode_shape_state(document)?;
    let selected = if let Some(receipt) = receipt {
        let owned = receipt
            .open_code_version
            .ok_or(ManagerError::InvalidOwnerReceipt)?;
        if requested.is_some_and(|requested| requested != owned) {
            return Err(ManagerError::HostConflict(
                "the requested OpenCode version differs from the manager-owned entry".to_owned(),
            ));
        }
        owned
    } else if let Some(requested) = requested {
        requested
    } else if state.beta_container {
        OpenCodeVersion::BetaV2
    } else {
        OpenCodeVersion::StableV1
    };
    if state.conflicts_with(selected) {
        return Err(ManagerError::HostConflict(
            "stable-v1 and beta-v2 OpenCode shapes are both present or conflict with the requested target; manual review is required"
                .to_owned(),
        ));
    }
    Ok(selected)
}

fn parse_json_document(snapshot: &Snapshot) -> Result<Value> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(Value::Object(Map::new()));
    };
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Map::new()));
    }
    let document: Value = serde_json::from_slice(bytes).map_err(|_| {
        ManagerError::InvalidHostConfig(
            "expected strict JSON; JSONC files must be migrated to .json before manager edits"
                .to_owned(),
        )
    })?;
    if !document.is_object() {
        return Err(ManagerError::InvalidHostConfig(
            "top-level value must be an object".to_owned(),
        ));
    }
    Ok(document)
}

fn encode_json_document(document: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|_| ManagerError::InvalidHostConfig("cannot encode JSON".to_owned()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn get_json_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn set_json_path(value: &mut Value, path: &[&str], member: Value) -> Result<()> {
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| ManagerError::InvalidHostConfig("empty structured path".to_owned()))?;
    let mut current = value;
    for key in parents {
        let object = current
            .as_object_mut()
            .ok_or_else(|| ManagerError::InvalidHostConfig(format!("{key} is not an object")))?;
        current = object
            .entry((*key).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    current
        .as_object_mut()
        .ok_or_else(|| ManagerError::InvalidHostConfig("parent is not an object".to_owned()))?
        .insert((*last).to_owned(), member);
    Ok(())
}

fn remove_json_path(value: &mut Value, path: &[&str]) -> Result<()> {
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| ManagerError::InvalidHostConfig("empty structured path".to_owned()))?;
    let mut current = value;
    for key in parents {
        current = current
            .get_mut(*key)
            .ok_or(ManagerError::InvalidOwnerReceipt)?;
    }
    let removed = current
        .as_object_mut()
        .ok_or(ManagerError::InvalidOwnerReceipt)?
        .remove(*last);
    if removed.is_none() {
        return Err(ManagerError::InvalidOwnerReceipt);
    }
    Ok(())
}

fn json_document_is_empty_shell(
    host: Host,
    open_code_version: Option<OpenCodeVersion>,
    document: &Value,
) -> bool {
    let mut expected = Value::Object(Map::new());
    let _ = match host {
        Host::ClaudeCode | Host::Cursor => {
            set_json_path(&mut expected, &["mcpServers"], Value::Object(Map::new()))
        }
        Host::OpenCode => match open_code_version.expect("OpenCode receipt records its version") {
            OpenCodeVersion::StableV1 => {
                set_json_path(&mut expected, &["mcp"], Value::Object(Map::new()))
            }
            OpenCodeVersion::BetaV2 => set_json_path(
                &mut expected,
                &["mcp", "servers"],
                Value::Object(Map::new()),
            ),
        },
        Host::Codex => Ok(()),
    };
    document == &expected || document.as_object().is_some_and(Map::is_empty)
}

fn codex_block(descriptor: &LaunchDescriptor, profile: &str) -> Result<String> {
    let command = serde_json::to_string(descriptor.command.to_str().ok_or(
        ManagerError::InvalidEngineContract {
            contract: "launch descriptor",
            reason: "command is not UTF-8",
        },
    )?)
    .map_err(|_| ManagerError::InvalidHostConfig("cannot encode command".to_owned()))?;
    let profile = serde_json::to_string(profile)
        .map_err(|_| ManagerError::InvalidHostConfig("cannot encode profile".to_owned()))?;
    Ok(format!(
        "{MARKER_START}\n\
         [mcp_servers.kaleidoscope]\n\
         command = {command}\n\
         args = [\"mcp\", \"--profile\", {profile}]\n\
         enabled = true\n\
         required = false\n\
         startup_timeout_sec = 10\n\
         tool_timeout_sec = 30\n\
         enabled_tools = [\"search\", \"remember\"]\n\
         default_tools_approval_mode = \"writes\"\n\
         \n\
         [mcp_servers.kaleidoscope.tools.search]\n\
         approval_mode = \"approve\"\n\
         {MARKER_END}\n"
    ))
}

fn snapshot_text(snapshot: &Snapshot) -> Result<String> {
    let bytes = snapshot.bytes.as_deref().unwrap_or_default();
    String::from_utf8(bytes.to_vec())
        .map_err(|_| ManagerError::InvalidHostConfig("configuration is not UTF-8".to_owned()))
}

fn validate_codex_document(text: &str) -> Result<()> {
    text.parse::<toml_edit::DocumentMut>()
        .map(|_| ())
        .map_err(|_| {
            ManagerError::InvalidHostConfig(
                "Codex configuration must be valid TOML before manager edits".to_owned(),
            )
        })
}

fn find_codex_block(text: &str) -> Result<Option<String>> {
    let starts = text.match_indices(MARKER_START).collect::<Vec<_>>();
    let ends = text.match_indices(MARKER_END).collect::<Vec<_>>();
    match (starts.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([(start, _)], [(end, _)]) if start < end => {
            let after = end + MARKER_END.len();
            let after = if text.as_bytes().get(after) == Some(&b'\n') {
                after + 1
            } else {
                after
            };
            Ok(Some(text[*start..after].to_owned()))
        }
        _ => Err(ManagerError::InvalidHostConfig(
            "manager marker block is duplicated or incomplete".to_owned(),
        )),
    }
}

fn contains_unmanaged_codex_table(text: &str) -> bool {
    text.lines().map(str::trim).any(|line| {
        line == "[mcp_servers.kaleidoscope]"
            || line == "[mcp_servers.\"kaleidoscope\"]"
            || line.starts_with("[mcp_servers.kaleidoscope.")
    })
}

fn install_codex_block(text: &str, current: Option<&str>, desired: &str) -> Result<String> {
    if let Some(current) = current {
        let count = text.matches(current).count();
        if count != 1 {
            return Err(ManagerError::InvalidHostConfig(
                "owned marker block is ambiguous".to_owned(),
            ));
        }
        return Ok(text.replacen(current, desired, 1));
    }
    let separator = if text.is_empty() || text.ends_with("\n\n") {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    Ok(format!("{text}{separator}{desired}"))
}

/// Take the owned block back out, and the separator with it -- but ONLY the
/// separator the manager itself inserted.
///
/// `inserted_separator` is false for an adopted block. `install_codex_block`
/// puts a `"\n"` before the block when the file did not already end in a blank
/// line, and this used to swallow one newline unconditionally to match. For a
/// block the manager NEVER INSERTED that is not symmetry, it is eating a byte
/// of the user's file -- measured: a hand-written `config.toml` came back one
/// newline shorter after adopt-then-teardown.
///
/// `instructions.rs` records the separator in the receipt for exactly this
/// reason ("two heuristics that must agree become one recorded fact"). This is
/// the same fix with the one bit the Codex receipt actually needs.
fn remove_codex_block(text: &str, block: &str, inserted_separator: bool) -> Result<String> {
    let Some(start) = text.find(block) else {
        return Err(ManagerError::InvalidOwnerReceipt);
    };
    if text[start + block.len()..].contains(block) {
        return Err(ManagerError::InvalidOwnerReceipt);
    }
    let mut removal_start = start;
    if inserted_separator && start >= 2 && &text[start - 2..start] == "\n\n" {
        removal_start -= 1;
    }
    let mut result = String::with_capacity(text.len() - (start + block.len() - removal_start));
    result.push_str(&text[..removal_start]);
    result.push_str(&text[start + block.len()..]);
    Ok(result)
}

fn action_word(action: ChangeAction) -> &'static str {
    match action {
        ChangeAction::Add => "Add",
        ChangeAction::Adopt => "Adopt",
        ChangeAction::Update => "Update",
        ChangeAction::Remove => "Remove",
        ChangeAction::AlreadyConnected | ChangeAction::AlreadyDisconnected => "Keep",
    }
}

/// What the target should look like immediately after `apply` wrote it.
///
/// The `Leave` arm answers with the ORIGINAL, and that arm is load-bearing:
/// this snapshot is what the receipt-write error path compares against before
/// deciding whether it is safe to restore, and an adoption's "after" state is
/// its "before" state.
fn snapshot_for_write(write: &TargetWrite, original: &Snapshot) -> Snapshot {
    match write {
        TargetWrite::Write(bytes) => Snapshot {
            bytes: Some(bytes.clone()),
            sha256: digest_bytes(bytes),
            unix_mode: original.unix_mode,
        },
        TargetWrite::Remove => Snapshot::absent(),
        TargetWrite::Leave => original.clone(),
    }
}

pub fn canonical_paths(
    explicit_project: Option<&Path>,
) -> Result<BTreeMap<(Host, Scope), PathBuf>> {
    let home = user_home()?;
    let project = project_root(explicit_project)?;
    Host::ALL
        .into_iter()
        .flat_map(|host| {
            [Scope::User, Scope::Project]
                .into_iter()
                .map(move |scope| (host, scope))
        })
        .map(|(host, scope)| {
            host_config_path(host, scope, &home, &project).map(|path| ((host, scope), path))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn descriptor(root: &Path) -> LaunchDescriptor {
        let engine = root.join("kscope");
        fs::write(&engine, b"fixture").unwrap();
        LaunchDescriptor {
            version: 1,
            transport: "stdio".to_owned(),
            command: engine,
            args: vec![
                "mcp".to_owned(),
                "--profile".to_owned(),
                "default".to_owned(),
            ],
            tools: vec!["search".to_owned(), "remember".to_owned()],
            environment: BTreeMap::new(),
        }
    }

    fn environment(temp: &TempDir) -> (PathBuf, PathBuf) {
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        (
            fs::canonicalize(home).unwrap(),
            fs::canonicalize(project).unwrap(),
        )
    }

    #[test]
    fn codex_marker_connect_disconnect_preserves_unrelated_text() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let target = project.join(".codex/config.toml");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "model = \"gpt-test\"\n").unwrap();
        let descriptor = descriptor(temp.path());

        let connect = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let connected = fs::read_to_string(&target).unwrap();
        assert!(connected.starts_with("model = \"gpt-test\"\n"));
        assert!(connected.contains(MARKER_START));

        let repeated = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        assert_eq!(repeated.action, ChangeAction::AlreadyConnected);

        let disconnect = plan_disconnect_at(Host::Codex, Scope::Project, &home, &project).unwrap();
        disconnect.apply().unwrap();
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "model = \"gpt-test\"\n"
        );
    }

    #[test]
    fn json_connect_disconnect_preserves_unrelated_values() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let target = project.join(".mcp.json");
        fs::write(&target, "{\"unrelated\":{\"keep\":true}}\n").unwrap();
        let descriptor = descriptor(temp.path());
        let connect = plan_connect_at(
            Host::ClaudeCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let connected: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(connected["unrelated"]["keep"], true);
        assert_eq!(connected["mcpServers"]["kaleidoscope"]["type"], "stdio");

        let disconnect =
            plan_disconnect_at(Host::ClaudeCode, Scope::Project, &home, &project).unwrap();
        disconnect.apply().unwrap();
        let disconnected: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(disconnected["unrelated"]["keep"], true);
        assert!(disconnected["mcpServers"]["kaleidoscope"].is_null());
    }

    #[test]
    fn opencode_exact_stable_shape_is_adopted_without_v2_migration() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let target = project.join("opencode.json");
        let descriptor = descriptor(temp.path());
        fs::write(
            &target,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://opencode.ai/config.json",
                "mcp": {
                    "kaleidoscope": desired_json_entry(
                        Host::OpenCode,
                        &descriptor,
                        Some(OpenCodeVersion::StableV1),
                    ),
                    "other": {"type": "remote", "url": "https://example.invalid/mcp"}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let plan = plan_connect_at(
            Host::OpenCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        let before = fs::read(&target).unwrap();
        assert_eq!(plan.action, ChangeAction::Adopt);
        plan.apply().unwrap();
        assert_eq!(fs::read(&target).unwrap(), before);
        let migrated: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(migrated["mcp"]["kaleidoscope"]["enabled"], true);
        assert!(migrated["mcp"]["servers"].is_null());
        assert_eq!(
            migrated["mcp"]["other"]["url"],
            "https://example.invalid/mcp"
        );
    }

    #[test]
    fn unmanaged_and_divergent_entries_refuse() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        fs::write(
            project.join(".mcp.json"),
            "{\"mcpServers\":{\"kaleidoscope\":{\"command\":\"other\"}}}",
        )
        .unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::ClaudeCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project
            ),
            Err(ManagerError::HostConflict(_))
        ));

        fs::write(
            project.join("opencode.json"),
            "{\"mcp\":{\"kaleidoscope\":{\"type\":\"local\",\"command\":[\"other\"],\"enabled\":true}}}",
        )
        .unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::OpenCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project
            ),
            Err(ManagerError::HostConflict(_))
        ));
    }

    #[test]
    fn concurrent_edit_after_preview_refuses() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let plan = plan_connect_at(
            Host::Cursor,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        fs::create_dir_all(project.join(".cursor")).unwrap();
        fs::write(project.join(".cursor/mcp.json"), "{\"changed\":true}\n").unwrap();
        assert!(matches!(plan.apply(), Err(ManagerError::ConcurrentEdit)));
    }

    #[test]
    fn codex_emits_exact_tool_allowlist_and_no_environment() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let plan = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        plan.apply().unwrap();
        let text = fs::read_to_string(project.join(".codex/config.toml")).unwrap();
        assert!(text.contains("enabled_tools = [\"search\", \"remember\"]"));
        assert!(text.contains("required = false"));
        assert!(text.contains("tool_timeout_sec = 30"));
        assert!(!text.contains("env ="));
        assert!(!text.contains("environment"));
    }

    #[test]
    fn codex_block_matches_public_golden_fixture() {
        let temp = TempDir::new().unwrap();
        let descriptor = descriptor(temp.path());
        let command = serde_json::to_string(descriptor.command.to_str().unwrap()).unwrap();
        let expected = include_str!("../tests/fixtures/codex-managed-block.toml")
            .replace("\"/absolute/path/to/kscope\"", &command);
        assert_eq!(codex_block(&descriptor, "default").unwrap(), expected);
    }

    #[test]
    fn opencode_blank_defaults_to_stable_v1_and_explicit_v2_is_beta_shape() {
        let stable_temp = TempDir::new().unwrap();
        let (stable_home, stable_project) = environment(&stable_temp);
        let stable_descriptor = descriptor(stable_temp.path());
        let stable = plan_connect_at(
            Host::OpenCode,
            Scope::Project,
            "default",
            &stable_descriptor,
            &stable_home,
            &stable_project,
        )
        .unwrap();
        stable.apply().unwrap();
        let document: Value =
            serde_json::from_slice(&fs::read(stable_project.join("opencode.json")).unwrap())
                .unwrap();
        assert_eq!(document["mcp"]["kaleidoscope"]["enabled"], true);
        assert!(document["mcp"]["servers"].is_null());

        let beta_temp = TempDir::new().unwrap();
        let (beta_home, beta_project) = environment(&beta_temp);
        let beta_descriptor = descriptor(beta_temp.path());
        let beta = plan_connect_at_version(
            Host::OpenCode,
            Scope::Project,
            "default",
            &beta_descriptor,
            &beta_home,
            &beta_project,
            Some(OpenCodeVersion::BetaV2),
        )
        .unwrap();
        beta.apply().unwrap();
        let document: Value =
            serde_json::from_slice(&fs::read(beta_project.join("opencode.json")).unwrap()).unwrap();
        assert_eq!(
            document["mcp"]["servers"]["kaleidoscope"]["codemode"],
            false
        );
        assert!(document["mcp"]["kaleidoscope"].is_null());
    }

    #[test]
    fn opencode_detects_and_adopts_exact_beta_v2_without_moving_it() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let desired =
            desired_json_entry(Host::OpenCode, &descriptor, Some(OpenCodeVersion::BetaV2));
        fs::write(
            project.join("opencode.json"),
            serde_json::to_vec_pretty(&json!({
                "mcp": {"servers": {"kaleidoscope": desired}}
            }))
            .unwrap(),
        )
        .unwrap();
        let adopt = plan_connect_at(
            Host::OpenCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        assert_eq!(adopt.action, ChangeAction::Adopt);
        adopt.apply().unwrap();
        let repeated = plan_connect_at(
            Host::OpenCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        assert_eq!(repeated.action, ChangeAction::AlreadyConnected);
    }

    #[test]
    fn opencode_dual_or_requested_conflicting_shapes_refuse() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        fs::write(
            project.join("opencode.json"),
            serde_json::to_vec(&json!({
                "mcp": {
                    "kaleidoscope": desired_json_entry(
                        Host::OpenCode,
                        &descriptor,
                        Some(OpenCodeVersion::StableV1)
                    ),
                    "servers": {}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::OpenCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::HostConflict(_))
        ));

        fs::write(
            project.join("opencode.json"),
            serde_json::to_vec(&json!({
                "mcp": {"kaleidoscope": desired_json_entry(
                    Host::OpenCode,
                    &descriptor,
                    Some(OpenCodeVersion::StableV1)
                )}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            plan_connect_at_version(
                Host::OpenCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
                Some(OpenCodeVersion::BetaV2),
            ),
            Err(ManagerError::HostConflict(_))
        ));
    }

    #[test]
    fn reconnect_is_idempotent_and_does_not_replace_backup() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let target = project.join(".cursor/mcp.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"{\"unrelated\":\"original\"}\n").unwrap();
        let descriptor = descriptor(temp.path());
        let connect = plan_connect_at(
            Host::Cursor,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let backup = connect.backup_path.clone();
        let before = fs::read(&backup).unwrap();
        #[cfg(unix)]
        let before_inode = {
            use std::os::unix::fs::MetadataExt as _;
            fs::metadata(&backup).unwrap().ino()
        };
        let repeated = plan_connect_at(
            Host::Cursor,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        assert_eq!(repeated.action, ChangeAction::AlreadyConnected);
        repeated.apply().unwrap();
        assert_eq!(fs::read(backup).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                fs::metadata(&repeated.backup_path).unwrap().ino(),
                before_inode
            );
        }
    }

    #[test]
    fn disconnect_refuses_an_unrelated_edit_after_preview() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let connect = plan_connect_at(
            Host::ClaudeCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let disconnect =
            plan_disconnect_at(Host::ClaudeCode, Scope::Project, &home, &project).unwrap();
        let target = project.join(".mcp.json");
        let mut document: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        document["unrelated"] = json!(true);
        fs::write(&target, encode_json_document(&document).unwrap()).unwrap();
        assert!(matches!(
            disconnect.apply(),
            Err(ManagerError::ConcurrentEdit)
        ));
    }

    #[test]
    fn hostile_marker_and_tampered_receipt_or_entry_refuse() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let codex_target = project.join(".codex/config.toml");
        fs::create_dir_all(codex_target.parent().unwrap()).unwrap();
        fs::write(&codex_target, format!("{MARKER_START}\nunterminated\n")).unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::Codex,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidHostConfig(_))
        ));

        fs::remove_file(&codex_target).unwrap();
        let connect = plan_connect_at(
            Host::Cursor,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&connect.receipt_path).unwrap()).unwrap();
        receipt["owner"] = json!("attacker");
        fs::write(
            &connect.receipt_path,
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            plan_disconnect_at(Host::Cursor, Scope::Project, &home, &project),
            Err(ManagerError::InvalidOwnerReceipt)
        ));

        fs::remove_file(&connect.receipt_path).unwrap();
        fs::write(&connect.receipt_path, b"{}").unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::Cursor,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidOwnerReceipt)
        ));
    }

    #[test]
    fn tampered_owned_entry_refuses_disconnect() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let connect = plan_connect_at(
            Host::ClaudeCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let target = project.join(".mcp.json");
        let mut document: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        document["mcpServers"]["kaleidoscope"]["command"] = json!("attacker");
        fs::write(&target, encode_json_document(&document).unwrap()).unwrap();
        assert!(matches!(
            plan_disconnect_at(Host::ClaudeCode, Scope::Project, &home, &project),
            Err(ManagerError::InvalidOwnerReceipt)
        ));
    }

    #[test]
    fn tampered_codex_owner_marker_refuses_disconnect() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let connect = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        connect.apply().unwrap();
        let text = fs::read_to_string(&connect.target)
            .unwrap()
            .replace("tool_timeout_sec = 30", "tool_timeout_sec = 300");
        fs::write(&connect.target, text).unwrap();
        assert!(matches!(
            plan_disconnect_at(Host::Codex, Scope::Project, &home, &project),
            Err(ManagerError::InvalidOwnerReceipt)
        ));
    }

    #[test]
    fn missing_files_work_invalid_preexisting_files_refuse() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let missing = plan_connect_at(
            Host::ClaudeCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        missing.apply().unwrap();
        plan_disconnect_at(Host::ClaudeCode, Scope::Project, &home, &project)
            .unwrap()
            .apply()
            .unwrap();
        assert!(!project.join(".mcp.json").exists());

        fs::write(project.join(".mcp.json"), b"{not-json").unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::ClaudeCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidHostConfig(_))
        ));

        let codex = project.join(".codex/config.toml");
        fs::create_dir_all(codex.parent().unwrap()).unwrap();
        fs::write(&codex, "invalid = [\n").unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::Codex,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidHostConfig(_))
        ));
        fs::write(
            &codex,
            "mcp_servers = { kaleidoscope = { command = \"other\" } }\n",
        )
        .unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::Codex,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidHostConfig(_))
        ));
        fs::write(project.join(".mcp.json"), b"[]").unwrap();
        assert!(matches!(
            plan_connect_at(
                Host::ClaudeCode,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
            ),
            Err(ManagerError::InvalidHostConfig(_))
        ));
    }

    #[test]
    fn spaces_unicode_and_sensitive_values_are_handled_without_leakage() {
        let temp = TempDir::new().unwrap();
        let home_raw = temp.path().join("home with spaces 🪞");
        let project_raw = temp.path().join("project ünicode");
        fs::create_dir_all(&home_raw).unwrap();
        fs::create_dir_all(&project_raw).unwrap();
        let home = fs::canonicalize(home_raw).unwrap();
        let project = fs::canonicalize(project_raw).unwrap();
        let descriptor = descriptor(temp.path());
        let plan = plan_connect_at(
            Host::Cursor,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        plan.apply().unwrap();
        let mut published = fs::read_to_string(&plan.target).unwrap();
        published.push_str(&fs::read_to_string(&plan.receipt_path).unwrap());
        for secret in [
            "vault-root-secret",
            "wsp_secret",
            "usr_secret",
            "journal:secret",
            "token-secret",
        ] {
            assert!(!published.contains(secret));
        }
    }
}

#[cfg(test)]
mod adoption_tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn descriptor(root: &Path) -> LaunchDescriptor {
        let engine = root.join("kscope");
        fs::write(&engine, b"fixture").unwrap();
        LaunchDescriptor {
            version: 1,
            transport: "stdio".to_owned(),
            command: engine,
            args: vec![
                "mcp".to_owned(),
                "--profile".to_owned(),
                "default".to_owned(),
            ],
            tools: vec!["search".to_owned(), "remember".to_owned()],
            environment: BTreeMap::new(),
        }
    }

    fn environment(temp: &TempDir) -> (PathBuf, PathBuf) {
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        (
            fs::canonicalize(home).unwrap(),
            fs::canonicalize(project).unwrap(),
        )
    }

    /// Every JSON host adopts an entry byte-identical to its own.
    ///
    /// The `host == Host::OpenCode` qualifier that used to guard this was never
    /// a property of `OpenCode` -- it was where the idea got written down first --
    /// so all three are asserted, and a per-host regression fails one arm.
    #[test]
    fn every_json_host_adopts_an_identical_entry_without_touching_the_file() {
        for host in [Host::ClaudeCode, Host::Cursor, Host::OpenCode] {
            let temp = TempDir::new().unwrap();
            let (home, project) = environment(&temp);
            let descriptor = descriptor(temp.path());
            let version = (host == Host::OpenCode).then_some(OpenCodeVersion::StableV1);
            let target = host_config_path(host, Scope::Project, &home, &project).unwrap();
            let mut document = Value::Object(Map::new());
            // A sibling key, so "the file survived" is distinguishable from
            // "the file was rewritten with only our entry".
            set_json_path(&mut document, &["zzz"], json!("keep me")).unwrap();
            set_json_path(
                &mut document,
                json_entry_path(host, version),
                desired_json_entry(host, &descriptor, version),
            )
            .unwrap();
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            // Hand-formatted: four-space indent, not the manager's encoding.
            fs::write(
                &target,
                serde_json::to_string_pretty(&document).unwrap() + "\n",
            )
            .unwrap();
            let before = digest_bytes(&fs::read(&target).unwrap());

            let plan = plan_connect_at_version(
                host,
                Scope::Project,
                "default",
                &descriptor,
                &home,
                &project,
                version,
            )
            .unwrap();
            assert_eq!(plan.action, ChangeAction::Adopt, "{host:?}");
            assert!(plan.adopted, "{host:?}");
            assert_eq!(plan.write, TargetWrite::Leave, "{host:?}");
            plan.apply().unwrap();
            assert_eq!(
                digest_bytes(&fs::read(&target).unwrap()),
                before,
                "{host:?}: adoption re-encoded the file"
            );
            assert!(
                !sibling_path(&target, ".kaleidoscope-backup")
                    .unwrap()
                    .exists(),
                "{host:?}: adoption wrote a backup"
            );

            // Teardown removes the ENTRY and keeps everything else.
            let removal = plan_disconnect_at(host, Scope::Project, &home, &project).unwrap();
            assert_eq!(removal.restore, Some(RestoreTier::Structural), "{host:?}");
            removal.apply().unwrap();
            let after: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
            assert!(
                get_json_path(&after, json_entry_path(host, version)).is_none(),
                "{host:?}: the entry survived teardown"
            );
            assert_eq!(
                after["zzz"],
                json!("keep me"),
                "{host:?}: a sibling key was lost"
            );
            assert!(target.exists(), "{host:?}: the file itself was deleted");
        }
    }

    /// A DIFFERING entry still refuses, and the message names the flag that
    /// proceeds plus the exact key to delete.
    #[test]
    fn a_differing_json_entry_refuses_and_names_the_way_forward() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let target = host_config_path(Host::ClaudeCode, Scope::Project, &home, &project).unwrap();
        fs::write(
            &target,
            br#"{"mcpServers":{"kaleidoscope":{"command":"somewhere-else"}}}"#,
        )
        .unwrap();
        let before = digest_bytes(&fs::read(&target).unwrap());
        let rendered = plan_connect_at(
            Host::ClaudeCode,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .expect_err("a foreign entry must refuse")
        .to_string();
        assert!(rendered.contains("--no-connect"), "{rendered}");
        assert!(rendered.contains("mcpServers.kaleidoscope"), "{rendered}");
        assert!(
            rendered.contains("delete the \"kaleidoscope\" key"),
            "{rendered}"
        );
        assert_eq!(digest_bytes(&fs::read(&target).unwrap()), before);
    }

    /// Codex adopts an identical marker block, and teardown splices it out
    /// leaving the REMAINDER BYTE-FOR-BYTE.
    ///
    /// The byte-for-byte half distinguishes the string-splice path from the
    /// re-encode path, which the reported tier alone does not.
    #[test]
    fn codex_adopts_an_identical_block_and_the_remainder_survives_byte_for_byte() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let target = host_config_path(Host::Codex, Scope::Project, &home, &project).unwrap();
        let mine = "model    =    \"o3\"\n# my own comment, oddly spaced\n\n";
        let block = codex_block(&descriptor, "default").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, format!("{mine}{block}")).unwrap();
        let before = digest_bytes(&fs::read(&target).unwrap());

        let plan = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .unwrap();
        assert_eq!(plan.action, ChangeAction::Adopt);
        assert_eq!(plan.write, TargetWrite::Leave);
        plan.apply().unwrap();
        assert_eq!(digest_bytes(&fs::read(&target).unwrap()), before);

        let removal = plan_disconnect_at(Host::Codex, Scope::Project, &home, &project).unwrap();
        removal.apply().unwrap();
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            mine,
            "the remainder must be spliced, not re-encoded"
        );
    }

    /// An UNMANAGED `[mcp_servers.kaleidoscope]` table is never adoptable --
    /// there is no delimited region a teardown could take back out -- so it
    /// keeps refusing, and the message names both ways forward.
    #[test]
    fn an_unmanaged_codex_table_is_not_adoptable_and_names_the_way_forward() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        let descriptor = descriptor(temp.path());
        let target = host_config_path(Host::Codex, Scope::Project, &home, &project).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "[mcp_servers.kaleidoscope]\ncommand = \"x\"\n").unwrap();
        let rendered = plan_connect_at(
            Host::Codex,
            Scope::Project,
            "default",
            &descriptor,
            &home,
            &project,
        )
        .expect_err("an undelimited table must refuse")
        .to_string();
        assert!(rendered.contains("--no-connect"), "{rendered}");
        assert!(rendered.contains("by hand"), "{rendered}");
    }

    /// Project scope NEVER moves with an environment variable.
    ///
    /// The user-scope arms honour `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME` and
    /// `$XDG_CONFIG_HOME` (asserted in `tests/manager_cli.rs`, where each case
    /// gets its own child process -- `set_var` is process-global and this crate
    /// forbids `unsafe`). The property worth pinning HERE is the other half: a
    /// project's files live in the project, and no ambient variable may move
    /// shared, version-controlled configuration outside the checkout.
    #[test]
    fn project_scope_paths_never_leave_the_project() {
        let temp = TempDir::new().unwrap();
        let (home, project) = environment(&temp);
        for host in Host::ALL {
            let path = host_config_path(host, Scope::Project, &home, &project).unwrap();
            assert!(
                path.starts_with(&project),
                "{host:?} project-scope path escaped the project: {}",
                path.display()
            );
        }
    }
}
