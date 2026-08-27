use std::io;

/// Stable public-manager failure categories.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("{0}")]
    Usage(String),
    #[error("engine executable was not found; install kscope or pass --engine PATH")]
    EngineNotFound,
    #[error("unsafe {target} path: {reason}")]
    UnsafePath {
        target: &'static str,
        reason: &'static str,
    },
    #[error("{operation} failed ({kind:?})")]
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
    #[error("engine command failed: {message}")]
    EngineRefused { message: String },
    #[error("engine returned an invalid {contract}: {reason}")]
    InvalidEngineContract {
        contract: &'static str,
        reason: &'static str,
    },
    #[error("manager configuration is invalid: {0}")]
    InvalidManagerConfig(&'static str),
    #[error("host configuration is invalid: {0}")]
    InvalidHostConfig(String),
    #[error("host configuration conflict: {0}")]
    HostConflict(String),
    /// The message names the harness because this now happens on the DEFAULT
    /// path. `~/.claude.json` is Claude Code's own live configuration -- it
    /// rewrites the file itself, whenever it feels like it -- and user scope
    /// made that file the manager's default target. Surfacing the race rather
    /// than clobbering it is correct; leaving the user with no idea what raced
    /// them is not.
    #[error(
        "host configuration changed between the preview and the write, so nothing was overwritten. If the target is ~/.claude.json, Claude Code rewrites that file itself: close it (or wait for it to settle) and re-run."
    )]
    ConcurrentEdit,
    /// The managed entry and its owner receipt no longer agree.
    ///
    /// The noun used to be "connection", which is wrong for the instruction and
    /// hook receipts that also reach this arm, and the message named no way
    /// forward at all -- a user who had hand-edited a manager-owned `.mcp.json`
    /// entry got rc=2 from `teardown`, `teardown --force` and `disconnect`
    /// alike and no third option.
    ///
    /// **There is deliberately no `--force` through the host-config planners,
    /// and that is now a decision rather than an outstanding item.** An
    /// instruction block is delimited by the manager's own markers, so forcing
    /// there discards bytes provably inside its own region, disclosed and
    /// backed up first. A foreign `mcpServers.kaleidoscope` entry has no such
    /// proof -- it may be another tool's, or a hand-tuned command line -- and
    /// discarding it is unrecoverable. The manual remedy is one action, is
    /// reversible by the user, and `unmanaged_json_entry_message` now spells it
    /// out with the exact path and key.
    ///
    /// Deleting the receipt is also SAFE for the first time: since adoption, a
    /// re-run over unchanged content adopts it instead of refusing it, so the
    /// remedy below no longer trades one wedge for another.
    #[error(
        "the manager-owned entry no longer matches its owner receipt, so no manager command will edit it. Nothing was changed. If you edited it on purpose, delete the Kaleidoscope entry and its `*.kaleidoscope-owner.json` (or `*.kaleidoscope-instruction-owner.json`) receipt beside it by hand, then re-run `kaleidoscope init`."
    )]
    InvalidOwnerReceipt,
    #[error("operation cancelled; no files were changed")]
    Cancelled,
    #[error("profile name is invalid")]
    InvalidProfileName,
    #[error("active profile is not configured; run kaleidoscope init or profile use")]
    NoActiveProfile,
    /// The cause is CARRIED. Without it this message named the recovery command
    /// and nothing else, so an unwritable config directory, a symlinked
    /// ancestor and a concurrent edit were one indistinguishable string -- and
    /// `kaleidoscope profile use` fails the same way, so the advice looped.
    #[error(
        "manager state could not be published after native initialization ({cause}); the vault and native profile were preserved; run kaleidoscope profile use {profile}"
    )]
    InitManagerStateRecovery { profile: String, cause: String },
    /// `--root` names a different vault from the one the existing profile is
    /// bound to. Never silently repoint a profile at a different vault.
    #[error(
        "profile {profile} is already bound to {existing}; --root named {requested}. Repointing a profile at a different vault is never implied: choose the existing root, pick another --profile name, or remove the profile first."
    )]
    ProfileRootMismatch {
        profile: String,
        existing: String,
        requested: String,
    },
    /// Several vaults were found and none is the obvious one. The message
    /// carries every candidate with the rule that found it, because a refusal
    /// that does not say what would work costs a round trip and invites a guess.
    #[error("{0}")]
    AmbiguousVault(String),
    /// `init-profile` on a root that already probes as a vault. This refusal
    /// exists even when the user asked for `--create`, because forking is never
    /// what "create" meant.
    ///
    /// The message used to assert that "every read and write on the new profile
    /// then reports corrupt state". That clause was not measured and it is not
    /// reliable. Forced on a real engine twice from a clean vault: the first
    /// time `search` and `remember` on the NEW profile both returned rc=0 and
    /// `remember` reported `canonical_effect: committed`, while the ORIGINAL
    /// profile answered `discover_active found corrupt state: current reference
    /// names an absent version`; the second time it was the new profile that
    /// failed, with `commit_record conflicted: idempotency key reused for a
    /// different ...`, and the original that answered normally. Which side
    /// breaks, and how, varied. What DID reproduce every time is what the
    /// message now says: the workspace count goes 1 -> 2, the two profiles hold
    /// separate memory in one directory, and `profile import` refuses
    /// afterwards -- including after `profile remove` of the forked profile,
    /// because the extra workspace directory stays.
    ///
    /// A refusal that overstates its consequence is still a correct refusal,
    /// and this one is worth keeping; the overstatement is not.
    #[error(
        "{root} is already a Kaleidoscope vault ({workspaces} workspace(s)). Creating a profile there would FORK it -- the engine adds a SECOND workspace to the same directory, the two profiles then hold separate memory in it, and `profile import` refuses afterwards because the vault has two workspaces, so no manager command undoes it. Re-run without --create to adopt it, or name an empty --root."
    )]
    WouldForkVault { root: String, workspaces: usize },
    /// `doctor` ran to completion and at least one check reported an issue.
    ///
    /// The ONLY error mapped to exit 3, and the only one constructed outside a
    /// failure path: `doctor` succeeded at its job, which is to find problems.
    /// It is separated from the generic rc=2 because a script that runs
    /// `doctor` needs to tell "the report says there are issues" from "the
    /// command could not run", and both used to be indistinguishable -- rc=0
    /// with `status: "issues"` on one side and rc=2 on the other.
    #[error("doctor found {0} issue(s); see the checks array")]
    DoctorIssues(usize),
    /// A host configuration file the manager cannot safely read whole.
    ///
    /// Carried separately from `UnsafePath` because `~/.claude.json` -- 152 KB
    /// here, holding Claude Code's OAuth account, project list and caches, at
    /// ~15% of the 1 MiB cap and growing -- is now the DEFAULT target. "unsafe
    /// host configuration path: not a bounded regular file" is an opaque
    /// sentence to meet on the path every user takes.
    #[error("{0}")]
    HostConfigTooLarge(String),
    #[error(transparent)]
    Account(#[from] crate::account::AccountError),
}

impl ManagerError {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ManagerError>;
