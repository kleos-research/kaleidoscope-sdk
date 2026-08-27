use std::env;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{ManagerError, Result};
use crate::model::{
    Durability, InitResult, LaunchDescriptor, Profile, ProfileList, RemoveResult,
    validate_profile_name,
};

const MAX_ENGINE_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ENGINE_ERROR_BYTES: usize = 8 * 1024;
const ENGINE_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "SystemRoot",
    "SYSTEMROOT",
    "TMPDIR",
    "TEMP",
    "TMP",
    // This public, non-secret override selects the native profile registry.
    "KSCOPE_PROFILE_HOME",
    // Two allowlists exist and they are different BY DESIGN, not by drift.
    //
    // This one forwards KSCOPE_PROFILE_HOME, which the SDKs deliberately never
    // forward. The SDKs forward XDG_CONFIG_HOME, SHELL, TERM and the rest of the
    // bootstrap set, which the manager does not need.
    //
    // The SHARED SUBSET is the entitlement pair -- KALEIDOSCOPE_API_KEY and
    // KSCOPE_ENTITLEMENT_HOME -- and it must stay identical in both, or a
    // manager-spawned engine and an SDK-spawned engine disagree about where the
    // key lives and whether there is one.
    // `engine_env_allowlist_contains_the_shared_entitlement_subset` asserts that
    // against reference/entitlement-contract-v1.json.
    //
    // Benign until it is not: the manager runs only ungated commands today
    // (--version, profile list|show|remove|launch, init-profile, profile
    // import). It stops being benign the moment anything here touches a gated
    // command, because env_clear() below would strip the key and the engine
    // would then report E_NO_KEY for a key the user did set -- a refusal
    // spelled as the wrong answer. And today already, a user who sets
    // KSCOPE_ENTITLEMENT_HOME gets a DIFFERENT entitlement directory from a
    // manager-spawned engine than from an SDK-spawned one.
    "KALEIDOSCOPE_API_KEY",
    "KSCOPE_ENTITLEMENT_HOME",
];

#[derive(Clone, Debug)]
pub struct Engine {
    path: PathBuf,
}

impl Engine {
    pub fn resolve(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Self::new(path);
        }
        if let Some(path) = env::var_os("KALEIDOSCOPE_ENGINE").filter(|value| !value.is_empty()) {
            return Self::new(Path::new(&path));
        }
        if let Ok(current) = env::current_exe() {
            if let Some(directory) = current.parent() {
                let sibling = directory.join(engine_file_name());
                if sibling.exists() {
                    return Self::new(&sibling);
                }
            }
        }
        if let Some(path) = find_on_path(engine_file_name()) {
            return Self::new(&path);
        }
        Err(ManagerError::EngineNotFound)
    }

    pub fn new(path: &Path) -> Result<Self> {
        // CANONICALISE FIRST, then validate what will actually be executed.
        //
        // This used to `symlink_metadata(path)` and refuse any symlink outright,
        // then canonicalise anyway and store the canonical path -- so the checks
        // were made against the LINK while the target is what gets run. The
        // refusal therefore bought nothing that canonicalising does not already
        // give, and it cost the documented distribution channel: `npm i -g`
        // installs every `bin` entry as a symlink in `<prefix>/bin`, so
        // `@kleos-research/kaleidoscope` put a `kscope` on PATH that this
        // function rejected with "unsafe engine path: selected executable is a
        // symlink". Measured with the same binary reached two ways: through the
        // symlink the SessionStart hook read "could not be resolved", through
        // the real path "connected".
        //
        // Validating the canonical target is strictly stronger, not weaker:
        // `canonicalize` resolves EVERY component, so what is stat'd here is
        // exactly what `Command::new(self.path)` runs, with no link left in the
        // path to be swapped between the check and the spawn.
        let canonical = fs::canonicalize(path)
            .map_err(|error| ManagerError::io("canonicalize engine", error))?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| ManagerError::io("inspect engine", error))?;
        if metadata.file_type().is_symlink() {
            // Unreachable through `canonicalize`, which leaves no link behind.
            // Kept because "the canonical path is not a link" is the property
            // the paragraph above depends on, and an assertion that can never
            // fire is cheaper than a comment that says it cannot.
            return Err(ManagerError::UnsafePath {
                target: "engine",
                reason: "selected executable is a symlink",
            });
        }
        if !metadata.is_file() {
            return Err(ManagerError::UnsafePath {
                target: "engine",
                reason: "not a regular file",
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(ManagerError::UnsafePath {
                    target: "engine",
                    reason: "not executable",
                });
            }
        }
        Ok(Self { path: canonical })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn version(&self) -> Result<String> {
        let bytes = self.run(&["--version"])?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| ManagerError::InvalidEngineContract {
                contract: "version",
                reason: "not UTF-8",
            })?;
        let version = text
            .strip_prefix("kscope ")
            .and_then(|value| value.strip_suffix('\n').or(Some(value)))
            .ok_or(ManagerError::InvalidEngineContract {
                contract: "version",
                reason: "unexpected format",
            })?;
        if version.is_empty() || version.chars().any(char::is_whitespace) {
            return Err(ManagerError::InvalidEngineContract {
                contract: "version",
                reason: "unexpected format",
            });
        }
        Ok(version.to_owned())
    }

    pub fn public_contract_seed(&self) -> Result<Value> {
        let value: Value = self.run_json(&["public-contract"])?;
        let valid = value["schema_version"] == "kaleidoscope.public-seed.v1"
            && value["capabilities"]["network_required"] == false
            && value["capabilities"]["local_vault"] == true
            && value["capabilities"]["stdio_mcp"] == true
            && value["capabilities"]["operator_commands_in_mcp"] == false;
        if !valid {
            return Err(ManagerError::InvalidEngineContract {
                contract: "public contract seed",
                reason: "unsupported capability boundary",
            });
        }
        Ok(value)
    }

    pub fn init_profile(
        &self,
        name: &str,
        root: &Path,
        created_at: &str,
        durability: Durability,
    ) -> Result<InitResult> {
        validate_profile_name(name)?;
        let root = root.to_str().ok_or(ManagerError::UnsafePath {
            target: "vault root",
            reason: "path is not UTF-8",
        })?;
        let result: InitResult =
            self.run_json(&["init-profile", name, root, created_at, durability.as_str()])?;
        if result.version != 1 || result.status != "initialized" {
            return Err(ManagerError::InvalidEngineContract {
                contract: "init-profile result",
                reason: "unexpected status",
            });
        }
        result.profile.validate(Some(name))?;
        result.launch.validate(&self.path, name)?;
        Ok(result)
    }

    /// Adopt an EXISTING vault under a new profile name.
    ///
    /// This is the engine call the manager never made. `init-profile` on a root
    /// that already holds a workspace succeeds and adds a second one; `profile
    /// import` reuses the workspace already there and leaves the count
    /// unchanged. The engine refuses, with rc=2 and nothing written, when the
    /// root is not a vault ("profile root is not a Kaleidoscope vault") or when
    /// it holds more than one workspace ("vault has 2 workspaces; select an
    /// explicit workspace instead of importing"). Both refusals are reported
    /// verbatim; the manager never falls back to creating.
    pub fn profile_import(
        &self,
        name: &str,
        root: &Path,
        durability: Durability,
    ) -> Result<Profile> {
        validate_profile_name(name)?;
        let root = root.to_str().ok_or(ManagerError::UnsafePath {
            target: "vault root",
            reason: "path is not UTF-8",
        })?;
        let profile: Profile =
            self.run_json(&["profile", "import", name, root, durability.as_str()])?;
        profile.validate(Some(name))?;
        Ok(profile)
    }

    pub fn profile_list(&self) -> Result<ProfileList> {
        let list: ProfileList = self.run_json(&["profile", "list"])?;
        list.validate()?;
        Ok(list)
    }

    pub fn profile_show(&self, name: &str) -> Result<Profile> {
        validate_profile_name(name)?;
        let profile: Profile = self.run_json(&["profile", "show", name])?;
        profile.validate(Some(name))?;
        Ok(profile)
    }

    pub fn profile_remove(&self, name: &str) -> Result<RemoveResult> {
        validate_profile_name(name)?;
        let removed: RemoveResult = self.run_json(&["profile", "remove", name])?;
        if removed.version != 1 || removed.name != name || removed.status != "removed" {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile removal",
                reason: "unexpected result",
            });
        }
        Ok(removed)
    }

    /// Where the project the caller is standing in starts, per the ENGINE.
    ///
    /// THE MANAGER DOES NOT WALK THE FILESYSTEM ITSELF, and that is the whole
    /// point of this method. The engine already resolves a
    /// project root over sixteen decision points (fourteen markers plus two
    /// `.git` checks) and redirects a linked worktree to its main checkout for
    /// vault purposes. A second copy of that walk in this crate would be free
    /// to drift -- and the divergence that rule exists to prevent is ALREADY
    /// present inside the engine's own resolver, where two doc comments disagreed
    /// with the code and with each other about the ordering. A third copy would
    /// make it worse.
    ///
    /// `where --root-only` rather than `where`: `where` resolves the full vault
    /// address and REFUSES, at rc=2 with an empty stdout, whenever the resolved
    /// root is not a vault. The manager's default vault root lives under the
    /// user data directory, not in the project, so for the manager that refusal
    /// is not an edge case -- it is the common case.
    ///
    /// Runs in `cwd`, because the answer is a function of where the caller is
    /// standing and `env_clear()` strips nothing that would carry that.
    pub fn resolved_project(&self, cwd: &Path) -> Result<ResolvedProject> {
        let value: ResolvedProject = self.run_json_in(Some(cwd), &["where", "--root-only"])?;
        value.validate()?;
        Ok(value)
    }

    pub fn profile_launch(&self, name: &str) -> Result<LaunchDescriptor> {
        validate_profile_name(name)?;
        let descriptor: LaunchDescriptor = self.run_json(&["profile", "launch", name])?;
        descriptor.validate(&self.path, name)?;
        Ok(descriptor)
    }

    /// The bounded runner, aimed at this engine.
    ///
    /// Every call the `SessionStart` hook makes goes through here rather than
    /// through `run_in`, because `run_in` has no timeout at all: it calls
    /// `Command::output()`, which blocks until the child decides to exit. That
    /// is correct for an operator typing a command and wrong for a hook the
    /// harness runs on every startup, resume, clear and compact.
    pub fn run_bounded_in(
        &self,
        cwd: Option<&Path>,
        arguments: &[&str],
        stdin_payload: Option<&[u8]>,
        timeout: Duration,
    ) -> std::result::Result<BoundedOutput, BoundedFailure> {
        run_bounded(&self.path, arguments, cwd, stdin_payload, timeout)
    }

    fn run_json<T: DeserializeOwned>(&self, arguments: &[&str]) -> Result<T> {
        self.run_json_in(None, arguments)
    }

    fn run_json_in<T: DeserializeOwned>(
        &self,
        cwd: Option<&Path>,
        arguments: &[&str],
    ) -> Result<T> {
        let bytes = self.run_in(cwd, arguments)?;
        serde_json::from_slice(&bytes).map_err(|_| ManagerError::InvalidEngineContract {
            contract: "JSON output",
            reason: "malformed or unknown fields",
        })
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        self.run_in(None, arguments)
    }

    /// One spawn site, with an optional working directory.
    ///
    /// A `cwd` PARAMETER rather than a second function: two copies of the
    /// `env_clear()`-plus-allowlist block would be two places for the
    /// entitlement pair to drift out of, and that allowlist has a test asserting
    /// its exact length for precisely that reason.
    fn run_in(&self, cwd: Option<&Path>, arguments: &[&str]) -> Result<Vec<u8>> {
        let mut command = Command::new(&self.path);
        command.args(arguments);
        apply_engine_environment(&mut command, cwd);
        let output = command
            .output()
            .map_err(|error| ManagerError::io("execute engine", error))?;
        if output.stdout.len() > MAX_ENGINE_OUTPUT_BYTES
            || output.stderr.len() > MAX_ENGINE_OUTPUT_BYTES
        {
            return Err(ManagerError::InvalidEngineContract {
                contract: "process output",
                reason: "size limit exceeded",
            });
        }
        if !output.status.success() {
            let raw = String::from_utf8_lossy(
                &output.stderr[..output.stderr.len().min(MAX_ENGINE_ERROR_BYTES)],
            );
            let message = summarize_engine_stderr(&raw);
            return Err(ManagerError::EngineRefused {
                message: if message.is_empty() {
                    "native engine refused the request".to_owned()
                } else {
                    annotate_engine_refusal(message)
                },
            });
        }
        Ok(output.stdout)
    }
}

/// The engine's stderr, reduced to something a person reads rather than scrolls.
///
/// It used to be the first 8 KB with every newline turned into a space. For a
/// one-line refusal that is right. For an argument the engine does not
/// recognise it is not: `kscope where --root-only` on a build without that flag
/// prints its ENTIRE usage text, and the manager wrapped 8,354 characters of it
/// onto a single line, with the one actionable sentence at the very end.
/// Measured: 8,354 bytes, 1 line.
///
/// So: prefer a line that announces itself as an error, fall back to the first
/// non-empty line, cap it, and SAY how much was dropped rather than dropping it
/// silently -- an operator who needs the full text can re-run the engine
/// command themselves, and cannot do that if they were never told there was
/// more.
fn summarize_engine_stderr(raw: &str) -> String {
    const BUDGET: usize = 300;
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return String::new();
    }
    let whole = lines.join(" ");
    if whole.chars().count() <= BUDGET {
        return whole;
    }
    let chosen = lines
        .iter()
        .find(|line| {
            // `error:` WITH the colon, which is how clap and the engine's own
            // refusals announce themselves. A bare `starts_with("error")`
            // matched prose inside the usage text -- the first attempt at this
            // picked the sentence "error, it is a different vault." out of the
            // help and presented it as the failure, which is worse than
            // printing the banner, because it looks like a real diagnosis.
            let lowered = line.to_ascii_lowercase();
            lowered.starts_with("error:") || lowered.starts_with("kscope:")
        })
        .unwrap_or(&lines[0]);
    let mut head: String = chosen.chars().take(BUDGET).collect();
    if chosen.chars().count() > BUDGET {
        head.push('\u{2026}');
    }
    let dropped = lines.len().saturating_sub(1);
    format!(
        "{head} [+{dropped} further line(s) of engine output not shown; run the engine command directly to see them]"
    )
}

/// One engine refusal that reads as a dead end, given its cause and its remedy.
///
/// A single registered profile whose vault root has been deleted makes the
/// engine refuse the WHOLE registry: `profile list` returns rc=2 `unsafe vault
/// root path: Missing`, and so does `profile remove <that profile>` -- the one
/// command that would fix it. Measured: two profiles registered, one root
/// removed, and the other profile became unlistable too; moving the offending
/// record aside restored the rest immediately.
///
/// The manager cannot repair it, because every route to the registry runs
/// through the engine, and it cannot say WHICH profile, because the refusal
/// does not name one. What it can do is stop the message reading as
/// "something is wrong with your vault" when the actual next step is one
/// `rm` -- so the cause and the remedy travel with it. Deleting a record is
/// deleting a pointer: the vault it names is not touched.
fn annotate_engine_refusal(message: String) -> String {
    const MISSING_ROOT: &str = "unsafe vault root path";
    if !message.contains(MISSING_ROOT) {
        return message;
    }
    let registry = env::var_os("KSCOPE_PROFILE_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(
            || " (the engine's profile registry)".to_owned(),
            |value| format!(" ({})", Path::new(&value).display()),
        );
    format!(
        "{message} -- one registered profile names a vault root the engine will not open, most often because the directory was deleted or moved. The engine refuses the entire registry until that record is gone, so `profile list`, `profile show` and `profile remove` all fail this way and no manager command can repair it. Delete the offending <NAME>.json from the profile registry{registry} by hand; that removes a pointer and does not touch any vault."
    )
}

/// The engine's answer to "where does this project start".
///
/// `project` is NOT `root.parent()` and NOT `repository`, and both mistakes are
/// easy to make. With `KSCOPE_ROOT` set the engine takes `root` verbatim and it
/// has no project relationship at all; and a marker can sit BELOW the git root,
/// so `repository` is a different directory again.
///
/// The distinction that matters most here is the worktree one. The engine
/// redirects a linked worktree's VAULT to the main checkout -- correct, because
/// all worktrees of a repository share one memory -- and reports the worktree
/// itself as `project`. Using `root`/`repository` for file placement would
/// write `.mcp.json` into the main checkout from a worktree session, turning
/// the very symptom this change set exists to remove from an accident into a
/// guarantee.
#[derive(Clone, Debug, Deserialize)]
pub struct ResolvedProject {
    pub project: PathBuf,
    pub project_source: String,
    #[serde(default)]
    pub project_marker: Option<String>,
    #[serde(default)]
    pub repository: Option<PathBuf>,
    /// Present in the engine's payload and deliberately IGNORED here. The
    /// manager asks the engine where the PROJECT is, never where a vault was
    /// configured; see `project_source == "environment"` below.
    #[serde(default)]
    #[allow(dead_code)]
    pub root: Option<PathBuf>,
    #[serde(default)]
    #[allow(dead_code)]
    pub source: Option<String>,
}

impl ResolvedProject {
    fn validate(&self) -> Result<()> {
        if !self.project.is_absolute() {
            return Err(ManagerError::InvalidEngineContract {
                contract: "project root",
                reason: "project is not absolute",
            });
        }
        if !self.project.is_dir() {
            return Err(ManagerError::InvalidEngineContract {
                contract: "project root",
                reason: "project is not an existing directory",
            });
        }
        // `KSCOPE_ROOT` is NOT in `ENGINE_ENV_ALLOWLIST` and must never be: it
        // answers "which vault", not "where is the project", and letting an
        // ambient vault path decide where the manager writes host configuration
        // is the same class of defect the engine's project-root resolution exists
        // to remove. If the
        // engine ever answers with it anyway, that is a contract violation
        // rather than a value to use.
        if self.project_source == "environment" {
            return Err(ManagerError::InvalidEngineContract {
                contract: "project root",
                reason: "project source must not come from the environment",
            });
        }
        Ok(())
    }
}

/// `env_clear()` plus the by-name allowlist, in ONE place.
///
/// Extracted so the bounded runner below cannot grow a second, drifting copy.
/// The allowlist has a test asserting its exact length precisely because a
/// second copy is how the entitlement pair goes missing on one path only.
fn apply_engine_environment(command: &mut Command, cwd: Option<&Path>) {
    command.env_clear();
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for name in ENGINE_ENV_ALLOWLIST {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

/// What a bounded run produced, with the wall time it took.
///
/// `elapsed` is not decoration. The `SessionStart` hook publishes it, because a
/// timing number nobody can see is a budget nobody can hold you to.
#[derive(Clone, Debug)]
pub struct BoundedOutput {
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub success: bool,
    pub elapsed: Duration,
}

/// Why a bounded run produced nothing. Deliberately NOT a `ManagerError`: these
/// are reported into a hook's context, never returned as a process failure.
#[derive(Clone, Debug)]
pub enum BoundedFailure {
    Spawn(String),
    TimedOut(Duration),
}

impl std::fmt::Display for BoundedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(reason) => write!(formatter, "could not start: {reason}"),
            Self::TimedOut(elapsed) => {
                write!(formatter, "timed out after {} ms", elapsed.as_millis())
            }
        }
    }
}

/// The cap on what a bounded run will read from either stream.
const MAX_BOUNDED_STREAM_BYTES: u64 = 256 * 1024;
/// How long the runner waits for a process that has already closed both streams.
const REAP_BUDGET: Duration = Duration::from_millis(250);

/// Run a program to completion, or kill it at `timeout`, and never block forever.
///
/// A FREE FUNCTION taking the program path, because the one caller that matters
/// -- the `SessionStart` MCP probe -- must run the command the HOST is
/// registered to run, which is read out of the host configuration and is not
/// necessarily `Engine::path`. Reporting on a different binary from the one the
/// harness launches is how a probe comes back green for a server nobody starts.
///
/// Both streams are drained on their own threads. Draining only one deadlocks
/// as soon as the other fills its pipe buffer, and `tools/list` on this engine
/// is ~20 KB against a 64 KiB pipe -- close enough that "it worked when I tried
/// it" is not evidence.
pub fn run_bounded(
    program: &Path,
    arguments: &[&str],
    cwd: Option<&Path>,
    stdin_payload: Option<&[u8]>,
    timeout: Duration,
) -> std::result::Result<BoundedOutput, BoundedFailure> {
    let started = Instant::now();
    let mut command = Command::new(program);
    command.args(arguments);
    apply_engine_environment(&mut command, cwd);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| BoundedFailure::Spawn(error.to_string()))?;

    // Written and then CLOSED, before either stream is read. The engine's stdio
    // verbs finish on EOF, so the close is what makes them exit; holding the
    // handle open would turn every probe into a timeout.
    if let Some(mut sink) = child.stdin.take() {
        let _ = sink.write_all(stdin_payload.unwrap_or(b""));
        let _ = sink.flush();
    }

    let (sender, receiver) = mpsc::channel::<(bool, Vec<u8>)>();
    for (is_stdout, stream) in [
        (true, child.stdout.take().map(Stdio2::Out)),
        (false, child.stderr.take().map(Stdio2::Err)),
    ] {
        let sender = sender.clone();
        match stream {
            Some(stream) => {
                std::thread::spawn(move || {
                    let mut buffer = Vec::new();
                    match stream {
                        Stdio2::Out(handle) => {
                            let _ = handle
                                .take(MAX_BOUNDED_STREAM_BYTES)
                                .read_to_end(&mut buffer);
                        }
                        Stdio2::Err(handle) => {
                            let _ = handle
                                .take(MAX_BOUNDED_STREAM_BYTES)
                                .read_to_end(&mut buffer);
                        }
                    }
                    let _ = sender.send((is_stdout, buffer));
                });
            }
            None => {
                let _ = sender.send((is_stdout, Vec::new()));
            }
        }
    }
    drop(sender);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut drained = 0_u8;
    while drained < 2 {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            break;
        };
        match receiver.recv_timeout(remaining) {
            Ok((true, bytes)) => {
                stdout = bytes;
                drained += 1;
            }
            Ok((false, bytes)) => {
                stderr = bytes;
                drained += 1;
            }
            Err(_) => break,
        }
    }
    if drained < 2 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(BoundedFailure::TimedOut(started.elapsed()));
    }

    // Both streams are at EOF, which for every well-behaved child means it is
    // already exiting. `wait()` is still not unconditionally safe -- a child may
    // close its descriptors and linger -- so it gets its own small budget and
    // then a kill, rather than the unbounded block that would otherwise be the
    // one remaining way this function hangs a session start.
    let reap_deadline = Instant::now() + REAP_BUDGET;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < reap_deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Err(_) => break false,
        }
    };
    Ok(BoundedOutput {
        stdout,
        stderr: summarize_engine_stderr(&String::from_utf8_lossy(
            &stderr[..stderr.len().min(MAX_ENGINE_ERROR_BYTES)],
        )),
        success,
        elapsed: started.elapsed(),
    })
}

/// Two concrete handle types behind one `move` into a thread. `ChildStdout` and
/// `ChildStderr` are different types and neither is boxed here, because a
/// `Box<dyn Read + Send>` would be the only alternative and this is cheaper to
/// read than a trait object.
enum Stdio2 {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

fn engine_file_name() -> &'static str {
    if cfg!(windows) {
        "kscope.exe"
    } else {
        "kscope"
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-B33. Two environment allowlists exist -- this one and the SDKs' -- and
    /// they are different BY DESIGN. What must NOT differ is the entitlement
    /// pair, or a manager-spawned engine and an SDK-spawned engine disagree
    /// about where the key lives and whether there is one.
    ///
    /// Reads the shared contract file rather than a local literal, so a change
    /// on either side fails here instead of drifting silently.
    #[test]
    fn engine_env_allowlist_contains_the_shared_entitlement_subset() {
        let contract: Value =
            serde_json::from_str(include_str!("../reference/entitlement-contract-v1.json"))
                .expect("the shared entitlement contract must parse");
        let required = contract["entitlement_environment"]
            .as_array()
            .expect("entitlement_environment must be an array");
        assert!(
            !required.is_empty(),
            "an empty required set would make this test vacuous"
        );
        for name in required {
            let name = name.as_str().expect("environment names are strings");
            assert!(
                ENGINE_ENV_ALLOWLIST.contains(&name),
                "the manager strips {name} before spawning the engine, so a key the user set would read as E_NO_KEY"
            );
        }
    }

    /// The other direction: the manager must NOT have quietly become a general
    /// environment passthrough. `env_clear()` plus a closed by-name list is the
    /// property; a decoy proves the list is still closed.
    #[test]
    fn the_engine_allowlist_is_still_closed() {
        for decoy in [
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "KSCOPE_ROOT",
            "KSCOPE_WORKSPACE",
            "KALEIDOSCOPE_TOKEN",
        ] {
            assert!(
                !ENGINE_ENV_ALLOWLIST.contains(&decoy),
                "{decoy} reached the manager's engine allowlist"
            );
        }
        assert_eq!(
            ENGINE_ENV_ALLOWLIST.len(),
            14,
            "the allowlist changed size; the only permitted direction is narrowing"
        );
    }
}
