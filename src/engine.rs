use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

    pub fn profile_launch(&self, name: &str) -> Result<LaunchDescriptor> {
        validate_profile_name(name)?;
        let descriptor: LaunchDescriptor = self.run_json(&["profile", "launch", name])?;
        descriptor.validate(&self.path, name)?;
        Ok(descriptor)
    }

    fn run_json<T: DeserializeOwned>(&self, arguments: &[&str]) -> Result<T> {
        let bytes = self.run(arguments)?;
        serde_json::from_slice(&bytes).map_err(|_| ManagerError::InvalidEngineContract {
            contract: "JSON output",
            reason: "malformed or unknown fields",
        })
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let mut command = Command::new(&self.path);
        command.args(arguments).env_clear();
        for name in ENGINE_ENV_ALLOWLIST {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
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
            let message = String::from_utf8_lossy(
                &output.stderr[..output.stderr.len().min(MAX_ENGINE_ERROR_BYTES)],
            )
            .trim()
            .replace(['\r', '\n'], " ");
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
        let contract: Value = serde_json::from_str(include_str!(
            "../reference/entitlement-contract-v1.json"
        ))
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
