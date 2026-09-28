use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ManagerError, Result};

pub const PROFILE_VERSION: u32 = 1;
pub const LAUNCH_DESCRIPTOR_VERSION: u32 = 1;
pub const PUBLIC_TOOLS: [&str; 2] = ["search", "remember"];
/// The one variable a launch descriptor's environment may carry: the profile
/// store an entry written under `KSCOPE_PROFILE_HOME` needs, so an agent
/// started outside the shell (from the Dock) finds the profile `kscope init`
/// made. The engine's decision 3 of 2026-09-28 (its journey-bugs.md RECOV-4).
pub const PROFILE_HOME_VARIABLE: &str = "KSCOPE_PROFILE_HOME";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    ProcessLocal,
    DurableLocal,
}

impl Durability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLocal => "process-local",
            Self::DurableLocal => "durable-local",
        }
    }
}

impl FromStr for Durability {
    type Err = ManagerError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "process-local" => Ok(Self::ProcessLocal),
            "durable-local" => Ok(Self::DurableLocal),
            _ => Err(ManagerError::Usage(
                "durability must be process-local or durable-local".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub name: String,
    pub root: PathBuf,
    pub workspace_id: String,
    pub principal_id: String,
    pub journal: String,
    pub durability: Durability,
}

impl Profile {
    pub fn validate(&self, expected_name: Option<&str>) -> Result<()> {
        if self.version != PROFILE_VERSION {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile",
                reason: "unsupported version",
            });
        }
        validate_profile_name(&self.name)?;
        if expected_name.is_some_and(|name| name != self.name) {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile",
                reason: "name mismatch",
            });
        }
        if !self.root.is_absolute()
            || self.workspace_id.is_empty()
            || self.principal_id.is_empty()
            || self.journal.is_empty()
        {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile",
                reason: "missing address field",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchDescriptor {
    pub version: u32,
    pub transport: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub tools: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

impl LaunchDescriptor {
    /// The descriptor a profile WOULD get, without creating one.
    ///
    /// `--dry-run` is documented as "an effect-free plan", and it was not: the
    /// vault and the profile were created before the flag was read, so a plan
    /// asked for on a clean machine left 42 files and a real redb vault behind.
    /// Making the flag honest means not calling the engine's `init-profile`,
    /// and that in turn means the host previews have to come from somewhere.
    ///
    /// This is NOT a second source of truth for the entry shape. `validate`
    /// immediately below is the authority, it is a CLOSED equality over every
    /// field, and `provisional_descriptor_passes_validate` asserts that what
    /// this builds is exactly what that accepts. If the engine's contract
    /// moves, `validate` moves with it and the test fails here -- which is the
    /// whole reason the constructor sits against the checker rather than in
    /// the CLI that wants it.
    pub fn provisional(engine: &std::path::Path, profile: &str) -> Result<Self> {
        validate_profile_name(profile)?;
        if !engine.is_absolute() {
            return Err(ManagerError::UnsafePath {
                target: "engine",
                reason: "path must be absolute",
            });
        }
        Ok(Self {
            version: LAUNCH_DESCRIPTOR_VERSION,
            transport: "stdio".to_owned(),
            command: engine.to_path_buf(),
            args: vec!["mcp".to_owned(), "--profile".to_owned(), profile.to_owned()],
            tools: PUBLIC_TOOLS.iter().map(|tool| (*tool).to_owned()).collect(),
            environment: BTreeMap::new(),
        })
    }

    /// The environment is closed too: empty, or the profile store and
    /// nothing else, as an absolute path. The engine's checks accept the same.
    fn environment_is_valid(&self) -> bool {
        match self.environment.len() {
            0 => true,
            1 => self
                .environment
                .get(PROFILE_HOME_VARIABLE)
                .is_some_and(|store| std::path::Path::new(store).is_absolute()),
            _ => false,
        }
    }

    pub fn validate(&self, expected_engine: &std::path::Path, profile: &str) -> Result<()> {
        validate_profile_name(profile)?;
        if self.version != LAUNCH_DESCRIPTOR_VERSION
            || self.transport != "stdio"
            || self.command != expected_engine
            || self.args != ["mcp", "--profile", profile]
            || self.tools != PUBLIC_TOOLS
            || !self.environment_is_valid()
            || !self.command.is_absolute()
        {
            return Err(ManagerError::InvalidEngineContract {
                contract: "launch descriptor",
                reason: "closed version-1 shape mismatch",
            });
        }
        Ok(())
    }
}

/// `kscope profile list`: the names, each name's entry, and how many entries
/// are stale.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileList {
    pub version: u32,
    pub profiles: Vec<String>,
    pub entries: Vec<ProfileEntry>,
    pub stale: usize,
}

/// One registered name. A stale entry is one whose vault the engine could no
/// longer open: it carries the engine's reason instead of a profile, so one
/// broken entry does not hide the others.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    pub name: String,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ProfileList {
    pub fn validate(&self) -> Result<()> {
        if self.version != PROFILE_VERSION
            || self.profiles.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .profiles
                .iter()
                .any(|name| validate_profile_name(name).is_err())
        {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile list",
                reason: "invalid version, name, or order",
            });
        }
        let names = self.entries.iter().map(|entry| &entry.name);
        if !names.eq(self.profiles.iter())
            || self.entries.iter().filter(|entry| !entry.valid).count() != self.stale
        {
            return Err(ManagerError::InvalidEngineContract {
                contract: "profile list",
                reason: "entries disagree with the names or the stale count",
            });
        }
        for entry in &self.entries {
            match (entry.valid, &entry.profile, &entry.detail) {
                (true, Some(profile), None) => profile.validate(Some(&entry.name))?,
                (false, None, Some(_)) => {}
                _ => {
                    return Err(ManagerError::InvalidEngineContract {
                        contract: "profile list",
                        reason: "an entry's validity disagrees with its profile",
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitResult {
    pub version: u32,
    pub status: String,
    pub profile: Profile,
    pub launch: LaunchDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveResult {
    pub version: u32,
    pub name: String,
    pub status: String,
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !name.is_ascii()
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ManagerError::InvalidProfileName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ProfileList;

    fn listing(stale: usize) -> ProfileList {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "profiles": ["gone", "kept"],
            "entries": [
                {"name": "gone", "valid": false, "detail": "the vault is missing"},
                {"name": "kept", "valid": true, "profile": {
                    "version": 1,
                    "name": "kept",
                    "root": "/vaults/kept",
                    "workspace_id": "wsp_fixture",
                    "principal_id": "usr_fixture",
                    "journal": "journal:fixture",
                    "durability": "process-local"
                }}
            ],
            "stale": stale
        }))
        .unwrap()
    }

    #[test]
    fn a_listing_with_a_stale_entry_is_accepted() {
        listing(1).validate().unwrap();
    }

    #[test]
    fn a_stale_count_the_entries_do_not_add_up_to_is_refused() {
        assert!(listing(0).validate().is_err());
    }

    /// The engine's decision 3 of 2026-09-28 (its journey-bugs.md RECOV-4): a
    /// v1 launch descriptor may carry the profile store an entry written under
    /// `KSCOPE_PROFILE_HOME` needs, as an absolute path, and nothing else. The
    /// engine's two checks and its downstream.toml accept the same shape.
    #[test]
    fn a_launch_descriptor_may_carry_the_profile_store_and_nothing_else() {
        use std::path::Path;

        use super::{LaunchDescriptor, PROFILE_HOME_VARIABLE};

        let engine = Path::new("/opt/kscope/bin/kscope");
        let bare = LaunchDescriptor::provisional(engine, "default").unwrap();
        bare.validate(engine, "default").unwrap();

        let mut carried = bare.clone();
        carried.environment.insert(
            PROFILE_HOME_VARIABLE.to_owned(),
            "/opt/kscope/profiles2".to_owned(),
        );
        carried.validate(engine, "default").unwrap();

        let mut relative = bare.clone();
        relative
            .environment
            .insert(PROFILE_HOME_VARIABLE.to_owned(), "profiles2".to_owned());
        assert!(relative.validate(engine, "default").is_err());
        let mut other = bare;
        other
            .environment
            .insert("KSCOPE_ROOT".to_owned(), "/vaults/kept".to_owned());
        assert!(other.validate(engine, "default").is_err());
        let mut both = carried;
        both.environment
            .insert("KSCOPE_ROOT".to_owned(), "/vaults/kept".to_owned());
        assert!(both.validate(engine, "default").is_err());
    }
}
