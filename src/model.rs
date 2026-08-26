use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ManagerError, Result};

pub const PROFILE_VERSION: u32 = 1;
pub const LAUNCH_DESCRIPTOR_VERSION: u32 = 1;
pub const PUBLIC_TOOLS: [&str; 2] = ["search", "remember"];

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
    pub fn validate(&self, expected_engine: &std::path::Path, profile: &str) -> Result<()> {
        validate_profile_name(profile)?;
        if self.version != LAUNCH_DESCRIPTOR_VERSION
            || self.transport != "stdio"
            || self.command != expected_engine
            || self.args != ["mcp", "--profile", profile]
            || self.tools != PUBLIC_TOOLS
            || !self.environment.is_empty()
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileList {
    pub version: u32,
    pub profiles: Vec<String>,
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
