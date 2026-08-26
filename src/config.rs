use std::collections::BTreeMap;
use std::env;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ManagerError, Result};
use crate::fs_safe::{FileLock, assert_unchanged, atomic_write, read_snapshot};
use crate::model::{Profile, validate_profile_name};

const MANAGER_CONFIG_VERSION: u32 = 2;
const LEGACY_MANAGER_CONFIG_VERSION: u32 = 1;
const MAX_MANAGER_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerConfig {
    pub version: u32,
    pub active_profile: Option<String>,
    /// Non-secret local references only. They never alter profile identity or
    /// carry a vault coordinate, account credential, entitlement or token.
    #[serde(default)]
    pub account_bindings: BTreeMap<String, Uuid>,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            version: MANAGER_CONFIG_VERSION,
            active_profile: None,
            account_bindings: BTreeMap::new(),
        }
    }
}

impl ManagerConfig {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.version,
            LEGACY_MANAGER_CONFIG_VERSION | MANAGER_CONFIG_VERSION
        ) {
            return Err(ManagerError::InvalidManagerConfig("unsupported version"));
        }
        if let Some(profile) = &self.active_profile {
            validate_profile_name(profile)?;
        }
        for (profile, account_id) in &self.account_bindings {
            validate_profile_name(profile)?;
            if account_id.is_nil() {
                return Err(ManagerError::InvalidManagerConfig(
                    "profile account binding is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    directory: PathBuf,
}

impl ConfigStore {
    pub fn resolve() -> Result<Self> {
        let directory = if let Some(override_path) =
            env::var_os("KALEIDOSCOPE_CONFIG_HOME").filter(|value| !value.is_empty())
        {
            PathBuf::from(override_path)
        } else {
            platform_config_base()?.join("kaleidoscope")
        };
        validate_config_path(&directory)?;
        Ok(Self { directory })
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.join("manager.json")
    }

    pub fn load(&self) -> Result<ManagerConfig> {
        let snapshot = read_snapshot(
            &self.path(),
            MAX_MANAGER_CONFIG_BYTES,
            "manager configuration",
        )?;
        let Some(bytes) = snapshot.bytes else {
            return Ok(ManagerConfig::default());
        };
        let mut config: ManagerConfig = serde_json::from_slice(&bytes)
            .map_err(|_| ManagerError::InvalidManagerConfig("malformed JSON"))?;
        config.validate()?;
        if config.version == LEGACY_MANAGER_CONFIG_VERSION {
            config.version = MANAGER_CONFIG_VERSION;
        }
        Ok(config)
    }

    pub fn save(&self, config: &ManagerConfig) -> Result<()> {
        let mut config = config.clone();
        config.version = MANAGER_CONFIG_VERSION;
        config.validate()?;
        let path = self.path();
        let original = read_snapshot(&path, MAX_MANAGER_CONFIG_BYTES, "manager configuration")?;
        let _lock = FileLock::acquire(&path)?;
        assert_unchanged(
            &path,
            &original,
            MAX_MANAGER_CONFIG_BYTES,
            "manager configuration",
        )?;
        let mut bytes = serde_json::to_vec_pretty(&config)
            .map_err(|_| ManagerError::InvalidManagerConfig("cannot encode JSON"))?;
        bytes.push(b'\n');
        atomic_write(&path, &bytes, Some(0o600))
    }

    pub fn set_active_profile(&self, profile: Option<&str>) -> Result<ManagerConfig> {
        if let Some(profile) = profile {
            validate_profile_name(profile)?;
        }
        let mut config = self.load()?;
        config.active_profile = profile.map(str::to_owned);
        self.save(&config)?;
        Ok(config)
    }

    pub fn selected_profile(&self, explicit: Option<&str>) -> Result<String> {
        if let Some(profile) = explicit {
            validate_profile_name(profile)?;
            return Ok(profile.to_owned());
        }
        Ok(self
            .load()?
            .active_profile
            .unwrap_or_else(|| "default".to_owned()))
    }

    /// Returns the non-secret account reference for a local profile, if one
    /// has been explicitly bound. This does not contact the account service.
    pub fn profile_account_binding(&self, profile: &str) -> Result<Option<Uuid>> {
        validate_profile_name(profile)?;
        Ok(self.load()?.account_bindings.get(profile).copied())
    }

    /// Binds a profile to an account UUID in manager-local state only.
    pub fn bind_profile_account(&self, profile: &str, account_id: Uuid) -> Result<ManagerConfig> {
        validate_profile_name(profile)?;
        if account_id.is_nil() {
            return Err(ManagerError::InvalidManagerConfig(
                "profile account binding is invalid",
            ));
        }
        let mut config = self.load()?;
        config
            .account_bindings
            .insert(profile.to_owned(), account_id);
        self.save(&config)?;
        Ok(config)
    }

    /// Removes a profile's local account reference without touching the
    /// account service, engine, profile file or local vault.
    pub fn unbind_profile_account(&self, profile: &str) -> Result<ManagerConfig> {
        validate_profile_name(profile)?;
        let mut config = self.load()?;
        config.account_bindings.remove(profile);
        self.save(&config)?;
        Ok(config)
    }

    /// Clears manager-local profile state after the engine has removed the
    /// profile. It deliberately does not inspect or modify the local vault.
    pub fn forget_profile(&self, profile: &str) -> Result<ManagerConfig> {
        validate_profile_name(profile)?;
        let mut config = self.load()?;
        if config.active_profile.as_deref() == Some(profile) {
            config.active_profile = None;
        }
        config.account_bindings.remove(profile);
        self.save(&config)?;
        Ok(config)
    }
}

pub fn user_home() -> Result<PathBuf> {
    let home = env::var_os("KALEIDOSCOPE_USER_HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("HOME").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .ok_or(ManagerError::InvalidManagerConfig(
            "user home is unavailable",
        ))?;
    canonical_directory(&home, "user home")
}

pub fn project_root(explicit: Option<&Path>) -> Result<PathBuf> {
    let root = explicit
        .map_or_else(env::current_dir, |path| Ok(path.to_path_buf()))
        .map_err(|error| ManagerError::io("resolve project directory", error))?;
    canonical_directory(&root, "project directory")
}

pub fn default_vault_root(profile: &str) -> Result<PathBuf> {
    validate_profile_name(profile)?;
    let base = if let Some(path) =
        env::var_os("KALEIDOSCOPE_DATA_HOME").filter(|value| !value.is_empty())
    {
        PathBuf::from(path)
    } else {
        platform_data_base()?.join("kaleidoscope")
    };
    validate_config_path(&base)?;
    Ok(base.join("vaults").join(profile))
}

fn canonical_directory(path: &Path, target: &'static str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "path is not absolute",
        });
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| ManagerError::io("canonicalize directory", error))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ManagerError::io("inspect directory", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "selected path is a symlink or not a directory",
        });
    }
    Ok(canonical)
}

fn validate_config_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ManagerError::UnsafePath {
            target: "manager configuration",
            reason: "path must be absolute and traversal-free",
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_config_base() -> Result<PathBuf> {
    Ok(user_home()?.join("Library").join("Application Support"))
}

#[cfg(target_os = "windows")]
fn platform_config_base() -> Result<PathBuf> {
    env::var_os("APPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ManagerError::InvalidManagerConfig("APPDATA is unavailable"))
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn platform_config_base() -> Result<PathBuf> {
    Ok(env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(user_home()?.join(".config")))
}

#[cfg(target_os = "macos")]
fn platform_data_base() -> Result<PathBuf> {
    Ok(user_home()?.join("Library").join("Application Support"))
}

#[cfg(target_os = "windows")]
fn platform_data_base() -> Result<PathBuf> {
    env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ManagerError::InvalidManagerConfig(
            "LOCALAPPDATA is unavailable",
        ))
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn platform_data_base() -> Result<PathBuf> {
    Ok(env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(user_home()?.join(".local").join("share")))
}

#[must_use]
pub fn profile_summary(profile: &Profile) -> serde_json::Value {
    serde_json::json!({
        "version": profile.version,
        "name": profile.name,
        "durability": profile.durability,
        "root": "<redacted>",
        "workspace_id": "<redacted>",
        "principal_id": "<redacted>",
        "journal": "<redacted>",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_manager_configuration_remains_readable_without_account_bindings() {
        let legacy: ManagerConfig =
            serde_json::from_str(r#"{"version":1,"active_profile":"default"}"#).unwrap();
        legacy.validate().unwrap();
        assert!(legacy.account_bindings.is_empty());
    }

    #[test]
    fn account_binding_rejects_the_nil_uuid() {
        let config = ManagerConfig {
            version: MANAGER_CONFIG_VERSION,
            active_profile: Some("default".to_owned()),
            account_bindings: BTreeMap::from([("default".to_owned(), Uuid::nil())]),
        };
        assert!(config.validate().is_err());
    }
}
