use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginMode {
    LoopbackPkce,
    Device,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutScope {
    CurrentSession,
    AllDevices,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalLogoutPolicy {
    RequireRemoteRevocation,
    ConfirmedLocalOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    SignedOut,
    Online,
    OfflineStale,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatus {
    pub version: u8,
    pub state: AccountState,
    pub account_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub stale: bool,
}

impl AccountStatus {
    pub(crate) const fn signed_out(state: AccountState) -> Self {
        Self {
            version: 1,
            state,
            account_id: None,
            device_id: None,
            stale: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginResult {
    pub version: u8,
    pub status: &'static str,
    pub account_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutResult {
    pub version: u8,
    pub status: &'static str,
    pub remote_revoked: bool,
    pub local_credential_removed: bool,
    pub warning: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkResult {
    pub version: u8,
    pub status: &'static str,
    pub verification_uri: Url,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnlinkResult {
    pub version: u8,
    pub status: &'static str,
    pub external_identity_id: Uuid,
}

/// One linked external identity that may be selected for a recoverable unlink.
/// The account service intentionally does not expose email or provider claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentitySummary {
    pub external_identity_id: Uuid,
    pub issuer: Url,
    pub linked_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentityList {
    pub version: u8,
    pub external_identities: Vec<ExternalIdentitySummary>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Macos,
    Windows,
    Linux,
}

impl DevicePlatform {
    #[must_use]
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    pub device_id: Uuid,
    pub label: String,
    pub platform: DevicePlatform,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    pub version: u8,
    pub devices: Vec<DeviceSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokeResult {
    pub version: u8,
    pub status: &'static str,
    pub device_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceDisplay {
    pub product_name: String,
    pub device_label: String,
    pub platform: DevicePlatform,
    pub application_version: String,
}

impl DeviceDisplay {
    pub(crate) fn validate(&self) -> bool {
        [
            self.product_name.as_str(),
            self.device_label.as_str(),
            self.application_version.as_str(),
        ]
        .iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= 100
                && !value.chars().any(char::is_control)
                && !looks_like_absolute_path(value)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAuthorizationPrompt {
    pub user_code: String,
    pub verification_uri: Url,
    pub expires_at: u64,
    pub interval_seconds: u32,
    pub display: DeviceDisplay,
}

fn looks_like_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("\\\\")
        || (value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .get(2)
                .is_some_and(|separator| matches!(separator, b'/' | b'\\')))
}
