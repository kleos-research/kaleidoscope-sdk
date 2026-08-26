use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "windows", target_os = "linux")
))]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt as _;
#[cfg(feature = "native-credential-store")]
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
#[cfg(feature = "native-credential-store")]
use zeroize::Zeroizing;

use super::error::{AccountError, AccountResult};
use super::secret::SecretString;

#[cfg(feature = "native-credential-store")]
const KEYRING_SERVICE: &str = "xyz.kleosresearch.kaleidoscope";
#[cfg(feature = "native-credential-store")]
const KEYRING_ACCOUNT: &str = "account-refresh-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStoreKind {
    MacOsKeychain,
    WindowsCredentialManager,
    LinuxSecretService,
    DeterministicFake,
    CompileGated,
    UnsupportedPlatform,
}

pub struct StoredCredential {
    account_id: Uuid,
    device_id: Uuid,
    token_family_id: Uuid,
    refresh_generation: u64,
    issuer: Url,
    audience: String,
    subject: String,
    refresh_token: SecretString,
}

impl StoredCredential {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        account_id: Uuid,
        device_id: Uuid,
        token_family_id: Uuid,
        refresh_generation: u64,
        issuer: Url,
        audience: String,
        subject: String,
        refresh_token: SecretString,
    ) -> AccountResult<Self> {
        let credential = Self {
            account_id,
            device_id,
            token_family_id,
            refresh_generation,
            issuer,
            audience,
            subject,
            refresh_token,
        };
        credential.validate()?;
        Ok(credential)
    }

    fn validate(&self) -> AccountResult<()> {
        if self.issuer.scheme() != "https"
            || self.issuer.host_str().is_none()
            || !self.issuer.username().is_empty()
            || self.issuer.password().is_some()
            || self.issuer.query().is_some()
            || self.issuer.fragment().is_some()
            || self.audience.is_empty()
            || self.audience.len() > 200
            || !self.audience.is_ascii()
            || self.subject.is_empty()
            || self.subject.len() > 512
            || self.subject.chars().any(char::is_control)
            || !self.refresh_token.is_bounded_ascii()
        {
            return Err(AccountError::CredentialStoreFailure);
        }
        Ok(())
    }

    pub(crate) const fn account_id(&self) -> Uuid {
        self.account_id
    }

    pub(crate) const fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub(crate) const fn token_family_id(&self) -> Uuid {
        self.token_family_id
    }

    pub(crate) const fn refresh_generation(&self) -> u64 {
        self.refresh_generation
    }

    pub(crate) const fn issuer(&self) -> &Url {
        &self.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    pub(crate) fn refresh_token(&self) -> &SecretString {
        &self.refresh_token
    }
}

impl Clone for StoredCredential {
    fn clone(&self) -> Self {
        Self {
            account_id: self.account_id,
            device_id: self.device_id,
            token_family_id: self.token_family_id,
            refresh_generation: self.refresh_generation,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            subject: self.subject.clone(),
            refresh_token: self.refresh_token.clone(),
        }
    }
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCredential")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("token_family_id", &self.token_family_id)
            .field("refresh_generation", &self.refresh_generation)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("subject", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

pub trait CredentialStore: Send + Sync {
    fn kind(&self) -> CredentialStoreKind;
    fn load(&self) -> AccountResult<Option<StoredCredential>>;
    fn save(&self, credential: &StoredCredential) -> AccountResult<()>;
    fn delete(&self) -> AccountResult<bool>;
}

#[cfg(feature = "native-credential-store")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialWireRef<'a> {
    version: u8,
    account_id: Uuid,
    device_id: Uuid,
    token_family_id: Uuid,
    refresh_generation: u64,
    issuer: &'a Url,
    audience: &'a str,
    subject: &'a str,
    refresh_token: &'a str,
}

#[cfg(feature = "native-credential-store")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialWire {
    version: u8,
    account_id: Uuid,
    device_id: Uuid,
    token_family_id: Uuid,
    refresh_generation: u64,
    issuer: Url,
    audience: String,
    subject: String,
    refresh_token: String,
}

#[cfg(feature = "native-credential-store")]
fn encode_credential(credential: &StoredCredential) -> AccountResult<Zeroizing<Vec<u8>>> {
    credential.validate()?;
    serde_json::to_vec(&CredentialWireRef {
        version: 1,
        account_id: credential.account_id,
        device_id: credential.device_id,
        token_family_id: credential.token_family_id,
        refresh_generation: credential.refresh_generation,
        issuer: &credential.issuer,
        audience: &credential.audience,
        subject: &credential.subject,
        refresh_token: credential.refresh_token.expose(),
    })
    .map(Zeroizing::new)
    .map_err(|_| AccountError::CredentialStoreFailure)
}

#[cfg(feature = "native-credential-store")]
#[allow(clippy::needless_pass_by_value)] // Ownership guarantees the serialized secret is zeroized.
fn decode_credential(bytes: Zeroizing<Vec<u8>>) -> AccountResult<StoredCredential> {
    let wire: CredentialWire =
        serde_json::from_slice(&bytes).map_err(|_| AccountError::CredentialStoreFailure)?;
    if wire.version != 1 {
        return Err(AccountError::CredentialStoreFailure);
    }
    StoredCredential::new(
        wire.account_id,
        wire.device_id,
        wire.token_family_id,
        wire.refresh_generation,
        wire.issuer,
        wire.audience,
        wire.subject,
        SecretString::new(wire.refresh_token),
    )
}

#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
pub struct MacOsKeychainStore;

#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
impl MacOsKeychainStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
impl Default for MacOsKeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
impl CredentialStore for MacOsKeychainStore {
    fn kind(&self) -> CredentialStoreKind {
        CredentialStoreKind::MacOsKeychain
    }

    fn load(&self) -> AccountResult<Option<StoredCredential>> {
        match security_framework::passwords::get_generic_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        {
            Ok(bytes) => decode_credential(Zeroizing::new(bytes)).map(Some),
            Err(error) if error.code() == security_framework_sys::base::errSecItemNotFound => {
                Ok(None)
            }
            Err(_) => Err(AccountError::CredentialStoreUnavailable(
                "macOS Keychain is unavailable or locked; unlock Keychain and retry",
            )),
        }
    }

    fn save(&self, credential: &StoredCredential) -> AccountResult<()> {
        let bytes = encode_credential(credential)?;
        security_framework::passwords::set_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            &bytes,
        )
        .map_err(|_| {
            AccountError::CredentialStoreUnavailable(
                "macOS Keychain is unavailable or locked; unlock Keychain and retry",
            )
        })
    }

    fn delete(&self) -> AccountResult<bool> {
        match security_framework::passwords::delete_generic_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
        ) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == security_framework_sys::base::errSecItemNotFound => {
                Ok(false)
            }
            Err(_) => Err(AccountError::CredentialStoreUnavailable(
                "macOS Keychain is unavailable or locked; unlock Keychain and retry",
            )),
        }
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
pub struct WindowsCredentialManagerStore;

#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
impl WindowsCredentialManagerStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
impl Default for WindowsCredentialManagerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
impl CredentialStore for WindowsCredentialManagerStore {
    fn kind(&self) -> CredentialStoreKind {
        CredentialStoreKind::WindowsCredentialManager
    }

    fn load(&self) -> AccountResult<Option<StoredCredential>> {
        load_keyring_credential(
            "Windows Credential Manager is unavailable or locked; unlock it and retry",
        )
    }

    fn save(&self, credential: &StoredCredential) -> AccountResult<()> {
        save_keyring_credential(
            credential,
            "Windows Credential Manager is unavailable or locked; unlock it and retry",
        )
    }

    fn delete(&self) -> AccountResult<bool> {
        delete_keyring_credential(
            "Windows Credential Manager is unavailable or locked; unlock it and retry",
        )
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
pub struct LinuxSecretServiceStore;

#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
impl LinuxSecretServiceStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
impl Default for LinuxSecretServiceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
impl CredentialStore for LinuxSecretServiceStore {
    fn kind(&self) -> CredentialStoreKind {
        CredentialStoreKind::LinuxSecretService
    }

    fn load(&self) -> AccountResult<Option<StoredCredential>> {
        load_keyring_credential(
            "Linux Secret Service is unavailable; install and unlock a Freedesktop Secret Service",
        )
    }

    fn save(&self, credential: &StoredCredential) -> AccountResult<()> {
        save_keyring_credential(
            credential,
            "Linux Secret Service is unavailable; install and unlock a Freedesktop Secret Service",
        )
    }

    fn delete(&self) -> AccountResult<bool> {
        delete_keyring_credential(
            "Linux Secret Service is unavailable; install and unlock a Freedesktop Secret Service",
        )
    }
}

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "windows", target_os = "linux")
))]
fn keyring_entry(guidance: &'static str) -> AccountResult<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|_| AccountError::CredentialStoreUnavailable(guidance))
}

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "windows", target_os = "linux")
))]
fn load_keyring_credential(guidance: &'static str) -> AccountResult<Option<StoredCredential>> {
    let entry = keyring_entry(guidance)?;
    match entry.get_password() {
        Ok(encoded) => {
            let encoded = Zeroizing::new(encoded);
            let bytes = STANDARD
                .decode(encoded.as_bytes())
                .map(Zeroizing::new)
                .map_err(|_| AccountError::CredentialStoreFailure)?;
            decode_credential(bytes).map(Some)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(AccountError::CredentialStoreUnavailable(guidance)),
    }
}

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "windows", target_os = "linux")
))]
fn save_keyring_credential(
    credential: &StoredCredential,
    guidance: &'static str,
) -> AccountResult<()> {
    let bytes = encode_credential(credential)?;
    let encoded = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
    keyring_entry(guidance)?
        .set_password(encoded.as_str())
        .map_err(|_| AccountError::CredentialStoreUnavailable(guidance))
}

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "windows", target_os = "linux")
))]
fn delete_keyring_credential(guidance: &'static str) -> AccountResult<bool> {
    match keyring_entry(guidance)?.delete_password() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(_) => Err(AccountError::CredentialStoreUnavailable(guidance)),
    }
}

#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
pub type NativeCredentialStore = MacOsKeychainStore;
#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
pub type NativeCredentialStore = WindowsCredentialManagerStore;
#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
pub type NativeCredentialStore = LinuxSecretServiceStore;

#[must_use]
pub const fn native_store_capability() -> CredentialStoreKind {
    if !cfg!(feature = "native-credential-store") {
        CredentialStoreKind::CompileGated
    } else if cfg!(target_os = "macos") {
        CredentialStoreKind::MacOsKeychain
    } else if cfg!(target_os = "windows") {
        CredentialStoreKind::WindowsCredentialManager
    } else if cfg!(target_os = "linux") {
        CredentialStoreKind::LinuxSecretService
    } else {
        CredentialStoreKind::UnsupportedPlatform
    }
}

pub trait RefreshLock: Send + Sync {
    fn acquire(&self, timeout: Duration) -> AccountResult<()>;
    fn release(&self);
}

#[derive(Default)]
pub struct ProcessRefreshLock {
    held: Mutex<bool>,
    changed: Condvar,
}

impl RefreshLock for ProcessRefreshLock {
    fn acquire(&self, timeout: Duration) -> AccountResult<()> {
        let started = Instant::now();
        let mut held = self
            .held
            .lock()
            .map_err(|_| AccountError::RefreshLockUnavailable)?;
        while *held {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(AccountError::RefreshLockUnavailable)?;
            let (next, result) = self
                .changed
                .wait_timeout(held, remaining)
                .map_err(|_| AccountError::RefreshLockUnavailable)?;
            held = next;
            if result.timed_out() && *held {
                return Err(AccountError::RefreshLockUnavailable);
            }
        }
        *held = true;
        Ok(())
    }

    fn release(&self) {
        if let Ok(mut held) = self.held.lock() {
            *held = false;
            self.changed.notify_one();
        }
    }
}

pub struct FileRefreshLock {
    path: PathBuf,
    held: Mutex<Option<File>>,
}

impl FileRefreshLock {
    pub fn new(path: PathBuf) -> AccountResult<Self> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(AccountError::RefreshLockUnavailable);
        }
        let parent = path.parent().ok_or(AccountError::RefreshLockUnavailable)?;
        let parent_metadata = parent
            .symlink_metadata()
            .map_err(|_| AccountError::RefreshLockUnavailable)?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(AccountError::RefreshLockUnavailable);
        }
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(AccountError::RefreshLockUnavailable);
        }
        Ok(Self {
            path,
            held: Mutex::new(None),
        })
    }

    fn open(path: &Path) -> AccountResult<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(path)
            .map_err(|_| AccountError::RefreshLockUnavailable)
    }
}

impl RefreshLock for FileRefreshLock {
    fn acquire(&self, timeout: Duration) -> AccountResult<()> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| AccountError::RefreshLockUnavailable)?;
        if held.is_some() {
            return Err(AccountError::RefreshLockUnavailable);
        }
        let file = Self::open(&self.path)?;
        let started = Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    *held = Some(file);
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if started.elapsed() >= timeout {
                        return Err(AccountError::RefreshLockUnavailable);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err(AccountError::RefreshLockUnavailable),
            }
        }
    }

    fn release(&self) {
        if let Ok(mut held) = self.held.lock() {
            if let Some(file) = held.take() {
                let _ = fs2::FileExt::unlock(&file);
            }
        }
    }
}

#[cfg(test)]
pub(crate) struct FakeCredentialStore {
    credential: Mutex<Option<StoredCredential>>,
    fail_load: Mutex<bool>,
    fail_save: Mutex<bool>,
    fail_delete: Mutex<bool>,
}

#[cfg(test)]
impl FakeCredentialStore {
    pub(crate) fn empty() -> Self {
        Self {
            credential: Mutex::new(None),
            fail_load: Mutex::new(false),
            fail_save: Mutex::new(false),
            fail_delete: Mutex::new(false),
        }
    }

    pub(crate) fn snapshot(&self) -> Option<StoredCredential> {
        self.credential.lock().unwrap().clone()
    }

    pub(crate) fn fail_next_save(&self) {
        *self.fail_save.lock().unwrap() = true;
    }
}

#[cfg(test)]
impl CredentialStore for FakeCredentialStore {
    fn kind(&self) -> CredentialStoreKind {
        CredentialStoreKind::DeterministicFake
    }

    fn load(&self) -> AccountResult<Option<StoredCredential>> {
        if std::mem::take(&mut *self.fail_load.lock().unwrap()) {
            return Err(AccountError::CredentialStoreFailure);
        }
        Ok(self.credential.lock().unwrap().clone())
    }

    fn save(&self, credential: &StoredCredential) -> AccountResult<()> {
        if std::mem::take(&mut *self.fail_save.lock().unwrap()) {
            return Err(AccountError::CredentialStoreFailure);
        }
        *self.credential.lock().unwrap() = Some(credential.clone());
        Ok(())
    }

    fn delete(&self) -> AccountResult<bool> {
        if std::mem::take(&mut *self.fail_delete.lock().unwrap()) {
            return Err(AccountError::CredentialStoreFailure);
        }
        Ok(self.credential.lock().unwrap().take().is_some())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn native_store_capability_is_explicit_and_has_no_plaintext_fallback() {
        let capability = native_store_capability();
        if cfg!(feature = "native-credential-store") {
            assert_ne!(capability, CredentialStoreKind::CompileGated);
        } else {
            assert_eq!(capability, CredentialStoreKind::CompileGated);
        }
        assert!(
            !format!("{capability:?}")
                .to_ascii_lowercase()
                .contains("file")
        );
    }

    #[test]
    fn refresh_lock_file_contains_no_credential_material() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("refresh.lock");
        let lock = FileRefreshLock::new(path.clone()).unwrap();
        lock.acquire(Duration::from_secs(1)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        lock.release();
    }
}
