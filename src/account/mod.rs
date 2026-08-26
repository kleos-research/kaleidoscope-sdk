//! Provider-neutral account client for the public manager.
//!
//! The account plane is deliberately separate from profiles and the native
//! memory engine. Only the closed account `OpenAPI` routes can be constructed;
//! local memory addresses and content are rejected before transport.

mod client;
mod error;
mod model;
#[cfg(feature = "native-account-http")]
mod native_http;
mod oidc;
mod protocol;
mod runtime;
mod secret;
mod store;

#[cfg(test)]
mod fake;

pub use client::AccountClient;
pub use error::{AccountError, AccountResult};
pub use model::{
    AccountState, AccountStatus, DeviceAuthorizationPrompt, DeviceDisplay, DeviceList,
    DevicePlatform, DeviceRevokeResult, DeviceSummary, ExternalIdentityList,
    ExternalIdentitySummary, LinkResult, LocalLogoutPolicy, LoginMode, LoginResult, LogoutResult,
    LogoutScope, UnlinkResult,
};
#[cfg(feature = "native-account-http")]
pub use native_http::NativeHttpsTransport;
pub use protocol::{
    ACCOUNT_OPENAPI_ROUTES, AccountClientConfig, AccountEndpoint, AccountTransport, Authentication,
    HttpMethod, OidcDocument, RouteSpec, WireRequest, WireResponse,
};
pub use runtime::{
    AccountRuntime, BrowserLinkInteraction, ConsoleDeviceInteraction, DeviceInteraction,
    LinkInteraction, NativeLoopbackInteraction, PkceCallback, PkceInteraction, SystemRuntime,
};
pub use store::{
    CredentialStore, CredentialStoreKind, FileRefreshLock, ProcessRefreshLock, RefreshLock,
    StoredCredential, native_store_capability,
};

#[cfg(all(
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub use store::NativeCredentialStore;

#[cfg(all(feature = "native-credential-store", target_os = "linux"))]
pub use store::LinuxSecretServiceStore;
#[cfg(all(feature = "native-credential-store", target_os = "macos"))]
pub use store::MacOsKeychainStore;
#[cfg(all(feature = "native-credential-store", target_os = "windows"))]
pub use store::WindowsCredentialManagerStore;
