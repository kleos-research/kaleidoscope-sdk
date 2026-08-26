/// Account-client failures are deliberately closed and never carry remote
/// response bodies, credentials, authorization codes, or user-supplied paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountError {
    #[error(
        "account provider is not configured in this build; AUTH-BOOT staging issuer/client configuration is still required"
    )]
    ProviderNotConfigured,
    #[error("account client configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("account request violates the closed endpoint or privacy contract")]
    UnsafeRequest,
    #[error("account service is unavailable; local memory remains available offline")]
    Offline,
    #[error("account request exceeded its bounded deadline")]
    DeadlineExceeded,
    #[error("account operation was cancelled")]
    Cancelled,
    #[error("authorization was denied")]
    AuthorizationDenied,
    #[error("device authorization expired")]
    DeviceAuthorizationExpired,
    #[error("account service rate limit was reached")]
    RateLimited,
    #[error("account service returned an invalid closed response")]
    InvalidResponse,
    #[error(
        "OIDC discovery, JWKS, issuer, audience, signature, expiry, or nonce validation failed"
    )]
    OidcVerification,
    #[error("PKCE callback state, redirect, code, or denial validation failed")]
    InvalidPkceCallback,
    #[error("the refresh-token family was revoked after reuse was detected; sign in again")]
    RefreshReuseDetected,
    #[error("the account session is expired or revoked; sign in again")]
    SessionRevoked,
    #[error("the operating-system credential store is unavailable: {0}")]
    CredentialStoreUnavailable(&'static str),
    #[error("the operating-system credential store refused the operation")]
    CredentialStoreFailure,
    #[error("an account session is already stored; log out before signing in again")]
    AlreadySignedIn,
    #[error("no account session is stored; run kaleidoscope login")]
    NotSignedIn,
    #[error("the refresh rotation lock is unavailable")]
    RefreshLockUnavailable,
    #[error(
        "remote revocation could not be confirmed; the local credential was preserved; retry online or explicitly request local-only logout"
    )]
    RemoteRevocationUnconfirmed,
    #[error("the browser or loopback callback adapter is unavailable")]
    InteractionUnavailable,
}

pub type AccountResult<T> = std::result::Result<T, AccountError>;
