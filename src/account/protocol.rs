use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;

use super::error::{AccountError, AccountResult};
use super::model::{DeviceDisplay, DevicePlatform, DeviceSummary};
use super::secret::SecretString;

pub const MAX_ACCOUNT_BODY_BYTES: usize = 64 * 1024;
pub const MAX_OIDC_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpMethod {
    Delete,
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    PublicNativeClient,
    AccountAccessToken,
    ExternalIdentityLinkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSpec {
    pub operation_id: &'static str,
    pub method: HttpMethod,
    pub path: &'static str,
    pub authentication: Authentication,
}

/// Exact route inventory from the private control-plane `OpenAPI` contract.
/// There is intentionally no catch-all or arbitrary path constructor.
pub const ACCOUNT_OPENAPI_ROUTES: &[RouteSpec] = &[
    RouteSpec {
        operation_id: "exchangePkceAuthorization",
        method: HttpMethod::Post,
        path: "/v1/login/pkce/exchange",
        authentication: Authentication::PublicNativeClient,
    },
    RouteSpec {
        operation_id: "beginDeviceAuthorization",
        method: HttpMethod::Post,
        path: "/v1/device-authorizations",
        authentication: Authentication::PublicNativeClient,
    },
    RouteSpec {
        operation_id: "pollDeviceAuthorization",
        method: HttpMethod::Post,
        path: "/v1/device-authorizations/token",
        authentication: Authentication::PublicNativeClient,
    },
    RouteSpec {
        operation_id: "refreshTokenFamily",
        method: HttpMethod::Post,
        path: "/v1/token/refresh",
        authentication: Authentication::PublicNativeClient,
    },
    RouteSpec {
        operation_id: "revokeTokenFamily",
        method: HttpMethod::Post,
        path: "/v1/token/revoke",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "getAccount",
        method: HttpMethod::Get,
        path: "/v1/account",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "beginExternalIdentityLink",
        method: HttpMethod::Post,
        path: "/v1/external-identities/link",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "completeExternalIdentityLink",
        method: HttpMethod::Post,
        path: "/v1/external-identities/link/complete",
        authentication: Authentication::ExternalIdentityLinkState,
    },
    RouteSpec {
        operation_id: "listExternalIdentities",
        method: HttpMethod::Get,
        path: "/v1/external-identities",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "unlinkExternalIdentity",
        method: HttpMethod::Delete,
        path: "/v1/external-identities/{external_identity_id}",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "listDevices",
        method: HttpMethod::Get,
        path: "/v1/devices",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "revokeDevice",
        method: HttpMethod::Post,
        path: "/v1/devices/{device_id}/revoke",
        authentication: Authentication::AccountAccessToken,
    },
    RouteSpec {
        operation_id: "listAuditEvents",
        method: HttpMethod::Get,
        path: "/v1/audit-events",
        authentication: Authentication::AccountAccessToken,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountEndpoint {
    ExchangePkce,
    BeginDeviceAuthorization,
    PollDeviceAuthorization,
    Refresh,
    RevokeTokenFamily,
    GetAccount,
    BeginExternalIdentityLink,
    CompleteExternalIdentityLink,
    ListExternalIdentities,
    UnlinkExternalIdentity(Uuid),
    ListDevices,
    RevokeDevice(Uuid),
    ListAuditEvents,
}

impl AccountEndpoint {
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        match self {
            Self::GetAccount
            | Self::ListExternalIdentities
            | Self::ListDevices
            | Self::ListAuditEvents => HttpMethod::Get,
            Self::UnlinkExternalIdentity(_) => HttpMethod::Delete,
            Self::ExchangePkce
            | Self::BeginDeviceAuthorization
            | Self::PollDeviceAuthorization
            | Self::Refresh
            | Self::RevokeTokenFamily
            | Self::BeginExternalIdentityLink
            | Self::CompleteExternalIdentityLink
            | Self::RevokeDevice(_) => HttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn authentication(&self) -> Authentication {
        match self {
            Self::ExchangePkce
            | Self::BeginDeviceAuthorization
            | Self::PollDeviceAuthorization
            | Self::Refresh => Authentication::PublicNativeClient,
            Self::CompleteExternalIdentityLink => Authentication::ExternalIdentityLinkState,
            Self::RevokeTokenFamily
            | Self::GetAccount
            | Self::BeginExternalIdentityLink
            | Self::ListExternalIdentities
            | Self::UnlinkExternalIdentity(_)
            | Self::ListDevices
            | Self::RevokeDevice(_)
            | Self::ListAuditEvents => Authentication::AccountAccessToken,
        }
    }

    #[must_use]
    pub fn path(&self) -> String {
        match self {
            Self::ExchangePkce => "/v1/login/pkce/exchange".to_owned(),
            Self::BeginDeviceAuthorization => "/v1/device-authorizations".to_owned(),
            Self::PollDeviceAuthorization => "/v1/device-authorizations/token".to_owned(),
            Self::Refresh => "/v1/token/refresh".to_owned(),
            Self::RevokeTokenFamily => "/v1/token/revoke".to_owned(),
            Self::GetAccount => "/v1/account".to_owned(),
            Self::BeginExternalIdentityLink => "/v1/external-identities/link".to_owned(),
            Self::CompleteExternalIdentityLink => {
                "/v1/external-identities/link/complete".to_owned()
            }
            Self::ListExternalIdentities => "/v1/external-identities".to_owned(),
            Self::UnlinkExternalIdentity(id) => format!("/v1/external-identities/{id}"),
            Self::ListDevices => "/v1/devices".to_owned(),
            Self::RevokeDevice(id) => format!("/v1/devices/{id}/revoke"),
            Self::ListAuditEvents => "/v1/audit-events".to_owned(),
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        match self {
            Self::ExchangePkce => "exchangePkceAuthorization",
            Self::BeginDeviceAuthorization => "beginDeviceAuthorization",
            Self::PollDeviceAuthorization => "pollDeviceAuthorization",
            Self::Refresh => "refreshTokenFamily",
            Self::RevokeTokenFamily => "revokeTokenFamily",
            Self::GetAccount => "getAccount",
            Self::BeginExternalIdentityLink => "beginExternalIdentityLink",
            Self::CompleteExternalIdentityLink => "completeExternalIdentityLink",
            Self::ListExternalIdentities => "listExternalIdentities",
            Self::UnlinkExternalIdentity(_) => "unlinkExternalIdentity",
            Self::ListDevices => "listDevices",
            Self::RevokeDevice(_) => "revokeDevice",
            Self::ListAuditEvents => "listAuditEvents",
        }
    }

    pub fn parse(method: HttpMethod, path: &str) -> AccountResult<Self> {
        let fixed = match (method, path) {
            (HttpMethod::Post, "/v1/login/pkce/exchange") => Some(Self::ExchangePkce),
            (HttpMethod::Post, "/v1/device-authorizations") => Some(Self::BeginDeviceAuthorization),
            (HttpMethod::Post, "/v1/device-authorizations/token") => {
                Some(Self::PollDeviceAuthorization)
            }
            (HttpMethod::Post, "/v1/token/refresh") => Some(Self::Refresh),
            (HttpMethod::Post, "/v1/token/revoke") => Some(Self::RevokeTokenFamily),
            (HttpMethod::Get, "/v1/account") => Some(Self::GetAccount),
            (HttpMethod::Post, "/v1/external-identities/link") => {
                Some(Self::BeginExternalIdentityLink)
            }
            (HttpMethod::Post, "/v1/external-identities/link/complete") => {
                Some(Self::CompleteExternalIdentityLink)
            }
            (HttpMethod::Get, "/v1/external-identities") => Some(Self::ListExternalIdentities),
            (HttpMethod::Get, "/v1/devices") => Some(Self::ListDevices),
            (HttpMethod::Get, "/v1/audit-events") => Some(Self::ListAuditEvents),
            _ => None,
        };
        if let Some(endpoint) = fixed {
            return Ok(endpoint);
        }
        if method == HttpMethod::Delete {
            if let Some(id) = path.strip_prefix("/v1/external-identities/") {
                return Uuid::parse_str(id)
                    .map(Self::UnlinkExternalIdentity)
                    .map_err(|_| AccountError::UnsafeRequest);
            }
        }
        if method == HttpMethod::Post {
            if let Some(id) = path
                .strip_prefix("/v1/devices/")
                .and_then(|value| value.strip_suffix("/revoke"))
            {
                return Uuid::parse_str(id)
                    .map(Self::RevokeDevice)
                    .map_err(|_| AccountError::UnsafeRequest);
            }
        }
        Err(AccountError::UnsafeRequest)
    }
}

#[derive(Clone, Debug)]
pub struct AccountClientConfig {
    pub control_plane_origin: Url,
    pub issuer: Url,
    pub audience: String,
    pub public_client_id: String,
    pub loopback_callback_path: String,
    pub request_timeout: Duration,
    pub interactive_timeout: Duration,
    pub device_timeout: Duration,
    allowed_oidc_origins: BTreeSet<String>,
}

impl AccountClientConfig {
    pub fn new(
        control_plane_origin: Url,
        issuer: Url,
        audience: String,
        public_client_id: String,
        loopback_callback_path: String,
    ) -> AccountResult<Self> {
        let issuer_origin = origin_key(&issuer)?;
        let mut config = Self {
            control_plane_origin,
            issuer,
            audience,
            public_client_id,
            loopback_callback_path,
            request_timeout: Duration::from_secs(15),
            interactive_timeout: Duration::from_secs(300),
            device_timeout: Duration::from_secs(600),
            allowed_oidc_origins: BTreeSet::from([issuer_origin]),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn allow_oidc_origin(mut self, origin: &Url) -> AccountResult<Self> {
        self.allowed_oidc_origins.insert(origin_key(origin)?);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&mut self) -> AccountResult<()> {
        validate_https_url(&self.control_plane_origin, false)?;
        if self.control_plane_origin.path() != "/"
            || self.control_plane_origin.query().is_some()
            || self.control_plane_origin.fragment().is_some()
        {
            return Err(AccountError::InvalidConfiguration(
                "control-plane origin must not contain a path, query, or fragment",
            ));
        }
        validate_https_url(&self.issuer, false)?;
        if self.issuer.query().is_some() || self.issuer.fragment().is_some() {
            return Err(AccountError::InvalidConfiguration(
                "issuer must not contain a query or fragment",
            ));
        }
        for identifier in [&self.audience, &self.public_client_id] {
            if identifier.is_empty()
                || identifier.len() > 200
                || !identifier.is_ascii()
                || identifier.bytes().any(|byte| byte.is_ascii_whitespace())
            {
                return Err(AccountError::InvalidConfiguration(
                    "audience and client id must be bounded ASCII identifiers",
                ));
            }
        }
        let callback = self.loopback_callback_path.as_str();
        if !callback.starts_with('/')
            || callback.len() > 120
            || callback.contains(['?', '#'])
            || callback.contains("..")
        {
            return Err(AccountError::InvalidConfiguration(
                "loopback callback path is invalid",
            ));
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&self.request_timeout)
            || !(Duration::from_secs(30)..=Duration::from_secs(900))
                .contains(&self.interactive_timeout)
            || !(Duration::from_secs(30)..=Duration::from_secs(900)).contains(&self.device_timeout)
        {
            return Err(AccountError::InvalidConfiguration(
                "account deadlines are outside the closed bounds",
            ));
        }
        if !self
            .allowed_oidc_origins
            .contains(&origin_key(&self.issuer)?)
        {
            return Err(AccountError::InvalidConfiguration(
                "issuer origin must be explicitly allowlisted",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_oidc_url(&self, url: &Url, allow_query: bool) -> AccountResult<()> {
        validate_https_url(url, allow_query)?;
        if !self.allowed_oidc_origins.contains(&origin_key(url)?) {
            return Err(AccountError::InvalidConfiguration(
                "OIDC endpoint origin is not allowlisted",
            ));
        }
        Ok(())
    }

    pub fn account_url(&self, endpoint: &AccountEndpoint) -> AccountResult<Url> {
        self.control_plane_origin
            .join(&endpoint.path())
            .map_err(|_| AccountError::InvalidConfiguration("account endpoint URL is invalid"))
    }

    pub(crate) fn validate_first_party_verification_url(&self, url: &Url) -> AccountResult<()> {
        validate_https_url(url, true)?;
        if origin_key(url)? != origin_key(&self.control_plane_origin)? {
            return Err(AccountError::InvalidResponse);
        }
        Ok(())
    }
}

fn origin_key(url: &Url) -> AccountResult<String> {
    validate_https_url(url, true)?;
    Ok(url.origin().ascii_serialization())
}

fn validate_https_url(url: &Url, allow_query: bool) -> AccountResult<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (!allow_query && url.query().is_some())
        || url.fragment().is_some()
    {
        return Err(AccountError::InvalidConfiguration(
            "account and OIDC endpoints require credential-free HTTPS URLs",
        ));
    }
    Ok(())
}

pub struct WireRequest {
    endpoint: AccountEndpoint,
    access_token: Option<SecretString>,
    body: Vec<u8>,
}

impl WireRequest {
    pub(crate) fn exchange_pkce(
        client_id: &str,
        code: &SecretString,
        verifier: &SecretString,
        redirect_uri: &Url,
        nonce: &SecretString,
        display: &DeviceDisplay,
    ) -> AccountResult<Self> {
        Self::public_json(
            AccountEndpoint::ExchangePkce,
            &PkceExchangeRequest {
                client_id,
                code: code.expose(),
                code_verifier: verifier.expose(),
                redirect_uri: redirect_uri.as_str(),
                nonce: nonce.expose(),
                device: DeviceDisplayWire::from(display),
            },
        )
    }

    pub(crate) fn begin_device(
        client_id: &str,
        nonce: &SecretString,
        display: &DeviceDisplay,
    ) -> AccountResult<Self> {
        Self::public_json(
            AccountEndpoint::BeginDeviceAuthorization,
            &BeginDeviceRequest {
                client_id,
                nonce: nonce.expose(),
                device: DeviceDisplayWire::from(display),
            },
        )
    }

    pub(crate) fn poll_device(client_id: &str, device_code: &SecretString) -> AccountResult<Self> {
        Self::public_json(
            AccountEndpoint::PollDeviceAuthorization,
            &PollDeviceRequest {
                client_id,
                device_code: device_code.expose(),
            },
        )
    }

    pub(crate) fn refresh(
        client_id: &str,
        refresh_token: &SecretString,
        nonce: &SecretString,
    ) -> AccountResult<Self> {
        Self::public_json(
            AccountEndpoint::Refresh,
            &RefreshRequest {
                client_id,
                refresh_token: refresh_token.expose(),
                nonce: nonce.expose(),
            },
        )
    }

    pub(crate) fn revoke(access_token: SecretString) -> AccountResult<Self> {
        Self::account_json(
            AccountEndpoint::RevokeTokenFamily,
            access_token,
            &EmptyRequest {},
        )
    }

    pub(crate) fn get_account(access_token: SecretString) -> AccountResult<Self> {
        Self::account_empty(AccountEndpoint::GetAccount, access_token)
    }

    pub(crate) fn begin_link(access_token: SecretString, provider: &str) -> AccountResult<Self> {
        validate_provider(provider)?;
        Self::account_json(
            AccountEndpoint::BeginExternalIdentityLink,
            access_token,
            &BeginLinkRequest { provider },
        )
    }

    pub(crate) fn unlink(
        access_token: SecretString,
        external_identity_id: Uuid,
    ) -> AccountResult<Self> {
        Self::account_empty(
            AccountEndpoint::UnlinkExternalIdentity(external_identity_id),
            access_token,
        )
    }

    pub(crate) fn list_external_identities(access_token: SecretString) -> AccountResult<Self> {
        Self::account_empty(AccountEndpoint::ListExternalIdentities, access_token)
    }

    pub(crate) fn list_devices(access_token: SecretString) -> AccountResult<Self> {
        Self::account_empty(AccountEndpoint::ListDevices, access_token)
    }

    pub(crate) fn revoke_device(
        access_token: SecretString,
        device_id: Uuid,
    ) -> AccountResult<Self> {
        Self::account_json(
            AccountEndpoint::RevokeDevice(device_id),
            access_token,
            &EmptyRequest {},
        )
    }

    fn public_json(endpoint: AccountEndpoint, body: &impl Serialize) -> AccountResult<Self> {
        Self::json(endpoint, None, body)
    }

    fn account_json(
        endpoint: AccountEndpoint,
        access_token: SecretString,
        body: &impl Serialize,
    ) -> AccountResult<Self> {
        Self::json(endpoint, Some(access_token), body)
    }

    fn account_empty(endpoint: AccountEndpoint, access_token: SecretString) -> AccountResult<Self> {
        let request = Self {
            endpoint,
            access_token: Some(access_token),
            body: Vec::new(),
        };
        request.validate()?;
        Ok(request)
    }

    fn json(
        endpoint: AccountEndpoint,
        access_token: Option<SecretString>,
        body: &impl Serialize,
    ) -> AccountResult<Self> {
        let body = serde_json::to_vec(body).map_err(|_| AccountError::UnsafeRequest)?;
        let request = Self {
            endpoint,
            access_token,
            body,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> AccountResult<()> {
        let reparsed = AccountEndpoint::parse(self.endpoint.method(), &self.endpoint.path())?;
        if reparsed != self.endpoint
            || (self.endpoint.authentication() == Authentication::AccountAccessToken)
                != self.access_token.is_some()
            || self
                .access_token
                .as_ref()
                .is_some_and(|token| !token.is_bounded_ascii())
            || self.body.len() > MAX_ACCOUNT_BODY_BYTES
        {
            return Err(AccountError::UnsafeRequest);
        }
        if !self.body.is_empty() {
            validate_account_payload(&self.body)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn endpoint(&self) -> &AccountEndpoint {
        &self.endpoint
    }

    /// Returns the bearer value only to the selected transport adapter. It
    /// must never be formatted, logged, persisted, or copied to an error.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        self.access_token.as_ref().map(SecretString::expose)
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireRequest")
            .field("operation", &self.endpoint.operation_id())
            .field("credentials", &"<redacted>")
            .field("body", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub struct WireResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl WireResponse {
    pub fn new(status: u16, body: Vec<u8>) -> AccountResult<Self> {
        if body.len() > MAX_OIDC_DOCUMENT_BYTES {
            return Err(AccountError::InvalidResponse);
        }
        Ok(Self { status, body })
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for WireResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcDocument {
    Discovery,
    Jwks,
}

pub trait AccountTransport: Send + Sync {
    fn send(&self, request: WireRequest, deadline_unix: u64) -> AccountResult<WireResponse>;

    fn get_oidc_document(
        &self,
        kind: OidcDocument,
        url: &Url,
        deadline_unix: u64,
    ) -> AccountResult<WireResponse>;
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceDisplayWire<'a> {
    product_name: &'a str,
    device_label: &'a str,
    platform: DevicePlatform,
    application_version: &'a str,
}

impl<'a> From<&'a DeviceDisplay> for DeviceDisplayWire<'a> {
    fn from(display: &'a DeviceDisplay) -> Self {
        Self {
            product_name: &display.product_name,
            device_label: &display.device_label,
            platform: display.platform,
            application_version: &display.application_version,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PkceExchangeRequest<'a> {
    client_id: &'a str,
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
    nonce: &'a str,
    device: DeviceDisplayWire<'a>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BeginDeviceRequest<'a> {
    client_id: &'a str,
    nonce: &'a str,
    device: DeviceDisplayWire<'a>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PollDeviceRequest<'a> {
    client_id: &'a str,
    device_code: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    refresh_token: &'a str,
    nonce: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BeginLinkRequest<'a> {
    provider: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionWire {
    pub token_type: String,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub expires_in: u32,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub token_family_id: Uuid,
    pub refresh_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceAuthorizationWire {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: Url,
    pub expires_at: u64,
    pub interval_seconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountWire {
    pub account_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkWire {
    pub verification_uri: Url,
    pub expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalIdentitiesWire {
    pub external_identities: Vec<super::model::ExternalIdentitySummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DevicesWire {
    pub devices: Vec<DeviceSummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorWire {
    pub error: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevicePollError {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Cancelled,
}

pub(crate) fn parse_success<T: for<'de> Deserialize<'de>>(
    response: &WireResponse,
    expected_status: u16,
) -> AccountResult<T> {
    if response.status != expected_status || response.body.len() > MAX_ACCOUNT_BODY_BYTES {
        return Err(map_error_response(response));
    }
    serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)
}

pub(crate) fn expect_empty_success(
    response: &WireResponse,
    expected_status: u16,
) -> AccountResult<()> {
    if response.status == expected_status
        && (response.body.is_empty()
            || serde_json::from_slice::<Value>(&response.body).is_ok_and(|value| value.is_null()))
    {
        Ok(())
    } else {
        Err(map_error_response(response))
    }
}

pub(crate) fn map_error_response(response: &WireResponse) -> AccountError {
    if response.status == 429 {
        return AccountError::RateLimited;
    }
    let code = serde_json::from_slice::<ErrorWire>(&response.body)
        .ok()
        .map(|body| body.error);
    match code.as_deref() {
        Some("authorization_pending" | "slow_down") => AccountError::InvalidResponse,
        Some("access_denied") => AccountError::AuthorizationDenied,
        Some("expired_token") => AccountError::DeviceAuthorizationExpired,
        Some("cancelled") => AccountError::Cancelled,
        Some("token_reuse") => AccountError::RefreshReuseDetected,
        Some("invalid_grant" | "session_revoked") => AccountError::SessionRevoked,
        _ if response.status >= 500 => AccountError::Offline,
        _ => AccountError::InvalidResponse,
    }
}

pub(crate) fn device_poll_error(response: &WireResponse) -> AccountResult<DevicePollError> {
    if response.status != 400 {
        return Err(map_error_response(response));
    }
    let error: ErrorWire =
        serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
    match error.error.as_str() {
        "authorization_pending" => Ok(DevicePollError::Pending),
        "slow_down" => Ok(DevicePollError::SlowDown),
        "access_denied" => Ok(DevicePollError::Denied),
        "expired_token" => Ok(DevicePollError::Expired),
        "cancelled" => Ok(DevicePollError::Cancelled),
        _ => Err(AccountError::InvalidResponse),
    }
}

pub(crate) fn pkce_challenge(verifier: &SecretString) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()))
}

pub(crate) fn build_authorization_url(
    endpoint: &Url,
    client_id: &str,
    redirect_uri: &Url,
    state: &SecretString,
    nonce: &SecretString,
    challenge: &str,
) -> Url {
    let mut url = endpoint.clone();
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("scope", "openid profile")
        .append_pair("state", state.expose())
        .append_pair("nonce", nonce.expose())
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

pub(crate) fn validate_provider(provider: &str) -> AccountResult<()> {
    if provider.is_empty()
        || provider.len() > 64
        || !provider.is_ascii()
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AccountError::UnsafeRequest);
    }
    Ok(())
}

pub(crate) fn validate_account_payload(bytes: &[u8]) -> AccountResult<()> {
    if bytes.len() > MAX_ACCOUNT_BODY_BYTES {
        return Err(AccountError::UnsafeRequest);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AccountError::UnsafeRequest)?;
    validate_account_value(&value)
}

fn validate_account_value(value: &Value) -> AccountResult<()> {
    const FORBIDDEN: &[&str] = &[
        "compiledcontext",
        "context",
        "journal",
        "localpath",
        "memory",
        "memoryid",
        "modelprovidertoken",
        "ontology",
        "principal",
        "principalid",
        "profile",
        "profileid",
        "prompt",
        "query",
        "remember",
        "root",
        "search",
        "searchquery",
        "semanticdelta",
        "semanticentity",
        "semanticfact",
        "semanticfacts",
        "toolpayload",
        "vault",
        "vaultfile",
        "workspace",
        "workspaceid",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if FORBIDDEN.contains(&normalized.as_str()) {
                    return Err(AccountError::UnsafeRequest);
                }
                validate_account_value(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_account_value(child)?;
            }
        }
        Value::String(value) if looks_like_absolute_path(value) => {
            return Err(AccountError::UnsafeRequest);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_allowlist_is_exactly_the_private_openapi_inventory() {
        let expected = [
            (HttpMethod::Post, "/v1/login/pkce/exchange"),
            (HttpMethod::Post, "/v1/device-authorizations"),
            (HttpMethod::Post, "/v1/device-authorizations/token"),
            (HttpMethod::Post, "/v1/token/refresh"),
            (HttpMethod::Post, "/v1/token/revoke"),
            (HttpMethod::Get, "/v1/account"),
            (HttpMethod::Post, "/v1/external-identities/link"),
            (HttpMethod::Post, "/v1/external-identities/link/complete"),
            (HttpMethod::Get, "/v1/external-identities"),
            (
                HttpMethod::Delete,
                "/v1/external-identities/{external_identity_id}",
            ),
            (HttpMethod::Get, "/v1/devices"),
            (HttpMethod::Post, "/v1/devices/{device_id}/revoke"),
            (HttpMethod::Get, "/v1/audit-events"),
        ];
        assert_eq!(
            ACCOUNT_OPENAPI_ROUTES
                .iter()
                .map(|route| (route.method, route.path))
                .collect::<Vec<_>>(),
            expected
        );
        for (method, path) in [
            (HttpMethod::Post, "/v1/search"),
            (HttpMethod::Get, "/v1/devices/anything"),
            (HttpMethod::Delete, "/v1/external-identities/not-a-uuid"),
            (HttpMethod::Get, "/v1/account/"),
            (HttpMethod::Get, "https://attacker.invalid/v1/account"),
        ] {
            assert_eq!(
                AccountEndpoint::parse(method, path),
                Err(AccountError::UnsafeRequest)
            );
        }
    }

    #[test]
    fn privacy_guard_rejects_every_local_memory_field_and_path_family() {
        for field in [
            "memory_id",
            "query",
            "compiledContext",
            "principal-id",
            "workspace_id",
            "journal",
            "vaultFile",
            "root",
            "profile",
            "semanticFacts",
            "tool_payload",
            "model_provider_token",
        ] {
            let body = serde_json::to_vec(&serde_json::json!({field: "canary"})).unwrap();
            assert_eq!(
                validate_account_payload(&body),
                Err(AccountError::UnsafeRequest)
            );
        }
        for path in [
            concat!("/", "Users", "/canary/vault"),
            "C:\\canary\\vault",
            "\\\\host\\share",
            "~/vault",
        ] {
            let body = serde_json::to_vec(&serde_json::json!({"device_label": path})).unwrap();
            assert_eq!(
                validate_account_payload(&body),
                Err(AccountError::UnsafeRequest)
            );
        }
        let safe = serde_json::to_vec(&serde_json::json!({
            "device_label": "Developer laptop",
            "platform": "macos",
            "application_version": "0.1.0"
        }))
        .unwrap();
        assert!(validate_account_payload(&safe).is_ok());
    }

    #[test]
    fn account_and_oidc_origins_are_closed_and_https_only() {
        let config = AccountClientConfig::new(
            Url::parse("https://account.example.invalid/").unwrap(),
            Url::parse("https://issuer.example.invalid/").unwrap(),
            "audience".to_owned(),
            "public-client".to_owned(),
            "/callback".to_owned(),
        )
        .unwrap();
        assert!(
            config
                .validate_oidc_url(
                    &Url::parse("https://issuer.example.invalid/jwks").unwrap(),
                    false
                )
                .is_ok()
        );
        assert!(
            config
                .validate_oidc_url(&Url::parse("https://attacker.invalid/jwks").unwrap(), false)
                .is_err()
        );
        assert!(
            AccountClientConfig::new(
                Url::parse("http://account.example.invalid/").unwrap(),
                Url::parse("https://issuer.example.invalid/").unwrap(),
                "audience".to_owned(),
                "public-client".to_owned(),
                "/callback".to_owned(),
            )
            .is_err()
        );
    }
}
