use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use url::{Host, Url};
use uuid::Uuid;

use super::error::{AccountError, AccountResult};
use super::model::{
    AccountState, AccountStatus, DeviceAuthorizationPrompt, DeviceDisplay, DeviceList,
    DeviceRevokeResult, ExternalIdentityList, LinkResult, LocalLogoutPolicy, LoginResult,
    LogoutResult, LogoutScope, UnlinkResult,
};
use super::oidc::ValidatedProvider;
use super::protocol::{
    AccountClientConfig, AccountTransport, AccountWire, DeviceAuthorizationWire, DevicePollError,
    DevicesWire, ExternalIdentitiesWire, LinkWire, SessionWire, WireRequest,
    build_authorization_url, device_poll_error, expect_empty_success, parse_success,
    pkce_challenge,
};
use super::runtime::{
    AccountRuntime, DeviceInteraction, LinkInteraction, PkceInteraction, fresh_secret,
};
use super::secret::SecretString;
use super::store::{CredentialStore, RefreshLock, StoredCredential};

const MAX_DEVICE_POLL_INTERVAL_SECONDS: u32 = 30;
const DEVICE_SLOW_DOWN_SECONDS: u32 = 5;

pub struct AccountClient<T, S, L, R> {
    config: AccountClientConfig,
    transport: T,
    store: S,
    refresh_lock: L,
    runtime: R,
}

impl<T, S, L, R> AccountClient<T, S, L, R>
where
    T: AccountTransport,
    S: CredentialStore,
    L: RefreshLock,
    R: AccountRuntime,
{
    pub fn new(
        mut config: AccountClientConfig,
        transport: T,
        store: S,
        refresh_lock: L,
        runtime: R,
    ) -> AccountResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            store,
            refresh_lock,
            runtime,
        })
    }

    #[must_use]
    pub const fn config(&self) -> &AccountClientConfig {
        &self.config
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub const fn credential_store(&self) -> &S {
        &self.store
    }

    pub fn login_pkce(
        &self,
        interaction: &dyn PkceInteraction,
        display: &DeviceDisplay,
    ) -> AccountResult<LoginResult> {
        self.ensure_signed_out()?;
        if !display.validate() {
            return Err(AccountError::UnsafeRequest);
        }
        let started = self.runtime.now_unix();
        let deadline = started.saturating_add(self.config.interactive_timeout.as_secs());
        let provider = self.discover_provider(deadline)?;
        let redirect_uri = interaction.prepare_redirect(&self.config.loopback_callback_path)?;
        validate_loopback_redirect(&redirect_uri, &self.config.loopback_callback_path)?;

        let verifier = fresh_secret(&self.runtime)?;
        let state = fresh_secret(&self.runtime)?;
        let nonce = fresh_secret(&self.runtime)?;
        let challenge = pkce_challenge(&verifier);
        let authorization_url = build_authorization_url(
            provider.authorization_endpoint(),
            &self.config.public_client_id,
            &redirect_uri,
            &state,
            &nonce,
            &challenge,
        );
        self.config.validate_oidc_url(&authorization_url, true)?;
        let callback = interaction.authorize(&authorization_url, deadline, &self.runtime)?;
        if !state.constant_time_eq(&callback.state)
            || callback.redirect_uri != redirect_uri
            || !callback.code.is_bounded_ascii()
        {
            return Err(AccountError::InvalidPkceCallback);
        }
        self.ensure_before(deadline)?;
        let request = WireRequest::exchange_pkce(
            &self.config.public_client_id,
            &callback.code,
            &verifier,
            &redirect_uri,
            &nonce,
            display,
        )?;
        let response = self
            .transport
            .send(request, self.request_deadline(deadline))?;
        let session = self.validate_session(&response, &provider, &nonce, None)?;
        self.publish_login(session)
    }

    pub fn login_device(
        &self,
        interaction: &dyn DeviceInteraction,
        display: &DeviceDisplay,
    ) -> AccountResult<LoginResult> {
        self.ensure_signed_out()?;
        if !display.validate() {
            return Err(AccountError::UnsafeRequest);
        }
        let started = self.runtime.now_unix();
        let overall_deadline = started.saturating_add(self.config.device_timeout.as_secs());
        let provider = self.discover_provider(overall_deadline)?;
        let nonce = fresh_secret(&self.runtime)?;
        let response = self.transport.send(
            WireRequest::begin_device(&self.config.public_client_id, &nonce, display)?,
            self.request_deadline(overall_deadline),
        )?;
        let authorization: DeviceAuthorizationWire = parse_success(&response, 200)?;
        let device_code = SecretString::new(authorization.device_code);
        if !device_code.is_bounded_ascii()
            || !valid_user_code(&authorization.user_code)
            || !(1..=MAX_DEVICE_POLL_INTERVAL_SECONDS).contains(&authorization.interval_seconds)
            || authorization.expires_at <= self.runtime.now_unix()
            || authorization.expires_at
                > started.saturating_add(self.config.device_timeout.as_secs())
        {
            return Err(AccountError::InvalidResponse);
        }
        self.config
            .validate_first_party_verification_url(&authorization.verification_uri)?;
        let prompt = DeviceAuthorizationPrompt {
            user_code: authorization.user_code,
            verification_uri: authorization.verification_uri,
            expires_at: authorization.expires_at,
            interval_seconds: authorization.interval_seconds,
            display: display.clone(),
        };
        interaction.display(&prompt)?;

        let deadline = overall_deadline.min(prompt.expires_at);
        let mut interval = prompt.interval_seconds;
        loop {
            if self.runtime.cancelled() {
                return Err(AccountError::Cancelled);
            }
            self.ensure_before(deadline)
                .map_err(|_| AccountError::DeviceAuthorizationExpired)?;
            self.runtime.sleep(Duration::from_secs(u64::from(interval)));
            if self.runtime.cancelled() {
                return Err(AccountError::Cancelled);
            }
            self.ensure_before(deadline)
                .map_err(|_| AccountError::DeviceAuthorizationExpired)?;
            let response = self.transport.send(
                WireRequest::poll_device(&self.config.public_client_id, &device_code)?,
                self.request_deadline(deadline),
            )?;
            if response.status == 200 {
                let session = self.validate_session(&response, &provider, &nonce, None)?;
                return self.publish_login(session);
            }
            match device_poll_error(&response)? {
                DevicePollError::Pending => {}
                DevicePollError::SlowDown => {
                    interval = interval
                        .saturating_add(DEVICE_SLOW_DOWN_SECONDS)
                        .min(MAX_DEVICE_POLL_INTERVAL_SECONDS);
                }
                DevicePollError::Denied => return Err(AccountError::AuthorizationDenied),
                DevicePollError::Expired => {
                    return Err(AccountError::DeviceAuthorizationExpired);
                }
                DevicePollError::Cancelled => return Err(AccountError::Cancelled),
            }
        }
    }

    pub fn status(&self) -> AccountResult<AccountStatus> {
        let Some(stored) = self.store.load()? else {
            return Ok(AccountStatus::signed_out(AccountState::SignedOut));
        };
        let account_id = stored.account_id();
        let device_id = stored.device_id();
        match self.refresh_access() {
            Ok(active) => {
                let response = self.transport.send(
                    WireRequest::get_account(active.access_token.clone())?,
                    self.request_deadline(u64::MAX),
                );
                match response {
                    Ok(response) => {
                        let account: AccountWire = parse_success(&response, 200)?;
                        if account.account_id != active.credential.account_id() {
                            return Err(AccountError::InvalidResponse);
                        }
                        Ok(AccountStatus {
                            version: 1,
                            state: AccountState::Online,
                            account_id: Some(account.account_id),
                            device_id: Some(active.credential.device_id()),
                            stale: false,
                        })
                    }
                    Err(AccountError::Offline | AccountError::DeadlineExceeded) => {
                        Ok(AccountStatus {
                            version: 1,
                            state: AccountState::OfflineStale,
                            account_id: Some(account_id),
                            device_id: Some(device_id),
                            stale: true,
                        })
                    }
                    Err(error) => Err(error),
                }
            }
            Err(AccountError::Offline | AccountError::DeadlineExceeded) => Ok(AccountStatus {
                version: 1,
                state: AccountState::OfflineStale,
                account_id: Some(account_id),
                device_id: Some(device_id),
                stale: true,
            }),
            Err(AccountError::RefreshReuseDetected | AccountError::SessionRevoked) => {
                Ok(AccountStatus::signed_out(AccountState::Revoked))
            }
            Err(error) => Err(error),
        }
    }

    pub fn logout(
        &self,
        scope: LogoutScope,
        local_policy: LocalLogoutPolicy,
    ) -> AccountResult<LogoutResult> {
        if self.store.load()?.is_none() {
            return Ok(LogoutResult {
                version: 1,
                status: "already_signed_out",
                remote_revoked: false,
                local_credential_removed: false,
                warning: None,
            });
        }
        if local_policy == LocalLogoutPolicy::ConfirmedLocalOnly {
            let removed = self.store.delete()?;
            return Ok(LogoutResult {
                version: 1,
                status: "local_only",
                remote_revoked: false,
                local_credential_removed: removed,
                warning: Some(
                    "remote session remains valid until expiry or revocation from the account web UI",
                ),
            });
        }

        let active = match self.refresh_access() {
            Ok(active) => active,
            Err(AccountError::RefreshReuseDetected | AccountError::SessionRevoked)
                if scope == LogoutScope::CurrentSession =>
            {
                let removed = self.store.delete()?;
                return Ok(LogoutResult {
                    version: 1,
                    status: "session_revoked",
                    remote_revoked: true,
                    local_credential_removed: removed,
                    warning: None,
                });
            }
            Err(AccountError::Offline | AccountError::DeadlineExceeded) => {
                return Err(AccountError::RemoteRevocationUnconfirmed);
            }
            Err(error) => return Err(error),
        };
        if scope == LogoutScope::AllDevices {
            let devices = self.list_devices_with_access(&active.access_token)?;
            for device in devices.devices {
                let response = self.transport.send(
                    WireRequest::revoke_device(active.access_token.clone(), device.device_id)?,
                    self.request_deadline(u64::MAX),
                )?;
                expect_empty_success(&response, 204)?;
            }
        }
        let response = self.transport.send(
            WireRequest::revoke(active.access_token)?,
            self.request_deadline(u64::MAX),
        )?;
        expect_empty_success(&response, 204)?;
        let removed = self.store.delete()?;
        Ok(LogoutResult {
            version: 1,
            status: match scope {
                LogoutScope::CurrentSession => "session_revoked",
                LogoutScope::AllDevices => "all_devices_revoked",
            },
            remote_revoked: true,
            local_credential_removed: removed,
            warning: None,
        })
    }

    pub fn link(
        &self,
        provider_name: &str,
        interaction: &dyn LinkInteraction,
    ) -> AccountResult<LinkResult> {
        let active = self.refresh_access()?;
        let response = self.transport.send(
            WireRequest::begin_link(active.access_token, provider_name)?,
            self.request_deadline(u64::MAX),
        )?;
        let link: LinkWire = parse_success(&response, 202)?;
        self.config
            .validate_first_party_verification_url(&link.verification_uri)?;
        if link.expires_at <= self.runtime.now_unix()
            || link.expires_at
                > self
                    .runtime
                    .now_unix()
                    .saturating_add(self.config.interactive_timeout.as_secs())
        {
            return Err(AccountError::InvalidResponse);
        }
        interaction.open(&link.verification_uri)?;
        Ok(LinkResult {
            version: 1,
            status: "fresh_auth_required",
            verification_uri: link.verification_uri,
            expires_at: link.expires_at,
        })
    }

    pub fn unlink(&self, external_identity_id: Uuid) -> AccountResult<UnlinkResult> {
        let active = self.refresh_access()?;
        let response = self.transport.send(
            WireRequest::unlink(active.access_token, external_identity_id)?,
            self.request_deadline(u64::MAX),
        )?;
        expect_empty_success(&response, 204)?;
        Ok(UnlinkResult {
            version: 1,
            status: "unlinked",
            external_identity_id,
        })
    }

    /// Lists the opaque identifiers accepted by [`Self::unlink`].
    pub fn external_identities(&self) -> AccountResult<ExternalIdentityList> {
        let active = self.refresh_access()?;
        let response = self.transport.send(
            WireRequest::list_external_identities(active.access_token)?,
            self.request_deadline(u64::MAX),
        )?;
        let wire: ExternalIdentitiesWire = parse_success(&response, 200)?;
        if wire.external_identities.len() > 100
            || wire.external_identities.iter().any(|identity| {
                identity.external_identity_id.is_nil()
                    || identity.linked_at > self.runtime.now_unix()
                    || self
                        .config
                        .validate_oidc_url(&identity.issuer, false)
                        .is_err()
            })
        {
            return Err(AccountError::InvalidResponse);
        }
        Ok(ExternalIdentityList {
            version: 1,
            external_identities: wire.external_identities,
        })
    }

    pub fn devices(&self) -> AccountResult<DeviceList> {
        let active = self.refresh_access()?;
        self.list_devices_with_access(&active.access_token)
    }

    pub fn revoke_device(&self, device_id: Uuid) -> AccountResult<DeviceRevokeResult> {
        let active = self.refresh_access()?;
        let response = self.transport.send(
            WireRequest::revoke_device(active.access_token, device_id)?,
            self.request_deadline(u64::MAX),
        )?;
        expect_empty_success(&response, 204)?;
        if device_id == active.credential.device_id() {
            self.store.delete()?;
        }
        Ok(DeviceRevokeResult {
            version: 1,
            status: "revoked",
            device_id,
        })
    }

    fn ensure_signed_out(&self) -> AccountResult<()> {
        if self.store.load()?.is_some() {
            Err(AccountError::AlreadySignedIn)
        } else {
            Ok(())
        }
    }

    fn discover_provider(&self, overall_deadline: u64) -> AccountResult<ValidatedProvider> {
        self.ensure_before(overall_deadline)?;
        ValidatedProvider::discover(
            &self.config,
            &self.transport,
            self.request_deadline(overall_deadline),
        )
    }

    fn validate_session(
        &self,
        response: &super::protocol::WireResponse,
        provider: &ValidatedProvider,
        nonce: &SecretString,
        expected: Option<&StoredCredential>,
    ) -> AccountResult<ActiveSession> {
        let wire: SessionWire = parse_success(response, 200)?;
        if wire.token_type != "Bearer"
            || !(1..=3600).contains(&wire.expires_in)
            || wire.account_id.is_nil()
            || wire.device_id.is_nil()
            || wire.token_family_id.is_nil()
        {
            return Err(AccountError::InvalidResponse);
        }
        let access_token = SecretString::new(wire.access_token);
        let refresh_token = SecretString::new(wire.refresh_token);
        let id_token = SecretString::new(wire.id_token);
        if !access_token.is_bounded_ascii()
            || !refresh_token.is_bounded_ascii()
            || !id_token.is_bounded_ascii()
            || access_token.constant_time_eq(&refresh_token)
        {
            return Err(AccountError::InvalidResponse);
        }
        let subject = provider.verify_id_token(
            &self.config,
            &id_token,
            Some(nonce),
            self.runtime.now_unix(),
        )?;
        if let Some(previous) = expected {
            if wire.account_id != previous.account_id()
                || wire.device_id != previous.device_id()
                || wire.token_family_id != previous.token_family_id()
                || previous.issuer() != &self.config.issuer
                || previous.audience() != self.config.audience
                || wire.refresh_generation
                    != previous
                        .refresh_generation()
                        .checked_add(1)
                        .ok_or(AccountError::InvalidResponse)?
                || previous.refresh_token().constant_time_eq(&refresh_token)
            {
                return Err(AccountError::InvalidResponse);
            }
        } else if wire.refresh_generation != 0 {
            return Err(AccountError::InvalidResponse);
        }
        let credential = StoredCredential::new(
            wire.account_id,
            wire.device_id,
            wire.token_family_id,
            wire.refresh_generation,
            self.config.issuer.clone(),
            self.config.audience.clone(),
            subject,
            refresh_token,
        )?;
        Ok(ActiveSession {
            access_token,
            credential,
        })
    }

    fn publish_login(&self, session: ActiveSession) -> AccountResult<LoginResult> {
        let result = LoginResult {
            version: 1,
            status: "signed_in",
            account_id: session.credential.account_id(),
            device_id: session.credential.device_id(),
        };
        if let Err(error) = self.store.save(&session.credential) {
            self.best_effort_revoke(session.access_token);
            return Err(error);
        }
        Ok(result)
    }

    fn refresh_access(&self) -> AccountResult<ActiveSession> {
        self.refresh_lock.acquire(self.config.request_timeout)?;
        let _release = RefreshRelease(&self.refresh_lock);
        let stored = self.store.load()?.ok_or(AccountError::NotSignedIn)?;
        if stored.issuer() != &self.config.issuer || stored.audience() != self.config.audience {
            return Err(AccountError::CredentialStoreFailure);
        }
        let provider = self.discover_provider(u64::MAX)?;
        let nonce = fresh_secret(&self.runtime)?;
        let response = self.transport.send(
            WireRequest::refresh(
                &self.config.public_client_id,
                stored.refresh_token(),
                &nonce,
            )?,
            self.request_deadline(u64::MAX),
        );
        let response = match response {
            Ok(response) => response,
            Err(error @ (AccountError::RefreshReuseDetected | AccountError::SessionRevoked)) => {
                let _ = self.store.delete();
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if response.status != 200 {
            let error = super::protocol::map_error_response(&response);
            if matches!(
                error,
                AccountError::RefreshReuseDetected | AccountError::SessionRevoked
            ) {
                let _ = self.store.delete();
            }
            return Err(error);
        }
        let session = self.validate_session(&response, &provider, &nonce, Some(&stored))?;
        if let Err(error) = self.store.save(&session.credential) {
            self.best_effort_revoke(session.access_token);
            let _ = self.store.delete();
            return Err(error);
        }
        Ok(session)
    }

    fn list_devices_with_access(&self, access_token: &SecretString) -> AccountResult<DeviceList> {
        let response = self.transport.send(
            WireRequest::list_devices(access_token.clone())?,
            self.request_deadline(u64::MAX),
        )?;
        let wire: DevicesWire = parse_success(&response, 200)?;
        let mut ids = BTreeSet::new();
        for device in &wire.devices {
            if device.device_id.is_nil()
                || !ids.insert(device.device_id)
                || device.label.is_empty()
                || device.label.len() > 100
                || device.label.chars().any(char::is_control)
                || device.last_seen_at < device.created_at
            {
                return Err(AccountError::InvalidResponse);
            }
        }
        Ok(DeviceList {
            version: 1,
            devices: wire.devices,
        })
    }

    fn best_effort_revoke(&self, access_token: SecretString) {
        if let Ok(request) = WireRequest::revoke(access_token) {
            let _ = self
                .transport
                .send(request, self.request_deadline(u64::MAX));
        }
    }

    fn request_deadline(&self, overall_deadline: u64) -> u64 {
        self.runtime
            .now_unix()
            .saturating_add(self.config.request_timeout.as_secs())
            .min(overall_deadline)
    }

    fn ensure_before(&self, deadline: u64) -> AccountResult<()> {
        if self.runtime.cancelled() {
            Err(AccountError::Cancelled)
        } else if self.runtime.now_unix() >= deadline {
            Err(AccountError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

struct ActiveSession {
    access_token: SecretString,
    credential: StoredCredential,
}

struct RefreshRelease<'a, L: RefreshLock>(&'a L);

impl<L: RefreshLock> Drop for RefreshRelease<'_, L> {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn validate_loopback_redirect(redirect: &Url, expected_path: &str) -> AccountResult<()> {
    let loopback = match redirect.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if redirect.scheme() != "http"
        || !loopback
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.port().is_none_or(|port| port < 1024)
        || redirect.path() != expected_path
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        return Err(AccountError::InvalidPkceCallback);
    }
    Ok(())
}

fn valid_user_code(code: &str) -> bool {
    (4..=20).contains(&code.len())
        && code.is_ascii()
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
