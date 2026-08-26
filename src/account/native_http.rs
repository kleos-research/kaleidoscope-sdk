use std::error::Error as _;
use std::fmt;
use std::io::Read as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use url::Url;
use zeroize::Zeroizing;

use super::error::{AccountError, AccountResult};
use super::protocol::{
    AccountClientConfig, AccountTransport, HttpMethod, MAX_ACCOUNT_BODY_BYTES,
    MAX_OIDC_DOCUMENT_BYTES, OidcDocument, WireRequest, WireResponse,
};

/// Bounded HTTPS transport for the closed account and OIDC allowlists.
/// Redirects and environment-provided proxies are disabled.
pub struct NativeHttpsTransport {
    config: AccountClientConfig,
    agent: ureq::Agent,
}

impl NativeHttpsTransport {
    pub fn new(config: &AccountClientConfig) -> AccountResult<Self> {
        let mut validated = config.clone();
        validated.validate()?;
        let timeout = validated.request_timeout;
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .user_agent(concat!("kaleidoscope-manager/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            config: validated,
            agent,
        })
    }

    fn request_timeout(&self, deadline_unix: u64) -> AccountResult<Duration> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if deadline_unix <= now {
            return Err(AccountError::DeadlineExceeded);
        }
        Ok(self
            .config
            .request_timeout
            .min(Duration::from_secs(deadline_unix.saturating_sub(now))))
    }

    fn execute(
        &self,
        mut request: ureq::Request,
        body: &[u8],
        bearer: Option<&str>,
        deadline_unix: u64,
        maximum_body: usize,
    ) -> AccountResult<WireResponse> {
        request = request
            .timeout(self.request_timeout(deadline_unix)?)
            .set("Accept", "application/json");
        if !body.is_empty() {
            request = request.set("Content-Type", "application/json");
        }
        let authorization = bearer.map(|token| Zeroizing::new(format!("Bearer {token}")));
        if let Some(value) = &authorization {
            request = request.set("Authorization", value.as_str());
        }
        let response = match if body.is_empty() {
            request.call()
        } else {
            request.send_bytes(body)
        } {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error))
                if error
                    .source()
                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                    .is_some_and(|source| source.kind() == std::io::ErrorKind::TimedOut) =>
            {
                return Err(AccountError::DeadlineExceeded);
            }
            Err(ureq::Error::Transport(_)) => return Err(AccountError::Offline),
        };
        if response
            .header("Content-Length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > maximum_body)
        {
            return Err(AccountError::InvalidResponse);
        }
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(
                u64::try_from(maximum_body)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|_| AccountError::Offline)?;
        if bytes.len() > maximum_body {
            return Err(AccountError::InvalidResponse);
        }
        WireResponse::new(status, bytes)
    }
}

impl fmt::Debug for NativeHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpsTransport")
            .field("control_plane_origin", &self.config.control_plane_origin)
            .field("issuer", &self.config.issuer)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AccountTransport for NativeHttpsTransport {
    fn send(&self, request: WireRequest, deadline_unix: u64) -> AccountResult<WireResponse> {
        request.validate()?;
        let url = self.config.account_url(request.endpoint())?;
        let method = match request.endpoint().method() {
            HttpMethod::Delete => "DELETE",
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        self.execute(
            self.agent.request(method, url.as_str()),
            request.body(),
            request.bearer_token(),
            deadline_unix,
            MAX_ACCOUNT_BODY_BYTES,
        )
    }

    fn get_oidc_document(
        &self,
        kind: OidcDocument,
        url: &Url,
        deadline_unix: u64,
    ) -> AccountResult<WireResponse> {
        self.config.validate_oidc_url(url, false)?;
        if kind == OidcDocument::Discovery && url != &discovery_url(&self.config.issuer)? {
            return Err(AccountError::UnsafeRequest);
        }
        self.execute(
            self.agent.get(url.as_str()),
            &[],
            None,
            deadline_unix,
            MAX_OIDC_DOCUMENT_BYTES,
        )
    }
}

fn discovery_url(issuer: &Url) -> AccountResult<Url> {
    let mut value = issuer.as_str().trim_end_matches('/').to_owned();
    value.push_str("/.well-known/openid-configuration");
    Url::parse(&value).map_err(|_| AccountError::OidcVerification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_construction_is_credential_free_and_debug_redacted() {
        let config = AccountClientConfig::new(
            Url::parse("https://account.example.invalid/").unwrap(),
            Url::parse("https://issuer.example.invalid/").unwrap(),
            "audience".to_owned(),
            "native-client".to_owned(),
            "/callback".to_owned(),
        )
        .unwrap();
        let transport = NativeHttpsTransport::new(&config).unwrap();
        let debug = format!("{transport:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("Authorization"));
    }
}
