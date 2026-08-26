use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use super::client::AccountClient;
use super::error::{AccountError, AccountResult};
use super::model::{
    AccountState, DeviceAuthorizationPrompt, DeviceDisplay, DevicePlatform, LocalLogoutPolicy,
    LogoutScope,
};
use super::protocol::{
    AccountClientConfig, AccountEndpoint, AccountTransport, OidcDocument, WireRequest, WireResponse,
};
use super::runtime::{
    AccountRuntime, DeviceInteraction, LinkInteraction, PkceCallback, PkceInteraction,
};
use super::secret::SecretString;
use super::store::{CredentialStore as _, FakeCredentialStore, ProcessRefreshLock};

const NOW: u64 = 1_900_000_000;
const ISSUER: &str = "https://issuer.example.invalid/";
const ACCOUNT_ORIGIN: &str = "https://account.example.invalid/";
const AUDIENCE: &str = "kaleidoscope-manager-tests";
const CLIENT_ID: &str = "kaleidoscope-native-tests";
const KEY_ID: &str = "dx05b-socket-free-test-key";
const SUBJECT: &str = "subject-for-socket-free-tests";
const ACCOUNT_ID: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
const DEVICE_ID: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
const OTHER_DEVICE_ID: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);
const FAMILY_ID: Uuid = Uuid::from_u128(0x4444_4444_4444_4444_8444_4444_4444_4444);

// RFC 7520 section 3.4 test key. It is test-only and never selected by production code.
const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4
rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwG
U/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpP
e7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw
OHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixo
R7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJK
Rn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW7
0PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+
Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxw
TgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVk
wZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnD
qQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9
nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQn
ev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2
dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwW
mtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoB
vyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL
2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E5
2IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYeg
mnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWce
TU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBi
At4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9
XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQ
SgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg
1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO
-----END RSA PRIVATE KEY-----";

const RSA_MODULUS: &str = concat!(
    "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT",
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV",
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-",
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde",
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC",
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g",
    "HdrNP5zw"
);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum OidcFault {
    #[default]
    None,
    BadIssuer,
    BadAudience,
    BadNonce,
    Expired,
    BadSignature,
    DuplicateKey,
    DiscoveryIssuer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PollOutcome {
    Pending,
    SlowDown,
    Success,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Default)]
struct RuntimeState {
    now: u64,
    random_counter: u8,
    sleeps: Vec<Duration>,
    cancelled: bool,
    cancel_on_sleep: Option<usize>,
}

#[derive(Clone)]
struct FakeRuntime(Arc<Mutex<RuntimeState>>);

impl FakeRuntime {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(RuntimeState {
            now: NOW,
            ..RuntimeState::default()
        })))
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.0.lock().unwrap().sleeps.clone()
    }

    fn cancel_on_sleep(&self, number: usize) {
        self.0.lock().unwrap().cancel_on_sleep = Some(number);
    }
}

impl AccountRuntime for FakeRuntime {
    fn now_unix(&self) -> u64 {
        self.0.lock().unwrap().now
    }

    fn fill_random(&self, output: &mut [u8]) -> AccountResult<()> {
        let mut state = self.0.lock().unwrap();
        let seed = state.random_counter;
        state.random_counter = state.random_counter.wrapping_add(1);
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = seed.wrapping_add(u8::try_from(index).unwrap_or(u8::MAX));
        }
        Ok(())
    }

    fn sleep(&self, duration: Duration) {
        let mut state = self.0.lock().unwrap();
        state.sleeps.push(duration);
        state.now = state.now.saturating_add(duration.as_secs());
        if state.cancel_on_sleep == Some(state.sleeps.len()) {
            state.cancelled = true;
        }
    }

    fn cancelled(&self) -> bool {
        self.0.lock().unwrap().cancelled
    }
}

#[derive(Default)]
struct PlaneState {
    offline: bool,
    oidc_fault: OidcFault,
    polls: VecDeque<PollOutcome>,
    device_nonce: Option<String>,
    current_refresh: Option<String>,
    consumed_refreshes: BTreeSet<String>,
    generation: u64,
    revoked: bool,
    operations: Vec<AccountEndpoint>,
    request_bodies: Vec<Vec<u8>>,
    revoked_devices: BTreeSet<Uuid>,
}

#[derive(Clone, Default)]
struct FakeControlPlane(Arc<Mutex<PlaneState>>);

impl FakeControlPlane {
    fn set_oidc_fault(&self, fault: OidcFault) {
        self.0.lock().unwrap().oidc_fault = fault;
    }

    fn set_polls(&self, polls: impl IntoIterator<Item = PollOutcome>) {
        self.0.lock().unwrap().polls = polls.into_iter().collect();
    }

    fn set_offline(&self, offline: bool) {
        self.0.lock().unwrap().offline = offline;
    }

    fn operations(&self) -> Vec<AccountEndpoint> {
        self.0.lock().unwrap().operations.clone()
    }

    fn captured_contains(&self, canary: &str) -> bool {
        self.0.lock().unwrap().request_bodies.iter().any(|body| {
            body.windows(canary.len())
                .any(|window| window == canary.as_bytes())
        })
    }
}

impl AccountTransport for FakeControlPlane {
    #[allow(clippy::too_many_lines)]
    fn send(&self, request: WireRequest, _deadline_unix: u64) -> AccountResult<WireResponse> {
        request.validate()?;
        let endpoint = request.endpoint().clone();
        let body = request.body().to_vec();
        let mut state = self.0.lock().unwrap();
        state.operations.push(endpoint.clone());
        state.request_bodies.push(body.clone());
        if state.offline {
            return Err(AccountError::Offline);
        }
        let body = parse_body(&body)?;

        match endpoint {
            AccountEndpoint::ExchangePkce => {
                require_string(&body, "client_id", CLIENT_ID)?;
                require_bounded_secret(&body, "code")?;
                require_bounded_secret(&body, "code_verifier")?;
                let nonce = require_bounded_secret(&body, "nonce")?;
                let redirect = body
                    .get("redirect_uri")
                    .and_then(Value::as_str)
                    .and_then(|value| Url::parse(value).ok())
                    .ok_or(AccountError::InvalidResponse)?;
                if redirect.scheme() != "http" || redirect.host_str() != Some("127.0.0.1") {
                    return Err(AccountError::InvalidResponse);
                }
                state.generation = 0;
                state.revoked = false;
                state.consumed_refreshes.clear();
                session_response(&mut state, &nonce)
            }
            AccountEndpoint::BeginDeviceAuthorization => {
                require_string(&body, "client_id", CLIENT_ID)?;
                let nonce = require_bounded_secret(&body, "nonce")?;
                state.device_nonce = Some(nonce);
                response_json(
                    200,
                    &json!({
                        "device_code": "device-code-for-socket-free-tests-00000001",
                        "user_code": "DX05-B",
                        "verification_uri": format!("{ACCOUNT_ORIGIN}activate"),
                        "expires_at": NOW + 120,
                        "interval_seconds": 2
                    }),
                )
            }
            AccountEndpoint::PollDeviceAuthorization => {
                require_string(&body, "client_id", CLIENT_ID)?;
                require_string(
                    &body,
                    "device_code",
                    "device-code-for-socket-free-tests-00000001",
                )?;
                match state.polls.pop_front().unwrap_or(PollOutcome::Success) {
                    PollOutcome::Pending => error_response("authorization_pending"),
                    PollOutcome::SlowDown => error_response("slow_down"),
                    PollOutcome::Denied => error_response("access_denied"),
                    PollOutcome::Expired => error_response("expired_token"),
                    PollOutcome::Cancelled => error_response("cancelled"),
                    PollOutcome::Success => {
                        let nonce = state
                            .device_nonce
                            .clone()
                            .ok_or(AccountError::InvalidResponse)?;
                        state.generation = 0;
                        state.revoked = false;
                        state.consumed_refreshes.clear();
                        session_response(&mut state, &nonce)
                    }
                }
            }
            AccountEndpoint::Refresh => {
                require_string(&body, "client_id", CLIENT_ID)?;
                let supplied = require_bounded_secret(&body, "refresh_token")?;
                let nonce = require_bounded_secret(&body, "nonce")?;
                if state.consumed_refreshes.contains(&supplied) {
                    state.revoked = true;
                    return response_json(400, &json!({"error": "token_reuse"}));
                }
                if state.revoked {
                    return response_json(400, &json!({"error": "session_revoked"}));
                }
                if state.current_refresh.as_deref() != Some(supplied.as_str()) {
                    return response_json(400, &json!({"error": "invalid_grant"}));
                }
                state.consumed_refreshes.insert(supplied);
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or(AccountError::InvalidResponse)?;
                session_response(&mut state, &nonce)
            }
            AccountEndpoint::RevokeTokenFamily => {
                require_bearer(&request)?;
                state.revoked = true;
                empty_response(204)
            }
            AccountEndpoint::GetAccount => {
                require_bearer(&request)?;
                if state.revoked {
                    response_json(401, &json!({"error": "session_revoked"}))
                } else {
                    response_json(200, &json!({"account_id": ACCOUNT_ID}))
                }
            }
            AccountEndpoint::BeginExternalIdentityLink => {
                require_bearer(&request)?;
                require_bounded_secret(&body, "provider")?;
                response_json(
                    202,
                    &json!({
                        "verification_uri": format!("{ACCOUNT_ORIGIN}external-identities/verify"),
                        "expires_at": NOW + 120
                    }),
                )
            }
            AccountEndpoint::ListExternalIdentities => {
                require_bearer(&request)?;
                response_json(
                    200,
                    &json!({
                        "external_identities": [{
                            "external_identity_id": "55555555-5555-4555-8555-555555555555",
                            "issuer": ISSUER,
                            "linked_at": NOW - 10
                        }]
                    }),
                )
            }
            AccountEndpoint::UnlinkExternalIdentity(_) => {
                require_bearer(&request)?;
                empty_response(204)
            }
            AccountEndpoint::ListDevices => {
                require_bearer(&request)?;
                response_json(
                    200,
                    &json!({
                        "devices": [
                            {
                                "device_id": DEVICE_ID,
                                "label": "Socket-free test laptop",
                                "platform": "macos",
                                "created_at": NOW - 100,
                                "last_seen_at": NOW,
                                "revoked": state.revoked_devices.contains(&DEVICE_ID)
                            },
                            {
                                "device_id": OTHER_DEVICE_ID,
                                "label": "Socket-free test runner",
                                "platform": "linux",
                                "created_at": NOW - 80,
                                "last_seen_at": NOW - 10,
                                "revoked": state.revoked_devices.contains(&OTHER_DEVICE_ID)
                            }
                        ]
                    }),
                )
            }
            AccountEndpoint::RevokeDevice(device_id) => {
                require_bearer(&request)?;
                state.revoked_devices.insert(device_id);
                empty_response(204)
            }
            AccountEndpoint::CompleteExternalIdentityLink | AccountEndpoint::ListAuditEvents => {
                Err(AccountError::UnsafeRequest)
            }
        }
    }

    fn get_oidc_document(
        &self,
        kind: OidcDocument,
        url: &Url,
        _deadline_unix: u64,
    ) -> AccountResult<WireResponse> {
        let state = self.0.lock().unwrap();
        if state.offline {
            return Err(AccountError::Offline);
        }
        match kind {
            OidcDocument::Discovery => {
                if url.as_str() != "https://issuer.example.invalid/.well-known/openid-configuration"
                {
                    return Err(AccountError::UnsafeRequest);
                }
                let issuer = if state.oidc_fault == OidcFault::DiscoveryIssuer {
                    "https://attacker.invalid/"
                } else {
                    ISSUER
                };
                response_json(
                    200,
                    &json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{ISSUER}authorize"),
                        "jwks_uri": format!("{ISSUER}jwks"),
                        "id_token_signing_alg_values_supported": ["RS256"]
                    }),
                )
            }
            OidcDocument::Jwks => {
                if url.as_str() != "https://issuer.example.invalid/jwks" {
                    return Err(AccountError::UnsafeRequest);
                }
                let key = json!({
                    "kty": "RSA",
                    "kid": KEY_ID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": RSA_MODULUS,
                    "e": "AQAB"
                });
                let keys = if state.oidc_fault == OidcFault::DuplicateKey {
                    vec![key.clone(), key]
                } else {
                    vec![key]
                };
                response_json(200, &json!({"keys": keys}))
            }
        }
    }
}

fn parse_body(body: &[u8]) -> AccountResult<Value> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body).map_err(|_| AccountError::InvalidResponse)
    }
}

fn require_string(body: &Value, field: &str, expected: &str) -> AccountResult<()> {
    if body.get(field).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(AccountError::InvalidResponse)
    }
}

fn require_bounded_secret(body: &Value, field: &str) -> AccountResult<String> {
    let value = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AccountError::InvalidResponse)?;
    if (1..=4096).contains(&value.len())
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        Ok(value.to_owned())
    } else {
        Err(AccountError::InvalidResponse)
    }
}

fn require_bearer(request: &WireRequest) -> AccountResult<()> {
    if request
        .bearer_token()
        .is_some_and(|token| token.len() >= 32)
    {
        Ok(())
    } else {
        Err(AccountError::InvalidResponse)
    }
}

fn error_response(error: &str) -> AccountResult<WireResponse> {
    response_json(400, &json!({"error": error}))
}

fn empty_response(status: u16) -> AccountResult<WireResponse> {
    WireResponse::new(status, Vec::new())
}

fn response_json(status: u16, value: &Value) -> AccountResult<WireResponse> {
    let body = serde_json::to_vec(value).map_err(|_| AccountError::InvalidResponse)?;
    WireResponse::new(status, body)
}

fn session_response(state: &mut PlaneState, nonce: &str) -> AccountResult<WireResponse> {
    let refresh = format!("refresh-token-generation-{:016}", state.generation);
    state.current_refresh = Some(refresh.clone());
    let id_token = sign_id_token(nonce, state.oidc_fault)?;
    response_json(
        200,
        &json!({
            "token_type": "Bearer",
            "access_token": format!("access-token-generation-{:016}", state.generation),
            "refresh_token": refresh,
            "id_token": id_token,
            "expires_in": 300,
            "account_id": ACCOUNT_ID,
            "device_id": DEVICE_ID,
            "token_family_id": FAMILY_ID,
            "refresh_generation": state.generation
        }),
    )
}

fn sign_id_token(nonce: &str, fault: OidcFault) -> AccountResult<String> {
    let issuer = if fault == OidcFault::BadIssuer {
        "https://attacker.invalid/"
    } else {
        ISSUER
    };
    let audience = if fault == OidcFault::BadAudience {
        "attacker-audience"
    } else {
        AUDIENCE
    };
    let nonce = if fault == OidcFault::BadNonce {
        "wrong-nonce-for-socket-free-test"
    } else {
        nonce
    };
    let exp = if fault == OidcFault::Expired {
        NOW - 1
    } else {
        NOW + 300
    };
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg": "RS256", "kid": KEY_ID, "typ": "JWT"}))
            .map_err(|_| AccountError::InvalidResponse)?,
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer,
            "aud": audience,
            "azp": CLIENT_ID,
            "sub": SUBJECT,
            "exp": exp,
            "iat": NOW - 1,
            "nonce": nonce
        }))
        .map_err(|_| AccountError::InvalidResponse)?,
    );
    let signing_input = format!("{header}.{claims}");
    let encoded = TEST_RSA_PRIVATE_KEY
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| AccountError::InvalidResponse)?;
    let key = RsaPrivateKey::from_pkcs1_der(&der).map_err(|_| AccountError::InvalidResponse)?;
    let mut signature = SigningKey::<sha2::Sha256>::new(key)
        .sign(signing_input.as_bytes())
        .to_vec();
    if fault == OidcFault::BadSignature {
        signature[0] ^= 1;
    }
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PkceFault {
    #[default]
    None,
    State,
    Redirect,
    Denied,
}

#[derive(Default)]
struct FakePkceInteraction {
    fault: PkceFault,
    authorization_url: Mutex<Option<Url>>,
}

impl FakePkceInteraction {
    fn with_fault(fault: PkceFault) -> Self {
        Self {
            fault,
            authorization_url: Mutex::new(None),
        }
    }

    fn authorization_url(&self) -> Url {
        self.authorization_url.lock().unwrap().clone().unwrap()
    }
}

impl PkceInteraction for FakePkceInteraction {
    fn prepare_redirect(&self, callback_path: &str) -> AccountResult<Url> {
        Url::parse(&format!("http://127.0.0.1:49152{callback_path}"))
            .map_err(|_| AccountError::InteractionUnavailable)
    }

    fn authorize(
        &self,
        authorization_url: &Url,
        deadline_unix: u64,
        runtime: &dyn AccountRuntime,
    ) -> AccountResult<PkceCallback> {
        if deadline_unix <= runtime.now_unix() {
            return Err(AccountError::DeadlineExceeded);
        }
        *self.authorization_url.lock().unwrap() = Some(authorization_url.clone());
        if self.fault == PkceFault::Denied {
            return Err(AccountError::AuthorizationDenied);
        }
        let state = authorization_url
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or(AccountError::InvalidPkceCallback)?;
        let state = if self.fault == PkceFault::State {
            "wrong-state-for-socket-free-test".to_owned()
        } else {
            state
        };
        let redirect_uri = if self.fault == PkceFault::Redirect {
            Url::parse("http://127.0.0.1:49153/callback")
        } else {
            Url::parse("http://127.0.0.1:49152/callback")
        }
        .map_err(|_| AccountError::InvalidPkceCallback)?;
        Ok(PkceCallback {
            redirect_uri,
            code: SecretString::new("authorization-code-for-socket-free-tests-0001".to_owned()),
            state: SecretString::new(state),
        })
    }
}

#[derive(Default)]
struct FakeDeviceInteraction(Mutex<Vec<DeviceAuthorizationPrompt>>);

impl DeviceInteraction for FakeDeviceInteraction {
    fn display(&self, prompt: &DeviceAuthorizationPrompt) -> AccountResult<()> {
        self.0.lock().unwrap().push(prompt.clone());
        Ok(())
    }
}

#[derive(Default)]
struct FakeLinkInteraction(Mutex<Vec<Url>>);

impl LinkInteraction for FakeLinkInteraction {
    fn open(&self, verification_uri: &Url) -> AccountResult<()> {
        self.0.lock().unwrap().push(verification_uri.clone());
        Ok(())
    }
}

type TestClient =
    AccountClient<FakeControlPlane, FakeCredentialStore, ProcessRefreshLock, FakeRuntime>;

fn fixture() -> (TestClient, FakeControlPlane, FakeRuntime) {
    let transport = FakeControlPlane::default();
    let runtime = FakeRuntime::new();
    let config = AccountClientConfig::new(
        Url::parse(ACCOUNT_ORIGIN).unwrap(),
        Url::parse(ISSUER).unwrap(),
        AUDIENCE.to_owned(),
        CLIENT_ID.to_owned(),
        "/callback".to_owned(),
    )
    .unwrap();
    let client = AccountClient::new(
        config,
        transport.clone(),
        FakeCredentialStore::empty(),
        ProcessRefreshLock::default(),
        runtime.clone(),
    )
    .unwrap();
    (client, transport, runtime)
}

fn display() -> DeviceDisplay {
    DeviceDisplay {
        product_name: "Kaleidoscope".to_owned(),
        device_label: "Socket-free test laptop".to_owned(),
        platform: DevicePlatform::Macos,
        application_version: "0.1.0-test".to_owned(),
    }
}

fn login(client: &TestClient) {
    client
        .login_pkce(&FakePkceInteraction::default(), &display())
        .unwrap();
}

#[test]
fn signed_out_status_is_local_closed_and_credential_free() {
    let (client, transport, _) = fixture();
    let status = client.status().unwrap();
    assert_eq!(status.version, 1);
    assert_eq!(status.state, AccountState::SignedOut);
    assert_eq!(status.account_id, None);
    assert_eq!(status.device_id, None);
    assert!(!status.stale);
    assert!(client.credential_store().snapshot().is_none());
    assert!(transport.operations().is_empty());
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        json!({
            "version": 1,
            "state": "signed_out",
            "account_id": null,
            "device_id": null,
            "stale": false
        })
    );
}

#[test]
fn pkce_login_status_refresh_and_redaction_are_end_to_end() {
    let (client, transport, _) = fixture();
    let interaction = FakePkceInteraction::default();
    let result = client.login_pkce(&interaction, &display()).unwrap();
    assert_eq!(result.account_id, ACCOUNT_ID);
    assert_eq!(result.device_id, DEVICE_ID);
    assert!(client.credential_store().snapshot().is_some());

    let authorization_url = interaction.authorization_url();
    let parameters = authorization_url.query_pairs().collect::<Vec<_>>();
    for expected in [
        ("response_type", "code"),
        ("code_challenge_method", "S256"),
        ("scope", "openid profile"),
    ] {
        assert!(
            parameters
                .iter()
                .any(|(key, value)| key == expected.0 && value == expected.1)
        );
    }
    assert!(parameters.iter().any(|(key, _)| key == "state"));
    assert!(parameters.iter().any(|(key, _)| key == "nonce"));
    assert!(parameters.iter().any(|(key, _)| key == "code_challenge"));

    let status = client.status().unwrap();
    assert_eq!(status.state, AccountState::Online);
    assert!(!status.stale);
    let credential = client.credential_store().snapshot().unwrap();
    assert_eq!(credential.refresh_generation(), 1);

    let debug = format!("{credential:?}");
    assert!(!debug.contains("refresh-token-generation"));
    assert!(!format!("{:?}", transport.operations()).contains("access-token"));
}

#[test]
fn oidc_issuer_audience_nonce_expiry_signature_and_jwk_fail_closed() {
    for fault in [
        OidcFault::BadIssuer,
        OidcFault::BadAudience,
        OidcFault::BadNonce,
        OidcFault::Expired,
        OidcFault::BadSignature,
        OidcFault::DuplicateKey,
        OidcFault::DiscoveryIssuer,
    ] {
        let (client, transport, _) = fixture();
        transport.set_oidc_fault(fault);
        assert_eq!(
            client
                .login_pkce(&FakePkceInteraction::default(), &display())
                .unwrap_err(),
            AccountError::OidcVerification,
            "fault {fault:?} did not fail closed"
        );
        assert!(client.credential_store().snapshot().is_none());
    }
}

#[test]
fn pkce_state_redirect_and_denial_fail_before_session_publish() {
    for (fault, expected) in [
        (PkceFault::State, AccountError::InvalidPkceCallback),
        (PkceFault::Redirect, AccountError::InvalidPkceCallback),
        (PkceFault::Denied, AccountError::AuthorizationDenied),
    ] {
        let (client, _, _) = fixture();
        assert_eq!(
            client
                .login_pkce(&FakePkceInteraction::with_fault(fault), &display())
                .unwrap_err(),
            expected
        );
        assert!(client.credential_store().snapshot().is_none());
    }
}

#[test]
fn device_pending_slow_down_success_and_terminal_states_are_bounded() {
    let (client, transport, runtime) = fixture();
    transport.set_polls([
        PollOutcome::Pending,
        PollOutcome::SlowDown,
        PollOutcome::Success,
    ]);
    let interaction = FakeDeviceInteraction::default();
    client.login_device(&interaction, &display()).unwrap();
    assert_eq!(
        runtime.sleeps(),
        [
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(7),
        ]
    );
    assert_eq!(interaction.0.lock().unwrap().len(), 1);

    for (outcome, expected) in [
        (PollOutcome::Denied, AccountError::AuthorizationDenied),
        (
            PollOutcome::Expired,
            AccountError::DeviceAuthorizationExpired,
        ),
        (PollOutcome::Cancelled, AccountError::Cancelled),
    ] {
        let (client, transport, _) = fixture();
        transport.set_polls([outcome]);
        assert_eq!(
            client
                .login_device(&FakeDeviceInteraction::default(), &display())
                .unwrap_err(),
            expected
        );
    }

    let (client, transport, runtime) = fixture();
    transport.set_polls([PollOutcome::Success]);
    runtime.cancel_on_sleep(1);
    assert_eq!(
        client
            .login_device(&FakeDeviceInteraction::default(), &display())
            .unwrap_err(),
        AccountError::Cancelled
    );
}

#[test]
fn rotated_refresh_reuse_revokes_family_and_deletes_local_credential() {
    let (client, _, _) = fixture();
    login(&client);
    let stale = client.credential_store().snapshot().unwrap();
    assert_eq!(client.status().unwrap().state, AccountState::Online);
    client.credential_store().save(&stale).unwrap();
    let status = client.status().unwrap();
    assert_eq!(status.state, AccountState::Revoked);
    assert!(client.credential_store().snapshot().is_none());
}

#[test]
fn link_unlink_devices_revoke_and_logout_have_closed_results() {
    let (client, transport, _) = fixture();
    login(&client);
    let link_interaction = FakeLinkInteraction::default();
    let linked = client.link("github", &link_interaction).unwrap();
    assert_eq!(linked.status, "fresh_auth_required");
    assert_eq!(link_interaction.0.lock().unwrap().len(), 1);

    let external_identity = Uuid::from_u128(0x5555_5555_5555_4555_8555_5555_5555_5555);
    let identities = client.external_identities().unwrap();
    assert_eq!(identities.version, 1);
    assert_eq!(identities.external_identities.len(), 1);
    assert_eq!(
        identities.external_identities[0].external_identity_id,
        external_identity
    );
    assert_eq!(
        client
            .unlink(external_identity)
            .unwrap()
            .external_identity_id,
        external_identity
    );
    assert_eq!(client.devices().unwrap().devices.len(), 2);
    assert_eq!(
        client.revoke_device(OTHER_DEVICE_ID).unwrap().device_id,
        OTHER_DEVICE_ID
    );

    let logout = client
        .logout(
            LogoutScope::AllDevices,
            LocalLogoutPolicy::RequireRemoteRevocation,
        )
        .unwrap();
    assert_eq!(logout.status, "all_devices_revoked");
    assert!(logout.remote_revoked);
    assert!(logout.local_credential_removed);
    assert!(client.credential_store().snapshot().is_none());
    assert!(
        transport
            .operations()
            .contains(&AccountEndpoint::RevokeTokenFamily)
    );
}

#[test]
fn offline_logout_preserves_remote_credential_unless_local_only_is_explicit() {
    let (client, transport, _) = fixture();
    login(&client);
    transport.set_offline(true);
    assert_eq!(
        client
            .logout(
                LogoutScope::CurrentSession,
                LocalLogoutPolicy::RequireRemoteRevocation,
            )
            .unwrap_err(),
        AccountError::RemoteRevocationUnconfirmed
    );
    assert!(client.credential_store().snapshot().is_some());
    let result = client
        .logout(
            LogoutScope::CurrentSession,
            LocalLogoutPolicy::ConfirmedLocalOnly,
        )
        .unwrap();
    assert!(!result.remote_revoked);
    assert!(result.warning.is_some());
    assert!(client.credential_store().snapshot().is_none());
}

#[test]
fn store_publish_failure_revokes_remote_and_privacy_canaries_never_cross_transport() {
    let (client, transport, _) = fixture();
    client.credential_store().fail_next_save();
    assert_eq!(
        client
            .login_pkce(&FakePkceInteraction::default(), &display())
            .unwrap_err(),
        AccountError::CredentialStoreFailure
    );
    assert!(
        transport
            .operations()
            .contains(&AccountEndpoint::RevokeTokenFamily)
    );
    for canary in [
        "MEMORY-CONTENT-CANARY",
        "QUERY-RESULT-CANARY",
        "mem_01_canary",
        concat!("/", "Users", "/canary/private/vault"),
        "wsp_canary",
        "usr_canary",
        "journal:canary",
    ] {
        assert!(!transport.captured_contains(canary));
    }
}
