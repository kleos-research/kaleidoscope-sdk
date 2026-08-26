use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs1v15;
use rsa::pss;
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use sha2::{Sha256, Sha384, Sha512};
use url::Url;

use super::error::{AccountError, AccountResult};
use super::protocol::{
    AccountClientConfig, AccountTransport, MAX_OIDC_DOCUMENT_BYTES, OidcDocument, WireResponse,
};
use super::secret::SecretString;

const MAX_COMPACT_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWT_PART_BYTES: usize = 12 * 1024;
const CLOCK_SKEW_SECONDS: u64 = 60;

pub(crate) struct ValidatedProvider {
    discovery: DiscoveryDocument,
    jwks: JwkSet,
}

impl ValidatedProvider {
    pub(crate) fn discover(
        config: &AccountClientConfig,
        transport: &dyn AccountTransport,
        deadline_unix: u64,
    ) -> AccountResult<Self> {
        let discovery_url = discovery_url(&config.issuer)?;
        config.validate_oidc_url(&discovery_url, false)?;
        let discovery_response =
            transport.get_oidc_document(OidcDocument::Discovery, &discovery_url, deadline_unix)?;
        let discovery: DiscoveryDocument = parse_document(&discovery_response)?;
        if discovery.issuer != config.issuer {
            return Err(AccountError::OidcVerification);
        }
        config.validate_oidc_url(&discovery.authorization_endpoint, true)?;
        config.validate_oidc_url(&discovery.jwks_uri, false)?;
        if discovery.id_token_signing_alg_values_supported.is_empty()
            || !discovery
                .id_token_signing_alg_values_supported
                .iter()
                .any(|algorithm| is_supported_algorithm(algorithm))
        {
            return Err(AccountError::OidcVerification);
        }

        let jwks_response =
            transport.get_oidc_document(OidcDocument::Jwks, &discovery.jwks_uri, deadline_unix)?;
        let jwks: JwkSet = parse_document(&jwks_response)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 100 {
            return Err(AccountError::OidcVerification);
        }
        Ok(Self { discovery, jwks })
    }

    pub(crate) const fn authorization_endpoint(&self) -> &Url {
        &self.discovery.authorization_endpoint
    }

    pub(crate) fn verify_id_token(
        &self,
        config: &AccountClientConfig,
        id_token: &SecretString,
        nonce: Option<&SecretString>,
        now_unix: u64,
    ) -> AccountResult<String> {
        let compact = id_token.expose();
        if compact.len() > MAX_COMPACT_TOKEN_BYTES || !compact.is_ascii() {
            return Err(AccountError::OidcVerification);
        }
        let mut parts = compact.split('.');
        let encoded_header = parts.next().ok_or(AccountError::OidcVerification)?;
        let encoded_claims = parts.next().ok_or(AccountError::OidcVerification)?;
        let encoded_signature = parts.next().ok_or(AccountError::OidcVerification)?;
        if parts.next().is_some()
            || encoded_header.is_empty()
            || encoded_claims.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(AccountError::OidcVerification);
        }

        let header: TokenHeader = decode_json_part(encoded_header)?;
        let claims: TokenClaims = decode_json_part(encoded_claims)?;
        let signature = decode_part(encoded_signature)?;
        if signature.len() > 1024
            || header.kid.is_empty()
            || header.kid.len() > 256
            || header.kid.chars().any(char::is_control)
            || header.crit.is_some()
            || header.typ.as_deref().is_some_and(|value| value != "JWT")
            || !self
                .discovery
                .id_token_signing_alg_values_supported
                .iter()
                .any(|algorithm| algorithm == &header.alg)
        {
            return Err(AccountError::OidcVerification);
        }
        if !is_supported_algorithm(&header.alg) {
            return Err(AccountError::OidcVerification);
        }
        let candidates = self
            .jwks
            .keys
            .iter()
            .filter(|key| key.kid == header.kid)
            .collect::<Vec<_>>();
        let [key] = candidates.as_slice() else {
            return Err(AccountError::OidcVerification);
        };
        if key.kty != "RSA"
            || key.use_.as_deref().is_some_and(|value| value != "sig")
            || key.alg.as_deref().is_some_and(|value| value != header.alg)
        {
            return Err(AccountError::OidcVerification);
        }
        let modulus = decode_jwk_component(&key.n)?;
        let exponent = decode_jwk_component(&key.e)?;
        let signing_input_length = encoded_header
            .len()
            .checked_add(encoded_claims.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(AccountError::OidcVerification)?;
        let signing_input = compact
            .get(..signing_input_length)
            .ok_or(AccountError::OidcVerification)?;
        let public_key = RsaPublicKey::new(
            BigUint::from_bytes_be(&modulus),
            BigUint::from_bytes_be(&exponent),
        )
        .map_err(|_| AccountError::OidcVerification)?;
        verify_rsa_signature(
            &header.alg,
            public_key,
            signing_input.as_bytes(),
            &signature,
        )?;

        validate_claims(config, claims, nonce, now_unix)
    }
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: Url,
    authorization_endpoint: Url,
    jwks_uri: Url,
    id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<RsaJwk>,
}

#[derive(Deserialize)]
struct RsaJwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct TokenHeader {
    alg: String,
    kid: String,
    typ: Option<String>,
    crit: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenClaims {
    iss: String,
    aud: AudienceClaim,
    azp: Option<String>,
    sub: String,
    exp: u64,
    iat: u64,
    nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

fn validate_claims(
    config: &AccountClientConfig,
    claims: TokenClaims,
    expected_nonce: Option<&SecretString>,
    now_unix: u64,
) -> AccountResult<String> {
    if claims.iss != config.issuer.as_str()
        || claims.sub.is_empty()
        || claims.sub.len() > 512
        || claims.sub.chars().any(char::is_control)
        || claims.exp <= now_unix
        || claims.iat > now_unix.saturating_add(CLOCK_SKEW_SECONDS)
        || claims.exp <= claims.iat
    {
        return Err(AccountError::OidcVerification);
    }

    let audiences = match claims.aud {
        AudienceClaim::One(audience) => vec![audience],
        AudienceClaim::Many(audiences) => audiences,
    };
    let distinct = audiences.iter().collect::<BTreeSet<_>>();
    if audiences.is_empty()
        || audiences.len() > 16
        || distinct.len() != audiences.len()
        || !audiences.iter().any(|value| value == &config.audience)
        || audiences
            .iter()
            .any(|value| value.is_empty() || value.len() > 512 || !value.is_ascii())
        || (audiences.len() > 1 && claims.azp.as_deref() != Some(config.public_client_id.as_str()))
        || claims
            .azp
            .as_deref()
            .is_some_and(|value| value != config.public_client_id)
    {
        return Err(AccountError::OidcVerification);
    }

    match (expected_nonce, claims.nonce) {
        (Some(expected), Some(actual)) => {
            let actual = SecretString::new(actual);
            if !actual.is_bounded_ascii() || !expected.constant_time_eq(&actual) {
                return Err(AccountError::OidcVerification);
            }
        }
        (Some(_), None) | (None, Some(_)) => return Err(AccountError::OidcVerification),
        (None, None) => {}
    }
    Ok(claims.sub)
}

fn discovery_url(issuer: &Url) -> AccountResult<Url> {
    let mut value = issuer.as_str().trim_end_matches('/').to_owned();
    value.push_str("/.well-known/openid-configuration");
    Url::parse(&value).map_err(|_| AccountError::OidcVerification)
}

fn parse_document<T: for<'de> Deserialize<'de>>(response: &WireResponse) -> AccountResult<T> {
    if response.status != 200 || response.body.len() > MAX_OIDC_DOCUMENT_BYTES {
        return Err(AccountError::OidcVerification);
    }
    serde_json::from_slice(&response.body).map_err(|_| AccountError::OidcVerification)
}

fn decode_json_part<T: for<'de> Deserialize<'de>>(value: &str) -> AccountResult<T> {
    let bytes = decode_part(value)?;
    serde_json::from_slice(&bytes).map_err(|_| AccountError::OidcVerification)
}

fn decode_part(value: &str) -> AccountResult<Vec<u8>> {
    if value.len() > MAX_JWT_PART_BYTES || value.contains('=') {
        return Err(AccountError::OidcVerification);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AccountError::OidcVerification)
}

fn decode_jwk_component(value: &str) -> AccountResult<Vec<u8>> {
    let bytes = decode_part(value)?;
    if bytes.is_empty() || bytes.len() > 1024 || bytes.first() == Some(&0) {
        return Err(AccountError::OidcVerification);
    }
    Ok(bytes)
}

fn is_supported_algorithm(value: &str) -> bool {
    matches!(
        value,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
    )
}

fn verify_rsa_signature(
    algorithm: &str,
    key: RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> AccountResult<()> {
    let valid = match algorithm {
        "RS256" => pkcs1v15::VerifyingKey::<Sha256>::new(key)
            .verify(
                message,
                &pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        "RS384" => pkcs1v15::VerifyingKey::<Sha384>::new(key)
            .verify(
                message,
                &pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        "RS512" => pkcs1v15::VerifyingKey::<Sha512>::new(key)
            .verify(
                message,
                &pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        "PS256" => pss::VerifyingKey::<Sha256>::new(key)
            .verify(
                message,
                &pss::Signature::try_from(signature).map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        "PS384" => pss::VerifyingKey::<Sha384>::new(key)
            .verify(
                message,
                &pss::Signature::try_from(signature).map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        "PS512" => pss::VerifyingKey::<Sha512>::new(key)
            .verify(
                message,
                &pss::Signature::try_from(signature).map_err(|_| AccountError::OidcVerification)?,
            )
            .is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AccountError::OidcVerification)
    }
}
