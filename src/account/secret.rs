use std::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// An ephemeral secret whose formatting is always redacted and whose backing
/// allocation is zeroized on drop.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.expose().as_bytes().ct_eq(other.expose().as_bytes()))
    }

    pub(crate) fn is_bounded_ascii(&self) -> bool {
        (32..=4096).contains(&self.0.len())
            && self.0.is_ascii()
            && !self.0.bytes().any(|byte| byte.is_ascii_whitespace())
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.expose().to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn formatting_never_exposes_secret_bytes() {
        let secret = SecretString::new("TOKEN-CANARY-DO-NOT-PRINT-123456".to_owned());
        assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
        assert_eq!(secret.to_string(), "<redacted>");
    }
}
