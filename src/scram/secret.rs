//! SCRAM verifiers and a pluggable, async store to fetch them.
//!
//! A [`ScramSecret`] is exactly what Postgres keeps in `pg_authid.rolpassword`:
//! `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`. It is *not* the
//! plaintext password — the proxy can verify a client and (reusing the client's
//! recovered `ClientKey`) reauthenticate upstream without ever holding it.
//!
//! [`ScramSecretStore`] resolves a secret from `(user, database, sni)`
//! asynchronously, so a real implementation can query `pg_authid` over a side
//! connection or hit a control plane. [`StaticSecretStore`] is the in-memory
//! implementation used for tests and simple deployments.

use std::collections::HashMap;
use std::future::Future;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use rama::error::BoxError;

use super::crypto::ScramKeys;

/// A SCRAM-SHA-256 verifier: the salt, iteration count, and the `StoredKey` /
/// `ServerKey` derived from the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramSecret {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl ScramSecret {
    /// Parse Postgres' textual verifier:
    /// `SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>`.
    pub fn parse(s: &str) -> Result<Self, BoxError> {
        let rest = s
            .strip_prefix("SCRAM-SHA-256$")
            .ok_or("scram secret: not a SCRAM-SHA-256 verifier")?;
        let (params, keys) = rest
            .split_once('$')
            .ok_or("scram secret: missing key section")?;
        let (iterations, salt) = params
            .split_once(':')
            .ok_or("scram secret: missing salt")?;
        let (stored_key, server_key) = keys
            .split_once(':')
            .ok_or("scram secret: missing server key")?;

        Ok(Self {
            iterations: iterations
                .parse()
                .map_err(|_| "scram secret: invalid iteration count")?,
            salt: BASE64_STANDARD.decode(salt)?,
            stored_key: decode_key(stored_key)?,
            server_key: decode_key(server_key)?,
        })
    }

    /// Build a verifier from a plaintext password (e.g. to seed a test backend
    /// or a config). Most deployments instead read the verifier from Postgres.
    pub fn from_password(password: &[u8], salt: Vec<u8>, iterations: u32) -> Self {
        let keys = ScramKeys::from_password(password, &salt, iterations);
        Self {
            iterations,
            salt,
            stored_key: keys.stored_key,
            server_key: keys.server_key,
        }
    }

    /// Render back to Postgres' textual verifier form.
    pub fn to_verifier_string(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            BASE64_STANDARD.encode(&self.salt),
            BASE64_STANDARD.encode(self.stored_key),
            BASE64_STANDARD.encode(self.server_key),
        )
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32], BoxError> {
    <[u8; 32]>::try_from(BASE64_STANDARD.decode(b64)?)
        .map_err(|_| "scram secret: key is not 32 bytes".into())
}

/// The key a [`ScramSecretStore`] resolves a verifier from. `user` and
/// `database` come from the StartupMessage; `sni` from the TLS handshake.
#[derive(Debug, Clone, Copy)]
pub struct SecretLookup<'a> {
    pub user: &'a str,
    pub database: Option<&'a str>,
    pub sni: Option<&'a str>,
}

/// A pluggable, async source of SCRAM verifiers.
pub trait ScramSecretStore: Send + Sync + 'static {
    /// Resolve the verifier for the given connection, or `None` if there is no
    /// such credential.
    fn get_secret(
        &self,
        lookup: SecretLookup<'_>,
    ) -> impl Future<Output = Result<Option<ScramSecret>, BoxError>> + Send;
}

/// An in-memory [`ScramSecretStore`] keyed by user name. Ignores `database` and
/// `sni`; a real store can route on all three.
#[derive(Debug, Clone, Default)]
pub struct StaticSecretStore {
    by_user: HashMap<String, ScramSecret>,
}

impl StaticSecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_secret(mut self, user: impl Into<String>, secret: ScramSecret) -> Self {
        self.by_user.insert(user.into(), secret);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.by_user.is_empty()
    }
}

impl ScramSecretStore for StaticSecretStore {
    async fn get_secret(
        &self,
        lookup: SecretLookup<'_>,
    ) -> Result<Option<ScramSecret>, BoxError> {
        Ok(self.by_user.get(lookup.user).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_string_round_trips() {
        let secret = ScramSecret::from_password(b"secret", b"0123456789abcdef".to_vec(), 4096);
        let parsed = ScramSecret::parse(&secret.to_verifier_string()).unwrap();
        assert_eq!(secret, parsed);
    }

    #[test]
    fn parses_postgres_style_verifier() {
        // Shape: SCRAM-SHA-256$<i>:<salt>$<stored>:<server>.
        let original = ScramSecret::from_password(b"pencil", b"some-16-byte-slt".to_vec(), 4096);
        let text = original.to_verifier_string();
        assert!(text.starts_with("SCRAM-SHA-256$4096:"));
        assert_eq!(text.matches('$').count(), 2);
        assert_eq!(ScramSecret::parse(&text).unwrap().iterations, 4096);
    }

    #[test]
    fn rejects_non_scram_verifier() {
        assert!(ScramSecret::parse("md5abc").is_err());
    }

    #[tokio::test]
    async fn static_store_resolves_by_user() {
        let secret = ScramSecret::from_password(b"secret", b"0123456789abcdef".to_vec(), 4096);
        let store = StaticSecretStore::new().with_secret("alice", secret.clone());

        let found = store
            .get_secret(SecretLookup {
                user: "alice",
                database: Some("shop"),
                sni: Some("db.example.com"),
            })
            .await
            .unwrap();
        assert_eq!(found, Some(secret));

        let missing = store
            .get_secret(SecretLookup {
                user: "bob",
                database: None,
                sni: None,
            })
            .await
            .unwrap();
        assert_eq!(missing, None);
    }
}
