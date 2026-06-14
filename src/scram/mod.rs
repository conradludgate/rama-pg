//! SCRAM-SHA-256 termination (RFC 5802 / RFC 7677).
//!
//! The proxy plays the SASL *server*: it offers `SCRAM-SHA-256`, runs the
//! four-message challenge/response against a static credential map, and on
//! success connects to the backend itself ([`ClientAuth::Terminated`]). The
//! backend's `AuthenticationOk` is then relayed to the client by the proxy's
//! startup splice, so this only supports a trust/already-satisfied backend for
//! now (proxy-to-backend reauth with the derived keys is future work).
//!
//! Channel binding (`SCRAM-SHA-256-PLUS`) is not offered, so the client's GS2
//! header must be `n,,` or `y,,`.
//!
//! Known simplifications: passwords are not SASLprep-normalised (fine for
//! ASCII), and unknown users are rejected without mock-authentication timing.

mod crypto;
mod secret;

pub use crypto::ScramKeys;
pub use secret::{ScramSecret, ScramSecretStore, SecretLookup, StaticSecretStore};

use std::collections::HashMap;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use rama::error::BoxError;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::auth::{Authenticator, ClientAuth};
use crate::protocol::codec::{self, read_message};
use crate::protocol::message;
use crate::protocol::startup::StartupMessage;

const MECHANISM: &str = "SCRAM-SHA-256";
const DEFAULT_ITERATIONS: u32 = 4096;
const NONCE_BYTES: usize = 18;
const SALT_BYTES: usize = 16;

/// SCRAM-SHA-256 authenticator backed by a static `user -> password` map.
#[derive(Debug, Clone, Default)]
pub struct ScramSha256 {
    credentials: HashMap<String, String>,
    iterations: u32,
}

impl ScramSha256 {
    pub fn new(credentials: HashMap<String, String>) -> Self {
        Self {
            credentials,
            iterations: DEFAULT_ITERATIONS,
        }
    }
}

impl Authenticator for ScramSha256 {
    async fn authenticate<IO>(
        &self,
        client: &mut IO,
        startup: &StartupMessage,
    ) -> Result<ClientAuth, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let user = startup.user().unwrap_or_default();

        // 1. Offer SCRAM-SHA-256.
        client
            .write_all(&message::authentication_sasl(&[MECHANISM]))
            .await?;
        client.flush().await?;

        // 2. SASLInitialResponse: mechanism + client-first-message.
        let initial = read_message(client).await?;
        if initial.tag() != codec::PASSWORD_MESSAGE {
            return Err(format!("scram: expected SASL response, got tag {:?}", initial.tag() as char).into());
        }
        let (mechanism, client_first) = parse_sasl_initial(initial.payload())?;
        if mechanism != MECHANISM {
            return self
                .deny(client, &format!("unsupported SASL mechanism {mechanism:?}"))
                .await;
        }
        let client_first = parse_client_first(&client_first)?;

        // 3. server-first-message with the combined nonce, salt, iteration count.
        let server_nonce = random_nonce();
        let full_nonce = format!("{}{server_nonce}", client_first.client_nonce);
        let salt = random_salt();
        let server_first = format!(
            "r={full_nonce},s={},i={}",
            BASE64_STANDARD.encode(salt),
            self.iterations,
        );
        client
            .write_all(&message::authentication_sasl_continue(server_first.as_bytes()))
            .await?;
        client.flush().await?;

        // 4. SASLResponse: client-final-message.
        let response = read_message(client).await?;
        if response.tag() != codec::PASSWORD_MESSAGE {
            return Err(format!("scram: expected SASL response, got tag {:?}", response.tag() as char).into());
        }
        let client_final = parse_client_final(std::str::from_utf8(response.payload())?)?;

        // The client must echo the full nonce and the GS2 header it committed to.
        if client_final.nonce != full_nonce {
            return self.deny(client, "scram: client nonce mismatch").await;
        }
        let channel_binding = BASE64_STANDARD.decode(&client_final.channel_binding)?;
        if channel_binding != client_first.gs2_header.as_bytes() {
            return self.deny(client, "scram: channel binding mismatch").await;
        }

        // 5. Verify the client proof against the stored password.
        let Some(password) = self.credentials.get(user) else {
            return self.deny(client, "scram: unknown user").await;
        };
        let keys = ScramKeys::from_password(password.as_bytes(), &salt, self.iterations);

        let auth_message = format!(
            "{},{server_first},{}",
            client_first.bare, client_final.without_proof
        );
        let client_signature = crypto::hmac_sha256(&keys.stored_key, auth_message.as_bytes());

        let proof = BASE64_STANDARD.decode(&client_final.proof)?;
        let Ok(proof) = <[u8; 32]>::try_from(proof) else {
            return self.deny(client, "scram: malformed client proof").await;
        };
        let recovered = crypto::recover_client_key(&proof, &client_signature);
        if !bool::from(crypto::sha256(&recovered).ct_eq(&keys.stored_key)) {
            return self.deny(client, "scram: client proof verification failed").await;
        }

        // 6. AuthenticationSASLFinal with the server signature, proving we hold
        // the same key material to the client.
        let server_signature = crypto::hmac_sha256(&keys.server_key, auth_message.as_bytes());
        let final_message = format!("v={}", BASE64_STANDARD.encode(server_signature));
        client
            .write_all(&message::authentication_sasl_final(final_message.as_bytes()))
            .await?;
        client.flush().await?;

        tracing::info!(user, "client authenticated (scram-sha-256, terminated)");
        Ok(ClientAuth::Terminated)
    }
}

impl ScramSha256 {
    /// Send a generic auth failure to the client and return an error. The detail
    /// is logged but masked from the client as `28P01`, matching Postgres.
    async fn deny<IO>(&self, client: &mut IO, detail: &str) -> Result<ClientAuth, BoxError>
    where
        IO: AsyncWrite + Unpin,
    {
        tracing::warn!(detail, "scram authentication failed");
        client
            .write_all(&message::fatal_error(
                "28P01",
                "password authentication failed",
            ))
            .await?;
        client.flush().await?;
        Err(detail.to_owned().into())
    }
}

/// Parsed `client-first-message`: the GS2 header (echoed back via channel
/// binding), the message-bare used in `AuthMessage`, and the client nonce.
struct ClientFirst {
    gs2_header: String,
    bare: String,
    client_nonce: String,
}

/// Parsed `client-final-message`: the base64 channel-binding (`c=`), the full
/// nonce (`r=`), the base64 client proof (`p=`), and the without-proof prefix
/// used in `AuthMessage`.
struct ClientFinal {
    channel_binding: String,
    nonce: String,
    proof: String,
    without_proof: String,
}

/// Parse a `SASLInitialResponse` payload: a mechanism cstring, an `Int32`
/// length, then the initial response bytes.
fn parse_sasl_initial(payload: &[u8]) -> Result<(String, Vec<u8>), BoxError> {
    let nul = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or("scram: missing mechanism terminator")?;
    let mechanism = std::str::from_utf8(&payload[..nul])?.to_owned();
    let rest = &payload[nul + 1..];
    if rest.len() < 4 {
        return Err("scram: truncated SASLInitialResponse".into());
    }
    // The Int32 length prefixes the initial response; we use the actual bytes.
    Ok((mechanism, rest[4..].to_vec()))
}

/// Parse `gs2-header + client-first-message-bare`. Rejects a `p` cbind flag
/// (channel binding required) since we only offer non-PLUS SCRAM.
fn parse_client_first(data: &[u8]) -> Result<ClientFirst, BoxError> {
    let s = std::str::from_utf8(data)?;
    if s.starts_with('p') {
        return Err("scram: channel binding requested but not supported".into());
    }
    // The GS2 header is `cbind-flag "," [authzid] ","` — up to the second comma.
    let mut commas = s.match_indices(',').map(|(i, _)| i);
    commas.next().ok_or("scram: malformed client-first (gs2 header)")?;
    let second = commas.next().ok_or("scram: malformed client-first (gs2 header)")?;

    let gs2_header = s[..=second].to_owned();
    let bare = s[second + 1..].to_owned();
    let client_nonce = bare
        .split(',')
        .find_map(|field| field.strip_prefix("r="))
        .ok_or("scram: missing client nonce")?
        .to_owned();

    Ok(ClientFirst {
        gs2_header,
        bare,
        client_nonce,
    })
}

/// Parse `c=...,r=...,p=...`, splitting off the proof to recover the
/// without-proof prefix.
fn parse_client_final(s: &str) -> Result<ClientFinal, BoxError> {
    let proof_at = s.rfind(",p=").ok_or("scram: missing client proof")?;
    let without_proof = s[..proof_at].to_owned();
    let proof = s[proof_at + 3..].to_owned();

    let mut channel_binding = None;
    let mut nonce = None;
    for field in without_proof.split(',') {
        if let Some(v) = field.strip_prefix("c=") {
            channel_binding = Some(v.to_owned());
        } else if let Some(v) = field.strip_prefix("r=") {
            nonce = Some(v.to_owned());
        }
    }

    Ok(ClientFinal {
        channel_binding: channel_binding.ok_or("scram: missing channel binding")?,
        nonce: nonce.ok_or("scram: missing nonce in client-final")?,
        proof,
        without_proof,
    })
}

fn random_salt() -> [u8; SALT_BYTES] {
    let mut salt = [0u8; SALT_BYTES];
    rand::fill(&mut salt[..]);
    salt
}

/// A printable, comma-free nonce (base64 has neither comma nor whitespace).
fn random_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::fill(&mut bytes[..]);
    BASE64_STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_client_first_with_y_flag() {
        // libpq over TLS sends a `y` cbind flag when the server offered no -PLUS.
        let cf = parse_client_first(b"y,,n=alice,r=abc123").unwrap();
        assert_eq!(cf.gs2_header, "y,,");
        assert_eq!(cf.bare, "n=alice,r=abc123");
        assert_eq!(cf.client_nonce, "abc123");
    }

    #[test]
    fn rejects_required_channel_binding() {
        assert!(parse_client_first(b"p=tls-server-end-point,,n=a,r=b").is_err());
    }
}
