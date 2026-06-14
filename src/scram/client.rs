//! Proxy-as-SCRAM-client: reauthenticate to the backend reusing the `ClientKey`
//! recovered during client termination.
//!
//! The proxy already forwarded the `StartupMessage`, so the backend responds
//! with `AuthenticationSASL`. We run a normal SCRAM-SHA-256 client exchange, but
//! instead of deriving keys from a password we reuse [`ScramKeys`] — valid
//! because the client computed its proof against the backend's own salt
//! (presented by the server side via the same verifier). Afterwards the proxy's
//! startup splice relays `AuthenticationOk` … `ReadyForQuery` to the client.

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use bytes::{BufMut, BytesMut};
use rama::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::crypto::{self, ScramKeys};
use crate::protocol::codec::{self, RawMessage, read_message};

const MECHANISM: &str = "SCRAM-SHA-256";

// Authentication sub-types.
const AUTH_SASL: i32 = 10;
const AUTH_SASL_CONTINUE: i32 = 11;
const AUTH_SASL_FINAL: i32 = 12;

/// Drive a SCRAM-SHA-256 client exchange against `backend`, reusing `keys`.
///
/// Consumes the backend's `AuthenticationSASL`/`SASLContinue`/`SASLFinal`; on
/// return the next backend message is `AuthenticationOk`, ready for the proxy's
/// startup splice.
pub async fn reauth_upstream<B>(backend: &mut B, keys: &ScramKeys) -> Result<(), BoxError>
where
    B: AsyncRead + AsyncWrite + Unpin,
{
    // 1. AuthenticationSASL — the backend must offer SCRAM-SHA-256.
    let sasl = read_message(backend).await?;
    expect_auth(&sasl, AUTH_SASL, "AuthenticationSASL")?;
    let mechanisms = parse_mechanisms(&sasl.payload()[4..]);
    if !mechanisms.iter().any(|m| m == MECHANISM) {
        return Err(format!("backend did not offer SCRAM-SHA-256 (offered {mechanisms:?})").into());
    }

    // 2. SASLInitialResponse with our client-first-message. The username is left
    // empty (`n=`) — the backend uses the StartupMessage user.
    let client_nonce = crypto::random_nonce();
    let client_first_bare = format!("n=,r={client_nonce}");
    let client_first = format!("n,,{client_first_bare}");
    backend
        .write_all(&sasl_initial_response(MECHANISM, client_first.as_bytes()))
        .await?;
    backend.flush().await?;

    // 3. AuthenticationSASLContinue — server-first-message.
    let cont = read_message(backend).await?;
    expect_auth(&cont, AUTH_SASL_CONTINUE, "AuthenticationSASLContinue")?;
    let server_first = std::str::from_utf8(&cont.payload()[4..])?.to_owned();
    let server_nonce = field(&server_first, "r=").ok_or("backend server-first missing r=")?;
    if !server_nonce.starts_with(&client_nonce) {
        return Err("backend server nonce does not extend client nonce".into());
    }

    // 4. SASLResponse with our client-final-message, proof from the reused keys.
    let channel_binding = BASE64_STANDARD.encode("n,,");
    let without_proof = format!("c={channel_binding},r={server_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let client_signature = crypto::hmac_sha256(&keys.stored_key, auth_message.as_bytes());
    let proof = crypto::client_proof(&keys.client_key, &client_signature);
    let client_final = format!("{without_proof},p={}", BASE64_STANDARD.encode(proof));
    backend
        .write_all(&sasl_response(client_final.as_bytes()))
        .await?;
    backend.flush().await?;

    // 5. AuthenticationSASLFinal — verify the backend's server signature.
    let final_msg = read_message(backend).await?;
    expect_auth(&final_msg, AUTH_SASL_FINAL, "AuthenticationSASLFinal")?;
    let server_final = std::str::from_utf8(&final_msg.payload()[4..])?;
    let server_sig = field(server_final, "v=").ok_or("backend SASLFinal missing v=")?;
    let expected = crypto::hmac_sha256(&keys.server_key, auth_message.as_bytes());
    if BASE64_STANDARD.decode(server_sig)? != expected {
        return Err("backend server signature verification failed".into());
    }

    Ok(())
}

/// Build a frontend `SASLInitialResponse`: mechanism cstring, `Int32` length,
/// then the client-first-message.
fn sasl_initial_response(mechanism: &str, client_first: &[u8]) -> BytesMut {
    let mut body = BytesMut::new();
    body.extend_from_slice(mechanism.as_bytes());
    body.put_u8(0);
    body.put_i32(client_first.len() as i32);
    body.extend_from_slice(client_first);
    codec::frame(codec::PASSWORD_MESSAGE, &body)
}

/// Build a frontend `SASLResponse` carrying the client-final-message.
fn sasl_response(client_final: &[u8]) -> BytesMut {
    codec::frame(codec::PASSWORD_MESSAGE, client_final)
}

fn expect_auth(msg: &RawMessage, subtype: i32, what: &str) -> Result<(), BoxError> {
    if msg.tag() != codec::AUTHENTICATION {
        return Err(format!("backend: expected {what}, got tag {:?}", msg.tag() as char).into());
    }
    let payload = msg.payload();
    if payload.len() < 4 || i32::from_be_bytes(payload[..4].try_into().unwrap()) != subtype {
        return Err(format!("backend: expected {what} (auth sub-type {subtype})").into());
    }
    Ok(())
}

/// The SASL mechanism list in an `AuthenticationSASL` payload: cstrings
/// terminated by an empty one.
fn parse_mechanisms(mut data: &[u8]) -> Vec<String> {
    let mut mechanisms = Vec::new();
    while let Some(nul) = data.iter().position(|&b| b == 0) {
        if nul == 0 {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&data[..nul]) {
            mechanisms.push(name.to_owned());
        }
        data = &data[nul + 1..];
    }
    mechanisms
}

/// Find a comma-separated SCRAM attribute (e.g. `r=`, `v=`) and return its value.
fn field<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    message.split(',').find_map(|f| f.strip_prefix(prefix))
}
