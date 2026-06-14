//! Pluggable client authentication.
//!
//! An [`Authenticator`] runs whatever client-side handshake a mechanism needs
//! over the (TLS) client stream, then reports how the proxy should continue
//! toward the backend via [`ClientAuth`]:
//!
//! - [`ClientAuth::PassThrough`] — the proxy did not interpret auth; it forwards
//!   the `StartupMessage` and relays the exchange so the *backend* authenticates.
//! - [`ClientAuth::Terminated`] — the proxy authenticated the client itself and
//!   tells the proxy how to reach the backend ([`BackendAuth`]): a trust backend
//!   (just relay its startup completion) or SCRAM reauth with recovered keys.

use std::collections::HashMap;
use std::future::Future;

use rama::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::protocol::codec::{self, read_message};
use crate::protocol::message;
use crate::protocol::startup::StartupMessage;
use crate::scram::{ScramKeys, ScramSecretStore, ScramSha256, StaticSecretStore};

/// Connection facts an [`Authenticator`] may key on: the parsed startup
/// parameters and the TLS SNI.
#[derive(Debug, Clone, Copy)]
pub struct AuthContext<'a> {
    pub startup: &'a StartupMessage,
    pub sni: Option<&'a str>,
}

/// How the proxy should reach the backend after client authentication.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// Forward the StartupMessage and relay; the backend authenticates.
    PassThrough,
    /// The proxy authenticated the client; reach the backend this way.
    Terminated(BackendAuth),
}

/// How the proxy authenticates to the backend in terminate mode.
#[derive(Debug, Clone)]
pub enum BackendAuth {
    /// Backend needs no auth (trust): relay its startup completion.
    Trust,
    /// Reauthenticate to the backend via SCRAM, reusing the recovered keys.
    Scram(ScramKeys),
}

/// A pluggable client-authentication mechanism.
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticate the just-connected client, reading from / writing to
    /// `client` as the mechanism requires.
    fn authenticate<IO>(
        &self,
        client: &mut IO,
        ctx: &AuthContext<'_>,
    ) -> impl Future<Output = Result<ClientAuth, BoxError>> + Send
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send;
}

/// Transparent pass-through: the proxy does not interpret auth at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThrough;

impl Authenticator for PassThrough {
    async fn authenticate<IO>(
        &self,
        _client: &mut IO,
        _ctx: &AuthContext<'_>,
    ) -> Result<ClientAuth, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        Ok(ClientAuth::PassThrough)
    }
}

/// Cleartext-password termination: the proxy plays the auth server, asking the
/// client for a cleartext password (safe only over TLS, which the proxy
/// enforces) and checking it against a static credential map. On success the
/// proxy connects to a trust backend ([`BackendAuth::Trust`]).
#[derive(Debug, Clone, Default)]
pub struct CleartextPassword {
    credentials: HashMap<String, String>,
}

impl CleartextPassword {
    pub fn new(credentials: HashMap<String, String>) -> Self {
        Self { credentials }
    }
}

impl Authenticator for CleartextPassword {
    async fn authenticate<IO>(
        &self,
        client: &mut IO,
        ctx: &AuthContext<'_>,
    ) -> Result<ClientAuth, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client
            .write_all(&message::authentication_cleartext_password())
            .await?;
        client.flush().await?;

        let msg = read_message(client).await?;
        if msg.tag() != codec::PASSWORD_MESSAGE {
            return Err(format!(
                "expected PasswordMessage, got tag {:?}",
                msg.tag() as char
            )
            .into());
        }

        let user = ctx.startup.user().unwrap_or_default();
        let supplied = password_bytes(msg.payload());
        let accepted = self
            .credentials
            .get(user)
            .is_some_and(|expected| expected.as_bytes() == supplied);

        if accepted {
            tracing::info!(user, "client authenticated (cleartext, terminated)");
            Ok(ClientAuth::Terminated(BackendAuth::Trust))
        } else {
            tracing::warn!(user, "cleartext password authentication failed");
            client
                .write_all(&message::fatal_error(
                    "28P01",
                    "password authentication failed",
                ))
                .await?;
            client.flush().await?;
            Err("password authentication failed".into())
        }
    }
}

/// The password in a `PasswordMessage` payload, stripped of its terminating nul.
fn password_bytes(payload: &[u8]) -> &[u8] {
    match payload.iter().position(|&b| b == 0) {
        Some(nul) => &payload[..nul],
        None => payload,
    }
}

/// A runtime-selected authenticator, dispatching to a concrete mechanism. The
/// SCRAM variant is generic over the secret store (defaulting to the in-memory
/// [`StaticSecretStore`]).
#[derive(Debug, Clone)]
pub enum Auth<S = StaticSecretStore> {
    PassThrough(PassThrough),
    Cleartext(CleartextPassword),
    Scram(ScramSha256<S>),
}

impl<S: ScramSecretStore> Authenticator for Auth<S> {
    async fn authenticate<IO>(
        &self,
        client: &mut IO,
        ctx: &AuthContext<'_>,
    ) -> Result<ClientAuth, BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match self {
            Auth::PassThrough(a) => a.authenticate(client, ctx).await,
            Auth::Cleartext(a) => a.authenticate(client, ctx).await,
            Auth::Scram(a) => a.authenticate(client, ctx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::codec::frame;
    use crate::protocol::startup::PROTOCOL_VERSION_3_0;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn startup_for(user: &str) -> StartupMessage {
        StartupMessage {
            protocol_version: PROTOCOL_VERSION_3_0,
            parameters: vec![("user".to_owned(), user.to_owned())],
        }
    }

    fn alice_creds() -> CleartextPassword {
        let mut creds = HashMap::new();
        creds.insert("alice".to_owned(), "secret".to_owned());
        CleartextPassword::new(creds)
    }

    /// Drive the client side of a cleartext exchange: assert the request, then
    /// send `password`. Returns the bytes the proxy sent back afterwards.
    async fn run_client(mut client: tokio::io::DuplexStream, password: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 9]; // 'R' + len(4) + subtype(4)
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], codec::AUTHENTICATION);
        assert_eq!(i32::from_be_bytes(header[5..9].try_into().unwrap()), 3);

        let mut body = password.to_vec();
        body.push(0);
        client.write_all(&frame(codec::PASSWORD_MESSAGE, &body)).await.unwrap();
        client.flush().await.unwrap();

        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        rest
    }

    #[tokio::test]
    async fn cleartext_accepts_correct_password() {
        let (client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(run_client(client, b"secret"));

        let startup = startup_for("alice");
        let ctx = AuthContext { startup: &startup, sni: None };
        let outcome = alice_creds().authenticate(&mut server, &ctx).await.unwrap();
        assert!(matches!(
            outcome,
            ClientAuth::Terminated(BackendAuth::Trust)
        ));
        drop(server); // EOF so the client's read_to_end returns
        task.await.unwrap();
    }

    #[tokio::test]
    async fn cleartext_rejects_wrong_password() {
        let (client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(run_client(client, b"wrong"));

        let startup = startup_for("alice");
        let ctx = AuthContext { startup: &startup, sni: None };
        let result = alice_creds().authenticate(&mut server, &ctx).await;
        assert!(result.is_err());
        drop(server); // EOF after the ErrorResponse

        // The client should have received an ErrorResponse.
        let trailing = task.await.unwrap();
        assert_eq!(trailing.first(), Some(&codec::ERROR_RESPONSE));
    }
}
