//! Direct 1:1 forwarding.

use std::sync::Arc;

use bytes::Bytes;
use rama::Service;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use super::{PgClient, reject};
use crate::auth::{BackendAuth, ClientAuth};
use crate::cancel::{Cancellation, UpstreamSession};
use crate::protocol::codec::{self, read_message};
use crate::protocol::message;
use crate::route::Router;

/// `Authentication` sub-type for success (`AuthenticationOk`).
const AUTH_OK: i32 = 0;
/// `Authentication` sub-type for `AuthenticationSASLFinal` — the only challenge
/// the backend does not expect a client response to (the server's signature; the
/// next message is `AuthenticationOk`).
const AUTH_SASL_FINAL: i32 = 12;

/// Direct 1:1 forwarding: resolve the backend from the SNI, replay the startup,
/// satisfy backend auth (pass-through / trust / SCRAM reauth), then relay bytes.
pub struct DirectForwarder {
    router: Arc<Router>,
    cancellation: Arc<dyn Cancellation>,
}

impl DirectForwarder {
    pub fn new(router: Arc<Router>, cancellation: Arc<dyn Cancellation>) -> Self {
        Self { router, cancellation }
    }
}

impl<IO> Service<PgClient<IO>> for DirectForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        let PgClient {
            mut stream,
            startup_frame,
            startup,
            sni,
            auth,
        } = client;

        let Some(backend) = self.router.route(sni.as_deref()) else {
            tracing::info!(?sni, user = ?startup.user(), "no backend route for SNI");
            return reject(
                &mut stream,
                "08004",
                "rama-pg: no backend configured for this server name",
            )
            .await;
        };
        let address = backend.address.clone();
        tracing::info!(
            ?sni,
            user = ?startup.user(),
            database = ?startup.database(),
            backend = %address,
            "routing connection",
        );

        let mut upstream = match TokioTcpStream::connect(&address).await {
            Ok(upstream) => upstream,
            Err(err) => {
                tracing::error!(%address, %err, "failed to connect to backend");
                return reject(&mut stream, "08006", "rama-pg: could not reach backend").await;
            }
        };
        // Replay the StartupMessage verbatim to the backend.
        upstream.write_all(&startup_frame).await?;
        upstream.flush().await?;

        // Relay the backend's startup completion to the client, intercepting
        // BackendKeyData so cancellation can be mediated. In pass-through the
        // client authenticates with the backend (interactive); in terminate mode
        // we already authenticated it, so we only splice the completion (after
        // satisfying the backend's own auth: nothing for trust, SCRAM reauth).
        let issued = match auth {
            ClientAuth::PassThrough => {
                relay_startup(&mut stream, &mut upstream, &address, &self.cancellation, true).await?
            }
            ClientAuth::Terminated(BackendAuth::Trust) => {
                relay_startup(&mut stream, &mut upstream, &address, &self.cancellation, false).await?
            }
            ClientAuth::Terminated(BackendAuth::Scram(keys)) => {
                crate::scram::reauth_upstream(&mut upstream, &keys).await?;
                relay_startup(&mut stream, &mut upstream, &address, &self.cancellation, false).await?
            }
        };

        let outcome = copy_bidirectional(&mut stream, &mut upstream).await;
        // Drop the cancel mapping now the session is over (best-effort).
        if let Some(key) = issued {
            self.cancellation.release(key).await;
        }
        let (client_to_backend, backend_to_client) = outcome?;
        tracing::info!(client_to_backend, backend_to_client, "session closed");
        Ok(())
    }
}

/// Relay the backend's startup/auth completion to the client up to its first
/// `ReadyForQuery`, intercepting `BackendKeyData` so the proxy can mediate
/// cancellation.
///
/// With `interactive_auth` (pass-through), backend auth challenges are relayed to
/// the client and its responses forwarded back, one round per challenge; without
/// it (the proxy already satisfied auth) a non-`Ok` challenge is an error. Reads
/// are exactly one message each (`read_message`), so no session bytes are
/// consumed and the caller can resume an opaque `copy_bidirectional`.
///
/// Returns the cancel key the proxy issued to the client (to release when the
/// session ends), or `None` if the backend's own key was passed through.
async fn relay_startup<C, B>(
    client: &mut C,
    backend: &mut B,
    backend_addr: &str,
    cancellation: &Arc<dyn Cancellation>,
    interactive_auth: bool,
) -> Result<Option<Bytes>, BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut issued = None;
    loop {
        let msg = read_message(backend).await?;
        match msg.tag() {
            codec::AUTHENTICATION => {
                let subtype = auth_subtype(&msg)?;
                if subtype == AUTH_OK {
                    // Forward to the client, which is awaiting it.
                    client.write_all(msg.as_bytes()).await?;
                } else if interactive_auth {
                    // Relay the challenge; unless it is the final SASL message,
                    // forward exactly one client response back to the backend.
                    client.write_all(msg.as_bytes()).await?;
                    client.flush().await?;
                    if subtype != AUTH_SASL_FINAL {
                        let response = read_message(client).await?;
                        backend.write_all(response.as_bytes()).await?;
                        backend.flush().await?;
                    }
                } else {
                    return Err(format!(
                        "backend requested authentication type {subtype}; \
                         proxy-to-backend auth is not supported in terminate mode"
                    )
                    .into());
                }
            }
            codec::BACKEND_KEY_DATA => {
                // Capture the backend's key, then advertise whatever the
                // cancellation provider issues (an opaque proxy key, or the
                // backend's own if it returns None).
                let session = UpstreamSession {
                    backend: backend_addr.to_owned(),
                    key: Bytes::copy_from_slice(msg.payload()),
                };
                match cancellation.issue(session).await? {
                    Some(key) => {
                        client.write_all(&message::backend_key_data_raw(&key)).await?;
                        issued = Some(key);
                    }
                    None => client.write_all(msg.as_bytes()).await?,
                }
            }
            codec::READY_FOR_QUERY => {
                client.write_all(msg.as_bytes()).await?;
                client.flush().await?;
                return Ok(issued);
            }
            codec::ERROR_RESPONSE => {
                client.write_all(msg.as_bytes()).await?;
                client.flush().await?;
                return Err("backend rejected startup".into());
            }
            _ => client.write_all(msg.as_bytes()).await?,
        }
    }
}

/// Read the `Int32` sub-type from an `Authentication` message payload.
fn auth_subtype(msg: &codec::RawMessage) -> Result<i32, BoxError> {
    let payload = msg.payload();
    if payload.len() < 4 {
        return Err("authentication message shorter than 4 bytes".into());
    }
    Ok(i32::from_be_bytes(payload[..4].try_into().unwrap()))
}
