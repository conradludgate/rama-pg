//! Direct 1:1 forwarding.

use std::sync::Arc;

use rama::Service;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use super::{PgClient, reject};
use crate::auth::{BackendAuth, ClientAuth};
use crate::protocol::codec::{self, read_message};
use crate::route::Router;

/// Direct 1:1 forwarding: resolve the backend from the SNI, replay the startup,
/// satisfy backend auth (pass-through / trust / SCRAM reauth), then relay bytes.
pub struct DirectForwarder {
    router: Arc<Router>,
}

impl DirectForwarder {
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
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

        // In terminate mode we authenticated the client ourselves, so satisfy
        // the backend's auth and splice its startup result (AuthenticationOk,
        // ParameterStatus, …, ReadyForQuery) to the client before relaying.
        match auth {
            ClientAuth::PassThrough => {}
            ClientAuth::Terminated(BackendAuth::Trust) => {
                relay_backend_startup(&mut stream, &mut upstream).await?;
            }
            ClientAuth::Terminated(BackendAuth::Scram(keys)) => {
                crate::scram::reauth_upstream(&mut upstream, &keys).await?;
                relay_backend_startup(&mut stream, &mut upstream).await?;
            }
        }

        let (client_to_backend, backend_to_client) =
            copy_bidirectional(&mut stream, &mut upstream).await?;
        tracing::info!(client_to_backend, backend_to_client, "session closed");
        Ok(())
    }
}

/// Relay the backend's startup-completion messages to the client, up to and
/// including `ReadyForQuery`.
///
/// Used in terminate mode, where the proxy authenticated the client and now
/// connects to the backend on its behalf. The backend must not issue a
/// credential challenge (we can't answer one here yet) — only a trust/already-
/// satisfied backend is supported, so a non-`Ok` `Authentication` message is an
/// error.
async fn relay_backend_startup<C, B>(client: &mut C, backend: &mut B) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let msg = read_message(backend).await?;
        match msg.tag() {
            codec::AUTHENTICATION => {
                let subtype = auth_subtype(&msg)?;
                if subtype != 0 {
                    return Err(format!(
                        "backend requested authentication type {subtype}; \
                         proxy-to-backend auth is not supported in terminate mode"
                    )
                    .into());
                }
                // AuthenticationOk: forward to the client, which is awaiting it.
                client.write_all(msg.as_bytes()).await?;
            }
            codec::READY_FOR_QUERY => {
                client.write_all(msg.as_bytes()).await?;
                client.flush().await?;
                return Ok(());
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
