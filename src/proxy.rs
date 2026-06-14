//! The L4 proxy service.
//!
//! Postgres TLS negotiation is non-standard: the client opens a bare TCP
//! connection and sends a plaintext `SSLRequest`; only after the server answers
//! with a single `S` byte does the TLS `ClientHello` follow. [`PgProxy`] is the
//! top-level [`Service`] that performs this pre-TLS shim on the raw socket and
//! then delegates the encrypted stream to a [`TlsAcceptorService`]-wrapped
//! [`PgSession`] — composing the non-HTTP handshake into rama's service stack.

use rama::error::BoxError;
use rama::net::stream::Stream;
use rama::net::tls::SecureTransport;
use rama::tcp::TcpStream;
use rama::tls::rustls::server::{TlsAcceptorData, TlsAcceptorService};
use rama::{Context, Service};
use tokio::io::AsyncWriteExt;

use crate::protocol::message::fatal_error;
use crate::protocol::startup::{StartupRequest, read_startup_request};

/// Top-level proxy service operating on a raw [`TcpStream`].
pub struct PgProxy {
    tls: TlsAcceptorService<PgSession>,
}

impl PgProxy {
    /// Build a proxy that terminates TLS with the given acceptor data and
    /// hands each established session to [`PgSession`].
    pub fn new(tls: TlsAcceptorData) -> Self {
        // `store_client_hello = true` so the SNI is captured into the context
        // for later routing.
        Self {
            tls: TlsAcceptorService::new(tls, PgSession, true),
        }
    }
}

impl<State> Service<State, TcpStream> for PgProxy
where
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<State>, mut stream: TcpStream) -> Result<(), BoxError> {
        loop {
            match read_startup_request(&mut stream).await? {
                StartupRequest::Ssl => {
                    // Accept TLS, then hand off the socket. The acceptor reads
                    // the ClientHello from the current cursor, so the bytes we
                    // already consumed (the SSLRequest) don't get in its way.
                    stream.write_all(b"S").await?;
                    stream.flush().await?;
                    return self.tls.serve(ctx, stream).await;
                }
                StartupRequest::GssEnc => {
                    // GSSAPI encryption is unsupported; decline so the client
                    // falls back to an SSLRequest on the same connection.
                    stream.write_all(b"N").await?;
                    stream.flush().await?;
                }
                StartupRequest::Startup(msg) => {
                    tracing::info!(user = ?msg.user(), "rejecting plaintext startup; TLS required");
                    reject(
                        &mut stream,
                        "08004",
                        "rama-pg requires a TLS connection (use sslmode=require or higher)",
                    )
                    .await?;
                    return Ok(());
                }
                StartupRequest::Cancel(req) => {
                    // CancelRequest routing needs a cancel-key map; out of scope
                    // for v1 (a known gap), so acknowledge by closing.
                    tracing::info!(
                        process_id = req.process_id,
                        "cancel request received (unsupported in v1)"
                    );
                    return Ok(());
                }
            }
        }
    }
}

/// Handles a single connection once TLS is established: reads the
/// `StartupMessage` and (for now) reports the routing keys before rejecting.
pub struct PgSession;

impl<State, IO> Service<State, IO> for PgSession
where
    State: Clone + Send + Sync + 'static,
    IO: Stream + Unpin,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<State>, mut stream: IO) -> Result<(), BoxError> {
        let sni = ctx
            .get::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|hello| hello.ext_server_name())
            .map(|host| host.to_string());

        match read_startup_request(&mut stream).await? {
            StartupRequest::Startup(msg) => {
                tracing::info!(
                    ?sni,
                    user = ?msg.user(),
                    database = ?msg.database(),
                    "startup received over TLS",
                );
                // No backend wiring yet (step 1): the handshake is proven, so
                // reject cleanly with a message the client will surface.
                reject(
                    &mut stream,
                    "08004",
                    "rama-pg: TLS + startup OK, but no backend is configured yet",
                )
                .await
            }
            other => {
                tracing::warn!(?other, "unexpected message after TLS handshake");
                reject(&mut stream, "08P01", "unexpected message after TLS handshake").await
            }
        }
    }
}

/// Send a fatal `ErrorResponse` and flush, so the client reports the reason
/// rather than seeing a bare connection drop.
async fn reject<IO>(stream: &mut IO, code: &str, message: &str) -> Result<(), BoxError>
where
    IO: Stream + Unpin,
{
    let err = fatal_error(code, message);
    stream.write_all(&err).await?;
    stream.flush().await?;
    Ok(())
}
