//! The L4 proxy service.
//!
//! Postgres TLS negotiation is non-standard: the client opens a bare TCP
//! connection and sends a plaintext `SSLRequest`; only after the server answers
//! with a single `S` byte does the TLS `ClientHello` follow. [`PgProxy`] is the
//! top-level [`Service`] that performs this pre-TLS shim on the raw socket and
//! then delegates the encrypted stream to a [`TlsAcceptorService`]-wrapped
//! [`PgSession`] — composing the non-HTTP handshake into rama's service stack.

use std::sync::Arc;

use rama::Service;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::net::tls::SecureTransport;
use rama::tcp::{TcpStream, TokioTcpStream};
use rama::tls::rustls::server::{TlsAcceptorData, TlsAcceptorService, TlsStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use crate::auth::{Authenticator, ClientAuth};
use crate::protocol::codec::{self, read_message};
use crate::protocol::message::fatal_error;
use crate::protocol::startup::{StartupRequest, read_startup_frame, read_startup_request};
use crate::route::Router;

/// Top-level proxy service operating on a raw [`TcpStream`].
pub struct PgProxy<A> {
    tls: TlsAcceptorService<PgSession<A>>,
}

impl<A: Authenticator> PgProxy<A> {
    /// Build a proxy that terminates TLS with the given acceptor data, routes
    /// on `router`, and authenticates clients with `auth`.
    pub fn new(tls: TlsAcceptorData, router: Arc<Router>, auth: Arc<A>) -> Self {
        // `store_client_hello = true` so the SNI is captured into the TLS
        // stream's extensions for routing.
        Self {
            tls: TlsAcceptorService::new(tls, PgSession::new(router, auth), true),
        }
    }
}

impl<A> Service<TcpStream> for PgProxy<A>
where
    A: Authenticator,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut stream: TcpStream) -> Result<(), BoxError> {
        loop {
            match read_startup_request(&mut stream).await? {
                StartupRequest::Ssl => {
                    // Accept TLS, then hand off the socket. The acceptor reads
                    // the ClientHello from the current cursor, so the bytes we
                    // already consumed (the SSLRequest) don't get in its way.
                    stream.write_all(b"S").await?;
                    stream.flush().await?;
                    return self.tls.serve(stream).await;
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
/// `StartupMessage`, resolves a backend from the SNI, authenticates the client,
/// and forwards to the backend (direct 1:1).
pub struct PgSession<A> {
    router: Arc<Router>,
    auth: Arc<A>,
}

impl<A> PgSession<A> {
    pub fn new(router: Arc<Router>, auth: Arc<A>) -> Self {
        Self { router, auth }
    }
}

impl<A> Service<TlsStream<TcpStream>> for PgSession<A>
where
    A: Authenticator,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut stream: TlsStream<TcpStream>) -> Result<(), BoxError> {
        // The TLS acceptor stored the ClientHello (and thus SNI) in the stream's
        // extensions.
        let sni = stream
            .extensions()
            .get_ref::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|hello| hello.ext_server_name())
            .map(|host| host.to_string());

        // Keep the raw frame so it can be replayed to the backend verbatim.
        let startup_frame = read_startup_frame(&mut stream).await?;
        let msg = match StartupRequest::parse(&startup_frame)? {
            StartupRequest::Startup(msg) => msg,
            other => {
                tracing::warn!(?other, "unexpected message after TLS handshake");
                return reject(&mut stream, "08P01", "unexpected message after TLS handshake").await;
            }
        };

        let Some(backend) = self.router.route(sni.as_deref()) else {
            tracing::info!(?sni, user = ?msg.user(), "no backend route for SNI");
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
            user = ?msg.user(),
            database = ?msg.database(),
            backend = %address,
            "routing connection",
        );

        // Authenticate the client; the outcome decides how we reach the backend.
        let outcome = self.auth.authenticate(&mut stream, &msg).await?;

        let mut upstream = match TokioTcpStream::connect(&address).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::error!(%address, %err, "failed to connect to backend");
                return reject(&mut stream, "08006", "rama-pg: could not reach backend").await;
            }
        };
        // Replay the StartupMessage verbatim to the backend.
        upstream.write_all(&startup_frame).await?;
        upstream.flush().await?;

        // In terminate mode we authenticated the client ourselves, so splice the
        // backend's startup result (AuthenticationOk, ParameterStatus, …,
        // ReadyForQuery) to the client before relaying the query phase.
        if outcome == ClientAuth::Terminated {
            relay_backend_startup(&mut stream, &mut upstream).await?;
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

/// Send a fatal `ErrorResponse` and flush, so the client reports the reason
/// rather than seeing a bare connection drop.
async fn reject<IO>(stream: &mut IO, code: &str, message: &str) -> Result<(), BoxError>
where
    IO: AsyncWrite + Unpin,
{
    let err = fatal_error(code, message);
    stream.write_all(&err).await?;
    stream.flush().await?;
    Ok(())
}
