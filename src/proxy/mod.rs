//! The L4 proxy service.
//!
//! Postgres TLS negotiation is non-standard: the client opens a bare TCP
//! connection and sends a plaintext `SSLRequest`; only after the server answers
//! with a single `S` byte does the TLS `ClientHello` follow. [`PgProxy`] is the
//! top-level [`Service`] that performs this pre-TLS shim on the raw socket and
//! then delegates the encrypted stream to a [`TlsAcceptorService`]-wrapped
//! [`PgSession`] — composing the non-HTTP handshake into rama's service stack.
//!
//! After auth, [`PgSession`] hands an authenticated [`PgClient`] to a *forwarding
//! leaf* — itself a [`rama::Service`]. The built-in leaves live in submodules:
//! [`DirectForwarder`] (direct 1:1), [`PooledForwarder`] (pooling + sharding),
//! and [`CustomForwarder`] (in-proxy queries). A new mode is just another
//! `Service<PgClient<…>>`; see [`PgProxy::with_forwarder`].

mod custom;
mod direct;
mod pooled;

pub use custom::CustomForwarder;
pub use direct::DirectForwarder;
pub use pooled::PooledForwarder;

use std::sync::Arc;

use bytes::BytesMut;
use rama::Service;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::net::tls::SecureTransport;
use rama::service::BoxService;
use rama::tcp::TcpStream;
use rama::tls::rustls::server::{TlsAcceptorData, TlsAcceptorService, TlsStream};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::auth::{AuthContext, Authenticator, ClientAuth};
use crate::cancel::Cancellation;
use crate::pool::BackendPool;
use crate::protocol::message::{
    authentication_ok, backend_key_data_raw, fatal_error, negotiate_protocol_version,
    ready_for_query,
};
use crate::protocol::startup::{
    ProtocolVersion, StartupMessage, StartupRequest, read_startup_frame, read_startup_request,
};
use crate::query::QueryHandler;
use crate::route::Router;

/// The forwarding leaf's input: an authenticated client ready for its session.
///
/// The shared front matter — TLS, `StartupMessage`, and auth — has already
/// happened; a *forwarder* takes it from here. Forwarders are plain
/// [`rama::Service`]s over a `PgClient`, so each mode (direct, pooled, custom)
/// is just a `Service` impl and a new one is "write a `Service`", selected at
/// construction via [`rama::service::BoxService`].
pub struct PgClient<IO> {
    /// The (TLS) client stream.
    pub stream: IO,
    /// The parsed startup parameters (and its raw frame, via `startup.frame()`,
    /// for replaying to a backend verbatim).
    pub startup: StartupMessage,
    /// The negotiated protocol version (the client's request capped at the
    /// proxy's max). Synthesized modes size their cancel key to it.
    pub protocol_version: ProtocolVersion,
    /// The TLS SNI, if the client sent one.
    pub sni: Option<String>,
    /// How the client authenticated — decides backend handling.
    pub auth: ClientAuth,
}

/// A boxed forwarding leaf operating on the proxy's concrete client stream.
pub type Forwarder = BoxService<PgClient<TlsStream<TcpStream>>, (), BoxError>;

/// Top-level proxy service operating on a raw [`TcpStream`].
pub struct PgProxy<A> {
    tls: TlsAcceptorService<PgSession<A>>,
    /// Handles `CancelRequest`s that arrive in the clear (the traditional libpq
    /// cancel path). Over-TLS cancels are handled by [`PgSession`].
    cancellation: Arc<dyn Cancellation>,
}

impl<A: Authenticator> PgProxy<A> {
    /// Build a proxy that terminates TLS with the given acceptor data and
    /// authenticates clients with `auth`. The forwarding mode is chosen by the
    /// optional `handler` (custom in-proxy queries, no backend) and `pool`
    /// (transaction pooling); with neither, it is direct 1:1 on `router`.
    /// `cancellation` mediates query cancellation (see [`crate::cancel`]).
    pub fn new(
        tls: TlsAcceptorData,
        router: Arc<Router>,
        auth: Arc<A>,
        pool: Option<Arc<BackendPool>>,
        handler: Option<Arc<dyn QueryHandler>>,
        cancellation: Arc<dyn Cancellation>,
    ) -> Self {
        let forwarder = if let Some(handler) = handler {
            CustomForwarder::new(handler, cancellation.clone()).boxed()
        } else if let Some(pool) = pool {
            PooledForwarder::new(pool, cancellation.clone()).boxed()
        } else {
            DirectForwarder::new(router, cancellation.clone()).boxed()
        };
        Self::with_forwarder(tls, auth, forwarder, cancellation)
    }

    /// Build a proxy with a caller-supplied forwarding [`Service`] — the
    /// composability seam for new modes beyond the built-in three. `cancellation`
    /// handles incoming `CancelRequest`s; the forwarder is responsible for
    /// issuing keys (see [`crate::cancel`]).
    pub fn with_forwarder<F>(
        tls: TlsAcceptorData,
        auth: Arc<A>,
        forwarder: F,
        cancellation: Arc<dyn Cancellation>,
    ) -> Self
    where
        F: Service<PgClient<TlsStream<TcpStream>>, Output = (), Error = BoxError>,
    {
        // `store_client_hello = true` so the SNI is captured into the TLS
        // stream's extensions for routing.
        Self {
            tls: TlsAcceptorService::new(
                tls,
                PgSession::new(auth, forwarder.boxed(), cancellation.clone()),
                true,
            ),
            cancellation,
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
        // Direct TLS (PostgreSQL 17+ `sslnegotiation=direct`): the client opens
        // with a TLS `ClientHello` instead of an `SSLRequest`. A TLS handshake
        // record starts with `0x16`; a Postgres startup packet starts with `0x00`
        // (the high byte of its length, capped well under 16 MiB), so the first
        // byte disambiguates. Peek it without consuming, then hand a ClientHello
        // straight to the TLS acceptor (no `S` shim). Direct TLS mandates the
        // `postgresql` ALPN, which the acceptor must advertise.
        let mut first = [0u8; 1];
        if let Ok(1) = stream.stream.peek(&mut first).await
            && first[0] == 0x16
        {
            tracing::info!("direct TLS connection (ClientHello first)");
            return self.tls.serve(stream).await;
        }

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
                    // Traditional libpq sends the CancelRequest in the clear on a
                    // fresh connection; hand it to the cancellation provider.
                    tracing::info!(process_id = ?req.process_id(), "cancel request (plaintext)");
                    if let Err(err) = self.cancellation.cancel(req.key).await {
                        tracing::warn!(%err, "cancellation failed");
                    }
                    return Ok(());
                }
            }
        }
    }
}

/// Runs the shared post-TLS front matter — read the `StartupMessage`, capture
/// the SNI, authenticate — then hands an authenticated [`PgClient`] to the
/// forwarding leaf.
pub struct PgSession<A> {
    auth: Arc<A>,
    forwarder: Forwarder,
    cancellation: Arc<dyn Cancellation>,
}

impl<A> PgSession<A> {
    fn new(auth: Arc<A>, forwarder: Forwarder, cancellation: Arc<dyn Cancellation>) -> Self {
        Self {
            auth,
            forwarder,
            cancellation,
        }
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

        // The parsed StartupMessage keeps its raw frame for verbatim replay.
        let startup = match StartupRequest::parse(read_startup_frame(&mut stream).await?.freeze())? {
            StartupRequest::Startup(msg) => msg,
            StartupRequest::Cancel(req) => {
                // Modern libpq (PG 17+) sends the CancelRequest over TLS, honoring
                // the connection's sslmode, so it arrives here rather than in the
                // clear. Same provider, different transport.
                tracing::info!(process_id = ?req.process_id(), "cancel request (over TLS)");
                if let Err(err) = self.cancellation.cancel(req.key).await {
                    tracing::warn!(%err, "cancellation failed");
                }
                return Ok(());
            }
            other => {
                tracing::warn!(?other, "unexpected message after TLS handshake");
                return reject(&mut stream, "08P01", "unexpected message after TLS handshake").await;
            }
        };

        // Only protocol major 3 exists.
        if startup.protocol_major() != 3 {
            tracing::warn!(version = startup.protocol_version().code(), "unsupported protocol major version");
            return reject(&mut stream, "0A000", "rama-pg: unsupported protocol major version").await;
        }
        // When the proxy terminates auth it is the negotiation authority: tell the
        // client about a minor-version downgrade or unrecognized `_pq_` options
        // *before* challenging it (pass-through lets the backend negotiate). The
        // negotiated version then sizes the synthesized cancel key.
        let negotiated = startup.negotiated_version();
        if self.auth.terminates() {
            let unsupported: Vec<&str> = startup.pq_options().collect();
            if negotiated != startup.protocol_version() || !unsupported.is_empty() {
                tracing::info!(requested = startup.protocol_version().code(), negotiated = negotiated.code(), "negotiating protocol version");
                stream
                    .write_all(&negotiate_protocol_version(negotiated, &unsupported))
                    .await?;
                stream.flush().await?;
            }
        }

        // Authenticate the client; the outcome decides how the forwarder reaches
        // the backend.
        let auth_ctx = AuthContext {
            startup: &startup,
            sni: sni.as_deref(),
        };
        let auth = self.auth.authenticate(&mut stream, &auth_ctx).await?;

        self.forwarder
            .serve(PgClient {
                stream,
                startup,
                protocol_version: negotiated,
                sni,
                auth,
            })
            .await
    }
}

/// Send a fatal `ErrorResponse` and flush, so the client reports the reason
/// rather than seeing a bare connection drop. Shared by the front matter and the
/// forwarder leaves.
async fn reject<IO>(stream: &mut IO, code: &str, message: &str) -> Result<(), BoxError>
where
    IO: AsyncWrite + Unpin,
{
    let err = fatal_error(code, message);
    stream.write_all(&err).await?;
    stream.flush().await?;
    Ok(())
}

/// Synthesize the startup completion the proxy sends a client when it terminated
/// auth itself: `AuthenticationOk`, the given `ParameterStatus` frames, the
/// `cancel_key` as `BackendKeyData`, and an idle `ReadyForQuery`. Used by the
/// pooled and custom leaves (which have no per-client backend to relay from); the
/// `cancel_key` is the payload the cancellation provider issued (or a random one
/// when cancellation is disabled).
async fn synthesize_startup<IO>(
    stream: &mut IO,
    params: &[BytesMut],
    cancel_key: &[u8],
) -> Result<(), BoxError>
where
    IO: AsyncWrite + Unpin,
{
    stream.write_all(&authentication_ok()).await?;
    for param in params {
        stream.write_all(param).await?;
    }
    stream.write_all(&backend_key_data_raw(cancel_key)).await?;
    stream.write_all(&ready_for_query(b'I')).await?;
    stream.flush().await?;
    Ok(())
}
