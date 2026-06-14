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
use crate::pool::BackendPool;
use crate::protocol::message::fatal_error;
use crate::protocol::startup::{
    StartupMessage, StartupRequest, read_startup_frame, read_startup_request,
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
    /// The raw `StartupMessage` frame, for replaying to a backend verbatim.
    pub startup_frame: BytesMut,
    /// The parsed startup parameters.
    pub startup: StartupMessage,
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
}

impl<A: Authenticator> PgProxy<A> {
    /// Build a proxy that terminates TLS with the given acceptor data and
    /// authenticates clients with `auth`. The forwarding mode is chosen by the
    /// optional `handler` (custom in-proxy queries, no backend) and `pool`
    /// (transaction pooling); with neither, it is direct 1:1 on `router`.
    pub fn new(
        tls: TlsAcceptorData,
        router: Arc<Router>,
        auth: Arc<A>,
        pool: Option<Arc<BackendPool>>,
        handler: Option<Arc<dyn QueryHandler>>,
    ) -> Self {
        let forwarder = if let Some(handler) = handler {
            CustomForwarder::new(handler).boxed()
        } else if let Some(pool) = pool {
            PooledForwarder::new(pool).boxed()
        } else {
            DirectForwarder::new(router).boxed()
        };
        Self::with_forwarder(tls, auth, forwarder)
    }

    /// Build a proxy with a caller-supplied forwarding [`Service`] — the
    /// composability seam for new modes beyond the built-in three.
    pub fn with_forwarder<F>(tls: TlsAcceptorData, auth: Arc<A>, forwarder: F) -> Self
    where
        F: Service<PgClient<TlsStream<TcpStream>>, Output = (), Error = BoxError>,
    {
        // `store_client_hello = true` so the SNI is captured into the TLS
        // stream's extensions for routing.
        Self {
            tls: TlsAcceptorService::new(tls, PgSession::new(auth, forwarder.boxed()), true),
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

/// Runs the shared post-TLS front matter — read the `StartupMessage`, capture
/// the SNI, authenticate — then hands an authenticated [`PgClient`] to the
/// forwarding leaf.
pub struct PgSession<A> {
    auth: Arc<A>,
    forwarder: Forwarder,
}

impl<A> PgSession<A> {
    fn new(auth: Arc<A>, forwarder: Forwarder) -> Self {
        Self { auth, forwarder }
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
        let startup = match StartupRequest::parse(&startup_frame)? {
            StartupRequest::Startup(msg) => msg,
            other => {
                tracing::warn!(?other, "unexpected message after TLS handshake");
                return reject(&mut stream, "08P01", "unexpected message after TLS handshake").await;
            }
        };

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
                startup_frame,
                startup,
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
