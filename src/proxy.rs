//! The L4 proxy service.
//!
//! Postgres TLS negotiation is non-standard: the client opens a bare TCP
//! connection and sends a plaintext `SSLRequest`; only after the server answers
//! with a single `S` byte does the TLS `ClientHello` follow. [`PgProxy`] is the
//! top-level [`Service`] that performs this pre-TLS shim on the raw socket and
//! then delegates the encrypted stream to a [`TlsAcceptorService`]-wrapped
//! [`PgSession`] — composing the non-HTTP handshake into rama's service stack.

use std::sync::Arc;

use bytes::BytesMut;
use rama::Service;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::net::tls::SecureTransport;
use rama::service::BoxService;
use rama::tcp::{TcpStream, TokioTcpStream};
use rama::tls::rustls::server::{TlsAcceptorData, TlsAcceptorService, TlsStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use crate::auth::{AuthContext, Authenticator, BackendAuth, ClientAuth};
use crate::pool::{BackendPool, PoolMode};
use crate::protocol::codec::{self, read_message};
use crate::protocol::message::{
    authentication_ok, backend_key_data, command_complete, data_row, error_response, fatal_error,
    parameter_status, ready_for_query, row_description,
};
use crate::protocol::startup::{
    StartupMessage, StartupRequest, read_startup_frame, read_startup_request,
};
use crate::query::{QueryContext, QueryHandler, QueryResponse, SessionState, TxnStatus};
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

/// Transaction-pooling forwarding (with round-robin replica sharding).
pub struct PooledForwarder {
    pool: Arc<BackendPool>,
}

impl PooledForwarder {
    pub fn new(pool: Arc<BackendPool>) -> Self {
        Self { pool }
    }
}

impl<IO> Service<PgClient<IO>> for PooledForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        let PgClient {
            stream,
            startup_frame,
            startup,
            sni,
            auth,
        } = client;
        let user = startup.user().unwrap_or_default().to_owned();
        let database = startup.database().unwrap_or_default().to_owned();
        tracing::info!(?sni, user, database, "pooled connection");
        serve_pooled(stream, &startup_frame, &user, &database, auth, self.pool.clone()).await
    }
}

/// Custom forwarding: answer queries in-proxy with no backend at all.
pub struct CustomForwarder {
    handler: Arc<dyn QueryHandler>,
}

impl CustomForwarder {
    pub fn new(handler: Arc<dyn QueryHandler>) -> Self {
        Self { handler }
    }
}

impl<IO> Service<PgClient<IO>> for CustomForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        let PgClient {
            stream,
            startup,
            sni,
            auth,
            ..
        } = client;
        let user = startup.user().unwrap_or_default().to_owned();
        let database = startup.database().unwrap_or_default().to_owned();
        tracing::info!(?sni, user, "custom query session");
        serve_custom(stream, &user, &database, auth, self.handler.clone()).await
    }
}

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

/// Transaction-pooling session: the proxy terminated the client's auth, so it
/// synthesizes the startup completion (from the pool's captured
/// `ParameterStatus`) and then multiplexes the client's transactions over the
/// shared backend pool, checking a backend out per transaction and returning it
/// at `ReadyForQuery` status `I`.
///
/// v1 limitation: aggressive pipelining across a transaction boundary (sending
/// the next transaction's commands before the prior `ReadyForQuery`) is not
/// handled — clients that wait for `ReadyForQuery` (psql, libpq, most drivers)
/// behave correctly.
async fn serve_pooled<C>(
    mut stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    outcome: ClientAuth,
    pool: Arc<BackendPool>,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if matches!(outcome, ClientAuth::PassThrough) {
        return reject(
            &mut stream,
            "0A000",
            "rama-pg: pooling requires a terminating auth mode (cleartext or scram)",
        )
        .await;
    }

    // The client is idle until it sends a query, so we don't hold a backend yet;
    // the pool gives us the (cached) ParameterStatus to replay.
    let params = pool.startup_params(startup_frame, user, database).await?;

    // Synthesize the startup completion to the client.
    stream.write_all(&authentication_ok()).await?;
    for param in &params {
        stream.write_all(param).await?;
    }
    stream
        .write_all(&backend_key_data(rand::random(), rand::random()))
        .await?;
    stream.write_all(&ready_for_query(b'I')).await?;
    stream.flush().await?;

    match pool.mode() {
        // One backend for the whole connection — relay opaquely until disconnect.
        PoolMode::Session => {
            let mut lease = pool.lease(startup_frame, user, database).await?;
            let (client_to_backend, backend_to_client) =
                copy_bidirectional(&mut stream, &mut lease).await?;
            tracing::info!(client_to_backend, backend_to_client, "session-pooled connection closed");
            // NOTE: no server reset (DISCARD ALL) before reuse — a real pooler
            // would run server_reset_query here.
            lease.checkin();
            Ok(())
        }
        mode => relay_pooled(stream, startup_frame, user, database, pool, mode).await,
    }
}

/// Transaction/statement pooling: lease a backend per transaction (or
/// statement), relaying until the appropriate `ReadyForQuery` boundary.
async fn relay_pooled<C>(
    stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    pool: Arc<BackendPool>,
    mode: PoolMode,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = codec::FramedReader::new(stream);
    loop {
        // Idle: wait for the client to begin a transaction/statement.
        let Some(first) = client.read_frame().await? else {
            break;
        };
        if first.tag() == codec::TERMINATE {
            break;
        }

        let mut lease = pool.lease(startup_frame, user, database).await?;
        lease.write_all(first.as_bytes()).await?;
        lease.flush().await?;

        // Relay until this lease's release boundary.
        loop {
            let Some(status) = relay_to_next_rfq(&mut client, &mut lease).await? else {
                lease.discard(); // client gone mid-statement
                return Ok(());
            };
            match mode {
                PoolMode::Transaction if status == b'I' => {
                    lease.checkin();
                    break;
                }
                // Still inside a transaction block — keep this backend.
                PoolMode::Transaction => {}
                PoolMode::Statement if status == b'I' => {
                    lease.checkin();
                    break;
                }
                PoolMode::Statement => {
                    tracing::warn!("statement mode: discarding backend left in a transaction");
                    lease.discard();
                    break;
                }
                PoolMode::Session => unreachable!("session mode handled separately"),
            }
        }
    }

    tracing::info!("pooled session closed");
    Ok(())
}

/// Relay between the client and a checked-out backend until the backend's next
/// `ReadyForQuery`, returning its transaction-status byte (`I`/`T`/`E`), or
/// `None` if the client disconnected first.
async fn relay_to_next_rfq<C, B>(
    client: &mut codec::FramedReader<C>,
    backend: &mut B,
) -> Result<Option<u8>, BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut backend = codec::FramedReader::new(backend);
    loop {
        tokio::select! {
            // Prefer draining the backend so a ReadyForQuery is handled before
            // forwarding any further client input.
            biased;
            backend_frame = backend.read_frame() => {
                let Some(msg) = backend_frame? else {
                    return Err("backend closed mid-statement".into());
                };
                client.get_mut().write_all(msg.as_bytes()).await?;
                match msg.tag() {
                    codec::READY_FOR_QUERY => {
                        client.get_mut().flush().await?;
                        return Ok(Some(msg.payload().first().copied().unwrap_or(b'I')));
                    }
                    codec::ERROR_RESPONSE => client.get_mut().flush().await?,
                    _ => {}
                }
            }
            client_frame = client.read_frame() => {
                match client_frame? {
                    None => return Ok(None),
                    Some(msg) => {
                        if msg.tag() == codec::TERMINATE {
                            backend.get_mut().write_all(msg.as_bytes()).await.ok();
                            return Ok(None);
                        }
                        backend.get_mut().write_all(msg.as_bytes()).await?;
                        backend.get_mut().flush().await?;
                    }
                }
            }
        }
    }
}

/// Custom-query session: answer simple-protocol queries in-proxy with no
/// backend. The proxy terminated auth, so it synthesizes the startup completion
/// (a canned `ParameterStatus` set), then handles `Query` messages, tracking the
/// transaction status in a per-connection [`SessionState`] for `ReadyForQuery`.
///
/// Only the simple query protocol is supported (no extended Parse/Bind/Execute).
async fn serve_custom<C>(
    mut stream: C,
    user: &str,
    database: &str,
    outcome: ClientAuth,
    handler: Arc<dyn QueryHandler>,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if matches!(outcome, ClientAuth::PassThrough) {
        return reject(
            &mut stream,
            "0A000",
            "rama-pg: custom-query mode requires a terminating auth mode",
        )
        .await;
    }

    // Synthesize the startup completion (there is no backend to capture from).
    stream.write_all(&authentication_ok()).await?;
    for (name, value) in VIRTUAL_PARAMETERS {
        stream.write_all(&parameter_status(name, value)).await?;
    }
    stream
        .write_all(&backend_key_data(rand::random(), rand::random()))
        .await?;
    stream
        .write_all(&ready_for_query(TxnStatus::Idle.code()))
        .await?;
    stream.flush().await?;

    let state = SessionState::default();
    loop {
        let message = match read_message(&mut stream).await {
            Ok(message) => message,
            Err(_) => break, // client gone
        };
        match message.tag() {
            codec::QUERY => {
                let sql = query_sql(message.payload());
                run_query(&mut stream, &state, &*handler, user, database, sql).await?;
            }
            codec::TERMINATE => break,
            other => {
                tracing::debug!(tag = ?(other as char), "unsupported message in custom mode");
                stream
                    .write_all(&error_response(
                        "ERROR",
                        "0A000",
                        "rama-pg virtual server supports only the simple query protocol",
                    ))
                    .await?;
                stream
                    .write_all(&ready_for_query(state.txn_status().code()))
                    .await?;
                stream.flush().await?;
            }
        }
    }
    tracing::info!("custom query session closed");
    Ok(())
}

/// `ParameterStatus` values the virtual server reports at startup.
const VIRTUAL_PARAMETERS: &[(&str, &str)] = &[
    ("server_version", "16.0 (rama-pg virtual)"),
    ("server_encoding", "UTF8"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
    ("TimeZone", "UTC"),
    ("standard_conforming_strings", "on"),
    ("integer_datetimes", "on"),
];

/// The SQL from a `Query` payload (a single null-terminated string).
fn query_sql(payload: &[u8]) -> &str {
    let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
    std::str::from_utf8(&payload[..end]).unwrap_or("")
}

/// Run one simple query: handle transaction control locally, delegate the rest
/// to the handler, then emit `ReadyForQuery` with the current transaction status.
async fn run_query<C>(
    client: &mut C,
    state: &SessionState,
    handler: &dyn QueryHandler,
    user: &str,
    database: &str,
    sql: &str,
) -> Result<(), BoxError>
where
    C: AsyncWrite + Unpin,
{
    let trimmed = sql.trim().trim_end_matches(';').trim();
    let verb = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let status = state.txn_status();

    if status == TxnStatus::Failed
        && !matches!(verb.as_str(), "COMMIT" | "ROLLBACK" | "END" | "ABORT")
    {
        // A failed transaction rejects everything until it ends.
        client
            .write_all(&error_response(
                "ERROR",
                "25P02",
                "current transaction is aborted, commands ignored until end of transaction block",
            ))
            .await?;
    } else {
        match verb.as_str() {
            "BEGIN" | "START" => {
                state.set_txn_status(TxnStatus::InTransaction);
                client.write_all(&command_complete("BEGIN")).await?;
            }
            "COMMIT" | "END" => {
                state.set_txn_status(TxnStatus::Idle);
                client.write_all(&command_complete("COMMIT")).await?;
            }
            "ROLLBACK" | "ABORT" => {
                state.set_txn_status(TxnStatus::Idle);
                client.write_all(&command_complete("ROLLBACK")).await?;
            }
            _ => {
                let ctx = QueryContext { user, database, state };
                match handler.handle(ctx, trimmed).await {
                    QueryResponse::Rows { columns, rows, tag } => {
                        let headers: Vec<&str> = columns.iter().map(String::as_str).collect();
                        client.write_all(&row_description(&headers)).await?;
                        for row in &rows {
                            let cells: Vec<Option<&str>> = row.iter().map(Option::as_deref).collect();
                            client.write_all(&data_row(&cells)).await?;
                        }
                        client.write_all(&command_complete(&tag)).await?;
                    }
                    QueryResponse::Command(tag) => {
                        client.write_all(&command_complete(&tag)).await?;
                    }
                    QueryResponse::Error { code, message } => {
                        client
                            .write_all(&error_response("ERROR", &code, &message))
                            .await?;
                        if status == TxnStatus::InTransaction {
                            state.set_txn_status(TxnStatus::Failed);
                        }
                    }
                }
            }
        }
    }

    client
        .write_all(&ready_for_query(state.txn_status().code()))
        .await?;
    client.flush().await?;
    Ok(())
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
