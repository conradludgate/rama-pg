//! Backend connection pooling for transaction pooling, built on rama's generic
//! client pool.
//!
//! The upstream side is expressed in rama's vocabulary: a [`PgConnector`]
//! ([`rama::net::client::ConnectorService`]) establishes a fresh backend, and
//! rama's [`PooledConnector`] + [`LruDropPool`] reuse connections keyed by a
//! [`ReqToConnID`] (here `(user, database)`). A checked-out connection is a
//! [`LeasedConnection`] that returns to the pool on `Drop` — which lines up with
//! transaction-boundary semantics: hold the lease for one transaction, drop it
//! at `ReadyForQuery` idle to return it, or [`Lease::discard`] a connection left
//! mid-transaction.
//!
//! Replica sharding: the pool round-robins each transaction across a list of
//! equivalent replica addresses (read load-balancing — no primary/replica split,
//! no key-based sharding, since replicas hold the same data). The chosen replica
//! joins the `(user, database)` pool key, so each replica keeps its own
//! connections.
//!
//! Backends may be trust or password-authenticated: a [`BackendCredentials`]
//! provider lets the connector satisfy a cleartext or SCRAM-SHA-256 challenge
//! over the (plaintext) backend link. A single address is just a one-element
//! replica list.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use rama::Service;
use rama::error::BoxError;
use rama::extensions::{Extension, Extensions, ExtensionsRef};
use rama::net::client::EstablishedClientConnection;
use rama::net::client::pool::{ConnID, LeasedConnection, LruDropPool, PooledConnector, ReqToConnID};
use rama::tcp::{TcpStream, TokioTcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::cancel::UpstreamSession;
use crate::protocol::codec::{self, read_message};

/// The connection type the pool stores (rama's `TcpStream` carries the
/// `Extensions` the pool and our captured params live in).
type PooledStream = TcpStream;

/// Pool key: `(user, database)` — the pgbouncer pooling unit — plus the chosen
/// replica `shard`, so a connection is only reused for the same replica.
#[derive(Debug, Clone, PartialEq)]
struct PgConnId {
    user: String,
    database: String,
    shard: String,
}

impl ConnID for PgConnId {}

/// `ParameterStatus` frames captured at backend startup, stashed on the
/// connection's extensions and replayed to clients during their startup.
#[derive(Debug, Clone)]
struct CapturedParams(Vec<BytesMut>);

impl Extension for CapturedParams {}

/// The backend's cancel target (address + captured `BackendKeyData`), stashed on
/// the connection so the pooled forwarder can route a client's cancel to whatever
/// backend it is currently leasing.
#[derive(Debug, Clone)]
struct CapturedCancel(UpstreamSession);

impl Extension for CapturedCancel {}

/// The request flowing through the connector + pool: what to dial, the startup
/// to replay, and the pool key.
#[derive(Debug)]
struct BackendRequest {
    extensions: Extensions,
    target: String,
    startup: BytesMut,
    id: PgConnId,
}

impl ExtensionsRef for BackendRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

/// Establishes a fresh backend: dial, replay the `StartupMessage`, drive the
/// (trust) startup to `ReadyForQuery`, capturing `ParameterStatus`.
struct PgConnector {
    credentials: Arc<dyn BackendCredentials>,
}

impl std::fmt::Debug for PgConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConnector").finish_non_exhaustive()
    }
}

impl Clone for PgConnector {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
        }
    }
}

// `Authentication` sub-types the pool connector handles.
const AUTH_OK: i32 = 0;
const AUTH_CLEARTEXT_PASSWORD: i32 = 3;
const AUTH_MD5_PASSWORD: i32 = 5;
const AUTH_SASL: i32 = 10;

impl PgConnector {
    /// The backend password for this request's role, erroring if a challenge
    /// arrived but no credentials are configured.
    async fn backend_password(&self, req: &BackendRequest) -> Result<String, BoxError> {
        self.credentials
            .password(&req.id.user, &req.id.database)
            .await?
            .ok_or_else(|| {
                format!(
                    "backend requires authentication but no credentials are configured for user {:?}",
                    req.id.user
                )
                .into()
            })
    }
}

impl Service<BackendRequest> for PgConnector {
    type Output = EstablishedClientConnection<PooledStream, BackendRequest>;
    type Error = BoxError;

    async fn serve(&self, req: BackendRequest) -> Result<Self::Output, Self::Error> {
        let mut conn = TokioTcpStream::connect(&req.target).await?;
        conn.write_all(&req.startup).await?;
        conn.flush().await?;

        // Auth phase: satisfy the backend's challenge (trust / cleartext / SCRAM,
        // over this plaintext link) until `AuthenticationOk`.
        loop {
            let msg = read_message(&mut conn).await?;
            match msg.tag() {
                codec::AUTHENTICATION => match auth_subtype(&msg) {
                    AUTH_OK => break,
                    AUTH_CLEARTEXT_PASSWORD => {
                        let mut body = self.backend_password(&req).await?.into_bytes();
                        body.push(0);
                        conn.write_all(&codec::frame(codec::PASSWORD_MESSAGE, &body)).await?;
                        conn.flush().await?;
                    }
                    AUTH_SASL => {
                        let password = self.backend_password(&req).await?;
                        crate::scram::authenticate_password(&mut conn, &msg, &password).await?;
                    }
                    AUTH_MD5_PASSWORD => {
                        return Err("pool backend requested md5 auth; only trust, \
                                    cleartext, and scram-sha-256 are supported"
                            .into());
                    }
                    other => {
                        return Err(format!(
                            "pool backend requested unsupported authentication type {other}"
                        )
                        .into());
                    }
                },
                codec::ERROR_RESPONSE => return Err("pool backend rejected authentication".into()),
                other => {
                    return Err(format!(
                        "unexpected backend message during auth: tag {:?}",
                        other as char
                    )
                    .into());
                }
            }
        }

        // Post-auth: capture `ParameterStatus` and the cancel key up to `ReadyForQuery`.
        let mut params = Vec::new();
        let mut cancel_key = None;
        loop {
            let msg = read_message(&mut conn).await?;
            match msg.tag() {
                codec::PARAMETER_STATUS => params.push(BytesMut::from(msg.as_bytes())),
                // Capture the backend's cancel key so a client leasing this
                // connection can be cancelled at whatever backend it lands on.
                codec::BACKEND_KEY_DATA => cancel_key = Some(Bytes::copy_from_slice(msg.payload())),
                codec::READY_FOR_QUERY => break,
                codec::ERROR_RESPONSE => return Err("pool backend rejected startup".into()),
                _ => {} // NoticeResponse, etc. — ignored.
            }
        }

        let conn = TcpStream::new(conn);
        conn.extensions().insert(CapturedParams(params));
        if let Some(key) = cancel_key {
            conn.extensions().insert(CapturedCancel(UpstreamSession {
                backend: req.target.clone(),
                key,
            }));
        }
        Ok(EstablishedClientConnection { input: req, conn })
    }
}

/// The `Int32` sub-type of an `Authentication` message (or `-1` if truncated).
fn auth_subtype(msg: &codec::RawMessage) -> i32 {
    let payload = msg.payload();
    if payload.len() >= 4 {
        i32::from_be_bytes(payload[..4].try_into().unwrap())
    } else {
        -1
    }
}

/// Supplies the password the pool uses to authenticate to a backend as a role.
/// The pool connects to backends over plaintext TCP and may be challenged for a
/// cleartext or SCRAM-SHA-256 password; returning `None` means a trust backend.
#[async_trait]
pub trait BackendCredentials: Send + Sync + 'static {
    async fn password(&self, user: &str, database: &str) -> Result<Option<String>, BoxError>;
}

/// A trust backend: no credentials (the backend must not challenge for auth).
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustBackend;

#[async_trait]
impl BackendCredentials for TrustBackend {
    async fn password(&self, _user: &str, _database: &str) -> Result<Option<String>, BoxError> {
        Ok(None)
    }
}

/// In-memory `user -> password` backend credentials.
#[derive(Debug, Clone, Default)]
pub struct StaticBackendCredentials {
    passwords: HashMap<String, String>,
}

impl StaticBackendCredentials {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the backend password for `user`.
    pub fn with_password(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.passwords.insert(user.into(), password.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.passwords.is_empty()
    }
}

#[async_trait]
impl BackendCredentials for StaticBackendCredentials {
    async fn password(&self, user: &str, _database: &str) -> Result<Option<String>, BoxError> {
        Ok(self.passwords.get(user).cloned())
    }
}

/// Maps a [`BackendRequest`] to its pool key (composed in [`BackendPool::lease`]).
#[derive(Debug, Clone)]
struct RequestKey;

impl ReqToConnID<BackendRequest> for RequestKey {
    type ID = PgConnId;

    fn id(&self, req: &BackendRequest) -> Result<Self::ID, BoxError> {
        Ok(req.id.clone())
    }
}

type Connector = PooledConnector<PgConnector, LruDropPool<PooledStream, PgConnId>, RequestKey>;

/// When a leased backend is returned to the pool (pgbouncer-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolMode {
    /// One backend per client connection, returned on disconnect.
    Session,
    /// A backend per transaction, returned at `ReadyForQuery` idle (the default).
    #[default]
    Transaction,
    /// A backend per statement, returned after each `ReadyForQuery`; a backend
    /// left mid-transaction is discarded (multi-statement transactions break).
    Statement,
}

/// A transaction-pooling backend pool that round-robins transactions across one
/// or more equivalent replica addresses.
pub struct BackendPool {
    replicas: Vec<String>,
    mode: PoolMode,
    next: AtomicUsize,
    /// `ParameterStatus` frames captured per `(user, database)` and replayed to
    /// that role's clients during their synthesized startup. Keyed by role/db so
    /// role-dependent params (e.g. `is_superuser`) aren't replayed across roles.
    params: Mutex<HashMap<(String, String), Vec<BytesMut>>>,
    /// Query run on a backend before it returns to the pool (transaction /
    /// statement modes), to clear leftover session state so it can't leak to the
    /// next client that reuses the connection. `None` disables the reset.
    reset_query: Option<BytesMut>,
    connector: Connector,
}

impl BackendPool {
    /// Create a pool of up to `max_size` connections (total, across replicas),
    /// round-robining transactions across `replicas`, with the given pool `mode`.
    /// Backends are assumed to be trust; use [`with_credentials`](Self::with_credentials)
    /// for backends that require a password.
    pub fn new(replicas: Vec<String>, max_size: usize, mode: PoolMode) -> Arc<Self> {
        Self::with_credentials(replicas, max_size, mode, Arc::new(TrustBackend))
    }

    /// Like [`new`](Self::new), but authenticates to backends with `credentials`
    /// (cleartext or SCRAM-SHA-256, over the plaintext backend link).
    pub fn with_credentials(
        replicas: Vec<String>,
        max_size: usize,
        mode: PoolMode,
        credentials: Arc<dyn BackendCredentials>,
    ) -> Arc<Self> {
        assert!(!replicas.is_empty(), "backend pool needs at least one replica");
        let max = max_size.max(1);
        let pool = LruDropPool::try_new(max, max)
            .expect("valid pool size")
            // We use the lease as a raw relay stream, not as a rama Service, so
            // `got_response` is never set; without this the pool would discard
            // every connection on return.
            .with_drop_connection_if_no_response(false);
        Arc::new(Self {
            replicas,
            mode,
            next: AtomicUsize::new(0),
            params: Mutex::new(HashMap::new()),
            // Reset session state before reuse so one client's non-`LOCAL`
            // `SET`/`PREPARE`/temp-table/`LISTEN` can't leak into the next.
            // `DISCARD ALL` is the safe default (it runs on standbys too).
            reset_query: Some(codec::frame(codec::QUERY, b"DISCARD ALL\0")),
            connector: PooledConnector::new(PgConnector { credentials }, pool, RequestKey),
        })
    }

    /// The pool mode (when a backend is returned).
    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    /// The frame to send a backend to reset its session state before it returns
    /// to the pool, or `None` if resetting is disabled.
    pub fn reset_query(&self) -> Option<&[u8]> {
        self.reset_query.as_deref()
    }

    /// The `ParameterStatus` frames to replay to a client during its synthesized
    /// startup. Captured once per `(user, database)` and cached, so it doesn't
    /// perturb the per-transaction round-robin after the first client and a
    /// role's params aren't replayed to a different role.
    pub async fn startup_params(
        &self,
        startup_frame: &[u8],
        user: &str,
        database: &str,
    ) -> Result<Vec<BytesMut>, BoxError> {
        let key = (user.to_owned(), database.to_owned());
        if let Some(params) = self.params.lock().unwrap().get(&key).cloned() {
            return Ok(params);
        }
        // This lease runs no client SQL, so the backend stays pristine and can
        // return to the pool without a reset.
        let lease = self.lease(startup_frame, user, database).await?;
        let params = lease.params();
        lease.checkin();
        self.params.lock().unwrap().insert(key, params.clone());
        Ok(params)
    }

    /// Pick the next replica, round-robin.
    fn next_replica(&self) -> String {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.replicas.len();
        self.replicas[index].clone()
    }

    /// Lease a backend connection for one transaction: pick a replica, then
    /// reuse an idle connection for the `(user, database, replica)` key or
    /// establish a new one (replaying `startup_frame`). Blocks at capacity.
    pub async fn lease(
        &self,
        startup_frame: &[u8],
        user: &str,
        database: &str,
    ) -> Result<Lease, BoxError> {
        let shard = self.next_replica();
        let req = BackendRequest {
            extensions: Extensions::new(),
            target: shard.clone(),
            startup: BytesMut::from(startup_frame),
            id: PgConnId {
                user: user.to_owned(),
                database: database.to_owned(),
                shard,
            },
        };
        let established = self.connector.serve(req).await?;
        Ok(Lease {
            conn: established.conn,
        })
    }
}

/// A backend connection leased for one transaction. It is an opaque
/// `AsyncRead`/`AsyncWrite` stream; [`checkin`](Self::checkin) returns it to the
/// pool, [`discard`](Self::discard) drops it.
pub struct Lease {
    conn: LeasedConnection<PooledStream, PgConnId>,
}

impl Lease {
    /// The backend's captured `ParameterStatus` frames, to replay to the client.
    pub fn params(&self) -> Vec<BytesMut> {
        self.conn
            .extensions()
            .get_ref::<CapturedParams>()
            .map(|captured| captured.0.clone())
            .unwrap_or_default()
    }

    /// The backend's cancel target (address + captured `BackendKeyData`), so the
    /// forwarder can route a client's `CancelRequest` to this backend while the
    /// lease is held. `None` if the backend issued no key.
    pub fn cancel_target(&self) -> Option<UpstreamSession> {
        self.conn
            .extensions()
            .get_ref::<CapturedCancel>()
            .map(|captured| captured.0.clone())
    }

    /// Reset the backend's session state by running `reset_frame` (e.g. the
    /// pool's `DISCARD ALL`) and draining its response, so leftover
    /// `SET`/`PREPARE`/temp-table/`LISTEN` state from the previous transaction
    /// can't leak to the next client that reuses this backend.
    ///
    /// Must be called only at an idle transaction boundary, and the reset itself
    /// must leave the backend idle (`ReadyForQuery 'I'`). On any error the caller
    /// should [`discard`](Self::discard) the connection rather than pool it.
    pub async fn reset(&mut self, reset_frame: &[u8]) -> Result<(), BoxError> {
        self.conn.write_all(reset_frame).await?;
        self.conn.flush().await?;
        loop {
            let msg = read_message(&mut self.conn).await?;
            match msg.tag() {
                codec::READY_FOR_QUERY => {
                    return match msg.payload().first() {
                        Some(b'I') => Ok(()),
                        _ => Err("reset query left the backend in a transaction".into()),
                    };
                }
                codec::ERROR_RESPONSE => return Err("reset query failed".into()),
                _ => {} // CommandComplete, NoticeResponse, …
            }
        }
    }

    /// Return the connection to the pool (transaction completed, idle).
    pub fn checkin(self) {
        drop(self.conn); // LeasedConnection returns itself to the pool on drop.
    }

    /// Discard the connection (left mid-transaction); it is not pooled.
    pub fn discard(self) {
        let _ = self.conn.into_connection();
    }
}

impl AsyncRead for Lease {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Lease {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}
