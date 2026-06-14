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
//! v1 scope: trust backends only (the connector can't satisfy a credential
//! challenge). A single address is just a one-element replica list.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use rama::Service;
use rama::error::BoxError;
use rama::extensions::{Extension, Extensions, ExtensionsRef};
use rama::net::client::EstablishedClientConnection;
use rama::net::client::pool::{ConnID, LeasedConnection, LruDropPool, PooledConnector, ReqToConnID};
use rama::tcp::{TcpStream, TokioTcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

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
#[derive(Debug, Clone)]
struct PgConnector;

impl Service<BackendRequest> for PgConnector {
    type Output = EstablishedClientConnection<PooledStream, BackendRequest>;
    type Error = BoxError;

    async fn serve(&self, req: BackendRequest) -> Result<Self::Output, Self::Error> {
        let mut conn = TokioTcpStream::connect(&req.target).await?;
        conn.write_all(&req.startup).await?;
        conn.flush().await?;

        let mut params = Vec::new();
        loop {
            let msg = read_message(&mut conn).await?;
            match msg.tag() {
                codec::AUTHENTICATION => {
                    let payload = msg.payload();
                    let subtype = if payload.len() >= 4 {
                        i32::from_be_bytes(payload[..4].try_into().unwrap())
                    } else {
                        -1
                    };
                    if subtype != 0 {
                        return Err(format!(
                            "pool backend requested authentication type {subtype}; \
                             only a trust backend is supported"
                        )
                        .into());
                    }
                }
                codec::PARAMETER_STATUS => params.push(BytesMut::from(msg.as_bytes())),
                codec::READY_FOR_QUERY => break,
                codec::ERROR_RESPONSE => return Err("pool backend rejected startup".into()),
                _ => {} // BackendKeyData, NoticeResponse, etc. — ignored.
            }
        }

        let conn = TcpStream::new(conn);
        conn.extensions().insert(CapturedParams(params));
        Ok(EstablishedClientConnection { input: req, conn })
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
    /// `ParameterStatus` captured once (replicas are equivalent) and replayed to
    /// every client's synthesized startup.
    params: Mutex<Option<Vec<BytesMut>>>,
    connector: Connector,
}

impl BackendPool {
    /// Create a pool of up to `max_size` connections (total, across replicas),
    /// round-robining transactions across `replicas`, with the given pool `mode`.
    pub fn new(replicas: Vec<String>, max_size: usize, mode: PoolMode) -> Arc<Self> {
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
            params: Mutex::new(None),
            connector: PooledConnector::new(PgConnector, pool, RequestKey),
        })
    }

    /// The pool mode (when a backend is returned).
    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    /// The `ParameterStatus` frames to replay to a client during its synthesized
    /// startup. Captured once from a backend and cached, so it doesn't perturb
    /// the per-transaction round-robin after the first client.
    pub async fn startup_params(
        &self,
        startup_frame: &[u8],
        user: &str,
        database: &str,
    ) -> Result<Vec<BytesMut>, BoxError> {
        if let Some(params) = self.params.lock().unwrap().clone() {
            return Ok(params);
        }
        let lease = self.lease(startup_frame, user, database).await?;
        let params = lease.params();
        lease.checkin();
        *self.params.lock().unwrap() = Some(params.clone());
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
