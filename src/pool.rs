//! A pool of backend connections for transaction pooling.
//!
//! Each pooled connection is established once — TCP connect, replay a captured
//! `StartupMessage`, drive the (trust) backend startup to `ReadyForQuery` — and
//! then reused across many client transactions. A connection is checked out for
//! the duration of one transaction and returned at `ReadyForQuery` status `I`.
//!
//! v1 scope: a single backend address, a trust backend (the pool can't satisfy
//! a credential challenge), and one shared startup template — so all clients are
//! assumed to use the same user/database. Per-(user,database) pools and
//! non-trust backends are future work.

use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::protocol::codec::{self, read_message};

/// A fixed-capacity pool of established backend connections to one address.
#[derive(Debug)]
pub struct BackendPool {
    address: String,
    permits: Arc<Semaphore>,
    inner: Mutex<PoolInner>,
}

#[derive(Debug, Default)]
struct PoolInner {
    /// Idle, reusable connections (each at `ReadyForQuery` idle).
    idle: Vec<TokioTcpStream>,
    /// The `StartupMessage` frame used to bring up new connections.
    startup_template: Option<BytesMut>,
    /// `ParameterStatus` frames captured at startup, replayed to clients.
    params: Option<Vec<BytesMut>>,
}

impl BackendPool {
    /// Create a pool of up to `max_size` connections to `address`.
    pub fn new(address: impl Into<String>, max_size: usize) -> Arc<Self> {
        Arc::new(Self {
            address: address.into(),
            permits: Arc::new(Semaphore::new(max_size.max(1))),
            inner: Mutex::new(PoolInner::default()),
        })
    }

    /// The captured `ParameterStatus` frames to replay to a client, available
    /// once at least one backend has been established.
    pub fn params(&self) -> Vec<BytesMut> {
        self.inner.lock().unwrap().params.clone().unwrap_or_default()
    }

    /// Check out a connection, establishing a new one (using `startup_frame` as
    /// the template the first time) if none are idle. Blocks once `max_size`
    /// connections are concurrently in use.
    pub async fn checkout(
        self: &Arc<Self>,
        startup_frame: &[u8],
    ) -> Result<PooledBackend, BoxError> {
        let permit = self.permits.clone().acquire_owned().await?;

        let idle = self.inner.lock().unwrap().idle.pop();
        let conn = match idle {
            Some(conn) => conn,
            None => self.establish(startup_frame).await?,
        };

        Ok(PooledBackend {
            pool: Arc::clone(self),
            conn: Some(conn),
            _permit: permit,
        })
    }

    /// Establish a fresh backend connection and bring it to `ReadyForQuery`,
    /// capturing `ParameterStatus` the first time.
    async fn establish(&self, startup_frame: &[u8]) -> Result<TokioTcpStream, BoxError> {
        let template = {
            let mut inner = self.inner.lock().unwrap();
            inner
                .startup_template
                .get_or_insert_with(|| BytesMut::from(startup_frame))
                .clone()
        };

        let mut conn = TokioTcpStream::connect(&self.address).await?;
        conn.write_all(&template).await?;
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

        let mut inner = self.inner.lock().unwrap();
        if inner.params.is_none() {
            inner.params = Some(params);
        }
        Ok(conn)
    }

    fn return_idle(&self, conn: TokioTcpStream) {
        self.inner.lock().unwrap().idle.push(conn);
    }
}

/// A connection checked out of a [`BackendPool`]. Returned to the pool on
/// [`checkin`](Self::checkin); on drop without checkin it is discarded (a
/// possibly-dirty connection is never reused). The capacity permit is released
/// in all cases.
pub struct PooledBackend {
    pool: Arc<BackendPool>,
    conn: Option<TokioTcpStream>,
    _permit: OwnedSemaphorePermit,
}

impl PooledBackend {
    /// The underlying stream, for relaying.
    pub fn stream(&mut self) -> &mut TokioTcpStream {
        self.conn.as_mut().expect("connection checked out")
    }

    /// Return the connection to the pool for reuse (call at a transaction end,
    /// `ReadyForQuery` status `I`).
    pub fn checkin(mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_idle(conn);
        }
    }

    /// Discard the connection (e.g. the client left mid-transaction); it is not
    /// returned to the pool.
    pub fn discard(mut self) {
        self.conn = None;
    }
}
