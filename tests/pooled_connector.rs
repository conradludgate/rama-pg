use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use rama::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
};
use rama_pg::{
    auth::{BackendAuth, ClientAuth},
    cancel::{Cancellation, RegistryCancellation},
    connect::BackendConnection,
    pool::{BackendPool, PoolMode, StaticBackendCredentials, TrustBackend},
    protocol::{
        codec, message,
        startup::{self, CancelKey, ProtocolVersion, StartupRequest},
    },
    proxy::{PgClient, PooledForwarder},
    route::Backend,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{Notify, mpsc},
    task::JoinSet,
};

struct Stream {
    io: DuplexStream,
    extensions: Extensions,
    drops: Arc<AtomicUsize>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
impl ExtensionsRef for Stream {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn key(id: usize) -> CancelKey {
    CancelKey::from_bytes(Bytes::copy_from_slice(&(id as u64).to_be_bytes()))
}

// Intentionally not Clone: the pool retains one shared target for the backend.
struct Cancel {
    id: usize,
    sent: mpsc::UnboundedSender<(usize, CancelKey)>,
    notify: Arc<Notify>,
}
impl Service<CancelKey> for Cancel {
    type Output = ();
    type Error = io::Error;
    async fn serve(&self, key: CancelKey) -> io::Result<()> {
        self.sent
            .send((self.id, key))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.notify.notify_one();
        Ok(())
    }
}

struct Connector {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    cancelled: mpsc::UnboundedSender<(usize, CancelKey)>,
    queries: mpsc::UnboundedSender<(usize, Vec<u8>)>,
    tasks: Mutex<JoinSet<()>>,
    password: bool,
    fail_reset: bool,
}

struct Observe {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    cancelled: mpsc::UnboundedReceiver<(usize, CancelKey)>,
    queries: mpsc::UnboundedReceiver<(usize, Vec<u8>)>,
}

fn connector(password: bool, fail_reset: bool) -> (Connector, Observe) {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let (cancelled, cancels) = mpsc::unbounded_channel();
    let (queries, observed) = mpsc::unbounded_channel();
    (
        Connector {
            calls: calls.clone(),
            drops: drops.clone(),
            cancelled,
            queries,
            tasks: Mutex::new(JoinSet::new()),
            password,
            fail_reset,
        },
        Observe {
            calls,
            drops,
            cancelled: cancels,
            queries: observed,
        },
    )
}

impl Service<Backend> for Connector {
    type Output = BackendConnection<Stream, Cancel>;
    type Error = BoxError;
    async fn serve(&self, backend: Backend) -> Result<Self::Output, BoxError> {
        assert_eq!(backend.address, "logical-replica");
        let id = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        let (io, server) = tokio::io::duplex(4096);
        let notify = Arc::new(Notify::new());
        self.tasks.lock().unwrap().spawn(backend_session(
            server,
            id,
            self.password,
            self.fail_reset,
            self.queries.clone(),
            notify.clone(),
        ));
        Ok(BackendConnection {
            conn: Stream {
                io,
                extensions: Extensions::new(),
                drops: self.drops.clone(),
            },
            cancellation: Cancel {
                id,
                sent: self.cancelled.clone(),
                notify,
            },
        })
    }
}

async fn backend_session(
    mut io: DuplexStream,
    id: usize,
    password: bool,
    fail_reset: bool,
    queries: mpsc::UnboundedSender<(usize, Vec<u8>)>,
    cancel: Arc<Notify>,
) {
    let Ok(frame) = startup::read_startup_frame(&mut io).await else {
        return;
    };
    assert!(matches!(
        StartupRequest::parse(frame.freeze()).unwrap(),
        StartupRequest::Startup(_)
    ));
    if password {
        io.write_all(&message::authentication_cleartext_password())
            .await
            .unwrap();
        let Ok(reply) = codec::read_message(&mut io).await else {
            return;
        };
        assert_eq!(reply.tag(), codec::PASSWORD_MESSAGE);
        assert_eq!(reply.payload(), b"secret\0");
    }
    io.write_all(&message::authentication_ok()).await.unwrap();
    io.write_all(&message::parameter_status(
        "test_connection",
        &id.to_string(),
    ))
    .await
    .unwrap();
    io.write_all(&message::backend_key_data_raw(key(id).as_bytes()))
        .await
        .unwrap();
    io.write_all(&message::ready_for_query(b'I')).await.unwrap();
    while let Ok(message) = codec::read_message(&mut io).await {
        if message.tag() == codec::TERMINATE {
            break;
        }
        assert_eq!(message.tag(), codec::QUERY);
        let query = message.payload();
        let _ = queries.send((id, query.to_vec()));
        if query == b"DISCARD ALL\0" && fail_reset {
            let _ = io
                .write_all(&codec::frame(
                    codec::ERROR_RESPONSE,
                    b"SERROR\0CXX000\0Mreset failed\0\0",
                ))
                .await;
            return;
        }
        if query == b"WAIT\0" {
            cancel.notified().await;
            if io
                .write_all(&codec::frame(
                    codec::ERROR_RESPONSE,
                    b"SERROR\0C57014\0Mcancelled\0\0",
                ))
                .await
                .is_err()
            {
                return;
            }
        } else if io
            .write_all(&codec::frame(codec::COMMAND_COMPLETE, b"OK\0"))
            .await
            .is_err()
        {
            return;
        }
        if io.write_all(&message::ready_for_query(b'I')).await.is_err() {
            return;
        }
    }
}

fn startup() -> Bytes {
    startup::startup_message(&[("user", "alice"), ("database", "app")]).freeze()
}

fn client(stream: DuplexStream) -> PgClient<DuplexStream> {
    let StartupRequest::Startup(startup) = StartupRequest::parse(startup()).unwrap() else {
        panic!("startup fixture")
    };
    PgClient {
        stream,
        startup,
        protocol_version: ProtocolVersion::V3_0,
        sni: None,
        auth: ClientAuth::Terminated(BackendAuth::Trust),
    }
}

async fn startup_key(frontend: &mut DuplexStream) -> CancelKey {
    let mut key = None;
    loop {
        let message = codec::read_message(frontend).await.unwrap();
        if message.tag() == codec::BACKEND_KEY_DATA {
            key = Some(CancelKey::from_bytes(Bytes::copy_from_slice(
                message.payload(),
            )));
        }
        if message.tag() == codec::READY_FOR_QUERY {
            return key.unwrap();
        }
    }
}

async fn query(frontend: &mut DuplexStream, sql: &[u8], response: u8) {
    frontend
        .write_all(&codec::frame(codec::QUERY, sql))
        .await
        .unwrap();
    assert_eq!(codec::read_message(frontend).await.unwrap().tag(), response);
    assert_eq!(
        codec::read_message(frontend).await.unwrap().tag(),
        codec::READY_FOR_QUERY
    );
}

#[tokio::test]
async fn typed_pool_reuses_stream_and_retains_one_cancel_target() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, mut seen) = connector(false, false);
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Transaction,
            Arc::new(TrustBackend),
            connector,
        );
        let first = pool.lease(&startup(), "alice", "app").await.unwrap();
        let target = first.cancel_target().unwrap();
        first.checkin();
        let second = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_eq!(seen.calls.load(Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(&target, &second.cancel_target().unwrap()));
        target.cancel().await.unwrap();
        assert_eq!(seen.cancelled.recv().await.unwrap(), (1, key(1)));
        second.discard();
        assert_eq!(seen.drops.load(Ordering::Relaxed), 1);
        let third = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_eq!(seen.calls.load(Ordering::Relaxed), 2);
        assert!(!Arc::ptr_eq(&target, &third.cancel_target().unwrap()));
        drop(third);
        assert_eq!(seen.drops.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn transaction_forwarding_resets_before_reuse() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, mut seen) = connector(false, false);
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Transaction,
            Arc::new(TrustBackend),
            connector,
        );
        let forwarder = PooledForwarder::new(pool.clone(), Arc::new(RegistryCancellation::new()));
        let (mut frontend, stream) = tokio::io::duplex(4096);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        startup_key(&mut frontend).await;
        query(&mut frontend, b"SELECT 1\0", codec::COMMAND_COMPLETE).await;
        query(&mut frontend, b"SELECT 2\0", codec::COMMAND_COMPLETE).await;
        frontend
            .write_all(&codec::frame(codec::TERMINATE, b""))
            .await
            .unwrap();
        driver.await.unwrap().unwrap();
        assert_eq!(seen.calls.load(Ordering::Relaxed), 1);
        let mut events = Vec::new();
        while let Ok(event) = seen.queries.try_recv() {
            events.push(event);
        }
        assert_eq!(
            events,
            vec![
                (1, b"SELECT 1\0".to_vec()),
                (1, b"DISCARD ALL\0".to_vec()),
                (1, b"SELECT 2\0".to_vec()),
                (1, b"DISCARD ALL\0".to_vec())
            ]
        );
        drop(pool);
        assert_eq!(seen.drops.load(Ordering::Relaxed), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_reset_discards_backend_before_next_query() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, seen) = connector(false, true);
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Transaction,
            Arc::new(TrustBackend),
            connector,
        );
        let forwarder = PooledForwarder::new(pool.clone(), Arc::new(RegistryCancellation::new()));
        let (mut frontend, stream) = tokio::io::duplex(4096);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        startup_key(&mut frontend).await;
        query(&mut frontend, b"SELECT 1\0", codec::COMMAND_COMPLETE).await;
        query(&mut frontend, b"SELECT 2\0", codec::COMMAND_COMPLETE).await;
        frontend
            .write_all(&codec::frame(codec::TERMINATE, b""))
            .await
            .unwrap();
        driver.await.unwrap().unwrap();
        assert_eq!(seen.calls.load(Ordering::Relaxed), 2);
        assert_eq!(seen.drops.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn active_query_cancellation_uses_the_leased_backend_service() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, mut seen) = connector(false, false);
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Transaction,
            Arc::new(TrustBackend),
            connector,
        );
        let registry = Arc::new(RegistryCancellation::new());
        let forwarder = PooledForwarder::new(pool, registry.clone());
        let (mut frontend, stream) = tokio::io::duplex(4096);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        let advertised = startup_key(&mut frontend).await;
        frontend
            .write_all(&codec::frame(codec::QUERY, b"WAIT\0"))
            .await
            .unwrap();
        assert_eq!(seen.queries.recv().await.unwrap(), (1, b"WAIT\0".to_vec()));
        registry.cancel(advertised).await.unwrap();
        assert_eq!(seen.cancelled.recv().await.unwrap(), (1, key(1)));
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::ERROR_RESPONSE
        );
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::READY_FOR_QUERY
        );
        frontend
            .write_all(&codec::frame(codec::TERMINATE, b""))
            .await
            .unwrap();
        driver.await.unwrap().unwrap();
        assert!(registry.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn backend_credentials_remain_separate_from_transport() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, seen) = connector(true, false);
        let credentials =
            Arc::new(StaticBackendCredentials::new().with_password("alice", "secret"));
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Transaction,
            credentials,
            connector,
        );
        let lease = pool.lease(&startup(), "alice", "app").await.unwrap();
        lease.discard();
        let bob = startup::startup_message(&[("user", "bob"), ("database", "app")]);
        assert!(pool.lease(&bob, "bob", "app").await.is_err());
        assert_eq!(seen.calls.load(Ordering::Relaxed), 2);
        assert_eq!(seen.drops.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn session_mode_discards_its_opaque_relay_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connector, seen) = connector(false, false);
        let pool = BackendPool::with_connector(
            vec!["logical-replica".into()],
            1,
            PoolMode::Session,
            Arc::new(TrustBackend),
            connector,
        );
        let forwarder = PooledForwarder::new(pool, Arc::new(RegistryCancellation::new()));
        let (mut frontend, stream) = tokio::io::duplex(4096);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        startup_key(&mut frontend).await;
        query(&mut frontend, b"SELECT 1\0", codec::COMMAND_COMPLETE).await;
        frontend
            .write_all(&codec::frame(codec::TERMINATE, b""))
            .await
            .unwrap();
        frontend.shutdown().await.unwrap();
        driver.await.unwrap().unwrap();
        assert_eq!(seen.calls.load(Ordering::Relaxed), 1);
        assert_eq!(seen.drops.load(Ordering::Relaxed), 1);
    })
    .await
    .unwrap();
}
