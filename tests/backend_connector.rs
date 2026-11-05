use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use rama::{Service, service::service_fn};
use rama_pg::{
    auth::ClientAuth,
    cancel::{Cancellation, NoCancellation, RegistryCancellation},
    connect::{BackendConnection, TcpBackendConnector},
    protocol::{
        codec, message,
        startup::{self, CancelKey, ProtocolVersion, StartupRequest},
    },
    proxy::{DirectForwarder, PgClient},
    route::Backend,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpListener,
    sync::mpsc,
};

fn key() -> CancelKey {
    CancelKey::from_bytes(Bytes::from_static(&[0, 0, 0, 1, 2, 3, 4, 5]))
}

fn client(stream: DuplexStream) -> PgClient<DuplexStream> {
    let StartupRequest::Startup(startup) =
        StartupRequest::parse(startup::startup_message(&[("user", "alice")]).freeze()).unwrap()
    else {
        panic!("startup fixture")
    };
    PgClient {
        stream,
        startup,
        protocol_version: ProtocolVersion::V3_0,
        sni: None,
        auth: ClientAuth::PassThrough,
    }
}

#[derive(Clone)]
struct RecordCancel(mpsc::Sender<CancelKey>);

impl Service<CancelKey> for RecordCancel {
    type Output = ();
    type Error = io::Error;
    async fn serve(&self, key: CancelKey) -> io::Result<()> {
        self.0
            .send(key)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

struct Connector {
    stream: Mutex<Option<DuplexStream>>,
    cancellation: RecordCancel,
}

// Custom targets can carry connection policy rather than a TCP address.
struct TenantTarget(&'static str);

impl Service<TenantTarget> for Connector {
    type Output = BackendConnection<DuplexStream, RecordCancel>;
    type Error = io::Error;
    async fn serve(&self, backend: TenantTarget) -> io::Result<Self::Output> {
        // This is a logical route, deliberately not a dialable TCP address.
        assert_eq!(backend.0, "tenant-route");
        Ok(BackendConnection {
            conn: self.stream.lock().unwrap().take().unwrap(),
            cancellation: self.cancellation.clone(),
        })
    }
}

async fn scripted_backend(mut io: DuplexStream) {
    startup::read_startup_frame(&mut io).await.unwrap();
    io.write_all(&message::authentication_ok()).await.unwrap();
    io.write_all(&message::backend_key_data_raw(key().as_bytes()))
        .await
        .unwrap();
    io.write_all(&message::ready_for_query(b'I')).await.unwrap();
    tokio::io::copy(&mut io, &mut tokio::io::sink())
        .await
        .unwrap();
}

#[tokio::test]
async fn injected_transport_supplies_the_actual_cancellation_service() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (conn, backend_io) = tokio::io::duplex(1024);
        let backend = tokio::spawn(scripted_backend(backend_io));
        let (tx, mut rx) = mpsc::channel(1);
        let connector = Connector {
            stream: Mutex::new(Some(conn)),
            cancellation: RecordCancel(tx),
        };
        let router = service_fn(|client: PgClient<DuplexStream>| async {
            Ok::<_, io::Error>((client, Some(TenantTarget("tenant-route"))))
        });
        let registry = Arc::new(RegistryCancellation::new());
        let forwarder = DirectForwarder::new(router, registry.clone()).with_connector(connector);
        let (mut frontend, stream) = tokio::io::duplex(1024);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::AUTHENTICATION
        );
        let advertised = codec::read_message(&mut frontend).await.unwrap();
        assert_eq!(advertised.tag(), codec::BACKEND_KEY_DATA);
        let proxy_key = CancelKey::from_bytes(Bytes::copy_from_slice(advertised.payload()));
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::READY_FOR_QUERY
        );
        assert_eq!(registry.len(), 1);
        registry.cancel(proxy_key).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), key());
        frontend.shutdown().await.unwrap();
        driver.await.unwrap().unwrap();
        backend.await.unwrap();
        assert!(registry.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn disabling_mediation_preserves_the_backend_key() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (conn, backend_io) = tokio::io::duplex(1024);
        let backend = tokio::spawn(scripted_backend(backend_io));
        let (tx, mut rx) = mpsc::channel(1);
        let connector = Connector {
            stream: Mutex::new(Some(conn)),
            cancellation: RecordCancel(tx),
        };
        let router = service_fn(|client: PgClient<DuplexStream>| async {
            Ok::<_, io::Error>((client, Some(TenantTarget("tenant-route"))))
        });
        let forwarder =
            DirectForwarder::new(router, Arc::new(NoCancellation)).with_connector(connector);
        let (mut frontend, stream) = tokio::io::duplex(1024);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        codec::read_message(&mut frontend).await.unwrap();
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().payload(),
            key().as_bytes()
        );
        codec::read_message(&mut frontend).await.unwrap();
        frontend.shutdown().await.unwrap();
        driver.await.unwrap().unwrap();
        backend.await.unwrap();
        assert!(rx.recv().await.is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rama_tcp_connector_cancels_at_its_connected_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connected = TcpBackendConnector::default()
            .serve(Backend::new(listener.local_addr().unwrap().to_string()))
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let BackendConnection {
            mut conn,
            cancellation,
        } = connected;
        conn.write_all(b"hello").await.unwrap();
        let mut hello = [0; 5];
        server.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        cancellation.serve(key()).await.unwrap();
        let (mut cancel, _) = listener.accept().await.unwrap();
        let StartupRequest::Cancel(request) = StartupRequest::parse(
            startup::read_startup_frame(&mut cancel)
                .await
                .unwrap()
                .freeze(),
        )
        .unwrap() else {
            panic!("cancel request")
        };
        assert_eq!(request.key, key());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connector_failure_reports_sqlstate_08006() {
    let router = service_fn(|client: PgClient<DuplexStream>| async {
        Ok::<_, io::Error>((client, Some(Backend::new("tenant-route"))))
    });
    let connector = service_fn(|_: Backend| async {
        Err::<BackendConnection<DuplexStream, RecordCancel>, _>(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        ))
    });
    let forwarder =
        DirectForwarder::new(router, Arc::new(NoCancellation)).with_connector(connector);
    let (mut frontend, stream) = tokio::io::duplex(1024);
    forwarder.serve(client(stream)).await.unwrap();
    let error = codec::read_message(&mut frontend).await.unwrap();
    assert_eq!(error.tag(), codec::ERROR_RESPONSE);
    assert!(error.payload().windows(5).any(|s| s == b"08006"));
}

#[tokio::test]
async fn missing_route_never_invokes_the_connector() {
    let invoked = Arc::new(AtomicBool::new(false));
    let flag = invoked.clone();
    let router =
        service_fn(|client: PgClient<DuplexStream>| async { Ok::<_, io::Error>((client, None)) });
    let connector = service_fn(move |_: Backend| {
        flag.store(true, Ordering::Relaxed);
        async {
            Err::<BackendConnection<DuplexStream, RecordCancel>, _>(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            ))
        }
    });
    let forwarder =
        DirectForwarder::new(router, Arc::new(NoCancellation)).with_connector(connector);
    let (_frontend, stream) = tokio::io::duplex(1024);
    forwarder.serve(client(stream)).await.unwrap();
    assert!(!invoked.load(Ordering::Relaxed));
}
