use std::{io, sync::Arc, time::Duration};

use rama::{Service, service::service_fn};
use rama_pg::{
    auth::ClientAuth,
    cancel::NoCancellation,
    protocol::{
        codec, message,
        startup::{self, ProtocolVersion, StartupRequest},
    },
    proxy::{DirectForwarder, PgClient},
    route::{Backend, Router},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    net::TcpListener,
};

fn client(stream: DuplexStream) -> PgClient<DuplexStream> {
    let StartupRequest::Startup(startup) = StartupRequest::parse(
        startup::startup_message(&[("user", "alice"), ("database", "analytics")]).freeze(),
    )
    .unwrap() else {
        panic!("startup fixture")
    };
    PgClient {
        stream,
        startup,
        protocol_version: ProtocolVersion::V3_0,
        sni: Some("tenant.example".to_owned()),
        auth: ClientAuth::PassThrough,
    }
}

#[tokio::test]
async fn async_routing_selects_a_backend_using_startup_metadata() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let backend = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let request = startup::read_startup_frame(&mut io).await.unwrap();
            let StartupRequest::Startup(startup) = StartupRequest::parse(request.freeze()).unwrap()
            else {
                panic!("startup")
            };
            assert_eq!(startup.user(), Some("alice"));
            assert_eq!(startup.database(), Some("analytics"));
            io.write_all(&message::authentication_ok()).await.unwrap();
            io.write_all(&message::ready_for_query(b'I')).await.unwrap();
            let query = codec::read_message(&mut io).await.unwrap();
            assert_eq!(query.payload(), b"select 1\0");
            io.write_all(&codec::frame(codec::COMMAND_COMPLETE, b"SELECT 1\0"))
                .await
                .unwrap();
        });
        let router = service_fn(move |client: PgClient<DuplexStream>| {
            let address = address.clone();
            async move {
                // A control-plane lookup may suspend without cloning startup
                // parameters or losing the client's transport.
                tokio::task::yield_now().await;
                assert_eq!(client.startup.user(), Some("alice"));
                assert_eq!(client.startup.database(), Some("analytics"));
                assert_eq!(client.sni.as_deref(), Some("tenant.example"));
                assert!(matches!(client.auth, ClientAuth::PassThrough));
                Ok::<_, io::Error>((client, Some(Backend::new(address))))
            }
        });
        let forwarder = DirectForwarder::new(router, Arc::new(NoCancellation));
        let (mut frontend, stream) = tokio::io::duplex(1024);
        let driver = tokio::spawn(async move { forwarder.serve(client(stream)).await });
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::AUTHENTICATION
        );
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().tag(),
            codec::READY_FOR_QUERY
        );
        let query = codec::frame(codec::QUERY, b"select 1\0");
        frontend.write_all(&query).await.unwrap();
        assert_eq!(
            codec::read_message(&mut frontend).await.unwrap().as_bytes(),
            codec::frame(codec::COMMAND_COMPLETE, b"SELECT 1\0")
        );
        frontend.shutdown().await.unwrap();
        driver.await.unwrap().unwrap();
        backend.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn missing_route_returns_a_postgres_error() {
    let router =
        service_fn(|client: PgClient<DuplexStream>| async { Ok::<_, io::Error>((client, None)) });
    let forwarder = DirectForwarder::new(router, Arc::new(NoCancellation));
    let (mut frontend, stream) = tokio::io::duplex(1024);
    forwarder.serve(client(stream)).await.unwrap();
    let error = codec::read_message(&mut frontend).await.unwrap();
    assert_eq!(error.tag(), codec::ERROR_RESPONSE);
    assert!(error.payload().windows(5).any(|bytes| bytes == b"08004"));
}

#[tokio::test]
async fn routing_errors_keep_their_original_type() {
    let router = service_fn(|_: PgClient<DuplexStream>| async {
        Err::<(PgClient<DuplexStream>, Option<Backend>), _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied",
        ))
    });
    let forwarder = DirectForwarder::new(router, Arc::new(NoCancellation));
    let (_, stream) = tokio::io::duplex(1024);
    let error = forwarder.serve(client(stream)).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn static_router_is_also_a_rama_service() {
    let router = Arc::new(
        Router::new()
            .with_default(Backend::new("fallback:5432"))
            .with_route("tenant.example", Backend::new("tenant:5432")),
    );
    let (_, stream) = tokio::io::duplex(1024);
    let (client, backend) = router.serve(client(stream)).await.unwrap();
    assert_eq!(backend.unwrap().address, "tenant:5432");
    assert_eq!(client.startup.database(), Some("analytics"));
}
