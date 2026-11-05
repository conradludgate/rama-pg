use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rama::Service;
use rama::extensions::{Extensions, ExtensionsRef};
use rama::layer::{Layer, MapInputLayer};
use rama::service::service_fn;
use rama_pg::auth::{ClientAuth, PassThrough};
use rama_pg::cancel::NoCancellation;
use rama_pg::protocol::{codec, startup};
use rama_pg::proxy::{PgClient, PgSession};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

// A transport owned by the caller, with the same extension seam Rama's TCP/TLS
// streams expose. No TCP socket or TLS implementation is involved.
struct Transport {
    io: DuplexStream,
    extensions: Extensions,
}

impl Transport {
    fn new(io: DuplexStream) -> Self {
        Self {
            io,
            extensions: Extensions::new(),
        }
    }
}

impl ExtensionsRef for Transport {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Transport {
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

#[tokio::test]
async fn session_composes_a_rama_layer_and_preserves_pipelined_input() {
    let forwarder = service_fn(|mut client: PgClient<Transport>| async move {
        assert_eq!(client.startup.user(), Some("alice"));
        assert_eq!(client.startup.database(), Some("app"));
        assert_eq!(client.sni.as_deref(), Some("selected.example"));
        assert!(matches!(client.auth, ClientAuth::PassThrough));
        let query = codec::read_message(&mut client.stream).await?;
        assert_eq!(query.tag(), codec::QUERY);
        assert_eq!(query.payload(), b"select 1\0");
        client.stream.write_all(b"ok").await
    });
    let forwarder = MapInputLayer::new(|mut client: PgClient<Transport>| {
        assert!(client.sni.is_none());
        client.sni = Some("selected.example".to_owned());
        client
    })
    .layer(forwarder);
    let session = PgSession::new(Arc::new(PassThrough), forwarder, Arc::new(NoCancellation));

    let (mut client, server) = tokio::io::duplex(1024);
    client
        .write_all(&startup::startup_message(&[
            ("user", "alice"),
            ("database", "app"),
        ]))
        .await
        .unwrap();
    client
        .write_all(&codec::frame(codec::QUERY, b"select 1\0"))
        .await
        .unwrap();
    session.serve(Transport::new(server)).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
}

#[tokio::test]
async fn session_accepts_a_forwarder_with_its_own_error_type() {
    let forwarder = service_fn(|_: PgClient<Transport>| async {
        Err::<(), _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy rejected session",
        ))
    });
    let session = PgSession::new(Arc::new(PassThrough), forwarder, Arc::new(NoCancellation));
    let (mut client, server) = tokio::io::duplex(1024);
    client
        .write_all(&startup::startup_message(&[("user", "alice")]))
        .await
        .unwrap();
    let error = session.serve(Transport::new(server)).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}
