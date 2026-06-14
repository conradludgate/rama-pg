//! rama-pg proxy binary.

use std::env;

use rama::error::BoxError;
use rama::net::tls::server::SelfSignedData;
use rama::tcp::server::TcpListener;
use rama::tls::rustls::server::TlsAcceptorDataBuilder;
use rama_pg::proxy::PgProxy;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rama_pg=debug")),
        )
        .init();

    // Self-signed cert for now; real SNI-matched certs arrive with routing.
    let tls = TlsAcceptorDataBuilder::new_self_signed(SelfSignedData::default())?.build();

    let listen = env::var("RAMA_PG_LISTEN").unwrap_or_else(|_| "127.0.0.1:6432".to_owned());
    tracing::info!(%listen, "rama-pg listening");

    TcpListener::bind(listen.as_str())
        .await?
        .serve(PgProxy::new(tls))
        .await;

    Ok(())
}
