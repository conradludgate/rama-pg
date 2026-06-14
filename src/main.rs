//! rama-pg proxy binary.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use rama::error::BoxError;
use rama::net::tls::server::SelfSignedData;
use rama::tcp::server::TcpListener;
use rama::tls::rustls::server::TlsAcceptorDataBuilder;
use rama_pg::auth::{Auth, CleartextPassword, PassThrough};
use rama_pg::proxy::PgProxy;
use rama_pg::route::{Backend, Router};
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

    let router = Arc::new(build_router());
    if router.is_empty() {
        tracing::warn!("no routes configured; set RAMA_PG_BACKEND and/or RAMA_PG_ROUTES");
    }

    let auth = Arc::new(build_auth());

    let listen = env::var("RAMA_PG_LISTEN").unwrap_or_else(|_| "127.0.0.1:6432".to_owned());
    tracing::info!(%listen, "rama-pg listening");

    TcpListener::bind(listen.as_str())
        .await?
        .serve(PgProxy::new(tls, router, auth))
        .await;

    Ok(())
}

/// Build the SNI router from environment configuration:
///
/// - `RAMA_PG_BACKEND` — catch-all backend `host:port`.
/// - `RAMA_PG_ROUTES` — `sni=host:port` pairs separated by `;`.
fn build_router() -> Router {
    let mut router = Router::new();

    if let Ok(default) = env::var("RAMA_PG_BACKEND") {
        router = router.with_default(Backend::new(default));
    }

    if let Ok(routes) = env::var("RAMA_PG_ROUTES") {
        for pair in routes.split(';').filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some((sni, addr)) => router = router.with_route(sni.trim(), Backend::new(addr.trim())),
                None => tracing::warn!(pair, "ignoring malformed RAMA_PG_ROUTES entry"),
            }
        }
    }

    router
}

/// Select the authenticator from environment configuration:
///
/// - `RAMA_PG_AUTH` — `passthrough` (default) or `cleartext`.
/// - `RAMA_PG_USERS` — `user:password` pairs separated by `;` (cleartext mode).
fn build_auth() -> Auth {
    if env::var("RAMA_PG_AUTH").as_deref() == Ok("cleartext") {
        let mut credentials = HashMap::new();
        if let Ok(users) = env::var("RAMA_PG_USERS") {
            for entry in users.split(';').filter(|e| !e.is_empty()) {
                match entry.split_once(':') {
                    Some((user, password)) => {
                        credentials.insert(user.trim().to_owned(), password.to_owned());
                    }
                    None => tracing::warn!(entry, "ignoring malformed RAMA_PG_USERS entry"),
                }
            }
        }
        tracing::info!(users = credentials.len(), "auth mode: cleartext (terminate)");
        Auth::Cleartext(CleartextPassword::new(credentials))
    } else {
        tracing::info!("auth mode: pass-through");
        Auth::PassThrough(PassThrough)
    }
}
