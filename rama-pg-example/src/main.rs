//! Example binary wiring the `rama-pg` library into a runnable proxy.
//!
//! Configuration is environment-driven so the same binary can demonstrate both
//! pass-through and terminating auth against different backends.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use rama::error::BoxError;
use rama::net::tls::server::SelfSignedData;
use rama::rt::Executor;
use rama::tcp::server::TcpListener;
use rama::tls::rustls::server::TlsAcceptorDataBuilder;
use rama_pg::auth::{Auth, CleartextPassword, PassThrough, StaticPasswordValidator};
use rama_pg::pool::BackendPool;
use rama_pg::proxy::PgProxy;
use rama_pg::route::{Backend, Router};
use rama_pg::scram::{ScramSecret, ScramSha256, StaticSecretStore};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rama_pg=debug")),
        )
        .init();

    // Self-signed cert for now; real SNI-matched certs arrive with routing.
    let tls = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData::default())?.build();

    let router = Arc::new(build_router());
    if router.is_empty() {
        tracing::warn!("no routes configured; set RAMA_PG_BACKEND and/or RAMA_PG_ROUTES");
    }

    let auth = Arc::new(build_auth());
    let pool = build_pool();
    let proxy = Arc::new(PgProxy::new(tls, router, auth, pool));

    let listen = env::var("RAMA_PG_LISTEN").unwrap_or_else(|_| "127.0.0.1:6432".to_owned());
    tracing::info!(%listen, "rama-pg listening");

    TcpListener::bind_address(listen.as_str(), Executor::new())
        .await?
        .serve(proxy)
        .await;

    Ok(())
}

/// Build the backend pool when transaction pooling is enabled:
///
/// - `RAMA_PG_POOL_SIZE` — max backend connections (total); enables pooling.
/// - `RAMA_PG_REPLICAS` — `host:port` replicas separated by `,` to round-robin
///   across (falls back to `RAMA_PG_BACKEND` as a single replica).
fn build_pool() -> Option<Arc<BackendPool>> {
    let size: usize = env::var("RAMA_PG_POOL_SIZE").ok()?.parse().ok()?;
    let replicas: Vec<String> = match env::var("RAMA_PG_REPLICAS") {
        Ok(list) => list
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => env::var("RAMA_PG_BACKEND").ok().into_iter().collect(),
    };
    if replicas.is_empty() {
        tracing::warn!("RAMA_PG_POOL_SIZE set but no RAMA_PG_REPLICAS/RAMA_PG_BACKEND; pooling disabled");
        return None;
    }
    tracing::info!(size, ?replicas, "transaction pooling enabled");
    Some(BackendPool::new(replicas, size))
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
/// - `RAMA_PG_AUTH` — `passthrough` (default), `cleartext`, or `scram`.
/// - `RAMA_PG_USERS` — `user:password` pairs separated by `;` (cleartext mode).
/// - `RAMA_PG_SCRAM_SECRETS` — `user=SCRAM-SHA-256$...` verifiers separated by
///   `;` (scram mode; copy from Postgres `pg_authid.rolpassword`).
fn build_auth() -> Auth {
    match env::var("RAMA_PG_AUTH").as_deref() {
        Ok("cleartext") => {
            let credentials = parse_users();
            tracing::info!(users = credentials.len(), "auth mode: cleartext (terminate)");
            Auth::Cleartext(CleartextPassword::new(StaticPasswordValidator::new(credentials)))
        }
        Ok("scram") => {
            let store = build_scram_store();
            tracing::info!("auth mode: scram-sha-256 (terminate + upstream reauth)");
            Auth::Scram(ScramSha256::new(store))
        }
        _ => {
            tracing::info!("auth mode: pass-through");
            Auth::PassThrough(PassThrough)
        }
    }
}

/// Parse `RAMA_PG_USERS` (`user:password` pairs separated by `;`).
fn parse_users() -> HashMap<String, String> {
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
    credentials
}

/// Build the SCRAM verifier store from `RAMA_PG_SCRAM_SECRETS`.
fn build_scram_store() -> StaticSecretStore {
    let mut store = StaticSecretStore::new();
    if let Ok(secrets) = env::var("RAMA_PG_SCRAM_SECRETS") {
        for entry in secrets.split(';').filter(|e| !e.is_empty()) {
            match entry.split_once('=') {
                Some((user, verifier)) => match ScramSecret::parse(verifier.trim()) {
                    Ok(secret) => store = store.with_secret(user.trim(), secret),
                    Err(err) => tracing::warn!(user, %err, "ignoring invalid SCRAM verifier"),
                },
                None => tracing::warn!(entry, "ignoring malformed RAMA_PG_SCRAM_SECRETS entry"),
            }
        }
    }
    if store.is_empty() {
        tracing::warn!("scram mode but no verifiers; set RAMA_PG_SCRAM_SECRETS");
    }
    store
}
