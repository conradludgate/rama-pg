//! A pgbouncer-like proxy built on `rama-pg`.
//!
//! Demonstrates how the pieces compose via `PgProxy::with_forwarder`:
//!
//! - **SCRAM auth, verifier fetched from `pg_authid` on demand** ([`PgAuthidStore`]).
//! - A **forwarder that routes on the startup database**: connections to the
//!   special `pgbouncer` database get the admin console (custom in-proxy `SHOW`
//!   queries, no backend); everything else is **pooled** with a configurable
//!   mode (session / transaction / statement).
//! - Live-ish **admin stats** shared between the pool path and the console.
//!
//! Config (env): `RAMA_PG_LISTEN`, `RAMA_PG_BACKEND` (also the `pg_authid`
//! source), `RAMA_PG_REPLICAS`, `RAMA_PG_POOL_SIZE`, `RAMA_PG_POOL_MODE`,
//! `RAMA_PG_ADMIN_USER`, `RAMA_PG_ADMIN_DB`.

use std::env;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rama::Service;
use rama::error::BoxError;
use rama::net::tls::server::SelfSignedData;
use rama::rt::Executor;
use rama::tcp::server::TcpListener;
use rama::tls::rustls::server::TlsAcceptorDataBuilder;
use rama_pg::pool::{BackendPool, PoolMode};
use rama_pg::proxy::{CustomForwarder, PgClient, PgProxy, PooledForwarder};
use rama_pg::query::{QueryContext, QueryHandler, QueryResponse};
use rama_pg::scram::{PgAuthidStore, ScramSha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing_subscriber::EnvFilter;

/// The special database whose connections get the admin console.
const ADMIN_DB: &str = "pgbouncer";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rama_pg=debug")),
        )
        .init();

    let tls = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData::default())?.build();

    let backend = env::var("RAMA_PG_BACKEND").unwrap_or_else(|_| "127.0.0.1:5434".to_owned());
    let admin_user = env::var("RAMA_PG_ADMIN_USER").unwrap_or_else(|_| "postgres".to_owned());
    let admin_db = env::var("RAMA_PG_ADMIN_DB").unwrap_or_else(|_| "postgres".to_owned());
    let max_size: usize = env::var("RAMA_PG_POOL_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let mode = match env::var("RAMA_PG_POOL_MODE").as_deref() {
        Ok("session") => PoolMode::Session,
        Ok("statement") => PoolMode::Statement,
        _ => PoolMode::Transaction,
    };
    let replicas: Vec<String> = match env::var("RAMA_PG_REPLICAS") {
        Ok(list) => list.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect(),
        Err(_) => vec![backend.clone()],
    };

    // SCRAM auth, verifier fetched from pg_authid over an admin connection.
    let auth = Arc::new(ScramSha256::new(PgAuthidStore::new(
        backend.clone(),
        admin_user,
        admin_db,
    )));

    let stats = Arc::new(Stats::new(mode, max_size, replicas.clone()));
    let forwarder = PgBouncerForwarder {
        admin: CustomForwarder::new(Arc::new(AdminConsole { stats: stats.clone() })),
        pool: PooledForwarder::new(BackendPool::new(replicas, max_size, mode)),
        stats,
    };

    let proxy = Arc::new(PgProxy::with_forwarder(tls, auth, forwarder));
    let listen = env::var("RAMA_PG_LISTEN").unwrap_or_else(|_| "127.0.0.1:6432".to_owned());
    tracing::info!(%listen, %backend, ?mode, "pgbouncer-like proxy listening");

    TcpListener::bind_address(listen.as_str(), Executor::new())
        .await?
        .serve(proxy)
        .await;
    Ok(())
}

/// Routes connections by their startup database: the `pgbouncer` database to the
/// admin console, everything else to the pool (tracking the connection in stats).
struct PgBouncerForwarder {
    admin: CustomForwarder,
    pool: PooledForwarder,
    stats: Arc<Stats>,
}

impl<IO> Service<PgClient<IO>> for PgBouncerForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        if client.startup.database() == Some(ADMIN_DB) {
            return self.admin.serve(client).await;
        }

        let user = client.startup.user().unwrap_or_default().to_owned();
        let database = client.startup.database().unwrap_or_default().to_owned();
        let id = self.stats.register(&user, &database);
        let result = self.pool.serve(client).await;
        self.stats.deregister(id);
        result
    }
}

/// Shared runtime stats, written by the pool path and read by the admin console.
struct Stats {
    mode: PoolMode,
    max_size: usize,
    replicas: Vec<String>,
    total_connections: AtomicU64,
    next_id: AtomicU64,
    clients: Mutex<Vec<ClientEntry>>,
}

#[derive(Clone)]
struct ClientEntry {
    id: u64,
    user: String,
    database: String,
}

impl Stats {
    fn new(mode: PoolMode, max_size: usize, replicas: Vec<String>) -> Self {
        Self {
            mode,
            max_size,
            replicas,
            total_connections: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            clients: Mutex::new(Vec::new()),
        }
    }

    fn register(&self, user: &str, database: &str) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.clients.lock().unwrap().push(ClientEntry {
            id,
            user: user.to_owned(),
            database: database.to_owned(),
        });
        id
    }

    fn deregister(&self, id: u64) {
        self.clients.lock().unwrap().retain(|client| client.id != id);
    }

    fn active(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

/// The admin console: answers a handful of `SHOW` commands from [`Stats`].
struct AdminConsole {
    stats: Arc<Stats>,
}

impl QueryHandler for AdminConsole {
    fn handle<'a>(
        &'a self,
        _ctx: QueryContext<'a>,
        sql: &'a str,
    ) -> Pin<Box<dyn Future<Output = QueryResponse> + Send + 'a>> {
        Box::pin(async move {
            let command = sql.trim().trim_end_matches(';').trim().to_ascii_uppercase();
            match command.as_str() {
                "SHOW POOLS" => rows(
                    &["database", "mode", "max_conn", "cl_active"],
                    vec![vec![
                        "*".to_owned(),
                        format!("{:?}", self.stats.mode).to_lowercase(),
                        self.stats.max_size.to_string(),
                        self.stats.active().to_string(),
                    ]],
                ),
                "SHOW CLIENTS" => {
                    let data = self
                        .stats
                        .clients
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|c| vec![c.id.to_string(), c.user.clone(), c.database.clone(), "active".to_owned()])
                        .collect();
                    rows(&["client_id", "user", "database", "state"], data)
                }
                "SHOW STATS" => rows(
                    &["total_connections", "active_clients"],
                    vec![vec![
                        self.stats.total_connections.load(Ordering::Relaxed).to_string(),
                        self.stats.active().to_string(),
                    ]],
                ),
                "SHOW LISTS" => rows(
                    &["list", "items"],
                    vec![
                        vec!["replicas".to_owned(), self.stats.replicas.len().to_string()],
                        vec!["clients".to_owned(), self.stats.active().to_string()],
                    ],
                ),
                "SHOW VERSION" => rows(&["version"], vec![vec!["rama-pg pgbouncer-like 0.1".to_owned()]]),
                other if other.starts_with("SHOW") => {
                    QueryResponse::error("0A000", format!("unsupported console command: {other}"))
                }
                _ => QueryResponse::error(
                    "0A000",
                    "rama-pg console: only SHOW POOLS/CLIENTS/STATS/LISTS/VERSION are supported",
                ),
            }
        })
    }
}

/// Build a `QueryResponse::Rows` from string columns and rows.
fn rows(columns: &[&str], data: Vec<Vec<String>>) -> QueryResponse {
    let tag = format!("SELECT {}", data.len());
    QueryResponse::Rows {
        columns: columns.iter().map(|c| (*c).to_owned()).collect(),
        rows: data
            .into_iter()
            .map(|row| row.into_iter().map(Some).collect())
            .collect(),
        tag,
    }
}
