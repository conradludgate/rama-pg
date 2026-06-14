//! Transaction-pooling forwarding (session / transaction / statement modes).

use std::sync::Arc;

use rama::Service;
use rama::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use super::{PgClient, reject, synthesize_startup};
use crate::auth::ClientAuth;
use crate::pool::{BackendPool, PoolMode};
use crate::protocol::codec;

/// Transaction-pooling forwarding (with round-robin replica sharding).
pub struct PooledForwarder {
    pool: Arc<BackendPool>,
}

impl PooledForwarder {
    pub fn new(pool: Arc<BackendPool>) -> Self {
        Self { pool }
    }
}

impl<IO> Service<PgClient<IO>> for PooledForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        let PgClient {
            stream,
            startup_frame,
            startup,
            sni,
            auth,
        } = client;
        let user = startup.user().unwrap_or_default().to_owned();
        let database = startup.database().unwrap_or_default().to_owned();
        tracing::info!(?sni, user, database, "pooled connection");
        serve_pooled(stream, &startup_frame, &user, &database, auth, self.pool.clone()).await
    }
}

/// Synthesize the startup completion, then run the pool's mode-specific relay.
async fn serve_pooled<C>(
    mut stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    outcome: ClientAuth,
    pool: Arc<BackendPool>,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if matches!(outcome, ClientAuth::PassThrough) {
        return reject(
            &mut stream,
            "0A000",
            "rama-pg: pooling requires a terminating auth mode (cleartext or scram)",
        )
        .await;
    }

    // The client is idle until it sends a query, so we don't hold a backend yet;
    // the pool gives us the (cached) ParameterStatus to replay.
    let params = pool.startup_params(startup_frame, user, database).await?;
    synthesize_startup(&mut stream, &params).await?;

    match pool.mode() {
        // One backend for the whole connection — relay opaquely until disconnect.
        PoolMode::Session => {
            let mut lease = pool.lease(startup_frame, user, database).await?;
            let (client_to_backend, backend_to_client) =
                copy_bidirectional(&mut stream, &mut lease).await?;
            tracing::info!(client_to_backend, backend_to_client, "session-pooled connection closed");
            // NOTE: no server reset (DISCARD ALL) before reuse — a real pooler
            // would run server_reset_query here.
            lease.checkin();
            Ok(())
        }
        mode => relay_pooled(stream, startup_frame, user, database, pool, mode).await,
    }
}

/// Transaction/statement pooling: lease a backend per transaction (or
/// statement), relaying until the appropriate `ReadyForQuery` boundary.
async fn relay_pooled<C>(
    stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    pool: Arc<BackendPool>,
    mode: PoolMode,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = codec::FramedReader::new(stream);
    loop {
        // Idle: wait for the client to begin a transaction/statement.
        let Some(first) = client.read_frame().await? else {
            break;
        };
        if first.tag() == codec::TERMINATE {
            break;
        }

        let mut lease = pool.lease(startup_frame, user, database).await?;
        lease.write_all(first.as_bytes()).await?;
        lease.flush().await?;

        // Relay until this lease's release boundary.
        loop {
            let Some(status) = relay_to_next_rfq(&mut client, &mut lease).await? else {
                lease.discard(); // client gone mid-statement
                return Ok(());
            };
            match mode {
                PoolMode::Transaction if status == b'I' => {
                    lease.checkin();
                    break;
                }
                // Still inside a transaction block — keep this backend.
                PoolMode::Transaction => {}
                PoolMode::Statement if status == b'I' => {
                    lease.checkin();
                    break;
                }
                PoolMode::Statement => {
                    tracing::warn!("statement mode: discarding backend left in a transaction");
                    lease.discard();
                    break;
                }
                PoolMode::Session => unreachable!("session mode handled separately"),
            }
        }
    }

    tracing::info!("pooled session closed");
    Ok(())
}

/// Relay between the client and a checked-out backend until the backend's next
/// `ReadyForQuery`, returning its transaction-status byte (`I`/`T`/`E`), or
/// `None` if the client disconnected first.
async fn relay_to_next_rfq<C, B>(
    client: &mut codec::FramedReader<C>,
    backend: &mut B,
) -> Result<Option<u8>, BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut backend = codec::FramedReader::new(backend);
    loop {
        tokio::select! {
            // Prefer draining the backend so a ReadyForQuery is handled before
            // forwarding any further client input.
            biased;
            backend_frame = backend.read_frame() => {
                let Some(msg) = backend_frame? else {
                    return Err("backend closed mid-statement".into());
                };
                client.get_mut().write_all(msg.as_bytes()).await?;
                match msg.tag() {
                    codec::READY_FOR_QUERY => {
                        client.get_mut().flush().await?;
                        return Ok(Some(msg.payload().first().copied().unwrap_or(b'I')));
                    }
                    codec::ERROR_RESPONSE => client.get_mut().flush().await?,
                    _ => {}
                }
            }
            client_frame = client.read_frame() => {
                match client_frame? {
                    None => return Ok(None),
                    Some(msg) => {
                        if msg.tag() == codec::TERMINATE {
                            backend.get_mut().write_all(msg.as_bytes()).await.ok();
                            return Ok(None);
                        }
                        backend.get_mut().write_all(msg.as_bytes()).await?;
                        backend.get_mut().flush().await?;
                    }
                }
            }
        }
    }
}
