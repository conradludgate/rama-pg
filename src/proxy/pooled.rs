//! Transaction-pooling forwarding (session / transaction / statement modes).

use std::sync::Arc;

use bytes::Bytes;
use rama::Service;
use rama::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use super::{PgClient, reject, synthesize_startup};
use crate::auth::ClientAuth;
use crate::cancel::{CancelHandle, Cancellation};
use crate::pool::{BackendPool, Lease, PoolMode};
use crate::protocol::codec;

/// Transaction-pooling forwarding (with round-robin replica sharding).
pub struct PooledForwarder {
    pool: Arc<BackendPool>,
    cancellation: Arc<dyn Cancellation>,
}

impl PooledForwarder {
    pub fn new(pool: Arc<BackendPool>, cancellation: Arc<dyn Cancellation>) -> Self {
        Self { pool, cancellation }
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
            protocol_version,
            sni,
            auth,
        } = client;
        let user = startup.user().unwrap_or_default().to_owned();
        let database = startup.database().unwrap_or_default().to_owned();
        tracing::info!(?sni, user, database, "pooled connection");
        // Begin a cancel session: the key to advertise (sized to the negotiated
        // protocol version), and a handle the relay updates to point at whichever
        // backend the client is currently leasing. Dropping the handle at the end
        // of `serve` ends the session.
        let (client_key, handle) = self.cancellation.begin(protocol_version).await?;
        serve_pooled(
            stream,
            &startup_frame,
            &user,
            &database,
            auth,
            self.pool.clone(),
            client_key,
            &handle,
        )
        .await
    }
}

/// Synthesize the startup completion, then run the pool's mode-specific relay.
#[allow(clippy::too_many_arguments)]
async fn serve_pooled<C>(
    mut stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    outcome: ClientAuth,
    pool: Arc<BackendPool>,
    client_key: Option<Bytes>,
    handle: &CancelHandle,
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
    // the pool gives us the (cached) ParameterStatus to replay. This is the first
    // backend contact, so a connection/auth failure surfaces here — report it as a
    // startup ErrorResponse rather than dropping the connection mid-handshake.
    let params = match pool.startup_params(startup_frame, user, database).await {
        Ok(params) => params,
        Err(err) => {
            tracing::error!(%err, "backend connection/authentication failed");
            return reject(&mut stream, "08006", "rama-pg: could not establish a backend connection").await;
        }
    };
    // Advertise the cancel key the provider issued, or a throwaway one when disabled.
    let cancel_key = client_key
        .unwrap_or_else(|| Bytes::copy_from_slice(&rand::random::<u64>().to_be_bytes()));
    synthesize_startup(&mut stream, &params, &cancel_key).await?;

    match pool.mode() {
        // One backend for the whole connection — relay opaquely until disconnect.
        PoolMode::Session => {
            let mut lease = pool.lease(startup_frame, user, database).await?;
            // Point cancellation at this backend for the life of the session.
            if let Some(target) = lease.cancel_target() {
                handle.set(target);
            }
            let outcome = copy_bidirectional(&mut stream, &mut lease).await;
            handle.clear();
            // The relay is opaque, so we can't prove the backend ended at an idle
            // boundary (the client may have bailed mid-query), and there's no
            // server reset — so never re-pool a session backend; discard it.
            // (Real session-pool *reuse* needs a `DISCARD ALL` reset hook.)
            lease.discard();
            let (client_to_backend, backend_to_client) = outcome?;
            tracing::info!(client_to_backend, backend_to_client, "session-pooled connection closed");
            Ok(())
        }
        mode => relay_pooled(stream, startup_frame, user, database, pool, mode, handle).await,
    }
}

/// Transaction/statement pooling: lease a backend per transaction (or
/// statement) and run it to its release boundary via [`run_lease`].
async fn relay_pooled<C>(
    stream: C,
    startup_frame: &[u8],
    user: &str,
    database: &str,
    pool: Arc<BackendPool>,
    mode: PoolMode,
    handle: &CancelHandle,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    // The reset query (e.g. DISCARD ALL) is replayed to a backend before it
    // returns to the pool; capture it once so each transaction can reuse it.
    let reset = pool.reset_query().map(<[u8]>::to_vec);
    let mut client = codec::FramedReader::new(stream);
    loop {
        // Idle: wait for the client to begin a transaction/statement.
        let Some(first) = client.read_frame().await? else {
            break;
        };
        if first.tag() == codec::TERMINATE {
            break;
        }

        let lease = pool.lease(startup_frame, user, database).await?;
        // Route cancellation at this backend while the client holds the lease;
        // clear it once the transaction is done (the client is idle again).
        if let Some(target) = lease.cancel_target() {
            handle.set(target);
        }
        let keep_serving = run_lease(&mut client, lease, first.as_bytes(), mode, reset.as_deref()).await;
        handle.clear();
        if !keep_serving? {
            break; // client gone
        }
    }

    tracing::info!("pooled session closed");
    Ok(())
}

/// Run one checked-out backend to its release boundary, owning the lease so the
/// re-pooling decision happens in exactly one place.
///
/// **Safety invariant:** the lease is checked back in *only* on a verified idle
/// `ReadyForQuery` (`b'I'`); every other exit — an IO error, the client going
/// away, or a backend left mid-transaction — `discard`s it. rama's pool returns
/// a dropped `LeasedConnection` to the pool unconditionally, so without this a
/// desynced backend could be re-pooled and leak the previous client's leftover
/// result frames to the next client of the same `(user, database)`.
///
/// Before a verified-idle checkin, the backend's session state is reset via
/// `reset` (when set) so non-`LOCAL` `SET`/`PREPARE`/temp-table/`LISTEN` state
/// can't leak across clients sharing the backend.
///
/// Returns `Ok(true)` to keep serving the client, `Ok(false)` once it has gone.
async fn run_lease<C>(
    client: &mut codec::FramedReader<C>,
    mut lease: Lease,
    first: &[u8],
    mode: PoolMode,
    reset: Option<&[u8]>,
) -> Result<bool, BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    // Forward the first frame of the transaction/statement.
    if let Err(err) = forward_first(&mut lease, first).await {
        lease.discard();
        return Err(err);
    }

    loop {
        match relay_to_next_rfq(client, &mut lease).await {
            Err(err) => {
                lease.discard();
                return Err(err);
            }
            Ok(None) => {
                lease.discard(); // client gone mid-statement
                return Ok(false);
            }
            // Verified idle: the only safe point to return the backend. Reset
            // its session state first so nothing leaks to the next client; a
            // failed reset just discards the backend (the client keeps serving).
            Ok(Some(b'I')) => {
                if let Some(reset) = reset
                    && let Err(err) = lease.reset(reset).await
                {
                    tracing::warn!(error = %err, "backend reset failed; discarding");
                    lease.discard();
                    return Ok(true);
                }
                lease.checkin();
                return Ok(true);
            }
            Ok(Some(_)) => match mode {
                // Still inside a transaction block — keep relaying on this backend.
                PoolMode::Transaction => {}
                // Statement mode forbids multi-statement transactions; the backend
                // is mid-transaction, so it cannot be reused — discard it.
                PoolMode::Statement => {
                    tracing::warn!("statement mode: discarding backend left in a transaction");
                    lease.discard();
                    return Ok(true);
                }
                PoolMode::Session => unreachable!("session mode handled separately"),
            },
        }
    }
}

/// Write the first client frame to the backend (split out so [`run_lease`] can
/// discard the lease on a write error).
async fn forward_first(lease: &mut Lease, frame: &[u8]) -> Result<(), BoxError> {
    lease.write_all(frame).await?;
    lease.flush().await?;
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
    // A fresh reader per call is safe because Postgres is half-duplex: after a
    // `ReadyForQuery` the backend is silent until the next query, so this
    // reader's buffer is always empty at the boundary where we drop it (and
    // where the reset path below reads directly from the same backend).
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
