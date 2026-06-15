//! Pluggable query-cancellation handling.
//!
//! Postgres cancellation is out-of-band: at startup the server hands the client
//! a `BackendKeyData` (a process id + secret key); to cancel a running query the
//! client opens a *fresh* connection and sends a `CancelRequest` carrying that
//! key. A proxy sits across both halves, and a bare `CancelRequest` carries no
//! routing information (no SNI, no startup parameters), so the proxy must have
//! recorded — at session-setup time — how to reach the backend the key belongs to.
//!
//! [`Cancellation`] is the pluggable seam for that, with two responsibilities:
//!   1. **issue** the cancel key the proxy advertises to a client — pass the
//!      backend's own key through, or mint an opaque proxy key and record the
//!      mapping; and
//!   2. **cancel** — act on a client's `CancelRequest`, routing it to the right
//!      backend.
//!
//! [`RegistryCancellation`] is the default: an in-memory map of opaque proxy keys
//! to upstream sessions, minting a fresh random key per session and dialing the
//! recorded backend to deliver the cancel. [`NoCancellation`] disables mediation
//! (the client sees the backend's own key; cancels are dropped).
//!
//! Keys are treated as opaque byte strings — a `BackendKeyData` payload reused
//! verbatim as a `CancelRequest` body — so protocol 3.0's 8-byte key and 3.2's
//! longer key both work without change (3.2 negotiation is not implemented yet).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use bytes::Bytes;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::AsyncWriteExt;

use crate::protocol::startup::cancel_request_frame;

/// A boxed future, so [`Cancellation`] is dyn-safe (it is shared as a trait
/// object across the proxy's startup, forwarding, and cancel paths).
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the proxy needs to cancel a query upstream: where the backend is, and the
/// key material it issued.
#[derive(Debug, Clone)]
pub struct UpstreamSession {
    /// `host:port` of the backend running the session.
    pub backend: String,
    /// The backend's `BackendKeyData` payload (`Int32 pid` + secret key), reused
    /// verbatim as the body of an upstream `CancelRequest`. Length-agnostic.
    pub key: Bytes,
}

/// Pluggable query-cancellation handling (see the module docs).
pub trait Cancellation: Send + Sync + 'static {
    /// Assign the cancel key the proxy advertises to the client for `upstream`,
    /// recording whatever is needed to cancel it later. Return `Some(payload)` to
    /// advertise that `BackendKeyData` payload, or `None` to pass the backend's
    /// own key through unchanged (no proxy mapping).
    fn issue(&self, upstream: UpstreamSession) -> BoxFuture<'_, Result<Option<Bytes>, BoxError>>;

    /// Act on a client's `CancelRequest`: `key` is the payload it presented
    /// (matching a prior [`issue`](Self::issue)). Best-effort — a miss or a
    /// delivery failure is generally logged, not surfaced to the client.
    fn cancel(&self, key: Bytes) -> BoxFuture<'_, Result<(), BoxError>>;

    /// Release a key previously [`issue`](Self::issue)d, when its session ends, so
    /// long-lived stores don't grow without bound. Default: no-op.
    fn release(&self, key: Bytes) -> BoxFuture<'_, ()> {
        let _ = key;
        Box::pin(async {})
    }
}

/// Default [`Cancellation`]: an in-memory registry mapping opaque proxy-issued
/// keys to the upstream sessions they can cancel.
#[derive(Debug, Default)]
pub struct RegistryCancellation {
    sessions: Mutex<HashMap<Bytes, UpstreamSession>>,
}

impl RegistryCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live (issued, not yet released) cancel keys.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Cancellation for RegistryCancellation {
    fn issue(&self, upstream: UpstreamSession) -> BoxFuture<'_, Result<Option<Bytes>, BoxError>> {
        Box::pin(async move {
            // A fresh opaque 8-byte key (the `Int32 pid` + `Int32 secret` size a
            // protocol-3.0 client expects). The values are random; the client only
            // echoes them back in a CancelRequest, so the proxy never exposes the
            // backend's real key.
            let mut key = [0u8; 8];
            rand::fill(&mut key[..]);
            let key = Bytes::copy_from_slice(&key);
            self.sessions.lock().unwrap().insert(key.clone(), upstream);
            Ok(Some(key))
        })
    }

    fn cancel(&self, key: Bytes) -> BoxFuture<'_, Result<(), BoxError>> {
        Box::pin(async move {
            let session = self.sessions.lock().unwrap().get(&key).cloned();
            let Some(session) = session else {
                tracing::debug!("cancel request for an unknown key; ignoring");
                return Ok(());
            };
            // Open a fresh connection to the backend and deliver its own cancel
            // key. Postgres acts on it and closes the socket; we don't await a reply.
            let mut conn = TokioTcpStream::connect(&session.backend).await?;
            conn.write_all(&cancel_request_frame(&session.key)).await?;
            conn.flush().await?;
            tracing::info!(backend = %session.backend, "forwarded cancel request upstream");
            Ok(())
        })
    }

    fn release(&self, key: Bytes) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.sessions.lock().unwrap().remove(&key);
        })
    }
}

/// A [`Cancellation`] that disables proxy mediation: the client sees the
/// backend's own cancel key, and incoming `CancelRequest`s are dropped (the proxy
/// has no mapping to route them by).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCancellation;

impl Cancellation for NoCancellation {
    fn issue(&self, _upstream: UpstreamSession) -> BoxFuture<'_, Result<Option<Bytes>, BoxError>> {
        Box::pin(async { Ok(None) })
    }

    fn cancel(&self, _key: Bytes) -> BoxFuture<'_, Result<(), BoxError>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> UpstreamSession {
        UpstreamSession {
            backend: "127.0.0.1:5432".to_owned(),
            key: Bytes::from_static(&[0, 0, 0, 1, 9, 9, 9, 9]),
        }
    }

    #[tokio::test]
    async fn registry_issues_a_fresh_key_and_records_it() {
        let registry = RegistryCancellation::new();
        let key = registry.issue(session()).await.unwrap().unwrap();
        assert_eq!(key.len(), 8); // protocol-3.0-shaped payload
        assert_eq!(registry.len(), 1);

        registry.release(key).await;
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn registry_ignores_an_unknown_cancel_key() {
        let registry = RegistryCancellation::new();
        // No mapping registered → best-effort no-op, not an error (and no dial).
        registry.cancel(Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8])).await.unwrap();
    }

    #[tokio::test]
    async fn no_cancellation_passes_the_backend_key_through() {
        let none = NoCancellation;
        assert!(none.issue(session()).await.unwrap().is_none());
        none.cancel(Bytes::from_static(&[0; 8])).await.unwrap();
    }
}
