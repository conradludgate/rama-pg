//! Pluggable query-cancellation handling.
//!
//! Postgres cancellation is out-of-band: at startup the server hands the client
//! a `BackendKeyData` (a process id + secret key); to cancel a running query the
//! client opens a *fresh* connection and sends a `CancelRequest` carrying that
//! key. A proxy sits across both halves, and a bare `CancelRequest` carries no
//! routing information (no SNI, no startup parameters), so the proxy must have
//! recorded — at session-setup time — how to reach the backend the key belongs to.
//!
//! [`Cancellation`] is the pluggable seam, with two responsibilities:
//!   1. **begin** a client session: assign the cancel key advertised to the
//!      client and return a [`CancelHandle`] the forwarder updates as the client's
//!      *current* backend changes; and
//!   2. **cancel** — act on a client's `CancelRequest`, routing it to whatever
//!      backend the client is using right now.
//!
//! The handle is what makes pooling work: a pooled client has no fixed backend —
//! each transaction leases a (possibly different) one — so the forwarder calls
//! [`CancelHandle::set`] on lease-acquire and [`CancelHandle::clear`] on release.
//! A direct 1:1 forwarder simply calls `set` once. The handle deregisters the key
//! when it is dropped (session end).
//!
//! [`RegistryCancellation`] is the default: an in-memory map of opaque proxy keys
//! to each client's current upstream, minting a fresh random key per session and
//! dialing the recorded backend to deliver the cancel. [`NoCancellation`] disables
//! mediation (the client sees the backend's own key; cancels are dropped).
//!
//! Keys are treated as opaque byte strings — a `BackendKeyData` payload reused
//! verbatim as a `CancelRequest` body — so protocol 3.0's 8-byte key and 3.2's
//! longer key both work without change (3.2 negotiation is not implemented yet).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::AsyncWriteExt;

use crate::protocol::startup::cancel_request_frame;

/// A boxed future, so [`Cancellation`] is dyn-safe (it is shared as a trait
/// object across the proxy's startup, forwarding, and cancel paths).
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The backend a client is currently using: where it is, and the key it issued.
#[derive(Debug, Clone)]
pub struct UpstreamSession {
    /// `host:port` of the backend running the client's current query.
    pub backend: String,
    /// The backend's `BackendKeyData` payload (`Int32 pid` + secret key), reused
    /// verbatim as the body of an upstream `CancelRequest`. Length-agnostic.
    pub key: Bytes,
}

/// The slot holding a client's current upstream, shared between the forwarder
/// (which updates it through a [`CancelHandle`]) and the provider (which reads it
/// on cancel). A custom [`Cancellation`] keeps a clone to read in `cancel` and
/// hands another to [`CancelHandle::new`].
pub type CancelSlot = Arc<Mutex<Option<UpstreamSession>>>;

/// A live client cancel session. The forwarder calls [`set`](Self::set) when the
/// client acquires a backend and [`clear`](Self::clear) when it releases one;
/// dropping the handle ends the session (and, for [`RegistryCancellation`],
/// removes the key from the registry).
pub struct CancelHandle {
    slot: CancelSlot,
    /// Runs once on drop, to deregister the key (no-op for a disabled handle).
    on_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl CancelHandle {
    /// Build a handle over `slot` (the provider keeps a clone to read on cancel),
    /// running `on_end` once when the session ends (the handle is dropped) — e.g.
    /// to deregister the key.
    pub fn new(slot: CancelSlot, on_end: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            slot,
            on_drop: Some(Box::new(on_end)),
        }
    }

    /// A handle that records nothing and deregisters nothing (cancellation off).
    pub fn disabled() -> Self {
        Self {
            slot: Arc::new(Mutex::new(None)),
            on_drop: None,
        }
    }

    /// Record the backend the client is now using (call on lease-acquire, or once
    /// for a fixed 1:1 backend).
    pub fn set(&self, upstream: UpstreamSession) {
        *self.slot.lock().unwrap() = Some(upstream);
    }

    /// Clear the current backend (call on lease-release; the client is idle, so a
    /// cancel arriving now has nothing to act on).
    pub fn clear(&self) {
        *self.slot.lock().unwrap() = None;
    }
}

impl Drop for CancelHandle {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

impl std::fmt::Debug for CancelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelHandle").finish_non_exhaustive()
    }
}

/// Pluggable query-cancellation handling (see the module docs).
pub trait Cancellation: Send + Sync + 'static {
    /// Begin a client cancel session. Returns the `BackendKeyData` payload to
    /// advertise to the client (or `None` to pass the backend's own key through,
    /// disabling mediation for this session) and a [`CancelHandle`] the forwarder
    /// uses to track the client's current backend.
    fn begin(&self) -> BoxFuture<'_, Result<(Option<Bytes>, CancelHandle), BoxError>>;

    /// Act on a client's `CancelRequest`: `key` is the payload it presented
    /// (matching a prior [`begin`](Self::begin)). Best-effort — an unknown key, an
    /// idle session, or a delivery failure is generally logged, not surfaced.
    fn cancel(&self, key: Bytes) -> BoxFuture<'_, Result<(), BoxError>>;
}

/// Default [`Cancellation`]: an in-memory registry mapping opaque proxy-issued
/// keys to each client's current upstream.
#[derive(Debug, Default, Clone)]
pub struct RegistryCancellation {
    sessions: Arc<Mutex<HashMap<Bytes, CancelSlot>>>,
}

impl RegistryCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live (begun, not yet ended) cancel sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Cancellation for RegistryCancellation {
    fn begin(&self) -> BoxFuture<'_, Result<(Option<Bytes>, CancelHandle), BoxError>> {
        Box::pin(async move {
            // A fresh opaque 8-byte key (the `Int32 pid` + `Int32 secret` size a
            // protocol-3.0 client expects). The values are random; the client only
            // echoes them back, so the proxy never exposes the backend's real key.
            let mut bytes = [0u8; 8];
            rand::fill(&mut bytes[..]);
            let key = Bytes::copy_from_slice(&bytes);

            let slot: CancelSlot = Arc::new(Mutex::new(None));
            self.sessions.lock().unwrap().insert(key.clone(), slot.clone());

            let sessions = self.sessions.clone();
            let registered = key.clone();
            let handle = CancelHandle::new(slot, move || {
                sessions.lock().unwrap().remove(&registered);
            });
            Ok((Some(key), handle))
        })
    }

    fn cancel(&self, key: Bytes) -> BoxFuture<'_, Result<(), BoxError>> {
        Box::pin(async move {
            let slot = self.sessions.lock().unwrap().get(&key).cloned();
            let target = slot.and_then(|slot| slot.lock().unwrap().clone());
            let Some(session) = target else {
                tracing::debug!("cancel request for an unknown or idle key; ignoring");
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
}

/// A [`Cancellation`] that disables proxy mediation: the client sees the
/// backend's own cancel key, and incoming `CancelRequest`s are dropped (the proxy
/// has no mapping to route them by).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCancellation;

impl Cancellation for NoCancellation {
    fn begin(&self) -> BoxFuture<'_, Result<(Option<Bytes>, CancelHandle), BoxError>> {
        Box::pin(async { Ok((None, CancelHandle::disabled())) })
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
    async fn registry_begins_a_session_and_ends_it_on_drop() {
        let registry = RegistryCancellation::new();
        let (key, handle) = registry.begin().await.unwrap();
        let key = key.unwrap();
        assert_eq!(key.len(), 8); // protocol-3.0-shaped payload
        assert_eq!(registry.len(), 1);

        drop(handle);
        assert!(registry.is_empty()); // RAII deregister
    }

    #[tokio::test]
    async fn registry_only_acts_when_a_backend_is_set() {
        let registry = RegistryCancellation::new();
        let (key, handle) = registry.begin().await.unwrap();
        let key = key.unwrap();

        // Idle (no backend set yet) → best-effort no-op, not an error.
        registry.cancel(key.clone()).await.unwrap();

        // After set, the target is the one we'd dial (we don't assert the dial
        // here — that needs a live backend; covered end-to-end against Postgres).
        handle.set(session());
        let slot = registry.sessions.lock().unwrap().get(&key).cloned().unwrap();
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().backend, "127.0.0.1:5432");

        handle.clear();
        assert!(slot.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn no_cancellation_advertises_no_key() {
        let none = NoCancellation;
        let (key, _handle) = none.begin().await.unwrap();
        assert!(key.is_none());
        none.cancel(Bytes::from_static(&[0; 8])).await.unwrap();
    }
}
