//! Pluggable client authentication.
//!
//! An [`Authenticator`] runs whatever client-side handshake a mechanism needs
//! over the (TLS) client stream, then reports how the proxy should continue
//! toward the backend:
//!
//! - [`ClientAuth::PassThrough`] — the proxy did not interpret auth; it forwards
//!   the client's `StartupMessage` and relays the auth exchange so the *backend*
//!   authenticates the client.
//! - [`ClientAuth::Terminated`] — the proxy authenticated the client itself; it
//!   then establishes the backend connection and splices the backend's startup
//!   result back to the client.

use std::future::Future;

use rama::error::BoxError;
use rama::net::stream::Stream;

use crate::protocol::startup::StartupMessage;

/// How the proxy should reach the backend after client authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// Forward the StartupMessage and relay; the backend authenticates.
    PassThrough,
    /// The proxy authenticated the client; it drives the backend itself.
    Terminated,
}

/// A pluggable client-authentication mechanism.
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticate the just-connected client, reading from / writing to
    /// `client` as the mechanism requires.
    fn authenticate<IO>(
        &self,
        client: &mut IO,
        startup: &StartupMessage,
    ) -> impl Future<Output = Result<ClientAuth, BoxError>> + Send
    where
        IO: Stream + Unpin;
}

/// Transparent pass-through: the proxy does not interpret auth at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThrough;

impl Authenticator for PassThrough {
    async fn authenticate<IO>(
        &self,
        _client: &mut IO,
        _startup: &StartupMessage,
    ) -> Result<ClientAuth, BoxError>
    where
        IO: Stream + Unpin,
    {
        Ok(ClientAuth::PassThrough)
    }
}
