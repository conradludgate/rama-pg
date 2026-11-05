//! Backend establishment and its matching cancellation transport.
//!
//! A connector is a Rama `Service<Target>` returning a [`BackendConnection`].
//! Its target can carry application-specific metadata. Its cancellation service
//! identifies the established upstream rather than reconstructing a destination
//! from the original route. Custom connectors are responsible for keeping that
//! service bound to the same upstream when it is cloned.

use std::fmt;

use async_trait::async_trait;
use rama::{
    Service,
    error::BoxError,
    extensions::Extensions,
    net::address::HostWithPort,
    rt::Executor,
    tcp::{TcpStream, client::default_tcp_connect},
};
use tokio::io::AsyncWriteExt;

use crate::{
    cancel::CancelTarget,
    protocol::startup::{CancelKey, cancel_request_frame},
    route::Backend,
};

/// An established backend stream and a service that delivers a cancellation key
/// to that same backend. The connector chooses both together; neither the
/// forwarder nor the cancellation registry needs to understand the transport.
pub struct BackendConnection<IO, Cancel> {
    pub conn: IO,
    /// A cloneable Rama `Service<CancelKey, Output = ()>`.
    pub cancellation: Cancel,
}

/// Plain TCP backend establishment using Rama's connector. Cancellation is
/// pinned to the connected peer address, rather than resolving the route again.
#[derive(Debug, Clone, Default)]
pub struct TcpBackendConnector {
    executor: Executor,
}

impl TcpBackendConnector {
    pub fn new(executor: Executor) -> Self {
        Self { executor }
    }
}

impl Service<Backend> for TcpBackendConnector {
    type Output = BackendConnection<TcpStream, TcpBackendCancellation>;
    type Error = BoxError;

    async fn serve(&self, backend: Backend) -> Result<Self::Output, Self::Error> {
        let (conn, peer) = default_tcp_connect(
            &Extensions::new(),
            backend.address.parse()?,
            self.executor.clone(),
        )
        .await?;
        Ok(BackendConnection {
            conn,
            cancellation: TcpBackendCancellation {
                executor: self.executor.clone(),
                authority: peer.into(),
            },
        })
    }
}

/// Deliver a PostgreSQL CancelRequest over a fresh Rama TCP connection to the
/// established backend peer. Instances are supplied by [`TcpBackendConnector`].
#[derive(Debug, Clone)]
pub struct TcpBackendCancellation {
    executor: Executor,
    authority: HostWithPort,
}

impl Service<CancelKey> for TcpBackendCancellation {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, key: CancelKey) -> Result<(), BoxError> {
        let (mut conn, _) = default_tcp_connect(
            &Extensions::new(),
            self.authority.clone(),
            self.executor.clone(),
        )
        .await?;
        conn.write_all(&cancel_request_frame(key.as_bytes()))
            .await?;
        conn.flush().await?;
        Ok(())
    }
}

pub(crate) struct BackendCancelTarget<S> {
    pub service: S,
    pub key: CancelKey,
}

impl<S> fmt::Debug for BackendCancelTarget<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendCancelTarget")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S> CancelTarget for BackendCancelTarget<S>
where
    S: Service<CancelKey, Output = (), Error: Into<BoxError>>,
{
    async fn cancel(&self) -> Result<(), BoxError> {
        self.service
            .serve(self.key.clone())
            .await
            .map_err(Into::into)
    }
}
