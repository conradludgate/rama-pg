//! rama-pg: a Postgres wire-protocol proxy built on [rama](https://ramaproxy.org).
//!
//! The proxy is a single L4 [`rama::Service`] over a `TcpStream`. It performs
//! Postgres' non-standard pre-TLS `SSLRequest` shim, upgrades the same socket to
//! TLS via rama's acceptor, parses the `StartupMessage`, and (incrementally)
//! authenticates and forwards to a backend.

pub mod auth;
pub mod protocol;
pub mod proxy;
pub mod route;
