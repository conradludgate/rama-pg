//! SNI-based routing to backend Postgres targets.
//!
//! Unlike HTTP there is no Host header, and the backend-selecting key (`user` /
//! `database`) only arrives after TLS. So the proxy routes on the TLS SNI — the
//! one key available at handshake time — through a static map. This mirrors how
//! managed Postgres providers route on SNI / endpoint id, minus a control-plane
//! lookup.

use std::collections::HashMap;

/// A backend Postgres target the proxy can forward to.
#[derive(Debug, Clone)]
pub struct Backend {
    /// `host:port` to dial.
    pub address: String,
}

impl Backend {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

/// Maps a TLS SNI hostname to a [`Backend`], with an optional catch-all default.
#[derive(Debug, Clone, Default)]
pub struct Router {
    routes: HashMap<String, Backend>,
    default: Option<Backend>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the catch-all backend used when no SNI route matches.
    pub fn with_default(mut self, backend: Backend) -> Self {
        self.default = Some(backend);
        self
    }

    /// Add an exact-match SNI → backend route.
    pub fn with_route(mut self, sni: impl Into<String>, backend: Backend) -> Self {
        self.routes.insert(sni.into(), backend);
        self
    }

    /// Resolve a backend for the given SNI, falling back to the default.
    pub fn route(&self, sni: Option<&str>) -> Option<&Backend> {
        sni.and_then(|name| self.routes.get(name))
            .or(self.default.as_ref())
    }

    /// True when no routes and no default are configured.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.default.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sni_wins_over_default() {
        let router = Router::new()
            .with_default(Backend::new("default:5432"))
            .with_route("a.example.com", Backend::new("a:5432"));

        assert_eq!(router.route(Some("a.example.com")).unwrap().address, "a:5432");
        assert_eq!(
            router.route(Some("other.example.com")).unwrap().address,
            "default:5432"
        );
        assert_eq!(router.route(None).unwrap().address, "default:5432");
    }

    #[test]
    fn no_match_without_default_is_none() {
        let router = Router::new().with_route("a.example.com", Backend::new("a:5432"));
        assert!(router.route(Some("b.example.com")).is_none());
        assert!(router.route(None).is_none());
    }
}
