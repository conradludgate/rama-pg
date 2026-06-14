//! Minimal pgbouncer-style INI configuration.
//!
//! A tiny hand-rolled INI parser (sections in `[brackets]`, `key = value`,
//! `;`/`#` comments) — enough to read the subset of `pgbouncer.ini` this example
//! uses, without pulling in a config crate.

use std::collections::HashMap;

use rama_pg::pool::PoolMode;

/// Proxy configuration parsed from a pgbouncer-style INI file.
#[derive(Debug)]
pub struct Config {
    /// `listen_addr:listen_port`.
    pub listen: String,
    /// Backend `host:port`, from the `[databases]` connection string. Also the
    /// `pg_authid` source.
    pub backend: String,
    pub pool_mode: PoolMode,
    pub pool_size: usize,
    /// Superuser + database for the on-demand `pg_authid` lookups.
    pub auth_user: String,
    pub auth_dbname: String,
}

impl Config {
    /// Parse a pgbouncer-style INI document.
    pub fn from_ini(text: &str) -> Result<Self, String> {
        let ini = parse_ini(text);
        let pg = ini.get("pgbouncer").cloned().unwrap_or_default();
        let setting = |key: &str, default: &str| pg.get(key).cloned().unwrap_or_else(|| default.to_owned());

        let listen = format!(
            "{}:{}",
            setting("listen_addr", "127.0.0.1"),
            setting("listen_port", "6432"),
        );
        let pool_mode = match pg.get("pool_mode").map(String::as_str) {
            Some("session") => PoolMode::Session,
            Some("statement") => PoolMode::Statement,
            _ => PoolMode::Transaction,
        };
        let pool_size = pg
            .get("default_pool_size")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        // Backend from [databases]: prefer the `*` wildcard, else any entry.
        let databases = ini
            .get("databases")
            .ok_or("config: missing [databases] section")?;
        let connstring = databases
            .get("*")
            .or_else(|| databases.values().next())
            .ok_or("config: [databases] has no entries")?;
        let backend = backend_address(connstring)
            .ok_or_else(|| format!("config: cannot parse host/port from {connstring:?}"))?;

        Ok(Self {
            listen,
            backend,
            pool_mode,
            pool_size,
            auth_user: setting("auth_user", "postgres"),
            auth_dbname: setting("auth_dbname", "postgres"),
        })
    }
}

/// Parse INI text into `section -> (key -> value)`.
fn parse_ini(text: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.trim().to_owned();
            sections.entry(current.clone()).or_default();
        } else if let Some((key, value)) = line.split_once('=') {
            // For `[databases]`, the value is itself a `key=value …` connstring;
            // splitting on the first `=` keeps it intact.
            sections
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    sections
}

/// Extract `host:port` from a libpq-style connection string.
fn backend_address(connstring: &str) -> Option<String> {
    let mut host = None;
    let mut port = None;
    for token in connstring.split_whitespace() {
        match token.split_once('=') {
            Some(("host", value)) => host = Some(value),
            Some(("port", value)) => port = Some(value),
            _ => {}
        }
    }
    Some(format!("{}:{}", host?, port.unwrap_or("5432")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pgbouncer_ini() {
        let cfg = Config::from_ini(
            "
            [databases]
            shop = host=10.0.0.1 port=5433
            * = host=127.0.0.1 port=5434

            [pgbouncer]
            listen_port = 7000
            pool_mode = statement
            default_pool_size = 25
            auth_user = admin
            ; a comment
            ",
        )
        .unwrap();

        assert_eq!(cfg.listen, "127.0.0.1:7000");
        assert_eq!(cfg.backend, "127.0.0.1:5434"); // the `*` wildcard wins
        assert_eq!(cfg.pool_mode, PoolMode::Statement);
        assert_eq!(cfg.pool_size, 25);
        assert_eq!(cfg.auth_user, "admin");
        assert_eq!(cfg.auth_dbname, "postgres"); // default
    }

    #[test]
    fn requires_databases_section() {
        assert!(Config::from_ini("[pgbouncer]\nlisten_port = 6432").is_err());
    }
}
