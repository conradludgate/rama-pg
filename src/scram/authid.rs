//! A [`ScramSecretStore`] that fetches verifiers from Postgres' `pg_authid` on
//! demand — the realistic source for a proxy that doesn't hold credentials.
//!
//! On each lookup it opens a short-lived admin connection, runs
//! `SELECT rolpassword FROM pg_authid WHERE rolname = $user`, and parses the
//! `SCRAM-SHA-256$…` verifier. `pg_authid` is superuser-only, so the admin
//! connection must be a superuser. For now that connection is unauthenticated
//! (trust) — real deployments would give it credentials; a connection per
//! lookup is also deliberately simple (no caching/pooling yet).

use bytes::BytesMut;
use rama::error::BoxError;
use rama::tcp::TokioTcpStream;
use tokio::io::AsyncWriteExt;

use super::{ScramSecret, ScramSecretStore, SecretLookup};
use crate::protocol::codec::{self, read_message};
use crate::protocol::startup::startup_message;

/// Fetches SCRAM verifiers from a Postgres `pg_authid` over an admin connection.
#[derive(Debug, Clone)]
pub struct PgAuthidStore {
    address: String,
    admin_user: String,
    admin_database: String,
}

impl PgAuthidStore {
    /// Connect to `address` as superuser `admin_user` on `admin_database` to read
    /// `pg_authid`.
    pub fn new(
        address: impl Into<String>,
        admin_user: impl Into<String>,
        admin_database: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            admin_user: admin_user.into(),
            admin_database: admin_database.into(),
        }
    }
}

impl ScramSecretStore for PgAuthidStore {
    async fn get_secret(
        &self,
        lookup: SecretLookup<'_>,
    ) -> Result<Option<ScramSecret>, BoxError> {
        let Some(verifier) = self.fetch_rolpassword(lookup.user).await? else {
            return Ok(None);
        };
        // A role may have no password, or a non-SCRAM (md5) one — not usable here.
        if verifier.starts_with("SCRAM-SHA-256$") {
            Ok(Some(ScramSecret::parse(&verifier)?))
        } else {
            tracing::warn!(user = lookup.user, "pg_authid role has no SCRAM verifier");
            Ok(None)
        }
    }
}

impl PgAuthidStore {
    /// Open an admin connection, query `pg_authid`, and return the role's
    /// `rolpassword` text (or `None` if the role is missing / has none).
    async fn fetch_rolpassword(&self, rolname: &str) -> Result<Option<String>, BoxError> {
        let mut conn = TokioTcpStream::connect(&self.address).await?;
        conn.write_all(&startup_message(&[
            ("user", &self.admin_user),
            ("database", &self.admin_database),
        ]))
        .await?;
        conn.flush().await?;

        // Drive the (trust) startup to ReadyForQuery.
        loop {
            let msg = read_message(&mut conn).await?;
            match msg.tag() {
                codec::AUTHENTICATION => {
                    let payload = msg.payload();
                    let subtype = if payload.len() >= 4 {
                        i32::from_be_bytes(payload[..4].try_into().unwrap())
                    } else {
                        -1
                    };
                    if subtype != 0 {
                        return Err("pg_authid admin connection requires auth (trust only)".into());
                    }
                }
                codec::READY_FOR_QUERY => break,
                codec::ERROR_RESPONSE => return Err("pg_authid admin startup rejected".into()),
                _ => {}
            }
        }

        // `rolname` is attacker-influenced (it's the client's startup user), so
        // escape the single quotes in the literal.
        let escaped = rolname.replace('\'', "''");
        let sql = format!("SELECT rolpassword FROM pg_authid WHERE rolname = '{escaped}'");
        let mut query = BytesMut::from(sql.as_bytes());
        query.extend_from_slice(&[0]);
        conn.write_all(&codec::frame(codec::QUERY, &query)).await?;
        conn.flush().await?;

        let mut value = None;
        loop {
            let msg = read_message(&mut conn).await?;
            match msg.tag() {
                codec::DATA_ROW => value = first_column(msg.payload()),
                codec::READY_FOR_QUERY => break,
                codec::ERROR_RESPONSE => return Err("pg_authid query failed".into()),
                _ => {} // RowDescription, CommandComplete, NoticeResponse, …
            }
        }

        // Best-effort terminate.
        let _ = conn.write_all(&codec::frame(codec::TERMINATE, &[])).await;
        Ok(value)
    }
}

/// The first column of a `DataRow` payload as text (`None` if absent or SQL NULL).
fn first_column(payload: &[u8]) -> Option<String> {
    if payload.len() < 2 {
        return None;
    }
    let columns = i16::from_be_bytes([payload[0], payload[1]]);
    if columns < 1 || payload.len() < 6 {
        return None;
    }
    let len = i32::from_be_bytes(payload[2..6].try_into().unwrap());
    if len < 0 {
        return None; // SQL NULL (e.g. role with no password)
    }
    let len = len as usize;
    let value = payload.get(6..6 + len)?;
    String::from_utf8(value.to_vec()).ok()
}
