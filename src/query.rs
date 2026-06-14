//! In-proxy query handling — a "virtual Postgres" that answers simple-protocol
//! queries with no backend at all.
//!
//! A [`QueryHandler`] is given the SQL and a [`QueryContext`] (including the
//! per-connection [`SessionState`]) and returns a [`QueryResponse`]; the session
//! ([`crate::proxy`]) owns the wire encoding and the transaction-status state
//! machine. The handler trait is boxed-future rather than RPITIT so it can be
//! used as `dyn QueryHandler` for runtime mode selection.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

/// Transaction status, reported in every `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxnStatus {
    /// Not in a transaction block.
    #[default]
    Idle,
    /// In a transaction block.
    InTransaction,
    /// In a failed transaction block (commands rejected until rollback).
    Failed,
}

impl TxnStatus {
    /// The `ReadyForQuery` status byte (`I` / `T` / `E`).
    pub fn code(self) -> u8 {
        match self {
            TxnStatus::Idle => b'I',
            TxnStatus::InTransaction => b'T',
            TxnStatus::Failed => b'E',
        }
    }
}

/// Per-connection, mutable session state shared with the (stateless, shared)
/// handler — currently the transaction status. Interior-mutable via a `Mutex`
/// so a `&SessionState` handed to the handler can still be updated per query.
///
/// This is the natural home for "per-connection mutable extension data": it can
/// also be parked in the stream's `Extensions` when middleware layers need it,
/// but a single handler is simpler to feed through [`QueryContext`].
#[derive(Debug, Default)]
pub struct SessionState {
    txn: Mutex<TxnStatus>,
}

impl SessionState {
    pub fn txn_status(&self) -> TxnStatus {
        *self.txn.lock().unwrap()
    }

    pub fn set_txn_status(&self, status: TxnStatus) {
        *self.txn.lock().unwrap() = status;
    }
}

/// What a [`QueryHandler`] is told about the connection.
pub struct QueryContext<'a> {
    pub user: &'a str,
    pub database: &'a str,
    pub state: &'a SessionState,
}

/// A handler's response to one simple query.
pub enum QueryResponse {
    /// A result set: column headers, rows of optional text values, and the
    /// `CommandComplete` tag (e.g. `SELECT 2`).
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
        tag: String,
    },
    /// A statement with no result set; carries the `CommandComplete` tag.
    Command(String),
    /// An error: SQLSTATE `code` + `message`.
    Error { code: String, message: String },
}

impl QueryResponse {
    /// A single-column, single-cell result (handy for greetings/probes).
    pub fn scalar(column: impl Into<String>, value: impl Into<String>) -> Self {
        QueryResponse::Rows {
            columns: vec![column.into()],
            rows: vec![vec![Some(value.into())]],
            tag: "SELECT 1".to_owned(),
        }
    }

    /// An error response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        QueryResponse::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A pluggable, async handler that answers simple-protocol queries in-proxy.
pub trait QueryHandler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        ctx: QueryContext<'a>,
        sql: &'a str,
    ) -> Pin<Box<dyn Future<Output = QueryResponse> + Send + 'a>>;
}
