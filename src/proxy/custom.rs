//! Custom forwarding: answer queries in-proxy with no backend ("virtual Postgres").

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rama::Service;
use rama::error::BoxError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{PgClient, reject, synthesize_startup};
use crate::auth::ClientAuth;
use crate::cancel::{CancelHandle, Cancellation, TokenCancel};
use crate::protocol::codec::{self, read_message};
use crate::protocol::message::{
    command_complete, data_row, error_response, parameter_status, ready_for_query, row_description,
};
use crate::protocol::startup::CancelKey;
use crate::query::{QueryContext, QueryHandler, QueryResponse, SessionState, TxnStatus};

/// Custom forwarding: answer queries in-proxy with no backend at all.
pub struct CustomForwarder {
    handler: Arc<dyn QueryHandler>,
    cancellation: Arc<dyn Cancellation>,
}

impl CustomForwarder {
    pub fn new(handler: Arc<dyn QueryHandler>, cancellation: Arc<dyn Cancellation>) -> Self {
        Self {
            handler,
            cancellation,
        }
    }
}

impl<IO> Service<PgClient<IO>> for CustomForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        let PgClient {
            stream,
            startup,
            protocol_version,
            sni,
            auth,
        } = client;
        let user = startup.user().unwrap_or_default().to_owned();
        let database = startup.database().unwrap_or_default().to_owned();
        tracing::info!(?sni, user, "custom query session");
        // Begin a cancel session: the key to advertise, and a handle the loop
        // points at a fresh per-query token so a client's CancelRequest fires it.
        let (client_key, handle) = self.cancellation.begin(protocol_version).await?;
        serve_custom(stream, &user, &database, auth, self.handler.clone(), client_key, &handle).await
    }
}

/// Custom-query session: synthesize the startup completion (a canned
/// `ParameterStatus` set), then handle `Query` messages, tracking the
/// transaction status in a per-connection [`SessionState`] for `ReadyForQuery`.
///
/// Only the simple query protocol is supported (no extended Parse/Bind/Execute).
#[allow(clippy::too_many_arguments)]
async fn serve_custom<C>(
    mut stream: C,
    user: &str,
    database: &str,
    outcome: ClientAuth,
    handler: Arc<dyn QueryHandler>,
    client_key: Option<CancelKey>,
    handle: &CancelHandle,
) -> Result<(), BoxError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if matches!(outcome, ClientAuth::PassThrough) {
        return reject(
            &mut stream,
            "0A000",
            "rama-pg: custom-query mode requires a terminating auth mode",
        )
        .await;
    }

    // Synthesize the startup completion (there is no backend to capture from),
    // advertising the cancel key the provider issued (or a throwaway when off).
    let params: Vec<BytesMut> = VIRTUAL_PARAMETERS
        .iter()
        .map(|(name, value)| parameter_status(name, value))
        .collect();
    let cancel_key = client_key.unwrap_or_else(|| {
        CancelKey::from_bytes(Bytes::copy_from_slice(&rand::random::<u64>().to_be_bytes()))
    });
    synthesize_startup(&mut stream, &params, cancel_key.as_bytes()).await?;

    let state = SessionState::default();
    loop {
        let message = match read_message(&mut stream).await {
            Ok(message) => message,
            Err(_) => break, // client gone
        };
        match message.tag() {
            codec::QUERY => {
                let sql = query_sql(message.payload());
                // A fresh token per query (a prior cancel must not pre-cancel this
                // one); point the cancel handle at it for the query's duration.
                let cancel = CancellationToken::new();
                handle.set(Arc::new(TokenCancel(cancel.clone())));
                let result = run_query(&mut stream, &state, &*handler, user, database, sql, &cancel).await;
                handle.clear();
                result?;
            }
            codec::TERMINATE => break,
            other => {
                tracing::debug!(tag = ?(other as char), "unsupported message in custom mode");
                stream
                    .write_all(&error_response(
                        "ERROR",
                        "0A000",
                        "rama-pg virtual server supports only the simple query protocol",
                    ))
                    .await?;
                stream
                    .write_all(&ready_for_query(state.txn_status().code()))
                    .await?;
                stream.flush().await?;
            }
        }
    }
    tracing::info!("custom query session closed");
    Ok(())
}

/// `ParameterStatus` values the virtual server reports at startup.
const VIRTUAL_PARAMETERS: &[(&str, &str)] = &[
    ("server_version", "16.0 (rama-pg virtual)"),
    ("server_encoding", "UTF8"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
    ("TimeZone", "UTC"),
    ("standard_conforming_strings", "on"),
    ("integer_datetimes", "on"),
];

/// The SQL from a `Query` payload (a single null-terminated string).
fn query_sql(payload: &[u8]) -> &str {
    let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
    std::str::from_utf8(&payload[..end]).unwrap_or("")
}

/// Run one simple query: handle transaction control locally, delegate the rest
/// to the handler, then emit `ReadyForQuery` with the current transaction status.
#[allow(clippy::too_many_arguments)]
async fn run_query<C>(
    client: &mut C,
    state: &SessionState,
    handler: &dyn QueryHandler,
    user: &str,
    database: &str,
    sql: &str,
    cancel: &CancellationToken,
) -> Result<(), BoxError>
where
    C: AsyncWrite + Unpin,
{
    let trimmed = sql.trim().trim_end_matches(';').trim();
    let verb = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let status = state.txn_status();

    if status == TxnStatus::Failed
        && !matches!(verb.as_str(), "COMMIT" | "ROLLBACK" | "END" | "ABORT")
    {
        // A failed transaction rejects everything until it ends.
        client
            .write_all(&error_response(
                "ERROR",
                "25P02",
                "current transaction is aborted, commands ignored until end of transaction block",
            ))
            .await?;
    } else {
        match verb.as_str() {
            "BEGIN" | "START" => {
                state.set_txn_status(TxnStatus::InTransaction);
                client.write_all(&command_complete("BEGIN")).await?;
            }
            "COMMIT" | "END" => {
                state.set_txn_status(TxnStatus::Idle);
                client.write_all(&command_complete("COMMIT")).await?;
            }
            "ROLLBACK" | "ABORT" => {
                state.set_txn_status(TxnStatus::Idle);
                client.write_all(&command_complete("ROLLBACK")).await?;
            }
            _ => {
                let ctx = QueryContext { user, database, state, cancel };
                match handler.handle(ctx, trimmed).await {
                    QueryResponse::Rows { columns, rows, tag } => {
                        let headers: Vec<&str> = columns.iter().map(String::as_str).collect();
                        client.write_all(&row_description(&headers)).await?;
                        for row in &rows {
                            let cells: Vec<Option<&str>> = row.iter().map(Option::as_deref).collect();
                            client.write_all(&data_row(&cells)).await?;
                        }
                        client.write_all(&command_complete(&tag)).await?;
                    }
                    QueryResponse::Command(tag) => {
                        client.write_all(&command_complete(&tag)).await?;
                    }
                    QueryResponse::Error { code, message } => {
                        client
                            .write_all(&error_response("ERROR", &code, &message))
                            .await?;
                        if status == TxnStatus::InTransaction {
                            state.set_txn_status(TxnStatus::Failed);
                        }
                    }
                }
            }
        }
    }

    client
        .write_all(&ready_for_query(state.txn_status().code()))
        .await?;
    client.flush().await?;
    Ok(())
}
