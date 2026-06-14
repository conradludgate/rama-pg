//! Parsing of the Postgres startup phase.
//!
//! Before a Postgres connection enters the regular tagged-message protocol it
//! exchanges a handful of untagged, length-prefixed packets: an optional
//! `SSLRequest`/`GSSENCRequest`, then either a `StartupMessage` carrying the
//! connection parameters or a `CancelRequest`. These packets share a layout of
//! `Int32 length` (inclusive of itself) followed by an `Int32` code that is
//! either a protocol version or one of the magic request codes below.

use std::io;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Postgres protocol 3.0 version number, sent as the code of a `StartupMessage`.
pub const PROTOCOL_VERSION_3_0: i32 = 196608;

/// Magic code occupying the version field of an `SSLRequest`.
pub const SSL_REQUEST_CODE: i32 = 80877103;
/// Magic code occupying the version field of a `GSSENCRequest`.
pub const GSSENC_REQUEST_CODE: i32 = 80877104;
/// Magic code occupying the version field of a `CancelRequest`.
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

/// Upper bound on a startup packet, mirroring Postgres' own 10000-byte limit.
/// Guards against a hostile or corrupt length prefix.
const MAX_STARTUP_PACKET_LEN: i32 = 10000;

/// A packet received during the startup phase, discriminated by its code.
#[derive(Debug, Clone)]
pub enum StartupRequest {
    /// Client requests a TLS upgrade (`SSLRequest`).
    Ssl,
    /// Client requests GSSAPI encryption (`GSSENCRequest`).
    GssEnc,
    /// Client wants to cancel a query running on another connection.
    Cancel(CancelRequest),
    /// Regular startup carrying connection parameters.
    Startup(StartupMessage),
}

/// A `CancelRequest`: identifies the backend connection to cancel by the
/// process id and secret key the server handed out at connection time.
#[derive(Debug, Clone, Copy)]
pub struct CancelRequest {
    pub process_id: i32,
    pub secret_key: i32,
}

/// A `StartupMessage`: the protocol version plus the connection parameters
/// (notably `user` and `database`).
#[derive(Debug, Clone, Default)]
pub struct StartupMessage {
    pub protocol_version: i32,
    pub parameters: Vec<(String, String)>,
}

impl StartupMessage {
    /// Look up a startup parameter by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The role to connect as. Required; libpq always sends it.
    pub fn user(&self) -> Option<&str> {
        self.get("user")
    }

    /// The database to connect to, defaulting to the user name when omitted
    /// (matching libpq's behaviour).
    pub fn database(&self) -> Option<&str> {
        self.get("database").or_else(|| self.user())
    }
}

/// Read a single startup-phase packet from `reader` and parse it.
///
/// Convenience over [`read_startup_frame`] + [`StartupRequest::parse`] for the
/// cases where the raw bytes aren't needed (e.g. the local SSLRequest shim).
pub async fn read_startup_request<R>(reader: &mut R) -> io::Result<StartupRequest>
where
    R: AsyncRead + Unpin,
{
    let frame = read_startup_frame(reader).await?;
    StartupRequest::parse(&frame)
}

/// Read a startup-phase frame, returning the complete on-wire bytes (the 4-byte
/// length prefix followed by the body).
///
/// Returning the raw frame lets the proxy forward a `StartupMessage` to a
/// backend verbatim, rather than re-serializing it.
pub async fn read_startup_frame<R>(reader: &mut R) -> io::Result<BytesMut>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_i32().await?;
    if !(8..=MAX_STARTUP_PACKET_LEN).contains(&len) {
        return Err(invalid(format!("invalid startup packet length: {len}")));
    }

    let mut frame = BytesMut::with_capacity(len as usize);
    frame.put_i32(len);
    frame.resize(len as usize, 0);
    reader.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

impl StartupRequest {
    /// Parse a startup-phase frame (as produced by [`read_startup_frame`]),
    /// dispatching on the code in the version field.
    pub fn parse(frame: &[u8]) -> io::Result<StartupRequest> {
        if frame.len() < 8 {
            return Err(invalid("startup frame shorter than 8 bytes"));
        }
        let len = i32::from_be_bytes(frame[..4].try_into().unwrap());
        let mut buf = &frame[4..];
        let code = buf.get_i32();

        match code {
            SSL_REQUEST_CODE if len == 8 => Ok(StartupRequest::Ssl),
            GSSENC_REQUEST_CODE if len == 8 => Ok(StartupRequest::GssEnc),
            CANCEL_REQUEST_CODE if len == 16 => Ok(StartupRequest::Cancel(CancelRequest {
                process_id: buf.get_i32(),
                secret_key: buf.get_i32(),
            })),
            version => Ok(StartupRequest::Startup(StartupMessage {
                protocol_version: version,
                parameters: parse_parameters(buf)?,
            })),
        }
    }
}

/// Parse the `key\0value\0...\0` parameter list of a `StartupMessage`, which is
/// terminated by an empty key (a lone null byte).
fn parse_parameters(mut buf: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut parameters = Vec::new();
    loop {
        let key = read_cstr(&mut buf)?;
        if key.is_empty() {
            return Ok(parameters);
        }
        let value = read_cstr(&mut buf)?;
        parameters.push((key, value));
    }
}

/// Read a null-terminated UTF-8 string from `buf`, advancing past the null.
fn read_cstr(buf: &mut &[u8]) -> io::Result<String> {
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| invalid("unterminated string in startup message"))?;
    let s = std::str::from_utf8(&buf[..nul])
        .map_err(|_| invalid("non-utf8 string in startup message"))?
        .to_owned();
    *buf = &buf[nul + 1..];
    Ok(s)
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(code: i32, body: &[u8]) -> Vec<u8> {
        let len = (body.len() + 8) as i32;
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    async fn parse(bytes: &[u8]) -> io::Result<StartupRequest> {
        read_startup_request(&mut &bytes[..]).await
    }

    #[tokio::test]
    async fn parses_ssl_request() {
        // SSLRequest is exactly the 8-byte length+code, no body.
        let bytes = encode(SSL_REQUEST_CODE, &[]);
        assert!(matches!(parse(&bytes).await.unwrap(), StartupRequest::Ssl));
    }

    #[tokio::test]
    async fn parses_gssenc_request() {
        let bytes = encode(GSSENC_REQUEST_CODE, &[]);
        assert!(matches!(
            parse(&bytes).await.unwrap(),
            StartupRequest::GssEnc
        ));
    }

    #[tokio::test]
    async fn parses_cancel_request() {
        let mut body = Vec::new();
        body.extend_from_slice(&42i32.to_be_bytes());
        body.extend_from_slice(&1337i32.to_be_bytes());
        let bytes = encode(CANCEL_REQUEST_CODE, &body);
        match parse(&bytes).await.unwrap() {
            StartupRequest::Cancel(c) => {
                assert_eq!(c.process_id, 42);
                assert_eq!(c.secret_key, 1337);
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parses_startup_parameters() {
        let body = b"user\0alice\0database\0shop\0\0";
        let bytes = encode(PROTOCOL_VERSION_3_0, body);
        match parse(&bytes).await.unwrap() {
            StartupRequest::Startup(msg) => {
                assert_eq!(msg.protocol_version, PROTOCOL_VERSION_3_0);
                assert_eq!(msg.user(), Some("alice"));
                assert_eq!(msg.database(), Some("shop"));
            }
            other => panic!("expected startup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn database_defaults_to_user() {
        let body = b"user\0bob\0\0";
        let bytes = encode(PROTOCOL_VERSION_3_0, body);
        match parse(&bytes).await.unwrap() {
            StartupRequest::Startup(msg) => assert_eq!(msg.database(), Some("bob")),
            other => panic!("expected startup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_short_length() {
        let bytes = 4i32.to_be_bytes();
        assert!(parse(&bytes).await.is_err());
    }

    #[tokio::test]
    async fn frame_preserves_raw_bytes() {
        // The raw frame must round-trip byte-for-byte so it can be forwarded
        // to a backend verbatim.
        let bytes = encode(PROTOCOL_VERSION_3_0, b"user\0alice\0\0");
        let frame = read_startup_frame(&mut &bytes[..]).await.unwrap();
        assert_eq!(&frame[..], &bytes[..]);
        assert!(matches!(
            StartupRequest::parse(&frame).unwrap(),
            StartupRequest::Startup(_)
        ));
    }
}
