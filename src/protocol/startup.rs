//! Parsing of the Postgres startup phase.
//!
//! Before a Postgres connection enters the regular tagged-message protocol it
//! exchanges a handful of untagged, length-prefixed packets: an optional
//! `SSLRequest`/`GSSENCRequest`, then either a `StartupMessage` carrying the
//! connection parameters or a `CancelRequest`. These packets share a layout of
//! `Int32 length` (inclusive of itself) followed by an `Int32` code that is
//! either a protocol version or one of the magic request codes below.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Postgres protocol 3.0 version number, sent as the code of a `StartupMessage`.
/// Encoded as `(major << 16) | minor`, so 3.0 is `(3 << 16) | 0`.
pub const PROTOCOL_VERSION_3_0: i32 = 196608;

/// Postgres protocol 3.2 version number (`(3 << 16) | 2`), introduced in
/// PostgreSQL 18. Its one wire change the proxy cares about is variable-length
/// cancel keys (3.0's are a fixed 4 bytes).
pub const PROTOCOL_VERSION_3_2: i32 = 196610;

/// Highest protocol version the proxy offers clients when it is the negotiating
/// authority (the synthesized/terminate paths). Newer requests are negotiated
/// down to this via `NegotiateProtocolVersion`.
pub const MAX_PROTOCOL_VERSION: i32 = PROTOCOL_VERSION_3_2;

/// The major version of a protocol version number (the high 16 bits).
pub fn protocol_major(version: i32) -> i32 {
    (version >> 16) & 0xffff
}

/// The minor version of a protocol version number (the low 16 bits).
pub fn protocol_minor(version: i32) -> i32 {
    version & 0xffff
}

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

/// A Postgres cancel key: the opaque `Int32 pid` + secret-key bytes carried
/// identically by a `BackendKeyData` payload and a `CancelRequest` body, so one
/// can be reused verbatim as the other. Length-agnostic (8 bytes in protocol 3.0,
/// longer in 3.2). The secret is never shown in `Debug`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CancelKey(Bytes);

impl CancelKey {
    /// Wrap the raw `pid + secret` payload bytes.
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// The raw payload, to forward as a `CancelRequest` body or `BackendKeyData`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The process id being targeted (the leading `Int32`), for logging. `None`
    /// if the key is too short.
    pub fn process_id(&self) -> Option<i32> {
        self.0.get(..4).map(|b| i32::from_be_bytes(b.try_into().unwrap()))
    }
}

impl std::fmt::Debug for CancelKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the secret: show only the pid and length.
        f.debug_struct("CancelKey")
            .field("process_id", &self.process_id())
            .field("len", &self.0.len())
            .finish()
    }
}

/// A `CancelRequest`: identifies the backend connection to cancel by the
/// [`CancelKey`] the server handed out at connection time (in `BackendKeyData`).
#[derive(Debug, Clone)]
pub struct CancelRequest {
    pub key: CancelKey,
}

impl CancelRequest {
    /// The process id being targeted, for logging.
    pub fn process_id(&self) -> Option<i32> {
        self.key.process_id()
    }
}

/// A `StartupMessage`: the protocol version plus the connection parameters
/// (notably `user` and `database`). A parsed message also keeps its original
/// on-wire [`frame`](Self::frame) so the proxy can replay it to a backend
/// verbatim — no need to carry the raw bytes alongside it.
#[derive(Debug, Clone, Default)]
pub struct StartupMessage {
    protocol_version: i32,
    parameters: Vec<(String, String)>,
    /// The original on-wire frame (empty for a synthetically-built message).
    raw: Bytes,
}

impl StartupMessage {
    /// Build a message with no raw frame, for synthetic use (e.g. tests). A
    /// *parsed* message instead carries its frame; see [`frame`](Self::frame).
    pub fn new(protocol_version: i32, parameters: Vec<(String, String)>) -> Self {
        Self {
            protocol_version,
            parameters,
            raw: Bytes::new(),
        }
    }

    /// The original startup frame, to replay to a backend verbatim (empty when
    /// the message was built synthetically rather than parsed off the wire).
    pub fn frame(&self) -> &[u8] {
        &self.raw
    }

    /// The requested protocol version code.
    pub fn protocol_version(&self) -> i32 {
        self.protocol_version
    }

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

    /// The requested major protocol version.
    pub fn protocol_major(&self) -> i32 {
        protocol_major(self.protocol_version)
    }

    /// The requested minor protocol version.
    pub fn protocol_minor(&self) -> i32 {
        protocol_minor(self.protocol_version)
    }

    /// Protocol-extension parameters (`_pq_.*`) the client offered. The proxy
    /// honours none of them, so these are reported back as unrecognised in a
    /// `NegotiateProtocolVersion`.
    pub fn pq_options(&self) -> impl Iterator<Item = &str> {
        self.parameters
            .iter()
            .filter(|(k, _)| k.starts_with("_pq_."))
            .map(|(k, _)| k.as_str())
    }

    /// The version the proxy will use with this client: the same major, with the
    /// minor capped at [`MAX_PROTOCOL_VERSION`].
    pub fn negotiated_version(&self) -> i32 {
        let minor = self.protocol_minor().min(protocol_minor(MAX_PROTOCOL_VERSION));
        (self.protocol_major() << 16) | minor
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
    StartupRequest::parse(frame.freeze())
}

/// Build a `StartupMessage` frame for the given connection `parameters`
/// (e.g. `[("user", "postgres"), ("database", "postgres")]`). Used when the
/// proxy opens its own connection to a backend.
pub fn startup_message(parameters: &[(&str, &str)]) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i32(PROTOCOL_VERSION_3_0);
    for (key, value) in parameters {
        body.extend_from_slice(key.as_bytes());
        body.put_u8(0);
        body.extend_from_slice(value.as_bytes());
        body.put_u8(0);
    }
    body.put_u8(0); // end of parameter list

    let mut frame = BytesMut::with_capacity(body.len() + 4);
    frame.put_i32((body.len() + 4) as i32);
    frame.extend_from_slice(&body);
    frame
}

/// Build a `CancelRequest` startup-phase frame carrying `key` (an `Int32 pid` +
/// secret key payload — e.g. a backend's captured `BackendKeyData` body). The
/// key length is not fixed, so a protocol-3.2 long key works unchanged.
pub fn cancel_request_frame(key: &[u8]) -> BytesMut {
    let len = 8 + key.len(); // length(4) + cancel code(4) + key
    let mut frame = BytesMut::with_capacity(len);
    frame.put_i32(len as i32);
    frame.put_i32(CANCEL_REQUEST_CODE);
    frame.extend_from_slice(key);
    frame
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
    /// dispatching on the code in the version field. Takes the frame by value so a
    /// `Startup`/`Cancel` can keep it (replayed verbatim / reused as a cancel key)
    /// without a copy.
    pub fn parse(frame: Bytes) -> io::Result<StartupRequest> {
        if frame.len() < 8 {
            return Err(invalid("startup frame shorter than 8 bytes"));
        }
        let len = i32::from_be_bytes(frame[..4].try_into().unwrap());
        let code = i32::from_be_bytes(frame[4..8].try_into().unwrap());

        match code {
            SSL_REQUEST_CODE if len == 8 => Ok(StartupRequest::Ssl),
            GSSENC_REQUEST_CODE if len == 8 => Ok(StartupRequest::GssEnc),
            // `len >= 16` rather than `== 16`: protocol 3.0's key is 8 bytes
            // (pid + Int32 secret), 3.2's is longer. The bytes after the code are
            // captured opaquely.
            CANCEL_REQUEST_CODE if len >= 16 => Ok(StartupRequest::Cancel(CancelRequest {
                key: CancelKey::from_bytes(frame.slice(8..)),
            })),
            version => Ok(StartupRequest::Startup(StartupMessage {
                protocol_version: version,
                parameters: parse_parameters(&frame[8..])?,
                raw: frame,
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
                assert_eq!(c.process_id(), Some(42));
                assert_eq!(c.key.as_bytes(), &body[..]);
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_request_frame_round_trips() {
        // A built CancelRequest parses back to the same opaque key.
        let key = [0u8, 0, 0, 7, 0xde, 0xad, 0xbe, 0xef];
        let frame = cancel_request_frame(&key);
        match read_startup_request(&mut &frame[..]).await.unwrap() {
            StartupRequest::Cancel(c) => {
                assert_eq!(c.key.as_bytes(), &key[..]);
                assert_eq!(c.process_id(), Some(7));
            }
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parses_a_longer_cancel_key() {
        // A protocol-3.2-style longer key is captured whole (no fixed 16-byte len).
        let body = vec![0xab; 32];
        let bytes = encode(CANCEL_REQUEST_CODE, &body);
        match parse(&bytes).await.unwrap() {
            StartupRequest::Cancel(c) => assert_eq!(c.key.as_bytes(), &body[..]),
            other => panic!("expected cancel, got {other:?}"),
        }
    }

    fn startup(version: i32, params: &[(&str, &str)]) -> StartupMessage {
        StartupMessage::new(
            version,
            params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        )
    }

    #[test]
    fn negotiates_minor_down_to_max() {
        let msg = startup((3 << 16) | 5, &[]); // client wants 3.5
        assert_eq!(msg.protocol_major(), 3);
        assert_eq!(msg.protocol_minor(), 5);
        assert_eq!(msg.negotiated_version(), PROTOCOL_VERSION_3_2); // capped at 3.2
    }

    #[test]
    fn keeps_a_supported_minor() {
        assert_eq!(startup(PROTOCOL_VERSION_3_0, &[]).negotiated_version(), PROTOCOL_VERSION_3_0);
        assert_eq!(startup(PROTOCOL_VERSION_3_2, &[]).negotiated_version(), PROTOCOL_VERSION_3_2);
    }

    #[test]
    fn collects_pq_options() {
        let msg = startup(
            PROTOCOL_VERSION_3_2,
            &[("user", "alice"), ("_pq_.foo", "1"), ("_pq_.bar", "2")],
        );
        assert_eq!(msg.pq_options().collect::<Vec<_>>(), vec!["_pq_.foo", "_pq_.bar"]);
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
        // The parsed StartupMessage carries the original frame verbatim.
        match StartupRequest::parse(frame.freeze()).unwrap() {
            StartupRequest::Startup(msg) => assert_eq!(msg.frame(), &bytes[..]),
            other => panic!("expected startup, got {other:?}"),
        }
    }
}
