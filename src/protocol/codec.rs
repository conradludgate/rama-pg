//! Regular-phase tagged-message framing.
//!
//! After startup, every Postgres message is `Int8 tag`, `Int32 length`
//! (inclusive of the length field, exclusive of the tag), then the body. The
//! proxy only needs to *interpret* a handful of these (auth, and later
//! `ReadyForQuery` for pooling); the rest are relayed opaquely. [`RawMessage`]
//! keeps the complete on-wire frame so it can be forwarded verbatim while still
//! exposing the tag and payload for inspection.

use std::io;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

// Backend → frontend tags.
/// `AuthenticationXxx` (the sub-type is the first Int32 of the payload).
pub const AUTHENTICATION: u8 = b'R';
/// `BackendKeyData` — the PID + secret key used for `CancelRequest`.
pub const BACKEND_KEY_DATA: u8 = b'K';
/// `ParameterStatus`.
pub const PARAMETER_STATUS: u8 = b'S';
/// `ReadyForQuery` — payload is the transaction status (`I`/`T`/`E`).
pub const READY_FOR_QUERY: u8 = b'Z';
/// `ErrorResponse`.
pub const ERROR_RESPONSE: u8 = b'E';
/// `RowDescription` — column metadata preceding a result set.
pub const ROW_DESCRIPTION: u8 = b'T';
/// `DataRow` — one row of a result set.
pub const DATA_ROW: u8 = b'D';
/// `CommandComplete` — carries the command tag (e.g. `SELECT 1`).
pub const COMMAND_COMPLETE: u8 = b'C';

// Frontend → backend tags.
/// `PasswordMessage` / SASL messages (cleartext password, JWT, SCRAM).
pub const PASSWORD_MESSAGE: u8 = b'p';
/// Simple `Query`.
pub const QUERY: u8 = b'Q';
/// `Terminate`.
pub const TERMINATE: u8 = b'X';

/// Sanity cap on an incoming frame: 1 GiB. Guards against a hostile length.
const MAX_MESSAGE_LEN: i32 = 1 << 30;

/// Tight cap for messages read during the pre-auth phase (the SASL / password
/// exchange). A cleartext password, a JWT-as-password, or any SCRAM message all
/// fit comfortably in 64 KiB, so bounding the length here stops an
/// *unauthenticated* peer from using a 5-byte header to force the full 1 GiB
/// up-front allocation that the regular [`MAX_MESSAGE_LEN`] would permit.
pub const MAX_AUTH_MESSAGE_LEN: i32 = 1 << 16;

/// A complete tagged frame, retained verbatim for opaque forwarding.
#[derive(Debug, Clone)]
pub struct RawMessage {
    /// `tag (1) | length (4) | body`.
    frame: BytesMut,
}

impl RawMessage {
    /// The message tag byte.
    pub fn tag(&self) -> u8 {
        self.frame[0]
    }

    /// The body, after the tag and length prefix.
    pub fn payload(&self) -> &[u8] {
        &self.frame[5..]
    }

    /// The complete on-wire frame (tag + length + body), ready to forward.
    pub fn as_bytes(&self) -> &[u8] {
        &self.frame
    }

    /// Consume into the owned frame bytes.
    pub fn into_bytes(self) -> BytesMut {
        self.frame
    }
}

/// Read one tagged message from `reader`, returning the complete frame.
///
/// Uses the regular [`MAX_MESSAGE_LEN`] cap; for streams from an
/// *unauthenticated* peer prefer [`read_message_capped`] with a tight bound.
pub async fn read_message<R>(reader: &mut R) -> io::Result<RawMessage>
where
    R: AsyncRead + Unpin,
{
    read_message_capped(reader, MAX_MESSAGE_LEN).await
}

/// Like [`read_message`], but rejects (rather than allocating for) any frame
/// whose declared length exceeds `max_len`. Pass a tight `max_len` such as
/// [`MAX_AUTH_MESSAGE_LEN`] on the pre-auth path so a hostile length can't drive
/// a large up-front allocation before the peer has authenticated.
pub async fn read_message_capped<R>(reader: &mut R, max_len: i32) -> io::Result<RawMessage>
where
    R: AsyncRead + Unpin,
{
    let tag = reader.read_u8().await?;
    let len = reader.read_i32().await?;
    if !(4..=max_len).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid message length {len} for tag {:?}", tag as char),
        ));
    }

    // Total frame = tag (1) + len (which already counts the 4 length bytes).
    let mut frame = BytesMut::with_capacity(len as usize + 1);
    frame.put_u8(tag);
    frame.put_i32(len);
    frame.resize(len as usize + 1, 0);
    reader.read_exact(&mut frame[5..]).await?;

    Ok(RawMessage { frame })
}

/// Build a tagged frame from a `tag` and `body`, wrapping it in the
/// `tag | Int32 length | body` envelope.
pub fn frame(tag: u8, body: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(body.len() + 5);
    out.put_u8(tag);
    out.put_i32((body.len() + 4) as i32);
    out.extend_from_slice(body);
    out
}

/// A buffered, **cancel-safe** frame reader.
///
/// Unlike [`read_message`], `read_frame` can be used in a `tokio::select!` arm:
/// any partially-read bytes live in the persistent buffer (filled via the
/// cancel-safe `read_buf`), so a cancelled read never drops data mid-frame.
/// This is what makes the bidirectional pooling relay correct.
#[derive(Debug)]
pub struct FramedReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
        }
    }

    /// Mutable access to the underlying stream (e.g. to write to it).
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Read one frame, `None` at a clean end of stream. Cancel-safe.
    pub async fn read_frame(&mut self) -> io::Result<Option<RawMessage>> {
        loop {
            if let Some(frame) = take_frame(&mut self.buf)? {
                return Ok(Some(frame));
            }
            if self.inner.read_buf(&mut self.buf).await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended mid-message",
                    ))
                };
            }
        }
    }
}

/// Split off a complete frame from `buf` if one is fully buffered.
fn take_frame(buf: &mut BytesMut) -> io::Result<Option<RawMessage>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = i32::from_be_bytes(buf[1..5].try_into().unwrap());
    if !(4..=MAX_MESSAGE_LEN).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid message length {len} for tag {:?}", buf[0] as char),
        ));
    }
    let total = 1 + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(RawMessage {
        frame: buf.split_to(total),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_message_round_trips_a_built_frame() {
        let built = frame(QUERY, b"select 1\0");
        let msg = read_message(&mut &built[..]).await.unwrap();
        assert_eq!(msg.tag(), QUERY);
        assert_eq!(msg.payload(), b"select 1\0");
        assert_eq!(msg.as_bytes(), &built[..]);
    }

    #[tokio::test]
    async fn rejects_undersized_length() {
        // tag 'Q', length 3 (< 4).
        let bytes = [QUERY, 0, 0, 0, 3];
        assert!(read_message(&mut &bytes[..]).await.is_err());
    }

    #[tokio::test]
    async fn capped_read_rejects_oversized_length_without_allocating() {
        // A 5-byte header declaring a 1 GiB body. Under the auth cap this is
        // rejected outright rather than triggering a huge up-front allocation,
        // closing the pre-auth amplification DoS.
        let bytes = [PASSWORD_MESSAGE, 0x40, 0, 0, 0]; // len = 1 GiB
        let err = read_message_capped(&mut &bytes[..], MAX_AUTH_MESSAGE_LEN)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn capped_read_accepts_a_small_frame() {
        let built = frame(PASSWORD_MESSAGE, b"hunter2\0");
        let msg = read_message_capped(&mut &built[..], MAX_AUTH_MESSAGE_LEN)
            .await
            .unwrap();
        assert_eq!(msg.tag(), PASSWORD_MESSAGE);
        assert_eq!(msg.payload(), b"hunter2\0");
    }

    #[tokio::test]
    async fn framed_reader_splits_consecutive_frames() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&frame(QUERY, b"select 1\0"));
        stream.extend_from_slice(&frame(READY_FOR_QUERY, b"I"));
        let bytes = stream.to_vec();

        let mut reader = FramedReader::new(&bytes[..]);
        let first = reader.read_frame().await.unwrap().unwrap();
        assert_eq!(first.tag(), QUERY);
        assert_eq!(first.payload(), b"select 1\0");
        let second = reader.read_frame().await.unwrap().unwrap();
        assert_eq!(second.tag(), READY_FOR_QUERY);
        assert_eq!(second.payload(), b"I");
        assert!(reader.read_frame().await.unwrap().is_none()); // clean EOF
    }
}
