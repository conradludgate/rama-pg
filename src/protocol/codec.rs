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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
/// `NegotiateProtocolVersion` — sent when the client asked for a newer minor
/// version (or unknown `_pq_` options) than the server supports.
pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
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

/// A validated five-byte tagged-message header, without a buffered body.
///
/// Inspect the tag to decide whether to decode a body or stream it unchanged.
/// The encoded length includes its four bytes, but excludes the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader([u8; 5]);

impl MessageHeader {
    fn parse(bytes: [u8; 5], max_len: i32) -> io::Result<Self> {
        let len = i32::from_be_bytes(bytes[1..].try_into().expect("four length bytes"));
        if !(4..=max_len).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid message length {len} for tag {:?}",
                    bytes[0] as char
                ),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn tag(self) -> u8 {
        self.0[0]
    }

    /// Number of body bytes following this header.
    pub fn body_len(self) -> usize {
        (i32::from_be_bytes(self.0[1..].try_into().expect("four length bytes")) - 4) as usize
    }

    /// The header as received, ready for verbatim forwarding.
    pub fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }

    /// Copy exactly this body's bytes using caller-owned scratch space.
    ///
    /// Does not allocate, flush, or consume the following frame. Empty scratch
    /// space is valid only for an empty body. This operation is not cancel-safe;
    /// after interruption or an I/O error, do not resume parsing this stream.
    pub async fn copy_body_to<R, W>(
        self,
        reader: &mut R,
        writer: &mut W,
        scratch: &mut [u8],
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut remaining = self.body_len();
        if remaining != 0 && scratch.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty body-copy buffer",
            ));
        }
        while remaining != 0 {
            let chunk = remaining.min(scratch.len());
            reader.read_exact(&mut scratch[..chunk]).await?;
            writer.write_all(&scratch[..chunk]).await?;
            remaining -= chunk;
        }
        Ok(())
    }
}

/// Read and validate a header before reading or allocating for its body.
/// `max_len` bounds the encoded length (including the four length bytes).
/// This operation is not cancel-safe; use [`FramedReader`] in `select!`.
pub async fn read_header<R>(reader: &mut R, max_len: i32) -> io::Result<MessageHeader>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0; 5];
    reader.read_exact(&mut bytes).await?;
    MessageHeader::parse(bytes, max_len)
}

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
/// a large up-front allocation before the peer has authenticated. Body storage
/// grows with received bytes, rather than the declared length. Not cancel-safe.
pub async fn read_message_capped<R>(reader: &mut R, max_len: i32) -> io::Result<RawMessage>
where
    R: AsyncRead + Unpin,
{
    let header = read_header(reader, max_len).await?;
    let mut frame = BytesMut::from(header.as_bytes().as_slice());
    let total = 5 + header.body_len();
    while frame.len() < total {
        let remaining = (total - frame.len()) as u64;
        if (&mut *reader).take(remaining).read_buf(&mut frame).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended mid-message",
            ));
        }
    }

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
    max_len: i32,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self::with_max_len(inner, MAX_MESSAGE_LEN)
    }

    /// Set the maximum encoded message length, including its four length bytes.
    /// Headers are validated before reading body bytes. Storage grows only as
    /// bytes arrive, and reads never consume bytes belonging to the next frame.
    pub fn with_max_len(inner: R, max_len: i32) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
            max_len,
        }
    }

    /// Mutable access to the underlying stream (e.g. to write to it).
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Read one frame, `None` at a clean end of stream. Cancel-safe.
    pub async fn read_frame(&mut self) -> io::Result<Option<RawMessage>> {
        loop {
            let missing = if self.buf.len() < 5 {
                5 - self.buf.len()
            } else {
                let header = MessageHeader::parse(
                    self.buf[..5]
                        .try_into()
                        .expect("five buffered header bytes"),
                    self.max_len,
                )?;
                let total = 5 + header.body_len();
                if self.buf.len() == total {
                    return Ok(Some(RawMessage {
                        frame: self.buf.split_to(total),
                    }));
                }
                total - self.buf.len()
            };
            // Reclaim/reuse a split buffer before reading, rather than issuing
            // extra reads into small leftover fragments. A declared large body
            // can reserve only one bounded chunk before any bytes arrive.
            self.buf.reserve(missing.min(8 * 1024));
            if (&mut self.inner)
                .take(missing as u64)
                .read_buf(&mut self.buf)
                .await?
                == 0
            {
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
