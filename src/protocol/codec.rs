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

// Frontend → backend tags.
/// `PasswordMessage` / SASL messages (cleartext password, JWT, SCRAM).
pub const PASSWORD_MESSAGE: u8 = b'p';
/// Simple `Query`.
pub const QUERY: u8 = b'Q';
/// `Terminate`.
pub const TERMINATE: u8 = b'X';

/// Sanity cap on an incoming frame: 1 GiB. Guards against a hostile length.
const MAX_MESSAGE_LEN: i32 = 1 << 30;

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
pub async fn read_message<R>(reader: &mut R) -> io::Result<RawMessage>
where
    R: AsyncRead + Unpin,
{
    let tag = reader.read_u8().await?;
    let len = reader.read_i32().await?;
    if !(4..=MAX_MESSAGE_LEN).contains(&len) {
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
}
