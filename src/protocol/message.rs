//! Server-to-client message builders.
//!
//! In the regular protocol phase every message is `Int8 tag`, `Int32 length`
//! (inclusive of itself, excluding the tag), then the body. For now we only
//! need to construct an `ErrorResponse`; the general tagged-frame codec lands
//! with the proxying work.

use bytes::{BufMut, BytesMut};

/// `ErrorResponse` message tag.
pub const ERROR_RESPONSE: u8 = b'E';

/// Build a fatal `ErrorResponse` frame.
///
/// `code` is the five-character SQLSTATE (e.g. `08004` server-rejected, `28P01`
/// invalid authorization). The message is what a client like psql prints.
pub fn fatal_error(code: &str, message: &str) -> BytesMut {
    error_response("FATAL", code, message)
}

/// Build an `ErrorResponse` with the given severity, SQLSTATE `code` and
/// human-readable `message`. Fields are each `Int8 type` + a null-terminated
/// string, and the field list is terminated by a single null byte.
pub fn error_response(severity: &str, code: &str, message: &str) -> BytesMut {
    let mut body = BytesMut::new();
    // 'S' localized severity and 'V' non-localized severity (3.0+).
    put_field(&mut body, b'S', severity);
    put_field(&mut body, b'V', severity);
    put_field(&mut body, b'C', code);
    put_field(&mut body, b'M', message);
    body.put_u8(0); // terminator

    frame(ERROR_RESPONSE, &body)
}

/// Wrap a body in the `tag` + `Int32 length` envelope.
fn frame(tag: u8, body: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(body.len() + 5);
    out.put_u8(tag);
    out.put_i32((body.len() + 4) as i32);
    out.extend_from_slice(body);
    out
}

fn put_field(buf: &mut BytesMut, field_type: u8, value: &str) {
    buf.put_u8(field_type);
    buf.extend_from_slice(value.as_bytes());
    buf.put_u8(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_error_is_well_framed() {
        let msg = fatal_error("08004", "no backend");
        assert_eq!(msg[0], ERROR_RESPONSE);
        let len = i32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        // length covers everything after the tag.
        assert_eq!(len as usize, msg.len() - 1);
        // body ends with the field-list terminator.
        assert_eq!(*msg.last().unwrap(), 0);
    }
}
