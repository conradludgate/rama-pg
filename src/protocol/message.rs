//! Server-to-client message builders.
//!
//! These construct specific frames on top of the generic framing in
//! [`crate::protocol::codec`]. For now we only need an `ErrorResponse`; auth
//! messages join as that work lands.

use bytes::{BufMut, BytesMut};

use super::codec::{
    AUTHENTICATION, BACKEND_KEY_DATA, COMMAND_COMPLETE, DATA_ROW, ERROR_RESPONSE, PARAMETER_STATUS,
    READY_FOR_QUERY, ROW_DESCRIPTION, frame,
};

/// Postgres OID for the `text` type — every column a virtual server emits is
/// sent as text.
const TEXT_OID: i32 = 25;

/// `Authentication` sub-type: the request succeeded (`AuthenticationOk`).
const AUTH_OK: i32 = 0;
/// `Authentication` sub-type: the client must send a cleartext password.
const AUTH_CLEARTEXT_PASSWORD: i32 = 3;
/// `Authentication` sub-type: begin a SASL exchange (`AuthenticationSASL`).
const AUTH_SASL: i32 = 10;
/// `Authentication` sub-type: SASL challenge (`AuthenticationSASLContinue`).
const AUTH_SASL_CONTINUE: i32 = 11;
/// `Authentication` sub-type: SASL completion (`AuthenticationSASLFinal`).
const AUTH_SASL_FINAL: i32 = 12;

/// Build an `AuthenticationOk` frame.
pub fn authentication_ok() -> BytesMut {
    frame(AUTHENTICATION, &AUTH_OK.to_be_bytes())
}

/// Build an `AuthenticationCleartextPassword` frame, asking the client to reply
/// with a `PasswordMessage` carrying the password in the clear (safe here only
/// because the client link is TLS).
pub fn authentication_cleartext_password() -> BytesMut {
    frame(AUTHENTICATION, &AUTH_CLEARTEXT_PASSWORD.to_be_bytes())
}

/// Build an `AuthenticationSASL` frame offering the given SASL `mechanisms`.
/// The mechanism list is a sequence of cstrings terminated by an empty one.
pub fn authentication_sasl(mechanisms: &[&str]) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i32(AUTH_SASL);
    for mechanism in mechanisms {
        body.extend_from_slice(mechanism.as_bytes());
        body.put_u8(0);
    }
    body.put_u8(0); // terminating empty mechanism name
    frame(AUTHENTICATION, &body)
}

/// Build an `AuthenticationSASLContinue` frame carrying SASL challenge `data`.
pub fn authentication_sasl_continue(data: &[u8]) -> BytesMut {
    sasl_message(AUTH_SASL_CONTINUE, data)
}

/// Build an `AuthenticationSASLFinal` frame carrying SASL completion `data`.
pub fn authentication_sasl_final(data: &[u8]) -> BytesMut {
    sasl_message(AUTH_SASL_FINAL, data)
}

fn sasl_message(subtype: i32, data: &[u8]) -> BytesMut {
    let mut body = BytesMut::with_capacity(data.len() + 4);
    body.put_i32(subtype);
    body.extend_from_slice(data);
    frame(AUTHENTICATION, &body)
}

/// Build a `ParameterStatus` frame (`name`/`value`), sent during startup.
pub fn parameter_status(name: &str, value: &str) -> BytesMut {
    let mut body = BytesMut::new();
    put_cstr(&mut body, name);
    put_cstr(&mut body, value);
    frame(PARAMETER_STATUS, &body)
}

/// Build a `RowDescription` frame describing `columns`, all typed as `text`.
pub fn row_description(columns: &[&str]) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i16(columns.len() as i16);
    for name in columns {
        put_cstr(&mut body, name);
        body.put_i32(0); // table OID
        body.put_i16(0); // column attribute number
        body.put_i32(TEXT_OID);
        body.put_i16(-1); // type size (variable)
        body.put_i32(-1); // type modifier
        body.put_i16(0); // format code: text
    }
    frame(ROW_DESCRIPTION, &body)
}

/// Build a `DataRow` frame; `None` values are sent as SQL NULL.
pub fn data_row(values: &[Option<&str>]) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i16(values.len() as i16);
    for value in values {
        match value {
            Some(text) => {
                body.put_i32(text.len() as i32);
                body.extend_from_slice(text.as_bytes());
            }
            None => body.put_i32(-1), // NULL
        }
    }
    frame(DATA_ROW, &body)
}

/// Build a `CommandComplete` frame carrying the command `tag` (e.g. `SELECT 1`).
pub fn command_complete(tag: &str) -> BytesMut {
    let mut body = BytesMut::new();
    put_cstr(&mut body, tag);
    frame(COMMAND_COMPLETE, &body)
}

/// Build a `BackendKeyData` frame (the PID + secret used for `CancelRequest`).
/// In pooling mode the proxy issues its own, since backends are shared.
pub fn backend_key_data(process_id: i32, secret_key: i32) -> BytesMut {
    let mut body = BytesMut::with_capacity(8);
    body.put_i32(process_id);
    body.put_i32(secret_key);
    frame(BACKEND_KEY_DATA, &body)
}

/// Build a `BackendKeyData` frame from a raw payload (`Int32 pid` + secret key),
/// e.g. a key minted by the cancellation provider. Length-agnostic, so a
/// protocol-3.2 long key works unchanged.
pub fn backend_key_data_raw(payload: &[u8]) -> BytesMut {
    frame(BACKEND_KEY_DATA, payload)
}

/// Build a `ReadyForQuery` frame with the given transaction status (`I`/`T`/`E`).
pub fn ready_for_query(status: u8) -> BytesMut {
    frame(READY_FOR_QUERY, &[status])
}

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

fn put_field(buf: &mut BytesMut, field_type: u8, value: &str) {
    buf.put_u8(field_type);
    put_cstr(buf, value);
}

/// Append a null-terminated string.
fn put_cstr(buf: &mut BytesMut, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.put_u8(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_and_data_are_well_framed() {
        let desc = row_description(&["id", "name"]);
        assert_eq!(desc[0], ROW_DESCRIPTION);
        assert_eq!(i16::from_be_bytes([desc[5], desc[6]]), 2); // field count after tag+len

        let row = data_row(&[Some("1"), None]);
        assert_eq!(row[0], DATA_ROW);
        let len = i32::from_be_bytes([row[1], row[2], row[3], row[4]]);
        assert_eq!(len as usize, row.len() - 1);

        let complete = command_complete("SELECT 1");
        assert_eq!(complete[0], COMMAND_COMPLETE);
        assert_eq!(*complete.last().unwrap(), 0); // cstring terminator
    }

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
