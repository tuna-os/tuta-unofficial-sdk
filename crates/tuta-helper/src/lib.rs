//! The `tuta-helper` JSON protocol as a library: the request and reply
//! objects the README documents, dispatched onto `tuta-unofficial-sdk`.
//!
//! The `tuta-helper` binary serves it over stdio, one request per process;
//! `tuta-ffi` serves the very same requests in process, so both front ends
//! accept, check and answer exactly alike. Nothing here reads stdin, writes
//! stdout or logs.
mod protocol;
pub mod watch;

use protocol::{Failure, Request};
use serde_json::{json, Value};
use tuta_unofficial_sdk::{Client, Error};

pub use protocol::{Identity, REQUEST_TIMEOUT, VERSION};

// Attachments ride in the request (base64), so the cap covers a large mail,
// not just a JSON envelope: the largest is an `import`, a whole message of up
// to `MAX_IMPORT_BYTES` (25 MiB), which base64 makes 33.4 MiB. 36 MiB bounds
// memory while leaving room for that.
/// The largest request accepted, in bytes.
pub const MAX_REQUEST_BYTES: usize = 36 * 1024 * 1024;

/// The reply to a whole request body (anything but `watch`), against
/// [`REQUEST_TIMEOUT`]: `{"version":1,"result":...}` or
/// `{"version":1,"error":{"code":...}}`.
pub async fn respond(client: &Client, input: &[u8]) -> Value {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let result = if input.len() > MAX_REQUEST_BYTES {
        Err(Error::InvalidRequest.into())
    } else {
        match serde_json::from_slice::<Request>(input) {
            Ok(request) if request.version != VERSION => Err(Error::UnsupportedVersion.into()),
            Ok(request) => protocol::dispatch(client, request.operation, deadline).await,
            Err(_) => Err(Error::InvalidRequest.into()),
        }
    };
    match result {
        Ok(result) => json!({"version": VERSION, "result": result}),
        Err(Failure {
            code,
            pending_session: Some(pending),
        }) => json!({"version": VERSION, "error": {"code": code, "pending_session": pending}}),
        Err(Failure { code, .. }) => error_reply(code),
    }
}

/// The error reply carrying `code`.
pub fn error_reply(code: Error) -> Value {
    json!({"version": VERSION, "error": {"code": code}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Identity::HELPER.client().unwrap()
    }

    #[tokio::test]
    async fn incompatible_version_never_connects() {
        let reply = respond(
            &client(),
            br#"{"version":2,"op":"login","email":"a@b","password":"fixture"}"#,
        )
        .await;
        assert_eq!(
            reply,
            json!({"version": 1, "error": {"code": "unsupported_version"}})
        );
    }

    #[tokio::test]
    async fn malformed_requests_are_invalid() {
        for body in [
            &b"garbage"[..],
            br#"{"version":1,"op":"star"}"#,
            br#"{"version":"1","op":"revoke"}"#,
            br#"{"op":"revoke"}"#,
        ] {
            assert_eq!(
                respond(&client(), body).await,
                json!({"version": 1, "error": {"code": "invalid_request"}}),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[tokio::test]
    async fn a_second_factor_reply_carries_the_pending_session() {
        let pending = json!({"login": "a@tuta.com", "user_id": "u",
            "access_token": "AAECAwQFBgcICQoLDA0ODw", "encrypted_passphrase_key": [1, 2]});
        let request = json!({"version": 1, "op": "login", "email": "a@tuta.com",
            "password": "p", "pending_session": pending});
        assert_eq!(
            respond(&client(), request.to_string().as_bytes()).await,
            json!({"version": 1, "error": {"code": "second_factor_required",
                "pending_session": pending}})
        );
    }

    #[tokio::test]
    async fn oversized_requests_are_invalid_before_parsing() {
        let body = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            respond(&client(), &body).await,
            json!({"version": 1, "error": {"code": "invalid_request"}})
        );
    }
}
