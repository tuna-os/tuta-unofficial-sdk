//! `tuta-helper`: one JSON request on stdin, one JSON reply on stdout, a
//! thin front end on `tuta-unofficial-sdk`. The protocol is described in
//! the repository README. No IMAP, SMTP, listener, keyring, database or
//! message logging.
//!
//! Started as `hylki-tuta` (a copy or a link with that name), it is the
//! helper Hylki runs: sessions are named "Hylki" and diagnostics follow
//! `HYLKI_TUTA_DEBUG=1` with the `hylki-tuta:` prefix. Otherwise sessions
//! are named "tuta-helper" and `TUTA_HELPER_DEBUG=1` turns diagnostics on.
mod protocol;
mod watch;

use protocol::{Identity, Request, REQUEST_TIMEOUT, VERSION};
use serde_json::json;
use std::{
    io::{self, BufRead, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tuta_unofficial_sdk::{diagnostics, Error};

// Attachments ride the same stdin pipe as the request (base64), so the cap
// covers a large mail, not just a JSON envelope: the largest is an `import`,
// a whole message of up to `MAX_IMPORT_BYTES` (25 MiB), which base64 makes
// 33.4 MiB. 36 MiB bounds memory while leaving room for that.
const MAX_REQUEST_BYTES: u64 = 36 * 1024 * 1024;

// The pinned SDK prints progress to stdout, which would corrupt the
// single-line reply the caller parses. Park fd 1 on /dev/null while SDK
// code runs; dropping the guard restores it.
pub(crate) struct QuietStdout {
    pub(crate) saved: OwnedFd,
}

fn quiet_stdout() -> io::Result<QuietStdout> {
    // SAFETY: dup hands back an owned fd on success; -1 is checked.
    let saved = unsafe {
        let fd = libc::dup(libc::STDOUT_FILENO);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    let null = std::fs::File::open("/dev/null")?;
    // SAFETY: both fds are valid; stdout now points at /dev/null.
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(QuietStdout { saved })
}

impl Drop for QuietStdout {
    fn drop(&mut self) {
        // SAFETY: the saved fd stays valid for the guard's lifetime.
        unsafe {
            libc::dup2(self.saved.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
}

/// The reply to a whole request body.
async fn respond(identity: Identity, input: &[u8]) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let result = match serde_json::from_slice::<Request>(input) {
        Ok(request) if request.version != VERSION => Err(Error::UnsupportedVersion),
        Ok(request) => protocol::dispatch(identity, request.operation, deadline).await,
        Err(_) => Err(Error::InvalidRequest),
    };
    match result {
        Ok(result) => json!({"version": VERSION, "result": result}),
        Err(code) => json!({"version": VERSION, "error": {"code": code}}),
    }
}

#[tokio::main]
async fn main() {
    let identity = Identity::from_program(std::env::args_os().next().as_deref());
    if std::env::var_os(identity.debug_variable).is_some_and(|v| v == "1") {
        diagnostics::enable(identity.prefix);
    }
    // If stdout cannot be parked the request still runs; a chatty SDK only
    // risks the reply, it must not fail the operation itself.
    let quiet = quiet_stdout().ok();
    let mut input = Vec::new();
    let mut stdin = io::stdin().lock().take(MAX_REQUEST_BYTES + 1);
    // `watch` is one newline-terminated line on a stdin that stays open;
    // every other request is read to EOF.
    let first = stdin.read_until(b'\n', &mut input);
    if first.is_ok() && watch::is_watch(&input) {
        drop(stdin);
        watch::serve(identity, &input, quiet.as_ref()).await;
        return;
    }
    let response = match first.and_then(|_| stdin.read_to_end(&mut input)) {
        Ok(_) if input.len() <= MAX_REQUEST_BYTES as usize => respond(identity, &input).await,
        _ => json!({"version": VERSION, "error": {"code": Error::InvalidRequest}}),
    };
    drop(quiet);
    println!("{response}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn stdout_is_parked_on_dev_null_while_held() {
        use std::os::unix::fs::MetadataExt;
        let target = |path: &str| {
            let meta = std::fs::metadata(path).unwrap();
            (meta.dev(), meta.ino())
        };
        let (null, before) = (target("/dev/null"), target("/proc/self/fd/1"));
        {
            let _quiet = quiet_stdout().unwrap();
            assert_eq!(target("/proc/self/fd/1"), null);
        }
        assert_eq!(target("/proc/self/fd/1"), before);
    }

    #[tokio::test]
    async fn incompatible_version_never_connects() {
        let reply = respond(
            Identity::HELPER,
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
                respond(Identity::HELPER, body).await,
                json!({"version": 1, "error": {"code": "invalid_request"}}),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
