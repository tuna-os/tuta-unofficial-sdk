//! `watch`: the one streaming operation.
//!
//! Every other operation answers with exactly one line. `watch` holds the
//! event bus open (`Session::watch`) and writes one JSON line per change
//! until its stdin closes, then exits without a further line. Each line
//! carries `version`:
//!
//! - `{"event":"ready"}`, `{"event":"reconnect"}`,
//!   `{"event":"folders_changed"}`, `{"event":"mail_changed","folder":...}`
//!   as `WatchEvent` describes them;
//! - a final `{"error":{"code":...}}` when the watch cannot go on, after
//!   which the helper exits.
//!
//! The request must be one newline-terminated line with stdin left open.
//! No per-operation timeout applies.
use crate::{
    protocol::{Identity, Operation, Request, Watch, VERSION},
    QuietStdout,
};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    os::fd::AsFd,
    pin::Pin,
};
use tokio::sync::watch;
use tuta_unofficial_sdk::{Error, Result, WatchEvent};

/// Just enough of a request to tell a watch from the rest without decoding
/// a large one twice.
#[derive(Deserialize)]
struct Peek {
    op: Option<String>,
}

/// Whether a newline-terminated first line asks for `watch`.
pub(crate) fn is_watch(line: &[u8]) -> bool {
    line.ends_with(b"\n")
        && serde_json::from_slice::<Peek>(line).is_ok_and(|p| p.op.as_deref() == Some("watch"))
}

/// One event as its line.
fn event_line(event: &WatchEvent) -> Value {
    let mut line = serde_json::to_value(event).expect("events serialize to JSON");
    line["version"] = json!(VERSION);
    line
}

/// Writes lines to the reply channel. A write failure means the reader is
/// gone, which ends the watch like a closed stdin.
struct Lines(Box<dyn Write + Send>);

impl Lines {
    fn emit(&mut self, line: &Value) -> bool {
        writeln!(self.0, "{line}")
            .and_then(|()| self.0.flush())
            .is_ok()
    }
}

/// The real stdout: the SDK prints progress to fd 1, which stays parked on
/// /dev/null for the whole watch; lines go to the saved descriptor.
fn reply_channel(quiet: Option<&QuietStdout>) -> Box<dyn Write + Send> {
    match quiet.and_then(|q| q.saved.as_fd().try_clone_to_owned().ok()) {
        Some(fd) => Box::new(std::fs::File::from(fd)),
        None => Box::new(io::stdout()),
    }
}

/// Fires once stdin reaches EOF (or fails): the caller's stop signal.
fn stdin_closed() -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 256];
        let mut stdin = io::stdin();
        while matches!(stdin.read(&mut buffer), Ok(n) if n > 0) {}
        let _ = tx.send(true);
    });
    rx
}

/// The next item of a stream.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Serve a watch request (`line`, newline included). Writes the reply lines
/// itself; returns when stdin closes or the watch fails.
pub(crate) async fn serve(identity: Identity, line: &[u8], quiet: Option<&QuietStdout>) {
    let mut lines = Lines(reply_channel(quiet));
    if let Err(code) = run(identity, line, &mut lines).await {
        lines.emit(&json!({"version": VERSION, "error": {"code": code}}));
    }
}

async fn run(identity: Identity, line: &[u8], lines: &mut Lines) -> Result<()> {
    let request: Request = serde_json::from_slice(line).map_err(|_| Error::InvalidRequest)?;
    if request.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let Operation::Watch(Watch { session }) = request.operation else {
        return Err(Error::InvalidRequest);
    };
    let mut stop = stdin_closed();
    let client = identity.client()?;
    let session = client.resume(session).await?;
    let mut events = session.watch().await?;
    loop {
        tokio::select! {
            _ = stop.changed() => {
                events.close().await;
                return Ok(());
            }
            event = next(&mut events) => match event {
                Some(Ok(event)) => {
                    if !lines.emit(&event_line(&event)) {
                        events.close().await;
                        return Ok(());
                    }
                }
                Some(Err(code)) => return Err(code),
                // The watch ended without saying why.
                None => return Err(Error::WatchFailed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_newline_terminated_watch_line_streams() {
        assert!(is_watch(
            b"{\"version\":1,\"op\":\"watch\",\"session\":{}}\n"
        ));
        assert!(!is_watch(
            b"{\"version\":1,\"op\":\"watch\",\"session\":{}}"
        ));
        assert!(!is_watch(b"{\"version\":1,\"op\":\"sync\"}\n"));
        assert!(!is_watch(b"{\"version\":1,\n"));
        assert!(!is_watch(b"\n"));
    }

    #[test]
    fn event_lines_carry_version_and_folder() {
        assert_eq!(
            event_line(&WatchEvent::MailChanged {
                folder: "a/b".into()
            }),
            json!({"version": 1, "event": "mail_changed", "folder": "a/b"})
        );
        assert_eq!(
            event_line(&WatchEvent::FoldersChanged),
            json!({"version": 1, "event": "folders_changed"})
        );
        assert_eq!(
            event_line(&WatchEvent::Ready),
            json!({"version": 1, "event": "ready"})
        );
        assert_eq!(
            event_line(&WatchEvent::Reconnect),
            json!({"version": 1, "event": "reconnect"})
        );
    }

    /// Captures what a watch writes.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    async fn reply(line: &[u8]) -> String {
        let captured = Captured::default();
        let mut lines = Lines(Box::new(captured.clone()));
        if let Err(code) = run(Identity::HELPER, line, &mut lines).await {
            lines.emit(&json!({"version": VERSION, "error": {"code": code}}));
        }
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn a_bad_watch_request_ends_with_one_error_line() {
        assert_eq!(
            reply(b"{\"version\":2,\"op\":\"watch\",\"session\":{\"login\":\"\",\"user_id\":\"\",\"access_token\":\"\",\"encrypted_passphrase_key\":[]}}\n").await,
            "{\"error\":{\"code\":\"unsupported_version\"},\"version\":1}\n"
        );
        assert_eq!(
            reply(b"{\"version\":1,\"op\":\"watch\"}\n").await,
            "{\"error\":{\"code\":\"invalid_request\"},\"version\":1}\n"
        );
    }
}
