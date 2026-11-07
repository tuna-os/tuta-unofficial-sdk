//! `watch`: the one streaming operation.
//!
//! Every other operation answers with exactly one reply. `watch` holds the
//! event bus open (`Session::watch`) and emits one JSON line per change until
//! the caller stops it. Each line carries `version`:
//!
//! - `{"event":"ready"}`, `{"event":"reconnect"}`,
//!   `{"event":"folders_changed"}`, `{"event":"mail_changed","folder":...}`
//!   as `WatchEvent` describes them;
//! - a final `{"error":{"code":...}}` when the watch cannot go on.
//!
//! No per-operation timeout applies. The `tuta-helper` binary stops a watch
//! when its stdin closes; `tuta-ffi` when its handle is closed.
use crate::{
    error_reply,
    protocol::{Operation, Request, Watch, VERSION},
};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{borrow::Borrow, future::Future, pin::pin};
use tuta_unofficial_sdk::{Client, Error, Result, WatchEvent};

/// Just enough of a request to tell a watch from the rest without decoding
/// a large one twice.
#[derive(Deserialize)]
struct Peek {
    op: Option<String>,
}

/// Whether a newline-terminated first line asks for `watch`.
pub fn is_watch(line: &[u8]) -> bool {
    line.ends_with(b"\n")
        && serde_json::from_slice::<Peek>(line).is_ok_and(|p| p.op.as_deref() == Some("watch"))
}

/// One event as its line.
fn event_line(event: &WatchEvent) -> Value {
    let mut line = serde_json::to_value(event).expect("events serialize to JSON");
    line["version"] = json!(VERSION);
    line
}

/// The next item of a stream.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx)).await
}

/// Serve a watch `request` (a whole `watch` request object).
///
/// `emit` gets each line; it returns false when nobody reads any more, which
/// ends the watch like `stop` does. A watch that cannot go on emits one
/// final error line. `connect` and `stop` are called only once the request
/// checked out: `connect` makes the client, and the watch ends quietly as
/// soon as the future `stop` returns resolves.
pub async fn serve<C, F>(
    request: &[u8],
    connect: impl FnOnce() -> Result<C>,
    stop: impl FnOnce() -> F,
    mut emit: impl FnMut(&Value) -> bool,
) where
    C: Borrow<Client>,
    F: Future<Output = ()>,
{
    if let Err(code) = run(request, connect, stop, &mut emit).await {
        emit(&error_reply(code));
    }
}

async fn run<C, F>(
    request: &[u8],
    connect: impl FnOnce() -> Result<C>,
    stop: impl FnOnce() -> F,
    emit: &mut impl FnMut(&Value) -> bool,
) -> Result<()>
where
    C: Borrow<Client>,
    F: Future<Output = ()>,
{
    let request: Request = serde_json::from_slice(request).map_err(|_| Error::InvalidRequest)?;
    if request.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let Operation::Watch(Watch { session }) = request.operation else {
        return Err(Error::InvalidRequest);
    };
    let mut stop = pin!(stop());
    let client = connect()?;
    let session = tokio::select! {
        biased;
        _ = &mut stop => return Ok(()),
        session = client.borrow().resume(session) => session?,
    };
    let mut events = tokio::select! {
        biased;
        _ = &mut stop => return Ok(()),
        events = session.watch() => events?,
    };
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => {
                events.close().await;
                return Ok(());
            }
            event = next(&mut events) => match event {
                Some(Ok(event)) => {
                    if !emit(&event_line(&event)) {
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
    use crate::Identity;

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

    async fn lines(request: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        serve(
            request,
            || Identity::HELPER.client(),
            std::future::pending,
            |line| {
                lines.push(line.to_string());
                true
            },
        )
        .await;
        lines
    }

    #[tokio::test]
    async fn a_bad_watch_request_ends_with_one_error_line() {
        assert_eq!(
            lines(b"{\"version\":2,\"op\":\"watch\",\"session\":{\"login\":\"\",\"user_id\":\"\",\"access_token\":\"\",\"encrypted_passphrase_key\":[]}}\n").await,
            ["{\"error\":{\"code\":\"unsupported_version\"},\"version\":1}"]
        );
        assert_eq!(
            lines(b"{\"version\":1,\"op\":\"watch\"}\n").await,
            ["{\"error\":{\"code\":\"invalid_request\"},\"version\":1}"]
        );
        assert_eq!(
            lines(b"{\"version\":1,\"op\":\"sync\",\"limit\":1,\"offset\":0}").await,
            ["{\"error\":{\"code\":\"invalid_request\"},\"version\":1}"]
        );
    }

    #[tokio::test]
    async fn a_stopped_watch_ends_quietly() {
        let mut connected = false;
        let mut lines = Vec::new();
        serve(
            b"{\"version\":1,\"op\":\"watch\",\"session\":{\"login\":\"\",\"user_id\":\"\",\"access_token\":\"\",\"encrypted_passphrase_key\":[]}}",
            || {
                connected = true;
                Identity::HELPER.client()
            },
            || std::future::ready(()),
            |line| {
                lines.push(line.to_string());
                true
            },
        )
        .await;
        assert!(connected);
        assert!(lines.is_empty(), "{lines:?}");
    }
}
