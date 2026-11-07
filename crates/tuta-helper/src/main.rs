//! `tuta-helper`: one JSON request on stdin, one JSON reply on stdout, a
//! thin front end on `tuta-unofficial-sdk`. The protocol is described in
//! the repository README and implemented by this crate's library. No IMAP,
//! SMTP, listener, keyring, database or message logging.
//!
//! Started as `hylki-tuta` (a copy or a link with that name), it is the
//! helper Hylki runs: sessions are named "Hylki" and diagnostics follow
//! `HYLKI_TUTA_DEBUG=1` with the `hylki-tuta:` prefix. Otherwise sessions
//! are named "tuta-helper" and `TUTA_HELPER_DEBUG=1` turns diagnostics on.
use std::{
    future::Future,
    io::{self, BufRead, Read, Write},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};
use tuta_helper::{error_reply, respond, watch, Identity, MAX_REQUEST_BYTES};
use tuta_unofficial_sdk::{diagnostics, Error};

// The pinned SDK may print to stdout, which would corrupt the single-line
// reply the caller parses. Park fd 1 on /dev/null while SDK code runs;
// dropping the guard restores it.
struct QuietStdout {
    saved: OwnedFd,
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

/// Where a watch writes its lines: fd 1 stays parked on /dev/null for the
/// whole watch, so they go to the saved descriptor.
fn reply_channel(quiet: Option<&QuietStdout>) -> Box<dyn Write + Send> {
    match quiet.and_then(|q| q.saved.as_fd().try_clone_to_owned().ok()) {
        Some(fd) => Box::new(std::fs::File::from(fd)),
        None => Box::new(io::stdout()),
    }
}

/// Resolves once stdin reaches EOF (or fails): a watch's stop signal.
fn stdin_closed() -> impl Future<Output = ()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 256];
        let mut stdin = io::stdin();
        while matches!(stdin.read(&mut buffer), Ok(n) if n > 0) {}
        let _ = tx.send(());
    });
    async move {
        let _ = rx.await;
    }
}

/// Serve a watch request (`line`, newline included) until stdin closes or
/// the watch fails. A write failure means the reader is gone, which ends the
/// watch like a closed stdin.
async fn serve_watch(identity: Identity, line: &[u8], quiet: Option<&QuietStdout>) {
    let mut out = reply_channel(quiet);
    watch::serve(
        line,
        || identity.client(),
        stdin_closed,
        |line| writeln!(out, "{line}").and_then(|()| out.flush()).is_ok(),
    )
    .await;
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
    let mut stdin = io::stdin().lock().take(MAX_REQUEST_BYTES as u64 + 1);
    // `watch` is one newline-terminated line on a stdin that stays open;
    // every other request is read to EOF.
    let first = stdin.read_until(b'\n', &mut input);
    if first.is_ok() && watch::is_watch(&input) {
        drop(stdin);
        serve_watch(identity, &input, quiet.as_ref()).await;
        return;
    }
    let response = match first.and_then(|_| stdin.read_to_end(&mut input)) {
        Ok(_) => match identity.client() {
            Ok(client) => respond(&client, &input).await,
            Err(code) => error_reply(code),
        },
        Err(_) => error_reply(Error::InvalidRequest),
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
}
