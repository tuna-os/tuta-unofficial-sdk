//! The helper end to end against Tuta's servers, ignored by default: one
//! sign-in through the binary, a sync and a message read with the session it
//! returned (once through the `hylki-tuta` name), then the session closed.
//! Nothing is sent or written.
//!
//! ```sh
//! TUTA_LIVE=1 TUTA_LIVE_EMAIL=... TUTA_LIVE_PASSWORD=... TUTA_LIVE_TOTP=... \
//!     cargo test -p tuta-helper --test live -- --ignored --nocapture
//! ```

use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

const HELPER: &str = env!("CARGO_BIN_EXE_tuta-helper");

fn call(program: &Path, request: &Value) -> Value {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the helper starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("the helper exits");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches('\n').count(), 1, "exactly one line");
    let reply: Value = serde_json::from_str(&stdout).expect("one JSON reply");
    assert_eq!(reply["version"], json!(1));
    reply
}

/// The result, or the error code as a panic (never the request).
fn result(reply: Value, what: &str) -> Value {
    match reply.get("result") {
        Some(result) => result.clone(),
        None => panic!("{what}: {}", reply["error"]["code"]),
    }
}

#[test]
#[ignore = "talks to Tuta's servers: set TUTA_LIVE=1 and the TUTA_LIVE_* credentials"]
fn sign_in_sync_read_and_revoke_through_the_helper() {
    if std::env::var("TUTA_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set TUTA_LIVE=1 and TUTA_LIVE_EMAIL/PASSWORD[/TOTP]");
        return;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let mut login = json!({"version": 1, "op": "login",
        "email": var("TUTA_LIVE_EMAIL"), "password": var("TUTA_LIVE_PASSWORD")});
    if let Some(totp) = std::env::var("TUTA_LIVE_TOTP")
        .ok()
        .filter(|t| !t.is_empty())
    {
        login["totp"] = json!(totp);
    }
    let helper = Path::new(HELPER);
    let session = result(call(helper, &login), "login")["session"].clone();
    drop(login);
    let read = std::panic::catch_unwind(|| {
        let page = result(
            call(
                helper,
                &json!({"version": 1, "op": "sync", "session": session, "limit": 3, "offset": 0}),
            ),
            "sync",
        );
        assert!(page["folders"].as_array().is_some_and(|f| !f.is_empty()));
        assert!(page["all_ids"].is_array());
        assert_eq!(page["offset"], json!(0));
        if let Some(newest) = page["messages"].as_array().and_then(|m| m.first()) {
            assert!(newest["labels"].is_array());
            // Read it through the name the Hylki fork looks the helper up by.
            let dir = std::env::temp_dir().join(format!("tuta-helper-live-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let alias = dir.join("hylki-tuta");
            let _ = std::fs::remove_file(&alias);
            std::os::unix::fs::symlink(HELPER, &alias).unwrap();
            let message = call(
                &alias,
                &json!({"version": 1, "op": "message", "session": session, "id": newest["id"]}),
            );
            std::fs::remove_dir_all(&dir).unwrap();
            let message = result(message, "message");
            assert_eq!(message["header"]["id"], newest["id"]);
            assert!(message["html"].is_string());
            assert!(message["attachments"].is_array());
        }
        let labels = result(
            call(
                helper,
                &json!({"version": 1, "op": "list_labels", "session": session}),
            ),
            "list_labels",
        );
        assert!(labels["labels"].is_array());
    });
    let revoked = call(
        helper,
        &json!({"version": 1, "op": "revoke", "session": session}),
    );
    if let Err(panic) = read {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(result(revoked, "revoke"), json!({}));
}
