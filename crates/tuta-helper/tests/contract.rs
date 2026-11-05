//! Offline probes of the helper's contract, run against the built binary:
//! every failure is one versioned error line on stdout, exit status 0.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const HELPER: &str = env!("CARGO_BIN_EXE_tuta-helper");

fn run_as(program: &Path, input: &[u8]) -> (String, bool) {
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
        .write_all(input)
        .expect("the request is written");
    let output = child.wait_with_output().expect("the helper exits");
    (
        String::from_utf8(output.stdout).expect("UTF-8 output"),
        output.status.success(),
    )
}

fn run(input: &[u8]) -> String {
    let (stdout, ok) = run_as(Path::new(HELPER), input);
    assert!(ok, "exit status");
    stdout
}

fn error_line(code: &str) -> String {
    format!("{{\"error\":{{\"code\":\"{code}\"}},\"version\":1}}\n")
}

#[test]
fn a_bad_version_is_refused_without_connecting() {
    assert_eq!(
        run(br#"{"version":2,"op":"login","email":"a@b","password":"x"}"#),
        error_line("unsupported_version")
    );
}

#[test]
fn an_unknown_operation_is_invalid() {
    assert_eq!(
        run(br#"{"version":1,"op":"star"}"#),
        error_line("invalid_request")
    );
}

#[test]
fn garbage_is_invalid() {
    assert_eq!(run(b"garbage"), error_line("invalid_request"));
    assert_eq!(run(b""), error_line("invalid_request"));
    assert_eq!(run(&[0xff, 0xfe, 0x00]), error_line("invalid_request"));
}

#[test]
fn unknown_fields_are_invalid() {
    assert_eq!(
        run(br#"{"version":1,"op":"login","email":"a@b","password":"x","extra":1}"#),
        error_line("invalid_request")
    );
}

#[test]
fn an_oversized_request_is_invalid() {
    let big = vec![b' '; 36 * 1024 * 1024 + 2];
    assert_eq!(run(&big), error_line("invalid_request"));
}

#[test]
fn offline_checks_answer_before_any_network() {
    let session = r#""session":{"login":"a@tuta.com","user_id":"u","access_token":"t","encrypted_passphrase_key":[]}"#;
    assert_eq!(
        run(
            format!(r#"{{"version":1,"op":"move",{session},"ids":[],"destination":"a/b"}}"#)
                .as_bytes()
        ),
        error_line("invalid_batch")
    );
    assert_eq!(
        run(format!(r#"{{"version":1,"op":"create_folder",{session},"name":"  "}}"#).as_bytes()),
        error_line("invalid_name")
    );
    assert_eq!(
        run(
            format!(r#"{{"version":1,"op":"contact_passwords",{session},"addresses":[]}}"#)
                .as_bytes()
        ),
        "{\"result\":{\"recipients\":[]},\"version\":1}\n"
    );
    // A revoke whose token holds no session id is refused before signing in.
    assert_eq!(
        run(format!(r#"{{"version":1,"op":"revoke",{session}}}"#).as_bytes()),
        error_line("session_invalid")
    );
}

#[test]
fn a_watch_line_needs_its_newline_and_a_good_version() {
    let watch = r#"{"version":1,"op":"watch","session":{"login":"","user_id":"","access_token":"","encrypted_passphrase_key":[]}}"#;
    // Without the newline it is not streamed, and a plain request cannot
    // watch.
    assert_eq!(run(watch.as_bytes()), error_line("invalid_request"));
    let bad_version = watch.replace("\"version\":1", "\"version\":3") + "\n";
    assert_eq!(
        run(bad_version.as_bytes()),
        error_line("unsupported_version")
    );
}

/// The fork looks the helper up as `hylki-tuta`; a link by that name is the
/// same program with the same contract.
#[cfg(unix)]
#[test]
fn the_hylki_tuta_name_speaks_the_same_contract() {
    let dir = std::env::temp_dir().join(format!("tuta-helper-alias-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let alias: PathBuf = dir.join("hylki-tuta");
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(HELPER, &alias).unwrap();
    let (stdout, ok) = run_as(&alias, br#"{"version":1,"op":"star"}"#);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok);
    assert_eq!(stdout, error_line("invalid_request"));
}
