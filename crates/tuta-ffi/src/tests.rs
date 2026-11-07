use super::*;
use std::{
    net::TcpListener,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

const SESSION: &str = r#"{"login":"a@tuta.com","user_id":"u","access_token":"AAECAwQFBgcICQoLDA0ODw","encrypted_passphrase_key":[1,2]}"#;

/// A port that accepts connections and never answers: requests to it hang.
fn silent_server() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (listener, url)
}

/// A port nothing listens on: requests to it fail at once.
fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    url
}

fn client(url: &str) -> Arc<TutaFfi> {
    TutaFfi::with_base_url("tuta-ffi-test".into(), url.into()).unwrap()
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

fn code(reply: &str) -> Option<String> {
    let reply: Value = serde_json::from_str(reply).unwrap();
    assert_eq!(reply["version"], 1, "{reply}");
    reply["error"]["code"].as_str().map(str::to_string)
}

#[test]
fn requests_are_checked_as_the_helper_checks_them() {
    let client = client(&closed_url());
    for (request, expected) in [
        ("garbage", "invalid_request"),
        (r#"{"version":1,"op":"star"}"#, "invalid_request"),
        (
            r#"{"version":2,"op":"login","email":"a@b","password":"p"}"#,
            "unsupported_version",
        ),
        (
            &format!(
                r#"{{"version":1,"op":"mark_read","session":{SESSION},"ids":["nope"],"is_read":true}}"#
            ),
            "invalid_id",
        ),
        (
            &format!(
                r#"{{"version":1,"op":"move","session":{SESSION},"ids":[],"destination":"a/b"}}"#
            ),
            "invalid_batch",
        ),
        (
            &format!(
                r#"{{"version":1,"op":"sync","session":{SESSION},"limit":0,"offset":0,"x":1}}"#
            ),
            "invalid_request",
        ),
        // A watch streams; it is never a single reply.
        (
            &format!(r#"{{"version":1,"op":"watch","session":{SESSION}}}"#),
            "invalid_request",
        ),
    ] {
        let reply = block_on(client.request(request.to_string()));
        assert_eq!(code(&reply).as_deref(), Some(expected), "{request}");
    }
}

#[test]
fn an_unreachable_server_is_a_transport_failure() {
    let client = client(&closed_url());
    let reply = block_on(
        client.request(r#"{"version":1,"op":"login","email":"a@tuta.com","password":"p"}"#.into()),
    );
    assert_eq!(code(&reply).as_deref(), Some("transport_failed"));
}

#[test]
fn every_code_and_the_version_are_exported() {
    let codes = error_codes();
    assert_eq!(codes.len(), Error::ALL.len());
    assert_eq!(codes.first().map(String::as_str), Some("login_failed"));
    assert!(codes.iter().any(|c| c == "send_uncertain"));
    assert!(codes.iter().all(|c| Error::from_code(c).is_some()));
    assert_eq!(protocol_version(), 1);
}

/// Collects a watch's lines and its end.
struct Probe {
    lines: Sender<String>,
    closed: Sender<()>,
    listening: bool,
}

impl WatchListener for Probe {
    fn on_line(&self, line: String) -> bool {
        let _ = self.lines.send(line);
        self.listening
    }
    fn on_closed(&self) {
        let _ = self.closed.send(());
    }
}

fn probe() -> (Box<Probe>, Receiver<String>, Receiver<()>) {
    let (lines, line_rx) = mpsc::channel();
    let (closed, closed_rx) = mpsc::channel();
    let probe = Probe {
        lines,
        closed,
        listening: true,
    };
    (Box::new(probe), line_rx, closed_rx)
}

const WAIT: Duration = Duration::from_secs(20);

#[test]
fn a_watch_with_a_bad_session_ends_with_one_error_line() {
    let client = client(&closed_url());
    let (listener, lines, closed) = probe();
    let _handle = client.watch("not json".into(), listener);
    closed.recv_timeout(WAIT).expect("on_closed");
    let lines: Vec<String> = lines.try_iter().collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(code(&lines[0]).as_deref(), Some("invalid_request"));
}

#[test]
fn a_watch_that_cannot_connect_reports_its_code() {
    let client = client(&closed_url());
    let (listener, lines, closed) = probe();
    let _handle = client.watch(SESSION.into(), listener);
    closed.recv_timeout(WAIT).expect("on_closed");
    let lines: Vec<String> = lines.try_iter().collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(code(&lines[0]).as_deref(), Some("transport_failed"));
}

#[test]
fn stopping_a_handle_ends_the_watch_quietly() {
    let (_server, url) = silent_server();
    let client = client(&url);
    let (listener, lines, closed) = probe();
    let handle = client.watch(SESSION.into(), listener);
    std::thread::sleep(Duration::from_millis(200));
    assert!(closed.try_recv().is_err(), "still waiting on the server");
    handle.stop();
    handle.stop();
    closed.recv_timeout(WAIT).expect("on_closed");
    assert_eq!(lines.try_iter().count(), 0);
    assert!(
        closed.recv_timeout(Duration::from_millis(200)).is_err(),
        "closed once"
    );
}

#[test]
fn dropping_the_client_ends_its_watches() {
    let (_server, url) = silent_server();
    let client = client(&url);
    let (listener, lines, closed) = probe();
    let _handle = client.watch(SESSION.into(), listener);
    std::thread::sleep(Duration::from_millis(200));
    drop(client);
    closed.recv_timeout(WAIT).expect("on_closed");
    assert_eq!(lines.try_iter().count(), 0);
}

#[test]
fn watch_requests_wrap_the_session_object() {
    let request = watch_request(Zeroizing::new(SESSION.into()));
    let request: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(request["op"], "watch");
    assert_eq!(request["version"], 1);
    assert_eq!(request["session"]["access_token"], "AAECAwQFBgcICQoLDA0ODw");
    assert_eq!(&*watch_request(Zeroizing::new("{".into())), b"null");
}

#[test]
fn wiping_zeroes_strings_and_numbers() {
    let mut tree = json!({"session": {"access_token": "secret", "key": [7, 8]}, "ok": true});
    wipe(&mut tree);
    assert_eq!(
        tree,
        json!({"session": {"access_token": "", "key": [0, 0]}, "ok": true})
    );
}
