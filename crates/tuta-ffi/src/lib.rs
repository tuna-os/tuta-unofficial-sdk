//! Kotlin bindings for `tuta-unofficial-sdk`, through uniffi and JNA.
//!
//! The surface is the `tuta-helper` protocol, in process. [`TutaFfi::request`]
//! takes one request object and answers with one reply object exactly as the
//! helper does over stdio: both call `tuta_helper::respond`, so the parsing,
//! the offline checks, the error codes, the limits and the 90-second
//! deadline are the same code, and the README's protocol section and the
//! helper's tests apply unchanged. [`TutaFfi::watch`] streams the helper's
//! watch lines to a [`WatchListener`]. The typed API is the hand-written
//! Kotlin layer on top (`android/tuta-sdk-android`).
//!
//! Nothing here prints or logs. Each request's bytes and each reply's tree
//! are zeroed on the Rust side once used; what crosses into the JVM is the
//! caller's to keep (JVM strings cannot be zeroed).
uniffi::setup_scaffolding!();

use serde_json::{json, Value};
use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
};
use tokio::{runtime::Runtime, sync::oneshot};
use tuta_helper::VERSION;
use tuta_unofficial_sdk::{Client, Error};
use zeroize::{Zeroize, Zeroizing};

/// Why a client could not be made: one of the protocol's fixed codes.
#[derive(Debug, uniffi::Error)]
pub enum NativeError {
    Failed { code: String },
}

impl From<Error> for NativeError {
    fn from(error: Error) -> Self {
        NativeError::Failed {
            code: error.code().to_string(),
        }
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeError::Failed { code } => f.write_str(code),
        }
    }
}

impl std::error::Error for NativeError {}

/// A connection to Tuta, with the runtime its requests run on. One per
/// application is enough: requests and watches may run concurrently.
#[derive(uniffi::Object)]
pub struct TutaFfi {
    client: Arc<Client>,
    /// Always `Some` until dropped (see `Drop`).
    runtime: Option<Runtime>,
}

#[uniffi::export]
impl TutaFfi {
    /// A client for Tuta's production API. `client_name` is the name Tuta
    /// lists the sessions it signs in under.
    #[uniffi::constructor]
    pub fn new(client_name: String) -> Result<Arc<Self>, NativeError> {
        Self::open(&client_name, None)
    }

    /// A client for another API origin, for tests against a stand-in
    /// server.
    #[uniffi::constructor]
    pub fn with_base_url(client_name: String, base_url: String) -> Result<Arc<Self>, NativeError> {
        Self::open(&client_name, Some(&base_url))
    }

    /// One `tuta-helper` request object in, one reply object out:
    /// `{"version":1,"result":...}` or `{"version":1,"error":{"code":...}}`.
    /// A `watch` request is `invalid_request` here; use [`TutaFfi::watch`].
    ///
    /// Cancelling the call abandons the reply, not the operation: it runs to
    /// its end (at most 90 seconds) so a send is never cut off half-way.
    pub async fn request(&self, json: String) -> String {
        let input = Zeroizing::new(json.into_bytes());
        let client = Arc::clone(&self.client);
        let task = self.runtime().spawn(async move {
            let mut reply = tuta_helper::respond(&client, &input).await;
            let line = reply.to_string();
            wipe(&mut reply);
            line
        });
        match task.await {
            Ok(line) => line,
            Err(error) => match error.try_into_panic() {
                Ok(panic) => std::panic::resume_unwind(panic),
                // The runtime lives as long as `self`, which this call borrows.
                Err(_) => unreachable!("a request outlived its client"),
            },
        }
    }

    /// Watch the session's event bus: `listener` gets the helper's watch
    /// lines (`{"event":...}`, or a final `{"error":{"code":...}}`), then
    /// `on_closed` once the watch is over, however it ended. `session_json`
    /// is the `session` object a `login` returned.
    pub fn watch(
        &self,
        session_json: String,
        listener: Box<dyn WatchListener>,
    ) -> Arc<WatchHandle> {
        let request = watch_request(Zeroizing::new(session_json));
        let client = Arc::clone(&self.client);
        let (stop, stopped) = oneshot::channel::<()>();
        self.runtime().spawn(async move {
            let listener = Listener(listener);
            tuta_helper::watch::serve(
                &request,
                || Ok(client),
                || async {
                    // A dropped handle stops the watch as well.
                    let _ = stopped.await;
                },
                |line| listener.0.on_line(line.to_string()),
            )
            .await;
        });
        Arc::new(WatchHandle {
            stop: Mutex::new(Some(stop)),
        })
    }
}

impl TutaFfi {
    fn open(client_name: &str, base_url: Option<&str>) -> Result<Arc<Self>, NativeError> {
        #[cfg(target_os = "android")]
        use_android_trust_store();
        let client = match base_url {
            Some(url) => Client::with_url(url)?,
            None => Client::new()?,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("tuta-ffi")
            .enable_all()
            .build()
            .map_err(|_| NativeError::from(Error::TransportFailed))?;
        Ok(Arc::new(TutaFfi {
            client: Arc::new(client.client_name(client_name)),
            runtime: Some(runtime),
        }))
    }

    fn runtime(&self) -> &Runtime {
        self.runtime.as_ref().expect("the runtime lives until drop")
    }
}

impl Drop for TutaFfi {
    fn drop(&mut self) {
        // Never block the (JVM) thread that let go of the client: running
        // requests and watches are dropped where they stand.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Receives a watch's lines, on a runtime thread.
#[uniffi::export(callback_interface)]
pub trait WatchListener: Send + Sync {
    /// One watch line. Return false when nobody listens any more: the watch
    /// then ends quietly. Must not throw.
    fn on_line(&self, line: String) -> bool;
    /// The watch is over: stopped, failed (after its error line), or its
    /// client was dropped. Called exactly once. Must not throw.
    fn on_closed(&self);
}

/// Calls `on_closed` when the watch task ends or is dropped.
struct Listener(Box<dyn WatchListener>);

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.on_closed();
    }
}

/// A running watch.
#[derive(uniffi::Object)]
pub struct WatchHandle {
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl WatchHandle {
    /// Stop the watch; `on_closed` follows. Stopping twice is harmless.
    /// (Not `close`: the Kotlin object's own `close` frees the handle.)
    pub fn stop(&self) {
        let stop = self
            .stop
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(stop) = stop {
            let _ = stop.send(());
        }
    }
}

/// Every error code the protocol can answer with, in the library's order.
#[uniffi::export]
pub fn error_codes() -> Vec<String> {
    Error::ALL.iter().map(|e| e.code().to_string()).collect()
}

/// The protocol version requests and replies carry.
#[uniffi::export]
pub fn protocol_version() -> u32 {
    VERSION
}

/// The `watch` request for a session object. Anything that is not JSON
/// yields a request the protocol refuses as `invalid_request`.
fn watch_request(session_json: Zeroizing<String>) -> Zeroizing<Vec<u8>> {
    let Ok(session) = serde_json::from_str::<Value>(&session_json) else {
        return Zeroizing::new(b"null".to_vec());
    };
    let mut request = json!({"version": VERSION, "op": "watch", "session": session});
    let bytes = Zeroizing::new(request.to_string().into_bytes());
    wipe(&mut request);
    bytes
}

/// Zero every string and number of a JSON tree before it is freed: replies
/// carry session tokens, key bytes and contact passwords. Keys are field
/// names, never secrets.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Number(number) => {
            // SAFETY: `number` is a valid, aligned, exclusive reference, and
            // without serde_json's `arbitrary_precision` feature a Number
            // owns no heap memory, so overwriting it without a drop leaks
            // nothing. The volatile write is not optimized away.
            unsafe { std::ptr::write_volatile(number, serde_json::Number::from(0u8)) }
        }
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => fields.values_mut().for_each(wipe),
        Value::Bool(_) | Value::Null => {}
    }
}

#[cfg(target_os = "android")]
/// rustls-native-certs looks for an OpenSSL-style store, which Android does
/// not have where it looks; point it at the system CA directory (the
/// updatable Conscrypt one from Android 14, else the system image's) unless
/// the process already chose a store.
fn use_android_trust_store() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some()
        {
            return;
        }
        let store = [
            "/apex/com.android.conscrypt/cacerts",
            "/system/etc/security/cacerts",
        ]
        .into_iter()
        .find(|dir| std::path::Path::new(dir).is_dir());
        if let Some(dir) = store {
            std::env::set_var("SSL_CERT_DIR", dir);
        }
    });
}

#[cfg(test)]
mod tests;
