//! Push notifications over Tuta's event bus.
//!
//! [`Session::watch`] holds the event bus websocket the official client
//! holds (`app-kit/local-store/event/EventBusClient.ts`, here through
//! tutabridge's `EventBusClient`) and yields one [`WatchEvent`] per change:
//!
//! - `Ready` once the bus first connects;
//! - `MailChanged { folder }` when mail in that folder was added, removed or
//!   changed (read state, labels); `folder` is empty when the folder could
//!   not be told, meaning "resync everything";
//! - `FoldersChanged` when a folder or label was created, renamed, moved or
//!   deleted, before the `MailChanged` events of the same batch;
//! - `Reconnect` after the bus dropped and came back. Missed batches are
//!   replayed by the server, but a caller should resync anyway.
//!
//! A final `Err` ends the stream when the watch cannot go on (session
//! revoked, client outdated, the bus gave up). While the bus reconnects the
//! session is checked over REST, so an expired session ends the watch
//! instead of retrying forever. Nothing about a mail beyond its folder is
//! reported.
use crate::{
    diag,
    ids::id,
    mailbox_ops::{is_label, load_mailbox},
    Error, Result, Session,
};
use futures_core::Stream;
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tutabridge_tuta::{
    event_bus::{
        EntityUpdateBatch, EventBusClient, EventBusError, EventBusMessage, Operation as BusOp,
        WsState,
    },
    mail::MailExtensions,
};
use tutasdk::{
    entities::{
        generated::{
            sys::User,
            tutanota::{Mail, MailSet, MailSetEntry},
        },
        Entity,
    },
    LoggedInSdk, TypeRef,
};

/// How long closing a watch waits for the bus to shut down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Events buffered between the bus and a slow reader.
const EVENT_BUFFER: usize = 64;

/// One change the event bus reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WatchEvent {
    /// The bus connected for the first time.
    Ready,
    /// The bus dropped and came back: resync.
    Reconnect,
    /// A folder or label was created, renamed, moved or deleted.
    FoldersChanged,
    /// Mail in `folder` arrived, left or changed; empty means "resync
    /// everything".
    MailChanged { folder: String },
}

fn type_id(type_ref: TypeRef) -> i64 {
    String::from(type_ref.type_id).parse().unwrap_or(-1)
}

/// What a batch means to a caller, in emission order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Change {
    Folders,
    Mail(String),
}

impl From<Change> for WatchEvent {
    fn from(change: Change) -> Self {
        match change {
            Change::Folders => WatchEvent::FoldersChanged,
            Change::Mail(folder) => WatchEvent::MailChanged { folder },
        }
    }
}

/// Mail set lookup by the list its entries live in, refreshed whenever a
/// mail set changes.
struct Folders {
    by_entries: HashMap<String, (String, bool)>,
    labels: BTreeSet<String>,
}

impl Folders {
    fn new(sets: &[MailSet]) -> Self {
        let mut by_entries = HashMap::new();
        let mut labels = BTreeSet::new();
        for set in sets {
            let Some(set_id) = set._id.as_ref().map(id) else {
                continue;
            };
            if is_label(set) {
                labels.insert(set_id.clone());
            }
            by_entries.insert(set.entries.to_string(), (set_id, is_label(set)));
        }
        Self { by_entries, labels }
    }
    async fn load(sdk: &LoggedInSdk) -> Result<Self> {
        Ok(Self::new(&load_mailbox(sdk).await?.sets))
    }
}

/// The folders (not labels) a mail is in.
fn mail_folders(sets: &[tutasdk::IdTupleGenerated], folders: &Folders) -> Vec<String> {
    sets.iter()
        .map(id)
        .filter(|set| !folders.labels.contains(set))
        .collect()
}

struct Types {
    mail: i64,
    mail_set: i64,
    entry: i64,
}

/// The changes one entity-update batch makes visible.
async fn changes(
    sdk: &Arc<LoggedInSdk>,
    folders: &mut Folders,
    types: &Types,
    batch: &EntityUpdateBatch,
) -> BTreeSet<Change> {
    let mut out = BTreeSet::new();
    let tutanota: Vec<_> = batch
        .updates
        .iter()
        .filter(|u| u.application == "tutanota")
        .collect();
    if tutanota.iter().any(|u| u.type_id == types.mail_set) {
        out.insert(Change::Folders);
        match Folders::load(sdk).await {
            Ok(fresh) => *folders = fresh,
            Err(code) => diag::note(&format!("watch: folder refresh failed: {code}")),
        }
    }
    for update in tutanota {
        if update.type_id == types.entry {
            match folders.by_entries.get(&update.instance_list_id) {
                // A label's entries change with the mail's own update,
                // which names its folders.
                Some((_, true)) => {}
                Some((folder, false)) => {
                    out.insert(Change::Mail(folder.clone()));
                }
                None => {
                    out.insert(Change::Mail(String::new()));
                }
            }
        } else if update.type_id == types.mail
            && matches!(update.operation, BusOp::Update | BusOp::Create)
        {
            match mail_sets(sdk, update).await {
                Some(sets) => {
                    out.extend(mail_folders(&sets, folders).into_iter().map(Change::Mail))
                }
                None => {
                    out.insert(Change::Mail(String::new()));
                }
            }
        }
    }
    out
}

/// The mail sets of a created or updated mail: from the inline instance
/// when the server sent one, else loaded.
async fn mail_sets(
    sdk: &Arc<LoggedInSdk>,
    update: &tutabridge_tuta::event_bus::EntityUpdateEvent,
) -> Option<Vec<tutasdk::IdTupleGenerated>> {
    if let Some(instance) = update.instance.as_deref() {
        match MailExtensions::new(sdk.clone())
            .decrypt_inline_and_parse::<Mail>(instance)
            .await
        {
            Ok(Some(mail)) => return Some(mail.sets),
            Ok(None) => {}
            Err(error) => diag::failed("watch: inline mail", &error),
        }
    }
    let mail_id = crate::ids::tuple(&format!(
        "{}/{}",
        update.instance_list_id, update.instance_id
    ))
    .ok()?;
    sdk.mail_facade()
        .get_crypto_entity_client()
        .load::<Mail, _>(&mail_id)
        .await
        .map_err(|error| diag::failed("watch: mail load", &error))
        .ok()
        .map(|mail| mail.sets)
}

/// The code a bus that gave up reports.
fn bus_error(error: &EventBusError) -> Error {
    match error {
        EventBusError::AuthenticationRejected(429) => Error::TransportFailed,
        EventBusError::AuthenticationRejected(_) => Error::SessionRevoked,
        EventBusError::InvalidMessage(_) => Error::WatchFailed,
        EventBusError::Stopped => Error::WatchFailed,
    }
}

/// Whether a failed session check ends the watch: only a definite verdict
/// on the session or client does; an outage just waits for the bus.
fn fatal(code: Error) -> bool {
    matches!(
        code,
        Error::SessionRevoked | Error::ClientOutdated | Error::SessionInvalid
    )
}

/// A running watch: a stream of [`WatchEvent`]s that ends after an `Err`.
/// Dropping it stops the bus in the background; [`Watch::close`] stops it
/// and waits for the websocket to close.
pub struct Watch {
    events: mpsc::Receiver<Result<WatchEvent>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Watch {
    /// Stop watching and wait (a few seconds at most) for the bus to shut
    /// down cleanly.
    pub async fn close(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl Stream for Watch {
    type Item = Result<WatchEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events.poll_recv(cx)
    }
}

impl Session {
    /// Hold Tuta's event bus open and stream what changes. Missed batches
    /// are replayed only while one watch runs: a new watch starts from the
    /// present.
    pub async fn watch(&self) -> Result<Watch> {
        let sdk = self.sdk.clone();
        let folders = Folders::load(&sdk).await?;
        let model_version = |type_ref: TypeRef| {
            sdk.type_model_provider
                .resolve_client_type_ref(&type_ref)
                .and_then(|model| u32::try_from(model.version).ok())
                .ok_or(Error::WatchFailed)
        };
        let bus = Arc::new(EventBusClient::new(
            self.base_url.clone(),
            model_version(User::type_ref())?,
            model_version(Mail::type_ref())?,
            tutasdk::CLIENT_VERSION.to_string(),
            String::new(),
        ));
        let (events_tx, events) = mpsc::channel(EVENT_BUFFER);
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(
            sdk,
            bus,
            self.saved.access_token().to_string(),
            self.saved.user_id().to_string(),
            folders,
            events_tx,
            stop_rx,
        ));
        Ok(Watch {
            events,
            stop,
            task: Some(task),
        })
    }
}

async fn run(
    sdk: Arc<LoggedInSdk>,
    bus: Arc<EventBusClient>,
    access_token: String,
    user_id: String,
    mut folders: Folders,
    events: mpsc::Sender<Result<WatchEvent>>,
    mut stop: watch::Receiver<bool>,
) {
    let types = Types {
        mail: type_id(Mail::type_ref()),
        mail_set: type_id(MailSet::type_ref()),
        entry: type_id(MailSetEntry::type_ref()),
    };
    let mut state = bus.state();
    let last_batch_ids = bus.last_batch_ids();
    let (tx, mut rx) = mpsc::channel(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runner = {
        let bus = bus.clone();
        tokio::spawn(async move { bus.run(access_token, user_id, tx, shutdown_rx).await })
    };
    let mut connected_once = false;
    let outcome: Result<()> = loop {
        tokio::select! {
            // A stop, or the watch dropped.
            _ = stop.changed() => break Ok(()),
            changed = state.changed() => {
                if changed.is_err() {
                    continue;
                }
                let now = *state.borrow_and_update();
                match now {
                    WsState::Connected => {
                        let event = if connected_once {
                            WatchEvent::Reconnect
                        } else {
                            WatchEvent::Ready
                        };
                        connected_once = true;
                        if events.send(Ok(event)).await.is_err() {
                            break Ok(());
                        }
                    }
                    // The bus retries an expired session forever; a REST
                    // call tells a dead session from a dead network.
                    WsState::Reconnecting => {
                        if let Err(code) = load_mailbox(&sdk).await {
                            if fatal(code) {
                                break Err(code);
                            }
                        }
                    }
                    WsState::Connecting | WsState::Stopped => {}
                }
            }
            message = rx.recv() => match message {
                Some(EventBusMessage::EntityUpdate(batch)) => {
                    let found = changes(&sdk, &mut folders, &types, &batch).await;
                    let mut reader_gone = false;
                    for change in found {
                        if events.send(Ok(change.into())).await.is_err() {
                            reader_gone = true;
                            break;
                        }
                    }
                    if reader_gone {
                        break Ok(());
                    }
                    // Processed: a reconnect resumes after this batch.
                    if let Ok(mut ids) = last_batch_ids.lock() {
                        ids.insert(batch.group_id.clone(), batch.batch_id.clone());
                    }
                }
                Some(_) => {}
                // The bus gave up; its result, read below, says why.
                None => break Err(Error::WatchFailed),
            },
        }
    };
    let _ = shutdown_tx.send(true);
    let finished = tokio::time::timeout(SHUTDOWN_GRACE, runner).await;
    let outcome = match (outcome, finished) {
        (Err(Error::WatchFailed), Ok(Ok(Err(error)))) => {
            diag::failed("watch: event bus", &error);
            Err(bus_error(&error))
        }
        (outcome, _) => outcome,
    };
    if let Err(code) = outcome {
        let _ = events.send(Err(code)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_become_events_folders_first() {
        assert_eq!(
            WatchEvent::from(Change::Mail("a/b".into())),
            WatchEvent::MailChanged {
                folder: "a/b".into()
            }
        );
        assert_eq!(
            serde_json::to_value(WatchEvent::from(Change::Mail("a/b".into()))).unwrap(),
            serde_json::json!({"event": "mail_changed", "folder": "a/b"})
        );
        assert_eq!(
            serde_json::to_value(WatchEvent::from(Change::Folders)).unwrap(),
            serde_json::json!({"event": "folders_changed"})
        );
        assert_eq!(
            serde_json::to_value(WatchEvent::Ready).unwrap(),
            serde_json::json!({"event": "ready"})
        );
        // Folder changes sort first, so a caller refreshes its tree before
        // syncing the folders named after it.
        let mut set = BTreeSet::new();
        set.insert(Change::Mail("z/z".into()));
        set.insert(Change::Folders);
        assert_eq!(set.into_iter().next(), Some(Change::Folders));
    }

    #[test]
    fn bus_failures_map_to_fixed_codes() {
        assert_eq!(
            bus_error(&EventBusError::AuthenticationRejected(401)),
            Error::SessionRevoked
        );
        assert_eq!(
            bus_error(&EventBusError::AuthenticationRejected(472)),
            Error::SessionRevoked
        );
        assert_eq!(
            bus_error(&EventBusError::AuthenticationRejected(429)),
            Error::TransportFailed
        );
        assert!(fatal(Error::SessionRevoked) && !fatal(Error::TransportFailed));
    }

    #[test]
    fn type_ids_match_the_model() {
        assert_eq!(type_id(Mail::type_ref()), 97);
        assert_eq!(type_id(MailSet::type_ref()), 429);
        assert_eq!(type_id(MailSetEntry::type_ref()), 1450);
    }

    #[test]
    fn mail_folders_leave_labels_out() {
        let folders = Folders {
            by_entries: HashMap::new(),
            labels: ["l/1".to_string()].into_iter().collect(),
        };
        let sets = [
            crate::ids::tuple("f/1").unwrap(),
            crate::ids::tuple("l/1").unwrap(),
        ];
        assert_eq!(mail_folders(&sets, &folders), ["f/1"]);
    }
}
