//! The protocol: one request object per reply, version 1, and the
//! dispatch onto the library. Every check that needs no network runs before
//! the session is resumed, in the order hylki-tuta made them.

use base64::{engine::general_purpose::STANDARD, Engine};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::Instant;
use tuta_unofficial_sdk::{
    contacts::{self, Passwords},
    drafts::{self, DraftRequest},
    Action, Client, Color, Error, FolderEdit, Id, ImportMessage, LabelChanges, LabelEdit, Name,
    OutgoingAttachment, Page, PendingSession, Recipient, Result, SavedSession, SendRequest,
    Session, Thread, MAIL_BATCH_LIMIT, MAX_IMPORT_BYTES,
};

/// The protocol version every request and reply carries.
pub const VERSION: u32 = 1;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Login {
        email: String,
        password: SecretString,
        totp: Option<String>,
        /// The session a `second_factor_required` (or a refused code)
        /// handed back: the code completes it instead of a new sign-in.
        pending_session: Option<PendingSession>,
    },
    Sync {
        session: SavedSession,
        folder: Option<String>,
        limit: usize,
        offset: usize,
    },
    Message {
        session: SavedSession,
        id: String,
    },
    MarkRead {
        session: SavedSession,
        ids: Vec<String>,
        is_read: bool,
    },
    Move {
        session: SavedSession,
        ids: Vec<String>,
        destination: String,
    },
    Send(Box<SendMail>),
    Revoke {
        session: SavedSession,
    },
    ListLabels(ListLabels),
    CreateFolder(CreateFolder),
    RenameFolder(RenameFolder),
    DeleteFolder(DeleteFolder),
    CreateLabel(CreateLabel),
    UpdateLabel(UpdateLabel),
    DeleteLabel(DeleteLabel),
    ApplyLabels(ApplyLabels),
    Delete(DeleteMails),
    EmptyFolder(EmptyFolder),
    SaveDraft(Box<SaveDraft>),
    ContactPasswords(ContactPasswords),
    StoreContactPasswords(StoreContactPasswords),
    DeleteDraft(DeleteDraft),
    Import(Import),
    /// Streaming; served by `watch::serve` before `dispatch` (see `main`).
    Watch(Watch),
}

#[derive(Deserialize)]
pub(crate) struct Request {
    pub(crate) version: u32,
    #[serde(flatten)]
    pub(crate) operation: Operation,
}

#[derive(Deserialize)]
pub(crate) struct WireRecipient {
    name: String,
    address: String,
}

#[derive(Deserialize)]
pub(crate) struct WireAttachment {
    name: String,
    mime_type: String,
    cid: Option<String>,
    /// Standard-base64 file bytes.
    data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendMail {
    session: SavedSession,
    sender: String,
    sender_name: String,
    to: Vec<WireRecipient>,
    cc: Vec<WireRecipient>,
    bcc: Vec<WireRecipient>,
    reply_tos: Vec<WireRecipient>,
    subject: String,
    body_html: String,
    /// End-to-end encryption asked for; an all-Tuta send is end-to-end
    /// encrypted either way.
    confidential: bool,
    ordinary_confirmed: bool,
    /// Passwords for the recipients outside Tuta of a confidential send.
    #[serde(default)]
    passwords: Passwords,
    attachments: Vec<WireAttachment>,
    /// The parent's Message-ID, for a reply or forward.
    in_reply_to: Option<String>,
    /// Whitespace-separated Message-IDs, oldest first.
    references: Option<String>,
    action: Option<Action>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListLabels {
    session: SavedSession,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateFolder {
    session: SavedSession,
    name: String,
    parent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameFolder {
    session: SavedSession,
    id: String,
    name: Option<String>,
    /// Absent keeps the parent, `""` moves the folder to the top level.
    parent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteFolder {
    session: SavedSession,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateLabel {
    session: SavedSession,
    name: String,
    color: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateLabel {
    session: SavedSession,
    id: String,
    name: Option<String>,
    color: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteLabel {
    session: SavedSession,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyLabels {
    session: SavedSession,
    ids: Vec<String>,
    add: Vec<String>,
    remove: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteMails {
    session: SavedSession,
    ids: Vec<String>,
    /// The Trash or Spam folder (or a subfolder) the mails are in.
    folder: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyFolder {
    session: SavedSession,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SaveDraft {
    session: SavedSession,
    /// The draft to update; absent creates a new one.
    draft_id: Option<String>,
    sender: String,
    sender_name: String,
    to: Vec<WireRecipient>,
    cc: Vec<WireRecipient>,
    bcc: Vec<WireRecipient>,
    reply_tos: Vec<WireRecipient>,
    subject: String,
    body_html: String,
    confidential: bool,
    attachments: Vec<WireAttachment>,
    in_reply_to: Option<String>,
    references: Option<String>,
    action: Option<Action>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactPasswords {
    session: SavedSession,
    addresses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreContactPasswords {
    session: SavedSession,
    passwords: Passwords,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteDraft {
    session: SavedSession,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Import {
    session: SavedSession,
    /// The target folder's compound id.
    folder: String,
    /// The whole message, standard base64.
    mime_base64: String,
    #[serde(default)]
    unread: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Watch {
    pub(crate) session: SavedSession,
}

/// How the helper presents itself: the session name Tuta lists, and the
/// diagnostics switch and prefix.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub client_name: &'static str,
    pub debug_variable: &'static str,
    pub prefix: &'static str,
}

impl Identity {
    pub const HELPER: Identity = Identity {
        client_name: "tuta-helper",
        debug_variable: "TUTA_HELPER_DEBUG",
        prefix: "tuta-helper",
    };
    /// Installed (or linked) as `hylki-tuta`, it is the helper Hylki has
    /// always run, and says so.
    pub const HYLKI: Identity = Identity {
        client_name: "Hylki",
        debug_variable: "HYLKI_TUTA_DEBUG",
        prefix: "hylki-tuta",
    };

    /// By the name the program was started under (argv[0]).
    pub fn from_program(argv0: Option<&std::ffi::OsStr>) -> Identity {
        let name = argv0
            .and_then(|path| std::path::Path::new(path).file_name())
            .and_then(|name| name.to_str());
        if name == Some("hylki-tuta") {
            Identity::HYLKI
        } else {
            Identity::HELPER
        }
    }

    pub fn client(&self) -> Result<Client> {
        Ok(Client::new()?.client_name(self.client_name))
    }
}

fn recipients(wire: Vec<WireRecipient>) -> Vec<Recipient> {
    wire.into_iter()
        .map(|r| Recipient {
            name: r.name,
            address: r.address,
        })
        .collect()
}

/// Decode the attachments' standard base64.
fn attachments(wire: Vec<WireAttachment>) -> Result<Vec<OutgoingAttachment>> {
    wire.into_iter()
        .map(|a| {
            Ok(OutgoingAttachment {
                data: STANDARD
                    .decode(a.data.as_bytes())
                    .map_err(|_| Error::AttachmentFailed)?,
                name: a.name,
                mime_type: a.mime_type,
                cid: a.cid,
            })
        })
        .collect()
}

fn ids(values: &[String]) -> Result<Vec<Id>> {
    values.iter().map(|value| Id::parse(value)).collect()
}

/// A mutation batch: 1 to `MAIL_BATCH_LIMIT` ids, size checked first.
fn batch(values: &[String]) -> Result<Vec<Id>> {
    if values.is_empty() || values.len() > MAIL_BATCH_LIMIT {
        return Err(Error::InvalidBatch);
    }
    ids(values)
}

fn value(result: impl serde::Serialize) -> Value {
    serde_json::to_value(result).expect("protocol types serialize to JSON")
}

/// Every operation but `watch`, against `deadline`.
pub(crate) async fn dispatch(
    client: &Client,
    operation: Operation,
    deadline: Instant,
) -> Result<Value, Failure> {
    match operation {
        Operation::Send(send) => Ok(send_mail(client, *send, deadline).await?),
        Operation::Login {
            email,
            password,
            totp,
            pending_session,
        } => tokio::time::timeout_at(
            deadline,
            login(client, &email, &password, totp.as_deref(), pending_session),
        )
        .await
        .unwrap_or(Err(Error::Timeout.into())),
        operation => Ok(tokio::time::timeout_at(deadline, run(client, operation))
            .await
            .unwrap_or(Err(Error::Timeout))?),
    }
}

/// A failed request: its code and, for a sign-in waiting on its second
/// factor, the session to retry the code on (`error.pending_session`).
pub(crate) struct Failure {
    pub(crate) code: Error,
    pub(crate) pending_session: Option<PendingSession>,
}

impl From<Error> for Failure {
    fn from(code: Error) -> Self {
        Failure {
            code,
            pending_session: None,
        }
    }
}

/// `login`: a new sign-in, or with `pending_session` the second factor of
/// one the server already opened. A pending session is for one address: a
/// request naming another is refused before any I/O.
async fn login(
    client: &Client,
    email: &str,
    password: &SecretString,
    totp: Option<&str>,
    pending: Option<PendingSession>,
) -> Result<Value, Failure> {
    let signed_in = match pending {
        Some(pending) => {
            let normalized = |address: &str| address.trim().to_lowercase();
            if normalized(pending.login()) != normalized(email) {
                return Err(Error::InvalidRequest.into());
            }
            let Some(code) = totp else {
                return Err(Failure {
                    code: Error::SecondFactorRequired,
                    pending_session: Some(pending),
                });
            };
            client.complete_sign_in(pending, code).await
        }
        None => client.sign_in(email, password, totp).await,
    };
    match signed_in {
        Ok(session) => Ok(json!({"session": session.saved()})),
        Err(failure) => Err(Failure {
            code: failure.code,
            pending_session: failure.pending,
        }),
    }
}

/// A send's own time limit: a send that overran after its submit left must
/// report what the submit got back, never a plain timeout (see
/// `Session::send_within`).
async fn send_mail(client: &Client, request: SendMail, deadline: Instant) -> Result<Value> {
    let thread = Thread::new(
        request.in_reply_to.as_deref(),
        request.references.as_deref(),
        request.action,
    )?;
    let attachments = attachments(request.attachments)?;
    let session = tokio::time::timeout_at(deadline, client.resume(request.session))
        .await
        .unwrap_or(Err(Error::Timeout))?;
    let outcome = session
        .send_within(
            SendRequest {
                sender: request.sender,
                sender_name: request.sender_name,
                to: recipients(request.to),
                cc: recipients(request.cc),
                bcc: recipients(request.bcc),
                reply_tos: recipients(request.reply_tos),
                subject: request.subject,
                body_html: request.body_html,
                confidential: request.confidential,
                ordinary_confirmed: request.ordinary_confirmed,
                passwords: request.passwords,
                attachments,
                thread,
            },
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
    Ok(value(outcome))
}

async fn resume(client: &Client, saved: SavedSession) -> Result<Session> {
    client.resume(saved).await
}

async fn run(client: &Client, operation: Operation) -> Result<Value> {
    match operation {
        Operation::Login { .. } => unreachable!("dispatch handles login"),
        Operation::Sync {
            session,
            folder,
            limit,
            offset,
        } => {
            let session = resume(client, session).await?;
            let page = Page::new(limit, offset)?;
            // A folder that is not even an id names no folder.
            let selected = match folder.as_deref().map(Id::parse) {
                Some(Err(_)) => return Err(Error::FolderNotFound),
                Some(Ok(id)) => Some(id),
                None => None,
            };
            Ok(value(session.sync(selected.as_ref(), page).await?))
        }
        Operation::Message { session, id } => {
            let session = resume(client, session).await?;
            let id = Id::parse(&id)?;
            Ok(value(session.message(&id).await?))
        }
        Operation::MarkRead {
            session,
            ids: values,
            is_read,
        } => {
            if values.len() > MAIL_BATCH_LIMIT {
                return Err(Error::InvalidBatch);
            }
            let parsed = ids(&values)?;
            let session = resume(client, session).await?;
            let rows = session.mark_read(&parsed, is_read).await?;
            Ok(json!({"outcomes": rows}))
        }
        Operation::Move {
            session,
            ids: values,
            destination,
        } => {
            let parsed = batch(&values)?;
            let destination = Id::parse(&destination)?;
            let session = resume(client, session).await?;
            let rows = session.move_mail(&parsed, &destination).await?;
            Ok(json!({"outcomes": rows}))
        }
        Operation::Send(_) => unreachable!("dispatch handles send"),
        Operation::Revoke { session } => {
            client.revoke(&session).await?;
            Ok(json!({}))
        }
        Operation::ListLabels(r) => {
            let session = resume(client, r.session).await?;
            Ok(json!({"labels": session.labels().await?}))
        }
        Operation::CreateFolder(r) => {
            let name = Name::new(&r.name)?;
            let parent = r.parent.as_deref().map(Id::parse).transpose()?;
            let session = resume(client, r.session).await?;
            let id = session.create_folder(&name, parent.as_ref()).await?;
            Ok(json!({"id": id}))
        }
        Operation::RenameFolder(r) => {
            let folder = Id::parse(&r.id)?;
            let name = r.name.as_deref().map(Name::new).transpose()?;
            let parent = match r.parent.as_deref() {
                None => None,
                Some("") => Some(None),
                Some(parent) => Some(Some(Id::parse(parent)?)),
            };
            let edit = FolderEdit::new(folder, name, parent)?;
            let session = resume(client, r.session).await?;
            session.rename_folder(&edit).await?;
            Ok(json!({}))
        }
        Operation::DeleteFolder(r) => {
            let folder = Id::parse(&r.id)?;
            let session = resume(client, r.session).await?;
            Ok(json!({"outcome": session.delete_folder(&folder).await?}))
        }
        Operation::CreateLabel(r) => {
            let name = Name::new(&r.name)?;
            let color = Color::new(&r.color)?;
            let session = resume(client, r.session).await?;
            Ok(json!({"id": session.create_label(&name, &color).await?}))
        }
        Operation::UpdateLabel(r) => {
            let label = Id::parse(&r.id)?;
            let name = r.name.as_deref().map(Name::new).transpose()?;
            let color = r.color.as_deref().map(Color::new).transpose()?;
            let edit = LabelEdit::new(name, color)?;
            let session = resume(client, r.session).await?;
            session.update_label(&label, &edit).await?;
            Ok(json!({}))
        }
        Operation::DeleteLabel(r) => {
            let label = Id::parse(&r.id)?;
            let session = resume(client, r.session).await?;
            session.delete_label(&label).await?;
            Ok(json!({}))
        }
        Operation::ApplyLabels(r) => {
            let parsed = batch(&r.ids)?;
            let changes = LabelChanges::new(ids(&r.add)?, ids(&r.remove)?)?;
            let session = resume(client, r.session).await?;
            let rows = session.apply_labels(&parsed, &changes).await?;
            Ok(json!({"outcomes": rows}))
        }
        Operation::Delete(r) => {
            let parsed = batch(&r.ids)?;
            let folder = Id::parse(&r.folder)?;
            let session = resume(client, r.session).await?;
            let rows = session.delete(&parsed, &folder).await?;
            Ok(json!({"outcomes": rows}))
        }
        Operation::EmptyFolder(r) => {
            let folder = Id::parse(&r.id)?;
            let session = resume(client, r.session).await?;
            Ok(json!({"deleted": session.empty_folder(&folder).await?}))
        }
        Operation::SaveDraft(r) => {
            let (session, request) = draft_request(*r)?;
            let session = resume(client, session).await?;
            Ok(json!({"id": drafts::save(&session, &request).await?}))
        }
        Operation::ContactPasswords(r) => {
            contacts::check_addresses(r.addresses.iter().map(String::as_str))?;
            if r.addresses.is_empty() {
                return Ok(json!({"recipients": []}));
            }
            let session = resume(client, r.session).await?;
            Ok(json!({"recipients": contacts::passwords(&session, &r.addresses).await?}))
        }
        Operation::StoreContactPasswords(r) => {
            contacts::check_addresses(r.passwords.addresses())?;
            if r.passwords.is_empty() {
                return Ok(json!({}));
            }
            let session = resume(client, r.session).await?;
            contacts::store_passwords(&session, &r.passwords).await?;
            Ok(json!({}))
        }
        Operation::DeleteDraft(r) => {
            let draft = Id::parse(&r.id)?;
            let session = resume(client, r.session).await?;
            drafts::delete(&session, &draft).await?;
            Ok(json!({}))
        }
        Operation::Import(r) => {
            let (folder, message) = import_request(&r)?;
            let session = resume(client, r.session).await?;
            Ok(json!({"id": session.import(&folder, message).await?}))
        }
        // A watch arrives here only without its newline or with stdin
        // already closed: there is nothing to stream to.
        Operation::Watch(_) => Err(Error::InvalidRequest),
    }
}

/// A `save_draft` request checked as hylki-tuta checked it: addresses and
/// body, then the thread, then the draft id.
fn draft_request(r: SaveDraft) -> Result<(SavedSession, DraftRequest)> {
    let mut request = DraftRequest {
        draft: None,
        sender: r.sender,
        sender_name: r.sender_name,
        to: recipients(r.to),
        cc: recipients(r.cc),
        bcc: recipients(r.bcc),
        reply_tos: recipients(r.reply_tos),
        subject: r.subject,
        body_html: r.body_html,
        confidential: r.confidential,
        attachments: Vec::new(),
        thread: Thread::default(),
    };
    request.check()?;
    request.thread = Thread::new(r.in_reply_to.as_deref(), r.references.as_deref(), r.action)?;
    request.draft = r.draft_id.as_deref().map(Id::parse).transpose()?;
    request.attachments = attachments(r.attachments)?;
    Ok((r.session, request))
}

/// An `import` request's folder and message, checked before any I/O. An
/// oversized message is refused before decoding, so it costs no copy.
fn import_request(r: &Import) -> Result<(Id, ImportMessage)> {
    let folder = Id::parse(&r.folder)?;
    if r.mime_base64.len() > MAX_IMPORT_BYTES.div_ceil(3) * 4 {
        return Err(Error::ImportTooLarge);
    }
    let bytes = STANDARD
        .decode(r.mime_base64.as_bytes())
        .map_err(|_| Error::InvalidRequest)?;
    Ok((folder, ImportMessage::parse(&bytes, r.unread)?))
}

/// How long one operation may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = r#""session":{"login":"a@tuta.com","user_id":"u",
        "access_token":"t","encrypted_passphrase_key":[]}"#;

    fn parse(body: &str) -> serde_json::Result<Request> {
        serde_json::from_str(body)
    }

    #[test]
    fn request_rejects_unrecognized_operations() {
        assert!(parse(r#"{"version":1,"op":"star"}"#).is_err());
    }

    fn send(fields: &str) -> serde_json::Result<Request> {
        parse(&format!(
            r#"{{"version":1,"op":"send",{SESSION},
            "sender":"a@tuta.com","sender_name":"A","to":[],"cc":[],"bcc":[],
            "reply_tos":[],"subject":"s","body_html":"b",
            "attachments":[]{fields}}}"#
        ))
    }

    #[test]
    fn send_parses_its_confidentiality_and_passwords() {
        let request = send(r#","confidential":false,"ordinary_confirmed":true"#).unwrap();
        match request.operation {
            Operation::Send(send) => {
                assert!(!send.confidential && send.ordinary_confirmed);
                assert_eq!(send.passwords.get("x@example.org"), None);
            }
            _ => panic!("not a send"),
        }
        let request = send(
            r#","confidential":true,"ordinary_confirmed":false,
            "passwords":{"x@example.org":"pw"}"#,
        )
        .unwrap();
        match request.operation {
            Operation::Send(send) => {
                assert!(send.confidential);
                assert_eq!(send.passwords.get("X@example.org"), Some("pw"));
            }
            _ => panic!("not a send"),
        }
        // The old delivery field is gone, and confidential has no default.
        assert!(send(r#","delivery":"ordinary","ordinary_confirmed":true"#).is_err());
        assert!(send(r#","ordinary_confirmed":true"#).is_err());
        assert!(send(r#","confidential":"yes","ordinary_confirmed":true"#).is_err());
    }

    #[test]
    fn send_takes_an_optional_place_in_a_conversation() {
        let parse = |extra: &str| {
            send(&format!(
                r#","confidential":false,"ordinary_confirmed":true{extra}"#
            ))
        };
        match parse("").unwrap().operation {
            Operation::Send(send) => {
                assert!(send.in_reply_to.is_none() && send.references.is_none());
                assert!(send.action.is_none());
            }
            _ => panic!("not a send"),
        }
        let reply =
            parse(r#","in_reply_to":"<p@x>","references":"<r@x> <p@x>","action":"reply_all""#);
        match reply.unwrap().operation {
            Operation::Send(send) => {
                assert!(send.in_reply_to.is_some() && send.references.is_some());
                assert_eq!(send.action, Some(Action::ReplyAll));
            }
            _ => panic!("not a send"),
        }
        assert!(parse(r#","action":"redirect""#).is_err());
        assert!(parse(r#","in_reply_to":1"#).is_err());
    }

    #[test]
    fn contact_password_operations_parse() {
        for body in [
            format!(r#"{{"version":1,"op":"contact_passwords",{SESSION},"addresses":["x@y.z"]}}"#),
            format!(
                r#"{{"version":1,"op":"store_contact_passwords",{SESSION},
                "passwords":{{"x@y.z":"pw"}}}}"#
            ),
        ] {
            assert!(parse(&body).is_ok(), "{body}");
        }
        assert!(parse(&format!(
            r#"{{"version":1,"op":"contact_passwords",{SESSION},"addresses":[],"extra":1}}"#
        ))
        .is_err());
    }

    #[test]
    fn every_operation_parses_through_the_envelope_and_refuses_unknown_fields() {
        let session: Value = serde_json::from_str(&format!("{{{SESSION}}}")).unwrap();
        let session = session["session"].clone();
        let parses = |request: &Value| serde_json::from_value::<Request>(request.clone()).is_ok();
        let requests = [
            json!({"op": "sync", "limit": 10, "offset": 0}),
            json!({"op": "sync", "folder": "a/b", "limit": 10, "offset": 0}),
            json!({"op": "message", "id": "a/b"}),
            json!({"op": "mark_read", "ids": ["a/b"], "is_read": true}),
            json!({"op": "move", "ids": ["a/b"], "destination": "f/f"}),
            json!({"op": "revoke"}),
            json!({"op": "list_labels"}),
            json!({"op": "create_folder", "name": "x"}),
            json!({"op": "create_folder", "name": "x", "parent": "a/b"}),
            json!({"op": "rename_folder", "id": "a/b", "name": "y"}),
            json!({"op": "rename_folder", "id": "a/b", "parent": ""}),
            json!({"op": "delete_folder", "id": "a/b"}),
            json!({"op": "create_label", "name": "x", "color": "#000000"}),
            json!({"op": "update_label", "id": "a/b", "color": "#000000"}),
            json!({"op": "delete_label", "id": "a/b"}),
            json!({"op": "apply_labels", "ids": ["a/b"], "add": ["l/1"], "remove": []}),
            json!({"op": "delete", "ids": ["a/b"], "folder": "t/t"}),
            json!({"op": "empty_folder", "id": "t/t"}),
            json!({"op": "delete_draft", "id": "a/b"}),
            json!({"op": "import", "folder": "a/b", "mime_base64": ""}),
            json!({"op": "watch"}),
        ];
        for mut request in requests {
            let fields = request.as_object_mut().unwrap();
            fields.insert("version".into(), json!(1));
            fields.insert("session".into(), session.clone());
            assert!(parses(&request), "{request}");
            request
                .as_object_mut()
                .unwrap()
                .insert("unexpected".into(), json!(true));
            assert!(!parses(&request), "{request}");
        }
        // Required fields stay required.
        assert!(!parses(
            &json!({"version": 1, "op": "delete", "session": session, "ids": ["a/b"]})
        ));
        assert!(!parses(
            &json!({"version": 1, "op": "login", "email": "a@b"})
        ));
        assert!(parses(
            &json!({"version": 1, "op": "login", "email": "a@b", "password": "p"})
        ));
    }

    fn draft(extra: Value) -> serde_json::Result<SaveDraft> {
        let mut base = json!({
            "session": {"login": "", "user_id": "", "access_token": "", "encrypted_passphrase_key": []},
            "sender": "me@example.org", "sender_name": "", "to": [], "cc": [], "bcc": [],
            "reply_tos": [], "subject": "", "body_html": "", "confidential": false,
            "attachments": [],
        });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(base)
    }

    fn checked(extra: Value) -> Result<DraftRequest> {
        draft_request(draft(extra).unwrap()).map(|(_, request)| request)
    }

    #[test]
    fn a_draft_needs_no_recipient_but_valid_addresses() {
        assert!(checked(json!({})).unwrap().draft.is_none());
        let bad = json!({"cc": [{"name": "", "address": "nope"}]});
        assert_eq!(checked(bad).err(), Some(Error::InvalidRecipient));
        let bad_reply = json!({"reply_tos": [{"name": "", "address": "a b@c"}]});
        assert_eq!(checked(bad_reply).err(), Some(Error::InvalidRecipient));
    }

    #[test]
    fn a_draft_id_and_body_are_checked_in_order() {
        let update = checked(json!({"draft_id": "list/elem"})).unwrap();
        assert_eq!(update.draft.unwrap().to_string(), "list/elem");
        assert_eq!(
            checked(json!({"draft_id": "elem"})).err(),
            Some(Error::InvalidId)
        );
        let big = "x".repeat(tuta_unofficial_sdk::MAX_BODY_BYTES + 1);
        assert_eq!(
            checked(json!({"body_html": big})).err(),
            Some(Error::BodyTooLarge)
        );
        // Addresses come before the thread, the thread before the id.
        assert_eq!(
            checked(json!({"to": [{"name": "", "address": "x"}], "in_reply_to": "a b"})).err(),
            Some(Error::InvalidRecipient)
        );
        assert_eq!(
            checked(json!({"in_reply_to": "a b", "draft_id": "bad"})).err(),
            Some(Error::InvalidThread)
        );
        assert_eq!(
            checked(
                json!({"attachments": [{"name": "a", "mime_type": "text/plain",
                "cid": null, "data": "not base64!"}]})
            )
            .err(),
            Some(Error::AttachmentFailed)
        );
    }

    #[test]
    fn a_reply_draft_names_its_parent() {
        assert_eq!(checked(json!({})).unwrap().thread.parent(), None);
        let reply = checked(json!({"in_reply_to": "<p@x>", "references": "<r@x> <p@x>",
            "action": "reply_all"}))
        .unwrap();
        assert_eq!(reply.thread.parent(), Some("p@x"));
        assert!(draft(json!({"action": "redirect"})).is_err());
    }

    #[test]
    fn unknown_and_missing_draft_fields_are_refused() {
        assert!(draft(json!({"delivery": "ordinary"})).is_err());
        let missing = json!({
            "session": {"login": "", "user_id": "", "access_token": "", "encrypted_passphrase_key": []},
            "sender": "me@example.org",
        });
        assert!(serde_json::from_value::<SaveDraft>(missing).is_err());
    }

    const RAW: &str = "From: Ada <ada@example.org>\r\nSubject: hi\r\n\r\nHello\r\n";

    fn import(fields: Value) -> serde_json::Result<Import> {
        let mut base = json!({
            "session": {"login": "l", "user_id": "u", "access_token": "t",
                "encrypted_passphrase_key": []},
            "folder": "list/element",
            "mime_base64": STANDARD.encode(RAW),
        });
        for (key, value) in fields.as_object().unwrap() {
            base[key] = value.clone();
        }
        serde_json::from_value(base)
    }

    fn prepared(fields: Value) -> Result<Id> {
        import_request(&import(fields).unwrap()).map(|(folder, _)| folder)
    }

    #[test]
    fn imports_are_checked_before_any_io() {
        assert_eq!(prepared(json!({})).unwrap().to_string(), "list/element");
        assert_eq!(
            prepared(json!({"folder": "nope"})).err(),
            Some(Error::InvalidId)
        );
        assert_eq!(
            prepared(json!({"mime_base64": "not base64!"})).err(),
            Some(Error::InvalidRequest)
        );
        assert_eq!(
            prepared(json!({"mime_base64": ""})).err(),
            Some(Error::ImportInvalid)
        );
        // Over the cap in base64 is refused before decoding.
        let over = "A".repeat(MAX_IMPORT_BYTES.div_ceil(3) * 4 + 4);
        assert_eq!(
            prepared(json!({"mime_base64": over})).err(),
            Some(Error::ImportTooLarge)
        );
        assert!(import(json!({"extra": 1})).is_err(), "unknown fields");
        assert!(
            import(json!({"mime_base64": null})).is_err(),
            "the message is required"
        );
    }

    #[test]
    fn the_program_name_picks_the_identity() {
        use std::ffi::OsStr;
        let named = |name: &str| Identity::from_program(Some(OsStr::new(name))).client_name;
        assert_eq!(named("/app/bin/hylki-tuta"), "Hylki");
        assert_eq!(named("hylki-tuta"), "Hylki");
        assert_eq!(named("/usr/bin/tuta-helper"), "tuta-helper");
        assert_eq!(named("hylki-tuta-old"), "tuta-helper");
        assert_eq!(Identity::from_program(None).client_name, "tuta-helper");
    }

    #[tokio::test]
    async fn offline_checks_never_connect() {
        let far = Instant::now() + REQUEST_TIMEOUT;
        let client = Identity::HELPER.client().unwrap();
        let request = |body: &str| parse(body).unwrap().operation;
        let session = SESSION;
        for (body, code) in [
            (
                format!(
                    r#"{{"version":1,"op":"mark_read",{session},"ids":["nope"],"is_read":true}}"#
                ),
                Error::InvalidId,
            ),
            (
                format!(r#"{{"version":1,"op":"move",{session},"ids":[],"destination":"a/b"}}"#),
                Error::InvalidBatch,
            ),
            (
                format!(
                    r#"{{"version":1,"op":"create_label",{session},"name":"x","color":"red"}}"#
                ),
                Error::InvalidColor,
            ),
            (
                format!(r#"{{"version":1,"op":"rename_folder",{session},"id":"a/b"}}"#),
                Error::InvalidRequest,
            ),
            (
                format!(
                    r#"{{"version":1,"op":"send",{session},"sender":"a@tuta.com","sender_name":"",
                    "to":[],"cc":[],"bcc":[],"reply_tos":[],"subject":"","body_html":"",
                    "confidential":true,"ordinary_confirmed":false,"attachments":[],
                    "action":"reply"}}"#
                ),
                Error::InvalidThread,
            ),
            (
                format!(r#"{{"version":1,"op":"contact_passwords",{session},"addresses":["x"]}}"#),
                Error::InvalidRecipient,
            ),
        ] {
            assert_eq!(
                dispatch(&client, request(&body), far)
                    .await
                    .err()
                    .map(|f| f.code),
                Some(code),
                "{body}"
            );
        }
        let empty = format!(r#"{{"version":1,"op":"contact_passwords",{session},"addresses":[]}}"#);
        assert_eq!(
            dispatch(&client, request(&empty), far).await.ok().unwrap(),
            json!({"recipients": []})
        );
    }

    const PENDING: &str = r#"{"login":"Ada@Tuta.com","user_id":"u",
        "access_token":"AAECAwQFBgcICQoLDA0ODw","encrypted_passphrase_key":[1,2]}"#;

    #[tokio::test]
    async fn a_pending_sign_in_is_checked_before_any_io_and_handed_back() {
        let far = Instant::now() + REQUEST_TIMEOUT;
        let client = Identity::HELPER.client().unwrap();
        let login = |extra: &str| {
            parse(&format!(
                r#"{{"version":1,"op":"login","email":"ada@tuta.com","password":"p",
                "pending_session":{PENDING}{extra}}}"#
            ))
            .unwrap()
            .operation
        };
        let pending: Value = serde_json::from_str(PENDING).unwrap();
        // No code yet: still waiting, same session back.
        let failure = dispatch(&client, login(""), far).await.err().unwrap();
        assert_eq!(failure.code, Error::SecondFactorRequired);
        assert_eq!(
            serde_json::to_value(failure.pending_session).unwrap(),
            pending
        );
        // A malformed code: refused, same session back for the next try.
        let failure = dispatch(&client, login(r#","totp":"12a""#), far)
            .await
            .err()
            .unwrap();
        assert_eq!(failure.code, Error::InvalidTotp);
        assert_eq!(
            serde_json::to_value(failure.pending_session).unwrap(),
            pending
        );
        // Another address cannot use it.
        let other = parse(&format!(
            r#"{{"version":1,"op":"login","email":"eve@tuta.com","password":"p",
            "totp":"123456","pending_session":{PENDING}}}"#
        ))
        .unwrap()
        .operation;
        let failure = dispatch(&client, other, far).await.err().unwrap();
        assert_eq!(failure.code, Error::InvalidRequest);
        assert!(failure.pending_session.is_none());
        // A pending session is a whole session object.
        assert!(parse(
            r#"{"version":1,"op":"login","email":"a","password":"p","pending_session":{"login":"a"}}"#
        )
        .is_err());
    }
}
