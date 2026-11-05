//! Listing and reading mail: the folder tree, labels, a folder's page of
//! headers, one decrypted message, and the read flag.

use crate::{
    ids::{id, Id},
    mailbox_ops::{self, IMPORTED_FOLDER_TYPE},
    thread, Error, Result, Session, MAIL_BATCH_LIMIT,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Serialize, Serializer};
use std::collections::HashSet;
use tutabridge_tuta::mail::MailExtensions;
use tutasdk::{
    entities::generated::tutanota::{Mail, MailAddress, MailSet, MailSetEntry},
    ListLoadDirection,
};

/// The most mails `sync` lists per page.
pub const MAX_PAGE_LIMIT: usize = 1000;
/// The furthest `sync` pages into a folder.
pub const MAX_PAGE_OFFSET: usize = 1_000_000;
/// TS `MailSetKind.INBOX`, what `sync` lists when no folder is named.
const INBOX_FOLDER_TYPE: i64 = 1;

/// What a system folder is for; custom folders are `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FolderRole {
    Inbox,
    Sent,
    Trash,
    Archive,
    /// Spam.
    Junk,
    Drafts,
    Other,
}

impl FolderRole {
    /// The role of a Tuta folder type, with the label a system folder shows
    /// when the server gives it no name.
    pub(crate) fn of(kind: i64) -> (FolderRole, &'static str) {
        match kind {
            1 => (FolderRole::Inbox, "Inbox"),
            2 => (FolderRole::Sent, "Sent"),
            3 => (FolderRole::Trash, "Trash"),
            4 => (FolderRole::Archive, "Archive"),
            5 => (FolderRole::Junk, "Spam"),
            6 => (FolderRole::Drafts, "Drafts"),
            _ => (FolderRole::Other, "Folder"),
        }
    }
}

/// One folder of the tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Folder {
    pub id: Id,
    pub role: FolderRole,
    /// Its name, or the role's English name for an unnamed system folder.
    pub label: String,
    /// The parent folder; None at the top level (`""` on the wire).
    #[serde(serialize_with = "id_or_empty")]
    pub parent: Option<Id>,
}

fn id_or_empty<S: Serializer>(
    value: &Option<Id>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(id) => serializer.collect_str(id),
        None => serializer.serialize_str(""),
    }
}

/// A label: a mail set beside the folders, colour `#rrggbb` (or empty).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Label {
    pub id: Id,
    pub name: String,
    pub color: String,
}

/// A name and an address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Address {
    pub name: String,
    pub address: String,
}

impl Address {
    fn of(address: &MailAddress) -> Self {
        Address {
            name: address.name.clone(),
            address: address.address.clone(),
        }
    }
}

/// A mail's header as listed and as read.
///
/// `conversation` is the conversation entry's list id: Tuta files every mail
/// of one conversation in one such list. `message_id` is the mail's own
/// Message-ID as its conversation entry keeps it, bare (None for a draft, or
/// when it could not be read): mail between Tuta accounts has no header block
/// that would carry one. `reply_type` is Tuta's own replied/forwarded mark
/// (0 none, 1 replied, 2 forwarded, 3 both).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MailHeader {
    pub id: Id,
    pub subject: String,
    pub date_ms: u64,
    pub sender: Address,
    pub recipient: Option<Address>,
    pub is_unread: bool,
    pub confidential: bool,
    pub conversation: String,
    pub message_id: Option<String>,
    pub has_attachments: bool,
    pub reply_type: i64,
}

impl MailHeader {
    pub(crate) fn of(mail: &Mail, message_id: Option<&str>) -> Result<Self> {
        if !mail._errors.is_empty() {
            return Err(Error::DecryptionFailed);
        }
        let mail_id = mail._id.clone().ok_or(Error::IncompleteResponse)?;
        Ok(MailHeader {
            id: Id::from_tuple(mail_id),
            subject: mail.subject.clone(),
            date_ms: mail.receivedDate.as_millis(),
            sender: Address::of(&mail.sender),
            recipient: mail.firstRecipient.as_ref().map(Address::of),
            is_unread: mail.unread,
            confidential: mail.confidential,
            conversation: mail.conversationEntry.list_id.to_string(),
            message_id: message_id.map(str::to_string),
            has_attachments: !mail.attachments.is_empty(),
            reply_type: mail.replyType,
        })
    }
}

/// A listed mail: its header and the labels it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedMail {
    #[serde(flatten)]
    pub header: MailHeader,
    pub labels: Vec<Id>,
}

/// Which slice of a folder `sync` lists, newest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    limit: usize,
    offset: usize,
}

impl Page {
    /// At most [`MAX_PAGE_LIMIT`] mails from `offset` (at most
    /// [`MAX_PAGE_OFFSET`]); a zero limit is [`Error::InvalidPage`].
    pub fn new(limit: usize, offset: usize) -> Result<Self> {
        if limit == 0 || limit > MAX_PAGE_LIMIT || offset > MAX_PAGE_OFFSET {
            return Err(Error::InvalidPage);
        }
        Ok(Page { limit, offset })
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}

/// One `sync` page: the folder tree, the labels, the selected folder's page
/// of mail, and on the first page (offset zero) every mail id it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncPage {
    pub folders: Vec<Folder>,
    pub labels: Vec<Label>,
    pub messages: Vec<ListedMail>,
    /// The folder listed.
    pub folder: Id,
    /// How many mails it holds.
    pub exists: usize,
    /// Every mail id it holds, newest first, on the first page only. It is
    /// authoritative: a caller may prune what it does not list.
    pub all_ids: Option<Vec<Id>>,
    pub offset: usize,
}

/// A decrypted message, in parts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Message {
    pub header: MailHeader,
    /// The HTML body.
    pub html: String,
    /// The original header block, empty for mail between Tuta accounts.
    pub headers: String,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub reply_to: Vec<Address>,
    pub attachments: Vec<Attachment>,
}

/// A decrypted attachment (standard base64 `data` on the wire).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Attachment {
    pub name: String,
    pub mime_type: Option<String>,
    pub cid: Option<String>,
    #[serde(serialize_with = "base64")]
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("mime_type", &self.mime_type)
            .field("cid", &self.cid)
            .field("bytes", &self.data.len())
            .finish()
    }
}

fn base64<S: Serializer>(data: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(data))
}

/// What became of one id of a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Applied (`null` on the wire).
    Applied,
    /// The batch holding it failed with this error.
    Failed(Error),
    /// A batch before it failed, so it was never tried (`not_attempted`).
    NotAttempted,
}

impl Serialize for Outcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Outcome::Applied => serializer.serialize_none(),
            Outcome::Failed(error) => serializer.serialize_str(error.code()),
            Outcome::NotAttempted => serializer.serialize_str("not_attempted"),
        }
    }
}

/// One id's outcome, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdOutcome {
    pub id: Id,
    pub code: Outcome,
}

/// Per-id outcomes for a mutation batch, in input order: every id up to the
/// first failure applied, the failed id carries its code, and the rest were
/// never attempted. A chunk is one service call, so a failed chunk reports
/// its head and the tail stays unknown -- all three mutations are idempotent,
/// and the next sync reconciles whatever the server did apply.
fn prefix_outcomes(ids: &[Id], applied: usize, code: Option<Error>) -> Vec<IdOutcome> {
    ids.iter()
        .enumerate()
        .map(|(index, id)| IdOutcome {
            id: id.clone(),
            code: if index < applied {
                Outcome::Applied
            } else if index == applied {
                code.map_or(Outcome::Applied, Outcome::Failed)
            } else {
                Outcome::NotAttempted
            },
        })
        .collect()
}

fn folder_row(folder: &MailSet, folder_id: Id) -> Folder {
    let (role, fallback) = FolderRole::of(folder.folderType);
    Folder {
        id: folder_id,
        role,
        label: if folder.name.is_empty() {
            fallback.to_string()
        } else {
            folder.name.clone()
        },
        parent: folder.parentFolder.clone().map(Id::from_tuple),
    }
}

impl Session {
    /// The folder tree, labels and the IMPORTED set left out.
    pub async fn folders(&self) -> Result<Vec<Folder>> {
        let mailbox = mailbox_ops::load_mailbox(&self.sdk).await?;
        let mut rows = Vec::new();
        for folder in &mailbox.sets {
            if mailbox_ops::is_label(folder) || folder.folderType == IMPORTED_FOLDER_TYPE {
                continue;
            }
            let folder_id = folder._id.clone().ok_or(Error::IncompleteResponse)?;
            rows.push(folder_row(folder, Id::from_tuple(folder_id)));
        }
        Ok(rows)
    }

    /// The labels.
    pub async fn labels(&self) -> Result<Vec<Label>> {
        let mailbox = mailbox_ops::load_mailbox(&self.sdk).await?;
        Ok(mailbox
            .sets
            .iter()
            .filter(|set| mailbox_ops::is_label(set))
            .filter_map(mailbox_ops::label_row)
            .collect())
    }

    /// List a folder (or a label's mail): the Inbox when `folder` is None.
    pub async fn sync(&self, selected: Option<&Id>, page: Page) -> Result<SyncPage> {
        let facade = self.sdk.mail_facade();
        let client = facade.get_crypto_entity_client();
        let mailbox = facade
            .load_user_mailbox()
            .await
            .map_err(|_| Error::RequestFailed)?;
        let folders: Vec<MailSet> = client
            .load_all(&mailbox.mailSets.mailSets, ListLoadDirection::ASC)
            .await
            .map_err(|_| Error::RequestFailed)?;
        let label_ids: HashSet<String> = folders
            .iter()
            .filter(|set| mailbox_ops::is_label(set))
            .filter_map(|set| set._id.as_ref().map(id))
            .collect();
        let mut folder_rows = Vec::new();
        let mut label_rows = Vec::new();
        let mut target: Option<MailSet> = None;
        for folder in folders {
            if !folder._errors.is_empty() {
                return Err(Error::DecryptionFailed);
            }
            let folder_id = Id::from_tuple(folder._id.clone().ok_or(Error::IncompleteResponse)?);
            // Labels are mail sets too, listed apart from the folder tree; a
            // label can still be selected to list its mail.
            if mailbox_ops::is_label(&folder) {
                label_rows.extend(mailbox_ops::label_row(&folder));
            } else if folder.folderType == IMPORTED_FOLDER_TYPE {
                // The set an import files its mail in besides the target
                // folder: the official client keeps it out of the folder tree
                // (`FolderSystem.importedMailSet`), and its mail is listed in
                // the folders it was imported into.
                continue;
            } else {
                folder_rows.push(folder_row(&folder, folder_id.clone()));
            }
            if selected == Some(&folder_id)
                || (selected.is_none() && folder.folderType == INBOX_FOLDER_TYPE)
            {
                target = Some(folder);
            }
        }
        let target = target.ok_or(Error::FolderNotFound)?;
        // Full entry enumeration is authoritative only on success; callers
        // must not prune on errors.
        let entries: Vec<MailSetEntry> = client
            .load_all(&target.entries, ListLoadDirection::DESC)
            .await
            .map_err(|_| Error::RequestFailed)?;
        let mut mails = Vec::new();
        for entry in entries.iter().skip(page.offset).take(page.limit) {
            let mail: Mail = client
                .load(&entry.mail)
                .await
                .map_err(|_| Error::RequestFailed)?;
            mails.push(mail);
        }
        let message_ids = thread::message_ids(&self.sdk, &mails).await;
        let mut messages = Vec::with_capacity(mails.len());
        for mail in &mails {
            messages.push(ListedMail {
                header: MailHeader::of(mail, thread::message_id_of(&message_ids, mail))?,
                labels: mailbox_ops::mail_labels(&mail.sets, &label_ids),
            });
        }
        let folder = Id::from_tuple(target._id.clone().ok_or(Error::IncompleteResponse)?);
        let exists = entries.len();
        let all_ids = (page.offset == 0).then(|| {
            entries
                .iter()
                .map(|entry| Id::from_tuple(entry.mail.clone()))
                .collect()
        });
        Ok(SyncPage {
            folders: folder_rows,
            labels: label_rows,
            messages,
            folder,
            exists,
            all_ids,
            offset: page.offset,
        })
    }

    /// One mail, decrypted: body, original headers, recipients, attachments.
    /// [`Message::to_mime`] puts it back together as an RFC 5322 message.
    pub async fn message(&self, mail_id: &Id) -> Result<Message> {
        let mail: Mail = self
            .sdk
            .mail_facade()
            .get_crypto_entity_client()
            .load(mail_id.tuple())
            .await
            .map_err(|_| Error::RequestFailed)?;
        let message_ids = thread::message_ids(&self.sdk, std::slice::from_ref(&mail)).await;
        let message_id = thread::message_id_of(&message_ids, &mail);
        let extensions = MailExtensions::new(self.sdk.clone());
        let details = if mail.mailDetailsDraft.is_some() {
            extensions.load_mail_details_draft(&mail).await
        } else if mail.mailDetails.is_some() {
            extensions.load_mail_details_blob(&mail).await
        } else {
            return Err(Error::UnsupportedLegacyBody);
        }
        .map_err(|_| Error::DecryptionFailed)?;
        if !details.body._errors.is_empty() {
            return Err(Error::DecryptionFailed);
        }
        let attachments = extensions
            .load_attachments(&mail)
            .await
            .map_err(|_| Error::AttachmentFailed)?;
        if attachments.iter().any(|(file, _)| !file._errors.is_empty()) {
            return Err(Error::AttachmentFailed);
        }
        let header = MailHeader::of(&mail, message_id)?;
        Ok(Message {
            header,
            html: details
                .body
                .compressedText
                .or(details.body.text)
                .ok_or(Error::IncompleteResponse)?,
            headers: details
                .headers
                .and_then(|h| h.compressedHeaders.or(h.headers))
                .unwrap_or_default(),
            to: details
                .recipients
                .toRecipients
                .iter()
                .map(Address::of)
                .collect(),
            cc: details
                .recipients
                .ccRecipients
                .iter()
                .map(Address::of)
                .collect(),
            reply_to: details
                .replyTos
                .iter()
                .map(|a| Address {
                    name: a.name.clone(),
                    address: a.address.clone(),
                })
                .collect(),
            attachments: attachments
                .into_iter()
                .map(|(file, data)| Attachment {
                    name: file.name,
                    mime_type: file.mimeType,
                    cid: file.cid,
                    data,
                })
                .collect(),
        })
    }

    /// Mark up to [`MAIL_BATCH_LIMIT`] mails read or unread.
    pub async fn mark_read(&self, ids: &[Id], is_read: bool) -> Result<Vec<IdOutcome>> {
        if ids.len() > MAIL_BATCH_LIMIT {
            return Err(Error::InvalidBatch);
        }
        let unread = !is_read;
        let tuples: Vec<_> = ids.iter().map(|id| id.tuple().clone()).collect();
        let mut applied = 0;
        for chunk in tuples.chunks(MAIL_BATCH_LIMIT) {
            if self
                .sdk
                .mail_facade()
                .set_unread_status_for_mails(chunk.to_vec(), unread)
                .await
                .is_err()
            {
                return Ok(prefix_outcomes(ids, applied, Some(Error::RequestFailed)));
            }
            applied += chunk.len();
        }
        Ok(prefix_outcomes(ids, applied, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn ids(values: &[&str]) -> Vec<Id> {
        values.iter().map(|v| Id::parse(v).unwrap()).collect()
    }

    #[test]
    fn unknown_folder_types_stay_browsable() {
        assert_eq!(FolderRole::of(1), (FolderRole::Inbox, "Inbox"));
        assert_eq!(FolderRole::of(5), (FolderRole::Junk, "Spam"));
        assert_eq!(FolderRole::of(99), (FolderRole::Other, "Folder"));
        assert_eq!(
            serde_json::to_value(FolderRole::Junk).unwrap(),
            json!("junk")
        );
    }

    #[test]
    fn batch_outcomes_report_the_successful_prefix() {
        let ids = ids(&["a/a", "b/b", "c/c"]);
        let codes = |rows: Vec<IdOutcome>| -> Vec<Value> {
            rows.iter()
                .map(|row| serde_json::to_value(row).unwrap()["code"].clone())
                .collect()
        };
        assert_eq!(
            codes(prefix_outcomes(&ids, 3, None)),
            vec![Value::Null, Value::Null, Value::Null]
        );
        let partial = codes(prefix_outcomes(&ids, 1, Some(Error::RequestFailed)));
        assert!(partial[0].is_null());
        assert_eq!(partial[1], json!("request_failed"));
        assert_eq!(partial[2], json!("not_attempted"));
        assert!(prefix_outcomes(&[], 0, None).is_empty());
        assert_eq!(
            serde_json::to_value(&prefix_outcomes(&ids[..1], 1, None)[0]).unwrap(),
            json!({"id": "a/a", "code": null})
        );
    }

    #[test]
    fn pages_are_bounded() {
        assert_eq!(Page::new(0, 0), Err(Error::InvalidPage));
        assert_eq!(Page::new(MAX_PAGE_LIMIT + 1, 0), Err(Error::InvalidPage));
        assert_eq!(Page::new(1, MAX_PAGE_OFFSET + 1), Err(Error::InvalidPage));
        let page = Page::new(MAX_PAGE_LIMIT, MAX_PAGE_OFFSET).unwrap();
        assert_eq!(
            (page.limit(), page.offset()),
            (MAX_PAGE_LIMIT, MAX_PAGE_OFFSET)
        );
    }

    fn header() -> MailHeader {
        MailHeader {
            id: Id::parse("l/m").unwrap(),
            subject: "s".into(),
            date_ms: 7,
            sender: Address {
                name: "A".into(),
                address: "a@tuta.com".into(),
            },
            recipient: None,
            is_unread: true,
            confidential: false,
            conversation: "c".into(),
            message_id: None,
            has_attachments: false,
            reply_type: 0,
        }
    }

    #[test]
    fn headers_serialize_as_the_protocol_names_them() {
        let listed = ListedMail {
            header: header(),
            labels: ids(&["x/y"]),
        };
        assert_eq!(
            serde_json::to_value(&listed).unwrap(),
            json!({"id": "l/m", "subject": "s", "date_ms": 7,
                "sender": {"name": "A", "address": "a@tuta.com"}, "recipient": null,
                "is_unread": true, "confidential": false, "conversation": "c",
                "message_id": null, "has_attachments": false, "reply_type": 0,
                "labels": ["x/y"]})
        );
        let folder = Folder {
            id: Id::parse("f/1").unwrap(),
            role: FolderRole::Other,
            label: "Folder".into(),
            parent: None,
        };
        assert_eq!(
            serde_json::to_value(&folder).unwrap(),
            json!({"id": "f/1", "role": "other", "label": "Folder", "parent": ""})
        );
        let attachment = Attachment {
            name: "a.txt".into(),
            mime_type: None,
            cid: Some("c1".into()),
            data: b"hi".to_vec(),
        };
        assert_eq!(
            serde_json::to_value(&attachment).unwrap(),
            json!({"name": "a.txt", "mime_type": null, "cid": "c1", "data": "aGk="})
        );
        assert!(!format!("{attachment:?}").contains("hi\""));
    }
}
