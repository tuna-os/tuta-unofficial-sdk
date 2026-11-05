//! Sending: one draft staged on the server and submitted through
//! `SendDraftService`, ordinarily or confidentially (see `delivery`).
//!
//! What a failed send reports is decided by what its submit did on the wire
//! (see `transport`), never by the SDK's error alone:
//!
//! - [`Error::SendUncertain`] only when the submit left the process and no
//!   definite answer came back (lost in flight, or a 5xx). The mail may have
//!   gone out and must not be resent; its draft is left alone.
//! - [`Error::SendFailed`] (or [`Error::SessionRevoked`] for 401/440,
//!   [`Error::ClientOutdated`] for 474) when the submit never left or the
//!   server refused it with a 4xx; its draft is discarded through Trash.
//! - Success with null ids when the server accepted the submit but its reply
//!   was lost or unreadable.

use crate::{
    contacts::{self, Passwords},
    delivery::{self, Delivered, RecipientReport},
    diag,
    ids::{id, Id},
    thread::{self, Thread},
    transport::{Submit, SubmitRecord},
    Error, Result, Session,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto_primitives::{
    aes::{Aes256Key, InitializationVector},
    key::GenericAesKey,
    randomizer_facade::RandomizerFacade,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tutabridge_tuta::mail::MailExtensions;
use tutasdk::{
    blobs::blob_facade::FileData,
    entities::{
        entity_facade::list_element_id,
        generated::{
            sys::PublicKeyGetIn,
            tutanota::{
                DraftAttachment, DraftCreateData, DraftData, DraftRecipient, EncryptedMailAddress,
                Mail, MailSet, MoveMailData, NewDraftAttachment, SendDraftReturn, TutanotaFile,
            },
        },
        Entity,
    },
    rest_error::HttpError,
    services::{
        generated::{
            sys::PublicKeyService,
            tutanota::{DraftService, MoveMailService, SendDraftService},
        },
        ExtraServiceParams,
    },
    tutanota_constants::{ArchiveDataType, PublicKeyIdentifierType},
    ApiCallError, CustomId, GeneratedId, IdTupleGenerated, ListLoadDirection, LoggedInSdk,
};

// Mirrors TS UNCOMPRESSED_MAX_SIZE: the official client refuses to create or
// update a draft past this body size.
/// The largest HTML body a send or draft takes, as the official client caps it.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
// Folder types, per `FolderRole::of`.
pub(crate) const SENT_FOLDER_TYPE: i64 = 2;
pub(crate) const TRASH_FOLDER_TYPE: i64 = 3;
const METHOD_NONE: i64 = 0;
// The notification language on the send call. Only the server's notification
// mail to a password-protected recipient reads it; an ordinary or all-Tuta
// send delivers as a normal mail.
pub(crate) const SEND_LANGUAGE: &str = "en";

/// A recipient: a display name (may be empty) and an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub name: String,
    pub address: String,
}

impl Recipient {
    pub fn new(name: &str, address: &str) -> Self {
        Recipient {
            name: name.to_string(),
            address: address.to_string(),
        }
    }
}

/// A file to attach.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingAttachment {
    pub name: String,
    pub mime_type: String,
    /// The Content-ID an inline image is referenced by.
    pub cid: Option<String>,
    pub data: Vec<u8>,
}

impl fmt::Debug for OutgoingAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingAttachment")
            .field("name", &self.name)
            .field("mime_type", &self.mime_type)
            .field("cid", &self.cid)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// A mail to send.
#[derive(Debug)]
pub struct SendRequest {
    /// One of the account's own addresses (primary or alias).
    pub sender: String,
    pub sender_name: String,
    pub to: Vec<Recipient>,
    pub cc: Vec<Recipient>,
    pub bcc: Vec<Recipient>,
    pub reply_tos: Vec<Recipient>,
    pub subject: String,
    pub body_html: String,
    /// End-to-end encryption asked for. An all-Tuta send is end-to-end
    /// encrypted either way; with recipients outside Tuta it reaches them
    /// password-protected, and every one of them needs a password.
    pub confidential: bool,
    /// Consent to ordinary delivery (encrypted in transit only) when a
    /// non-confidential send has recipients outside Tuta.
    pub ordinary_confirmed: bool,
    /// Passwords for the recipients outside Tuta of a confidential send.
    pub passwords: Passwords,
    pub attachments: Vec<OutgoingAttachment>,
    /// Its place in a conversation; [`Thread::default`] for new mail.
    pub thread: Thread,
}

/// What a sent mail reports. The ids are None when the server accepted the
/// submit but its reply was lost; the delivery fields are None only when a
/// run overran before the mode was decided, and `contacts_saved` when it
/// overran after the submit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendOutcome {
    /// The new mail's Message-ID.
    pub message_id: Option<String>,
    pub sent_date_ms: Option<u64>,
    /// The sent copy.
    pub sent_mail: Option<Id>,
    pub internal_recipients: Option<usize>,
    pub external_recipients: Option<usize>,
    /// Whether it went out end-to-end encrypted.
    pub confidential: Option<bool>,
    /// For a confidential send, each distinct Tuta recipient's key.
    pub recipients: Option<Vec<RecipientReport>>,
    /// The recipients outside Tuta that got it password-protected.
    pub secure_external: Option<Vec<String>>,
    /// Whether every password-protected recipient's password was kept on
    /// their contact.
    pub contacts_saved: Option<bool>,
    /// For a reply or forward: whether the mail it answers ended up marked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_marked: Option<bool>,
}

impl SendOutcome {
    /// A sent mail's outcome. Without the server's reply (accepted, but the
    /// reply was unreadable or the run overran after it) the ids are None:
    /// the mail went, and nothing a caller does with a send depends on them.
    fn sent(
        reply: Option<&SendDraftReturn>,
        counts: Option<(usize, usize)>,
        delivered: Option<&Delivered>,
    ) -> Self {
        SendOutcome {
            message_id: reply.map(|r| r.messageId.clone()),
            sent_date_ms: reply.map(|r| r.sentDate.as_millis()),
            sent_mail: reply.map(|r| Id::from_tuple(r.sentMail.clone())),
            internal_recipients: counts.map(|(internal, _)| internal),
            external_recipients: counts.map(|(_, external)| external),
            confidential: delivered.map(|d| d.confidential),
            recipients: delivered.map(|d| d.recipients.clone()),
            secure_external: delivered.map(|d| d.secure_external.clone()),
            contacts_saved: None,
            parent_marked: None,
        }
    }
}

/// What a send whose submit did not come back cleanly reports, decided by
/// what the submit request did on the wire (see `transport`), never by the
/// SDK's error alone: the SDK reports a 412 with a precondition reason it
/// does not know, a failed serialization before the request and an
/// unreadable reply after a 200 all as the same `InternalSdkError`.
///
/// Only a request that left the process and got no definite answer is
/// `send_uncertain`: the mail may have gone out, and retrying may deliver it
/// twice. A request that never left, or that the server refused with a 4xx,
/// sent nothing (`send_failed`, or the specific session/version code), so a
/// retry is safe. `Ok` is a submit the server accepted whose reply was lost
/// or unreadable afterwards: the mail went.
pub(crate) fn submit_outcome(submit: Submit) -> Result<()> {
    match submit {
        Submit::NotSent => Err(Error::SendFailed),
        Submit::NoStatus => Err(Error::SendUncertain),
        Submit::Answered(200..=299) => Ok(()),
        Submit::Answered(401 | 440) => Err(Error::SessionRevoked),
        Submit::Answered(474) => Err(Error::ClientOutdated),
        // Every other 4xx (and 47x) is a refusal decided before sending, as
        // is 507: the server checks storage before it accepts the mail.
        Submit::Answered(400..=499 | 507) => Err(Error::SendFailed),
        // 5xx from the server or a gateway, or a status nothing expects:
        // the request may have executed.
        Submit::Answered(_) => Err(Error::SendUncertain),
    }
}

/// What a send that overran its time limit reports. Before its submit left
/// the process nothing can have been delivered, so that is a plain
/// `timeout`; after it, what the submit got back decides.
pub(crate) fn timeout_outcome(
    submit: Submit,
    delivered: Option<&Delivered>,
) -> Result<SendOutcome> {
    if submit == Submit::NotSent {
        return Err(Error::Timeout);
    }
    submit_outcome(submit).map(|()| SendOutcome::sent(None, None, delivered))
}

/// One send's record: its submit on the wire, and the mode it went out in,
/// recorded just before the submit so a run that overruns its time limit
/// after the submit still reports it.
#[derive(Clone)]
struct SendTrace {
    submit: SubmitRecord,
    delivered: Arc<Mutex<Option<Delivered>>>,
}

impl SendTrace {
    fn new() -> Self {
        SendTrace {
            submit: SubmitRecord::new(),
            delivered: Arc::new(Mutex::new(None)),
        }
    }

    fn record(&self, delivered: &Delivered) {
        *self
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(delivered.clone());
    }

    fn delivered(&self) -> Option<Delivered> {
        self.delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl Session {
    /// Send a mail. Dropping the future part-way loses the outcome of a
    /// submit that may already have gone out; to bound a send in time, use
    /// [`Session::send_within`], which keeps the outcome rules.
    pub async fn send(&self, request: SendRequest) -> Result<SendOutcome> {
        let trace = SendTrace::new();
        trace.submit.scope(send(&self.sdk, request, &trace)).await
    }

    /// [`Session::send`] bounded by `limit`. A send that overruns before its
    /// submit left is [`Error::Timeout`] (nothing was sent); after it, the
    /// submit's own outcome decides, as for any failed submit: success with
    /// null ids, [`Error::SendUncertain`] or a definite failure.
    pub async fn send_within(&self, request: SendRequest, limit: Duration) -> Result<SendOutcome> {
        let trace = SendTrace::new();
        let sending = trace.submit.scope(send(&self.sdk, request, &trace));
        match tokio::time::timeout(limit, sending).await {
            Ok(outcome) => outcome,
            Err(_) => timeout_outcome(trace.submit.get(), trace.delivered().as_ref()),
        }
    }
}

/// Whether an address is shaped like one. Deliberately loose -- the server is
/// authoritative and rejects what is truly undeliverable -- so a strict check
/// here can only wrongly refuse mail. Anything without exactly one @, an
/// empty side, or whitespace/control characters is not an address at all.
pub(crate) fn valid_address(address: &str) -> bool {
    let mut parts = address.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && !domain.is_empty()
                && !address.chars().any(|c| c.is_whitespace() || c.is_control())
        }
        _ => false,
    }
}

pub(crate) fn normalise_mime(mime_type: &str) -> (&str, &str) {
    match mime_type.split_once('/') {
        Some((main, sub)) if !main.is_empty() && !sub.is_empty() => (main, sub),
        _ => ("application", "octet-stream"),
    }
}

/// Tuta's own mail domains, from `TUTA_MAIL_ADDRESS_DOMAINS` in the official
/// client (`platform-kit/app-env/TutanotaConstants.ts`). An address on one of
/// these is internal without a lookup, as `RecipientsModel` treats it.
const TUTA_MAIL_ADDRESS_DOMAINS: [&str; 6] = [
    "tuta.com",
    "tutamail.com",
    "tuta.io",
    "tutanota.com",
    "tutanota.de",
    "keemail.me",
];

fn is_tuta_address(address: &str) -> bool {
    address.rsplit_once('@').is_some_and(|(_, domain)| {
        TUTA_MAIL_ADDRESS_DOMAINS
            .iter()
            .any(|tuta| domain.trim().eq_ignore_ascii_case(tuta))
    })
}

/// What a recipient is to Tuta: another Tuta mailbox (internal), a mailbox
/// elsewhere (external), or unknown because the key lookup itself failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecipientKind {
    Internal,
    External,
    Unknown(Error),
}

/// Classify every recipient, as the official client's `RecipientsModel`
/// does: Tuta domains are internal outright, otherwise the public-key
/// service decides (a key means internal, 404 means external).
pub(crate) async fn classify_recipients(
    sdk: &LoggedInSdk,
    addresses: &[String],
) -> Vec<RecipientKind> {
    let mut kinds = Vec::with_capacity(addresses.len());
    for address in addresses {
        if is_tuta_address(address) {
            kinds.push(RecipientKind::Internal);
            continue;
        }
        let lookup = sdk
            .get_service_executor()
            .get::<PublicKeyService>(
                PublicKeyGetIn {
                    _format: 0,
                    identifier: address.clone(),
                    version: None,
                    identifierType: PublicKeyIdentifierType::MailAddress as i64,
                },
                ExtraServiceParams::default(),
            )
            .await;
        kinds.push(match lookup {
            Ok(_) => RecipientKind::Internal,
            Err(ApiCallError::ServerResponseError {
                source: HttpError::NotFoundError,
            }) => RecipientKind::External,
            Err(error) => {
                diag::failed("recipient resolution", &error);
                RecipientKind::Unknown(match error {
                    ApiCallError::RestClient { .. } => Error::TransportFailed,
                    _ => Error::SendFailed,
                })
            }
        });
    }
    kinds
}

/// The account's Trash and Sent folder ids.
pub(crate) async fn trash_and_sent(
    sdk: &LoggedInSdk,
) -> Option<(IdTupleGenerated, IdTupleGenerated)> {
    let mailbox = sdk.mail_facade().load_user_mailbox().await.ok()?;
    let folders: Vec<MailSet> = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .load_all(&mailbox.mailSets.mailSets, ListLoadDirection::ASC)
        .await
        .ok()?;
    let find = |kind: i64| {
        folders
            .iter()
            .find(|folder| folder.folderType == kind)
            .and_then(|folder| folder._id.clone())
    };
    Some((find(TRASH_FOLDER_TYPE)?, find(SENT_FOLDER_TYPE)?))
}

/// Discard a staged draft after a send that definitely did not go out, the
/// way the official client discards one: into Trash, then deleted for good
/// from there. The server refuses a permanent delete anywhere but Trash and
/// Spam (Bad Request from Drafts), so deleting it in place never worked.
/// Best-effort: a leftover draft is clutter, not data loss. Never called
/// after an uncertain submit -- a mail the server may still be sending is
/// left alone -- and the move skips anything already in Sent all the same.
async fn cleanup_draft(sdk: Arc<LoggedInSdk>, draft: &IdTupleGenerated) {
    let Some((trash, sent)) = trash_and_sent(&sdk).await else {
        diag::note("draft cleanup failed: no trash or sent folder");
        return;
    };
    if let Err(error) = sdk
        .get_service_executor()
        .post::<MoveMailService>(
            MoveMailData {
                _format: 0,
                moveReason: None,
                targetFolder: trash.clone(),
                mails: vec![draft.clone()],
                excludeMailSet: Some(sent),
            },
            ExtraServiceParams::default(),
        )
        .await
    {
        diag::failed("draft cleanup (move to trash)", &error);
        return;
    }
    if let Err(error) = MailExtensions::new(sdk)
        .delete_mails(vec![draft.clone()], trash)
        .await
    {
        diag::failed("draft cleanup (delete from trash)", &error);
    }
}

/// A name for an encrypted name field: the given one, else the address.
///
/// The pinned SDK writes an encrypted field holding its default value -- an
/// empty string -- as a bare `""` instead of ciphertext
/// (`encrypt_and_map_inner`), where the official client encrypts every
/// non-null value (`CryptoMapper.encryptValue`). The draft is stored either
/// way, but with an empty sender name, recipient name and bodyText the live
/// server answered `SendDraftService` with 500; with the address in the
/// names and the body in bodyText it answers 201. TutaBridge's live-tested
/// send makes the same two fallbacks.
pub(crate) fn encrypted_name(name: &str, address: &str) -> String {
    if name.is_empty() { address } else { name }.to_string()
}

pub(crate) fn draft_recipients(recipients: &[Recipient]) -> Vec<DraftRecipient> {
    recipients
        .iter()
        .map(|r| DraftRecipient {
            _id: None,
            name: encrypted_name(&r.name, &r.address),
            mailAddress: r.address.clone(),
            _errors: Default::default(),
        })
        .collect()
}

pub(crate) fn reply_addresses(reply_tos: &[Recipient]) -> Vec<EncryptedMailAddress> {
    reply_tos
        .iter()
        .map(|r| EncryptedMailAddress {
            _id: None,
            name: encrypted_name(&r.name, &r.address),
            address: r.address.clone(),
            _errors: Default::default(),
        })
        .collect()
}

/// A draft's content as `DraftService` takes it.
pub(crate) struct DraftContent<'a> {
    pub(crate) subject: &'a str,
    pub(crate) body_html: &'a str,
    pub(crate) sender: &'a str,
    pub(crate) sender_name: &'a str,
    pub(crate) to: &'a [Recipient],
    pub(crate) cc: &'a [Recipient],
    pub(crate) bcc: &'a [Recipient],
    pub(crate) reply_tos: &'a [Recipient],
}

pub(crate) fn draft_payload(
    content: &DraftContent<'_>,
    added_attachments: Vec<DraftAttachment>,
) -> DraftData {
    DraftData {
        _id: None,
        subject: content.subject.to_string(),
        // The official client leaves bodyText empty, which it encrypts; the
        // pinned SDK would send a bare "" instead (see `encrypted_name`), so
        // it carries the body too, as TutaBridge's live-tested send does.
        bodyText: content.body_html.to_string(),
        senderName: encrypted_name(content.sender_name, content.sender),
        senderMailAddress: content.sender.to_string(),
        // `send` sets it for a confidential send (see `delivery::plan`);
        // never flipped silently.
        confidential: false,
        method: METHOD_NONE,
        compressedBodyText: Some(content.body_html.to_string()),
        toRecipients: draft_recipients(content.to),
        ccRecipients: draft_recipients(content.cc),
        bccRecipients: draft_recipients(content.bcc),
        addedAttachments: added_attachments,
        removedAttachments: Vec::new(),
        replyTos: reply_addresses(content.reply_tos),
        _errors: Default::default(),
    }
}

/// A fresh aggregate id: four random bytes, base64url, as the official
/// client's worker and the SDK's own encrypting mapper mint them. The SDK
/// fills missing ones in only while encrypting, and `SendDraftData` is not
/// encrypted: without an id on every aggregate its serializer refuses the
/// request (`Invalid value: ... _id`) before anything is sent.
pub(crate) fn aggregate_id(randomizer: &RandomizerFacade) -> Option<CustomId> {
    Some(CustomId(
        URL_SAFE_NO_PAD.encode(randomizer.generate_random_array::<4>()),
    ))
}

struct StagedAttachment<'a> {
    attachment: &'a OutgoingAttachment,
    session_key: GenericAesKey,
}

async fn send(
    sdk: &Arc<LoggedInSdk>,
    request: SendRequest,
    trace: &SendTrace,
) -> Result<SendOutcome> {
    let SendRequest {
        sender,
        sender_name,
        to,
        cc,
        bcc,
        reply_tos,
        subject,
        body_html,
        confidential,
        ordinary_confirmed,
        passwords,
        attachments,
        thread,
    } = request;
    let addresses: Vec<String> = to
        .iter()
        .chain(cc.iter())
        .chain(bcc.iter())
        .map(|r| r.address.clone())
        .collect();
    if addresses.is_empty()
        || addresses.iter().any(|a| !valid_address(a))
        || reply_tos.iter().any(|r| !valid_address(&r.address))
    {
        return Err(Error::InvalidRecipient);
    }
    if body_html.len() > MAX_BODY_BYTES {
        return Err(Error::BodyTooLarge);
    }
    let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
    let staged: Vec<StagedAttachment> = attachments
        .iter()
        .map(|attachment| StagedAttachment {
            attachment,
            session_key: GenericAesKey::Aes256(Aes256Key::generate(&randomizer)),
        })
        .collect();
    // The sender must be one of the account's own addresses (primary or
    // alias); anything else is refused rather than sent from someone's name.
    let mail_group_id = match sdk
        .mail_facade()
        .get_group_id_for_mail_address(&sender)
        .await
    {
        Ok(group) => group,
        Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => return Err(Error::SenderUnknown),
        Err(error) => {
            diag::failed("sender lookup", &error);
            return Err(match error {
                ApiCallError::RestClient { .. } => Error::TransportFailed,
                _ => Error::SendFailed,
            });
        }
    };
    let mail_group_key = sdk
        .get_current_sym_group_key(&mail_group_id)
        .await
        .map_err(diag::fail("sender group key", Error::SendFailed))?;
    // Decided before any server-side write (blob upload, draft, submit): a
    // send that can go out in neither mode is refused here, and so is a
    // confidential one with an unknown Tuta recipient or a recipient outside
    // Tuta without a password. The recipients' keys are loaded and the
    // bucket key encrypted for them now, for the same reason; only a first
    // password-protected send to an address creates its external user here,
    // as the official client does while sending.
    let unique = delivery::unique_addresses(&addresses);
    let kinds = classify_recipients(sdk, &unique).await;
    let recipients: Vec<(String, RecipientKind)> = unique.into_iter().zip(kinds).collect();
    let plan = delivery::plan(confidential, ordinary_confirmed, &recipients, &passwords)?;
    let (counts, confidential) = match plan {
        delivery::Plan::Ordinary(counts) => (counts, None),
        delivery::Plan::Confidential { internal, external } => {
            let bucket_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer));
            let internal_keys =
                delivery::recipient_keys(sdk, &mail_group_id, &bucket_key, &internal).await?;
            let secure_external = delivery::secure_external_keys(
                sdk,
                &mail_group_id,
                &bucket_key,
                &external,
                &passwords,
            )
            .await?;
            (
                Some((internal.len(), external.len())),
                Some((bucket_key, internal_keys, secure_external, external)),
            )
        }
    };
    let sender_display_name = encrypted_name(&sender_name, &sender);
    let file_data: Vec<FileData> = staged
        .iter()
        .map(|s| FileData {
            session_key: s.session_key.clone(),
            data: &s.attachment.data,
        })
        .collect();
    // No attachments, no upload: the SDK would otherwise still fetch a blob
    // write token and post an upload of nothing (seen live).
    let reference_tokens = if file_data.is_empty() {
        Vec::new()
    } else {
        sdk.blob_facade()
            .encrypt_and_upload_multiple(
                ArchiveDataType::Attachments,
                &mail_group_id,
                file_data.iter(),
            )
            .await
            .map_err(diag::fail("blob upload", Error::AttachmentFailed))?
    };
    if reference_tokens.len() != staged.len() {
        return Err(Error::AttachmentFailed);
    }
    let mut added_attachments = Vec::with_capacity(staged.len());
    for (staged_attachment, tokens) in staged.iter().zip(reference_tokens) {
        let owner_enc = mail_group_key.encrypt_key(
            &staged_attachment.session_key,
            InitializationVector::generate(&randomizer),
        );
        let encrypt_meta = |text: &[u8]| {
            staged_attachment
                .session_key
                .encrypt_data(text, InitializationVector::generate(&randomizer))
        };
        let (main, sub) = normalise_mime(&staged_attachment.attachment.mime_type);
        let enc_cid = staged_attachment
            .attachment
            .cid
            .as_ref()
            .map(|cid| encrypt_meta(cid.as_bytes()))
            .transpose()
            .map_err(|_| Error::AttachmentFailed)?;
        added_attachments.push(DraftAttachment {
            _id: None,
            ownerEncFileSessionKey: owner_enc.object,
            ownerKeyVersion: i64::try_from(owner_enc.version).map_err(|_| Error::SendFailed)?,
            newFile: Some(NewDraftAttachment {
                _id: None,
                encFileName: encrypt_meta(staged_attachment.attachment.name.as_bytes())
                    .map_err(|_| Error::AttachmentFailed)?,
                encMimeType: encrypt_meta(format!("{main}/{sub}").as_bytes())
                    .map_err(|_| Error::AttachmentFailed)?,
                encCid: enc_cid,
                referenceTokens: tokens,
            }),
            existingFile: None,
        });
    }
    let mail_session_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer));
    let owner_enc = mail_group_key.encrypt_key(
        &mail_session_key,
        InitializationVector::generate(&randomizer),
    );
    let mut draft_data = draft_payload(
        &DraftContent {
            subject: &subject,
            body_html: &body_html,
            sender: &sender,
            sender_name: &sender_name,
            to: &to,
            cc: &cc,
            bcc: &bcc,
            reply_tos: &reply_tos,
        },
        added_attachments,
    );
    // The official client marks the draft itself confidential; the server
    // then expects bucket-encrypted keys at submit.
    draft_data.confidential = confidential.is_some();
    let created = sdk
        .get_service_executor()
        .post::<DraftService>(
            DraftCreateData {
                _format: 0,
                previousMessageId: thread.parent.clone(),
                conversationType: thread.conversation_type,
                ownerEncSessionKey: owner_enc.object,
                ownerKeyVersion: i64::try_from(owner_enc.version).map_err(|_| Error::SendFailed)?,
                draftData: draft_data,
                _errors: Default::default(),
            },
            ExtraServiceParams {
                session_key: Some(mail_session_key.clone()),
                ..Default::default()
            },
        )
        .await
        .map_err(diag::fail(
            "draft create (DraftService post)",
            Error::SendFailed,
        ))?;
    let draft = created.draft;
    // From here on every failure attempts to remove the staged draft, so a
    // failed send leaves no orphan behind.
    let mail: Mail = match sdk
        .mail_facade()
        .get_crypto_entity_client()
        .load(&draft)
        .await
    {
        Ok(mail) => mail,
        Err(error) => {
            diag::failed("draft load", &error);
            cleanup_draft(sdk.clone(), &draft).await;
            return Err(Error::SendFailed);
        }
    };
    let files = match file_session_keys(sdk, &mail).await {
        Ok(files) => files,
        Err(()) => {
            diag::note("attachment keys failed");
            cleanup_draft(sdk.clone(), &draft).await;
            return Err(Error::SendFailed);
        }
    };
    let (keys, delivered) = match confidential {
        Some((bucket_key, internal_keys, secure_external, external)) => {
            let delivered = Delivered {
                confidential: true,
                recipients: internal_keys.iter().map(RecipientReport::of).collect(),
                secure_external: external,
            };
            match delivery::confidential_keys(
                &bucket_key,
                &mail_session_key,
                &files,
                delivery::RecipientKeyData {
                    internal: internal_keys.into_iter().map(|key| key.key_data).collect(),
                    secure_external,
                },
                &sender_display_name,
                &randomizer,
            ) {
                Ok(keys) => (keys, delivered),
                Err(code) => {
                    cleanup_draft(sdk.clone(), &draft).await;
                    return Err(code);
                }
            }
        }
        None => (
            delivery::ordinary_keys(&mail_session_key, &files),
            Delivered::default(),
        ),
    };
    trace.record(&delivered);
    let reply = match sdk
        .get_service_executor()
        .post::<SendDraftService>(
            delivery::send_payload(draft.clone(), keys, &randomizer),
            ExtraServiceParams::default(),
        )
        .await
    {
        Ok(reply) => Some(reply),
        Err(error) => {
            let submit = trace.submit.get();
            diag::failed("send draft (SendDraftService post)", &error);
            diag::note(&format!("submit on the wire: {submit:?}"));
            match submit_outcome(submit) {
                Ok(()) => None,
                // The server may still be sending it: leave the draft alone.
                Err(code @ Error::SendUncertain) => return Err(code),
                Err(code) => {
                    cleanup_draft(sdk.clone(), &draft).await;
                    return Err(code);
                }
            }
        }
    };
    // The mail went out; nothing below may fail the send.
    let marked = thread::mark_parent(sdk, &mail, &thread).await;
    // Each password-protected recipient's password stays on their contact,
    // as the official client's `SendMailModel.updateContacts` keeps it.
    let named: Vec<(&str, &str)> = to
        .iter()
        .chain(&cc)
        .chain(&bcc)
        .map(|r| (r.address.as_str(), r.name.as_str()))
        .collect();
    let contacts_saved =
        contacts::save_for_sent(sdk, &delivered.secure_external, &passwords, &named)
            .await
            .is_ok();
    let mut outcome = SendOutcome::sent(reply.as_ref(), counts, Some(&delivered));
    outcome.contacts_saved = Some(contacts_saved);
    if thread.parent.is_some() {
        outcome.parent_marked = Some(marked);
    }
    Ok(outcome)
}

/// Each attachment file's session key, resolved from the server like the
/// official client does -- never by assuming the server lists the files in
/// upload order. A mismatched key would corrupt the attachment.
async fn file_session_keys(
    sdk: &LoggedInSdk,
    mail: &Mail,
) -> std::result::Result<Vec<(IdTupleGenerated, GenericAesKey)>, ()> {
    if mail.attachments.is_empty() {
        return Ok(Vec::new());
    }
    let type_ref = TutanotaFile::type_ref();
    let client = sdk.get_entity_client();
    let model = client
        .resolve_server_type_ref(&type_ref)
        .map_err(|error| diag::failed("attachment keys", &error))?;
    let mut lists: Vec<(GeneratedId, Vec<GeneratedId>)> = Vec::new();
    for file_id in &mail.attachments {
        match lists.iter_mut().find(|(list, _)| *list == file_id.list_id) {
            Some((_, elements)) if elements.contains(&file_id.element_id) => return Err(()),
            Some((_, elements)) => elements.push(file_id.element_id.clone()),
            None => lists.push((file_id.list_id.clone(), vec![file_id.element_id.clone()])),
        }
    }
    let crypto = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .get_crypto_facade()
        .clone();
    let mut keys = HashMap::new();
    for (list, elements) in &lists {
        let loaded = client
            .load_multiple(&type_ref, list, elements)
            .await
            .map_err(|error| diag::failed("attachment keys", &error))?;
        for parsed in loaded {
            let file_id = list_element_id(&model, &parsed).ok_or(())?;
            if file_id.list_id != *list || keys.contains_key(&id(&file_id)) {
                return Err(());
            }
            let resolved = crypto
                .resolve_session_key(&parsed, &model)
                .await
                .map_err(|error| diag::failed("attachment keys", &error))?
                .ok_or(())?;
            keys.insert(id(&file_id), resolved.session_key);
        }
    }
    mail.attachments
        .iter()
        .map(|file_id| keys.remove(&id(file_id)).map(|key| (file_id.clone(), key)))
        .collect::<Option<Vec<_>>>()
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn address_validation_rejects_only_the_shapeless() {
        for address in ["ada@tuta.com", "a+b@x.io", "Ada@Tuta.Com"] {
            assert!(valid_address(address), "{address}");
        }
        for address in [
            "",
            "ada",
            "@tuta.com",
            "ada@",
            "a@b@c",
            "a d@x.io",
            "a@x.io\n",
            "\t@x.io",
        ] {
            assert!(!valid_address(address), "{address:?}");
        }
    }

    #[test]
    fn mime_fallback_matches_the_read_path() {
        assert_eq!(normalise_mime("text/html"), ("text", "html"));
        assert_eq!(normalise_mime("noslash"), ("application", "octet-stream"));
        assert_eq!(normalise_mime("/html"), ("application", "octet-stream"));
        assert_eq!(normalise_mime("text/"), ("application", "octet-stream"));
    }

    #[test]
    fn a_submit_that_never_left_sent_nothing() {
        // A failed serialization or encryption, or a request the HTTP client
        // could not even build: the server never saw it.
        assert_eq!(submit_outcome(Submit::NotSent), Err(Error::SendFailed));
    }

    #[test]
    fn only_a_submit_lost_in_flight_or_failing_server_side_is_uncertain() {
        assert_eq!(submit_outcome(Submit::NoStatus), Err(Error::SendUncertain));
        for status in [500, 502, 503, 504, 0, 302] {
            assert_eq!(
                submit_outcome(Submit::Answered(status)),
                Err(Error::SendUncertain),
                "{status}"
            );
        }
    }

    #[test]
    fn a_refusal_is_definitive_whatever_the_sdk_made_of_it() {
        // 412 is what the SDK turns into an InternalSdkError when it does not
        // know the precondition reason; the status alone decides here.
        for status in [
            400, 403, 404, 405, 408, 412, 413, 423, 429, 470, 471, 472, 473, 475, 507,
        ] {
            assert_eq!(
                submit_outcome(Submit::Answered(status)),
                Err(Error::SendFailed),
                "{status}"
            );
        }
        assert_eq!(
            submit_outcome(Submit::Answered(401)),
            Err(Error::SessionRevoked)
        );
        assert_eq!(
            submit_outcome(Submit::Answered(440)),
            Err(Error::SessionRevoked)
        );
        assert_eq!(
            submit_outcome(Submit::Answered(474)),
            Err(Error::ClientOutdated)
        );
    }

    #[test]
    fn an_accepted_submit_with_an_unreadable_reply_was_sent() {
        assert_eq!(submit_outcome(Submit::Answered(200)), Ok(()));
        assert_eq!(submit_outcome(Submit::Answered(201)), Ok(()));
        let reply = serde_json::to_value(SendOutcome::sent(
            None,
            Some((0, 1)),
            Some(&Delivered::default()),
        ))
        .unwrap();
        assert!(reply["sent_mail"].is_null());
        assert_eq!(reply["external_recipients"], json!(1));
        assert_eq!(reply["confidential"], json!(false));
        assert_eq!(reply["recipients"], json!([]));
        assert!(reply["contacts_saved"].is_null());
        assert!(reply.get("parent_marked").is_none());
        // A run that overran before choosing a mode says so.
        let unknown = serde_json::to_value(SendOutcome::sent(None, None, None)).unwrap();
        assert!(unknown["confidential"].is_null());
        assert!(unknown["recipients"].is_null());
        assert!(unknown["secure_external"].is_null());
    }

    #[test]
    fn only_a_timeout_after_submit_can_be_uncertain() {
        assert_eq!(
            timeout_outcome(Submit::NotSent, None).err(),
            Some(Error::Timeout)
        );
        assert_eq!(
            timeout_outcome(Submit::NoStatus, None).err(),
            Some(Error::SendUncertain)
        );
        assert_eq!(
            timeout_outcome(Submit::Answered(400), None).err(),
            Some(Error::SendFailed)
        );
        let sent = timeout_outcome(Submit::Answered(200), Some(&Delivered::default())).unwrap();
        assert_eq!(sent.confidential, Some(false));
        assert_eq!(sent.message_id, None);
    }

    #[test]
    fn tuta_domains_are_internal_without_a_lookup() {
        for address in [
            "ada@tuta.io",
            "Ada@TUTA.COM",
            "a@tutanota.de",
            "a@keemail.me",
        ] {
            assert!(is_tuta_address(address), "{address}");
        }
        for address in [
            "ada@example.com",
            "ada@nottuta.io",
            "tuta.io",
            "ada@tuta.io.evil",
        ] {
            assert!(!is_tuta_address(address), "{address}");
        }
    }

    fn content<'a>(sender_name: &'a str, to: &'a [Recipient]) -> DraftContent<'a> {
        DraftContent {
            subject: "subject",
            body_html: "<p>body</p>",
            sender: "ada@tuta.com",
            sender_name,
            to,
            cc: &[],
            bcc: &[],
            reply_tos: &[],
        }
    }

    #[test]
    fn draft_payload_never_marks_ordinary_mail_confidential() {
        let to = [Recipient::new("Bo", "bo@example.com")];
        let payload = draft_payload(&content("Ada", &to), Vec::new());
        assert!(!payload.confidential);
        assert_eq!(payload.compressedBodyText.as_deref(), Some("<p>body</p>"));
        assert_eq!(payload.method, METHOD_NONE);
        assert_eq!(payload.toRecipients.len(), 1);
        assert_eq!(payload.senderName, "Ada");
    }

    #[test]
    fn no_encrypted_draft_text_is_left_empty() {
        // The pinned SDK sends an empty encrypted string as a bare "", which
        // the send service fails on: names fall back to the address and the
        // body rides in bodyText as well.
        let unnamed = [Recipient::new("", "bo@example.com")];
        let payload = draft_payload(&content("", &unnamed), Vec::new());
        assert_eq!(payload.senderName, "ada@tuta.com");
        assert_eq!(payload.toRecipients[0].name, "bo@example.com");
        assert_eq!(payload.bodyText, "<p>body</p>");
        assert_eq!(encrypted_name("Bo", "bo@example.com"), "Bo");
        let replies = reply_addresses(&[Recipient::new("", "r@x.io")]);
        assert_eq!(replies[0].name, "r@x.io");
    }

    #[test]
    fn attachment_metadata_round_trips_through_the_sdk_cipher() {
        // Offline proof that what the send path encrypts, the SDK's own
        // decrypt path reads back: same functions the official client's
        // format depends on.
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer));
        for text in ["résumé.pdf", "text/html", "part1"] {
            let encrypted = key
                .encrypt_data(text.as_bytes(), InitializationVector::generate(&randomizer))
                .unwrap();
            assert_eq!(key.decrypt_data(&encrypted).unwrap(), text.as_bytes());
        }
        let wrapped = key.encrypt_key(&key, InitializationVector::generate(&randomizer));
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn attachments_never_show_their_bytes_in_debug_output() {
        let attachment = OutgoingAttachment {
            name: "a".into(),
            mime_type: "text/plain".into(),
            cid: None,
            data: b"secret body".to_vec(),
        };
        assert!(!format!("{attachment:?}").contains("secret"));
    }
}
