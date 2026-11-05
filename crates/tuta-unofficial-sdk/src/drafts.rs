//! Server-side drafts: create or update one (`DraftService` POST/PUT), and
//! discard one. Mirrors TS `MailFacade.createDraft`/`updateDraft` and the
//! official client's discard (into Trash, then deleted from there).
//!
//! An update replaces the draft's recipients, subject, body and its whole
//! attachment set, wherever the draft is filed (a template folder works).
//! Both operations refuse any id that is not a draft, and both treat a
//! draft that is already gone as done.
use crate::{
    diag,
    error::api_code,
    ids::Id,
    send::{
        draft_payload, normalise_mime, trash_and_sent, valid_address, DraftContent,
        OutgoingAttachment, Recipient, MAX_BODY_BYTES,
    },
    thread::Thread,
    Error, Result, Session,
};
use crypto_primitives::{
    aes::{Aes256Key, InitializationVector},
    key::GenericAesKey,
    randomizer_facade::RandomizerFacade,
};
use tutabridge_tuta::mail::MailExtensions;
use tutasdk::{
    blobs::blob_facade::FileData,
    entities::generated::tutanota::{
        DraftAttachment, DraftCreateData, DraftUpdateData, Mail, MoveMailData, NewDraftAttachment,
    },
    rest_error::HttpError,
    services::{
        generated::tutanota::{DraftService, MoveMailService},
        ExtraServiceParams,
    },
    tutanota_constants::ArchiveDataType,
    ApiCallError, GeneratedId, IdTupleGenerated, LoggedInSdk,
};

/// TS `MailState.DRAFT`.
const MAIL_STATE_DRAFT: i64 = 0;

/// A draft to create, or to update when `draft` names one.
#[derive(Debug)]
pub struct DraftRequest {
    /// The draft to update; None creates a new one in Drafts.
    pub draft: Option<Id>,
    pub sender: String,
    pub sender_name: String,
    pub to: Vec<Recipient>,
    pub cc: Vec<Recipient>,
    pub bcc: Vec<Recipient>,
    pub reply_tos: Vec<Recipient>,
    pub subject: String,
    pub body_html: String,
    /// The draft's own end-to-end flag, as the official composer stores it.
    pub confidential: bool,
    /// The draft's complete attachment set: an update replaces the stored
    /// files with these.
    pub attachments: Vec<OutgoingAttachment>,
    /// Its place in a conversation, fixed when the draft is created: an
    /// update has nowhere to put it.
    pub thread: Thread,
}

impl DraftRequest {
    /// The checks [`save`] makes before any I/O. A draft may have no
    /// recipient yet, but every address it does carry must be one
    /// ([`Error::InvalidRecipient`]), and its body is at most 1 MiB
    /// ([`Error::BodyTooLarge`]).
    pub fn check(&self) -> Result<()> {
        let addresses = self
            .to
            .iter()
            .chain(&self.cc)
            .chain(&self.bcc)
            .chain(&self.reply_tos);
        if addresses
            .map(|r| r.address.as_str())
            .any(|a| !valid_address(a))
        {
            return Err(Error::InvalidRecipient);
        }
        if self.body_html.len() > MAX_BODY_BYTES {
            return Err(Error::BodyTooLarge);
        }
        Ok(())
    }
}

/// The sender's mail group: one of the account's own addresses, as in send.
async fn sender_group(sdk: &LoggedInSdk, sender: &str) -> Result<GeneratedId> {
    sdk.mail_facade()
        .get_group_id_for_mail_address(sender)
        .await
        .map_err(|error| {
            diag::failed("sender lookup", &error);
            api_code(error, Error::DraftFailed, Error::SenderUnknown)
        })
}

/// Upload the attachments and describe them for `DraftData.addedAttachments`,
/// each file key wrapped with the mail group key, as TS
/// `_createAddedAttachments` does for new files.
async fn stage_attachments(
    sdk: &LoggedInSdk,
    mail_group: &GeneratedId,
    group_key: &GenericAesKey,
    group_key_version: u64,
    attachments: &[OutgoingAttachment],
) -> Result<Vec<DraftAttachment>> {
    if attachments.is_empty() {
        // No upload at all: the SDK would still fetch a write token.
        return Ok(Vec::new());
    }
    let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
    let keys: Vec<GenericAesKey> = attachments
        .iter()
        .map(|_| GenericAesKey::Aes256(Aes256Key::generate(&randomizer)))
        .collect();
    let file_data: Vec<FileData> = attachments
        .iter()
        .zip(&keys)
        .map(|(attachment, key)| FileData {
            session_key: key.clone(),
            data: &attachment.data,
        })
        .collect();
    let tokens = sdk
        .blob_facade()
        .encrypt_and_upload_multiple(ArchiveDataType::Attachments, mail_group, file_data.iter())
        .await
        .map_err(diag::fail("blob upload", Error::AttachmentFailed))?;
    if tokens.len() != attachments.len() {
        return Err(Error::AttachmentFailed);
    }
    let version = i64::try_from(group_key_version).map_err(|_| Error::DraftFailed)?;
    let mut added = Vec::with_capacity(attachments.len());
    for ((attachment, key), tokens) in attachments.iter().zip(&keys).zip(tokens) {
        let encrypt = |text: &[u8]| {
            key.encrypt_data(text, InitializationVector::generate(&randomizer))
                .map_err(|_| Error::AttachmentFailed)
        };
        let (main, sub) = normalise_mime(&attachment.mime_type);
        added.push(DraftAttachment {
            _id: None,
            ownerEncFileSessionKey: group_key
                .encrypt_key(key, InitializationVector::generate(&randomizer)),
            ownerKeyVersion: version,
            newFile: Some(NewDraftAttachment {
                _id: None,
                encFileName: encrypt(attachment.name.as_bytes())?,
                encMimeType: encrypt(format!("{main}/{sub}").as_bytes())?,
                encCid: attachment
                    .cid
                    .as_ref()
                    .map(|cid| encrypt(cid.as_bytes()))
                    .transpose()?,
                referenceTokens: tokens,
            }),
            existingFile: None,
        });
    }
    Ok(added)
}

/// Load a stored draft, refusing anything that is not one: an id that
/// names a received or sent mail must never be overwritten or discarded.
async fn load_draft(sdk: &LoggedInSdk, draft: &IdTupleGenerated) -> Result<Mail> {
    let mail: Mail = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .load(draft)
        .await
        .map_err(|error| {
            diag::failed("draft load", &error);
            api_code(error, Error::DraftFailed, Error::DraftNotFound)
        })?;
    if !mail._errors.is_empty() {
        return Err(Error::DecryptionFailed);
    }
    if mail.state != MAIL_STATE_DRAFT || mail.mailDetailsDraft.is_none() {
        return Err(Error::NotADraft);
    }
    Ok(mail)
}

/// The draft's group key at the version it was written with and the draft's
/// session key under it, as TS `updateDraft` derives them.
async fn draft_keys(sdk: &LoggedInSdk, mail: &Mail) -> Result<(GenericAesKey, u64, GenericAesKey)> {
    let group = mail._ownerGroup.as_ref().ok_or(Error::IncompleteResponse)?;
    let encrypted = mail
        ._ownerEncSessionKey
        .as_ref()
        .ok_or(Error::IncompleteResponse)?;
    let version = mail._ownerKeyVersion.unwrap_or(0).unsigned_abs();
    let group_key = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .get_crypto_facade()
        .get_key_loader_facade()
        .load_sym_group_key(group, version, None)
        .await
        .map_err(|error| {
            diag::failed("draft group key", &error);
            Error::DraftFailed
        })?;
    let session_key = group_key.decrypt_aes_key(encrypted).map_err(|error| {
        diag::failed("draft session key", &error);
        Error::DecryptionFailed
    })?;
    Ok((group_key, version, session_key))
}

/// Create a draft in Drafts, or update the given one; returns its id.
pub async fn save(session: &Session, request: &DraftRequest) -> Result<Id> {
    request.check()?;
    let sdk = &session.sdk;
    let group = sender_group(sdk, &request.sender).await?;
    let content = DraftContent {
        subject: &request.subject,
        body_html: &request.body_html,
        sender: &request.sender,
        sender_name: &request.sender_name,
        to: &request.to,
        cc: &request.cc,
        bcc: &request.bcc,
        reply_tos: &request.reply_tos,
    };
    let payload = |added: Vec<DraftAttachment>| {
        let mut data = draft_payload(&content, added);
        data.confidential = request.confidential;
        data
    };
    if let Some(draft) = &request.draft {
        let draft = draft.tuple();
        let mail = load_draft(sdk, draft).await?;
        if mail._ownerGroup.as_ref() != Some(&group) {
            // The sender moved to another mailbox: the draft stays where it is.
            return Err(Error::SenderUnknown);
        }
        let (group_key, version, session_key) = draft_keys(sdk, &mail).await?;
        let added =
            stage_attachments(sdk, &group, &group_key, version, &request.attachments).await?;
        let mut data = payload(added);
        // The attachment set is replaced: every stored file goes, the given
        // ones come (TS `_getRemovedAttachments` with only new files).
        data.removedAttachments = mail.attachments.clone();
        data.method = mail.method;
        sdk.get_service_executor()
            .put::<DraftService>(
                DraftUpdateData {
                    _format: 0,
                    draftData: data,
                    draft: draft.clone(),
                    _errors: Default::default(),
                },
                ExtraServiceParams {
                    session_key: Some(session_key),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| {
                diag::failed("draft update (DraftService put)", &error);
                api_code(error, Error::DraftFailed, Error::DraftNotFound)
            })?;
        return Ok(Id::from_tuple(draft.clone()));
    }
    let group_key = sdk
        .get_current_sym_group_key(&group)
        .await
        .map_err(diag::fail("draft group key", Error::DraftFailed))?;
    let added = stage_attachments(
        sdk,
        &group,
        &group_key.object,
        group_key.version,
        &request.attachments,
    )
    .await?;
    let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
    let session_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer));
    let owner_enc =
        group_key.encrypt_key(&session_key, InitializationVector::generate(&randomizer));
    let created = sdk
        .get_service_executor()
        .post::<DraftService>(
            DraftCreateData {
                _format: 0,
                previousMessageId: request.thread.parent.clone(),
                conversationType: request.thread.conversation_type,
                ownerEncSessionKey: owner_enc.object,
                ownerKeyVersion: i64::try_from(owner_enc.version)
                    .map_err(|_| Error::DraftFailed)?,
                draftData: payload(added),
                _errors: Default::default(),
            },
            ExtraServiceParams {
                session_key: Some(session_key),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            diag::failed("draft create (DraftService post)", &error);
            api_code(error, Error::DraftFailed, Error::DraftFailed)
        })?;
    Ok(Id::from_tuple(created.draft))
}

/// Discard a draft the way the official client does: into Trash (never
/// out of Sent), then deleted for good from there. A draft that is already
/// gone counts as discarded.
pub async fn delete(session: &Session, draft_id: &Id) -> Result<()> {
    let sdk = &session.sdk;
    let draft = draft_id.tuple().clone();
    match load_draft(sdk, &draft).await {
        Ok(_) => {}
        Err(Error::DraftNotFound) => return Ok(()),
        Err(code) => return Err(code),
    }
    let (trash, sent) = trash_and_sent(sdk).await.ok_or(Error::DraftFailed)?;
    sdk.get_service_executor()
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
        .map_err(|error| {
            diag::failed("draft discard (move to trash)", &error);
            api_code(error, Error::DraftFailed, Error::DraftFailed)
        })?;
    match MailExtensions::new(sdk.clone())
        .delete_mails(vec![draft], trash)
        .await
    {
        Ok(())
        | Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => Ok(()),
        Err(error) => {
            diag::failed("draft discard (delete from trash)", &error);
            Err(api_code(error, Error::DraftFailed, Error::DraftFailed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> DraftRequest {
        DraftRequest {
            draft: None,
            sender: "me@example.org".into(),
            sender_name: String::new(),
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_tos: Vec::new(),
            subject: String::new(),
            body_html: String::new(),
            confidential: false,
            attachments: Vec::new(),
            thread: Thread::default(),
        }
    }

    #[test]
    fn a_draft_needs_no_recipient_but_valid_addresses() {
        assert_eq!(request().check(), Ok(()));
        let mut bad = request();
        bad.cc.push(Recipient::new("", "nope"));
        assert_eq!(bad.check(), Err(Error::InvalidRecipient));
        let mut bad_reply = request();
        bad_reply.reply_tos.push(Recipient::new("", "a b@c"));
        assert_eq!(bad_reply.check(), Err(Error::InvalidRecipient));
    }

    #[test]
    fn the_body_is_capped() {
        let mut big = request();
        big.body_html = "x".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(big.check(), Err(Error::BodyTooLarge));
        big.body_html.pop();
        assert_eq!(big.check(), Ok(()));
    }
}
