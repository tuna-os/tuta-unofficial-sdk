//! Folder, label, move and permanent-delete operations, each mirroring the
//! official client's `MailFacade`/`MailModel` (tutanota
//! `src/applications/common/api/worker/facades/lazy/MailFacade.ts` and
//! `src/applications/mail-app/mail/model/MailModel.ts`).
//!
//! Folders and labels are both `MailSet`s: a label is one of folder type 8.
//! Their names are encrypted with a fresh session key that is itself wrapped
//! with the mail group key, exactly as the official client creates them; the
//! SDK's service executor does the encryption (`ExtraServiceParams.session_key`).
use crate::{
    diag,
    error::api_code,
    ids::{id, Id},
    mail::{IdOutcome, Label, Outcome},
    send::TRASH_FOLDER_TYPE,
    Error, Result, Session, MAIL_BATCH_LIMIT,
};
use crypto_primitives::{
    aes::{Aes256Key, InitializationVector},
    key::GenericAesKey,
    randomizer_facade::RandomizerFacade,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use tutasdk::{
    entities::generated::tutanota::{
        ApplyLabelServicePostIn, CreateMailFolderData, DeleteMailData, DeleteMailFolderData,
        MailSet, MailSetEntry, ManageLabelServiceDeleteIn, ManageLabelServiceLabelData,
        ManageLabelServicePostIn, ManageLabelServicePutIn, MoveMailData, UpdateMailFolderData,
    },
    rest_error::HttpError,
    services::{
        generated::tutanota::{
            ApplyLabelService, MailFolderService, MailService, ManageLabelService, MoveMailService,
        },
        ExtraServiceParams,
    },
    ApiCallError, GeneratedId, IdTupleGenerated, ListLoadDirection, LoggedInSdk,
};

// TS `MailSetKind`.
pub(crate) const CUSTOM_FOLDER_TYPE: i64 = 0;
pub(crate) const SPAM_FOLDER_TYPE: i64 = 5;
pub(crate) const LABEL_FOLDER_TYPE: i64 = 8;
pub(crate) const IMPORTED_FOLDER_TYPE: i64 = 9;
/// TS `MAX_LABELS_PER_MAIL`: the official client never applies more.
pub const MAX_LABELS_PER_MAIL: usize = 5;
/// Longest folder or label name accepted, in characters. The official client
/// sets no explicit limit; this only keeps a pathological request off the
/// wire.
pub const MAX_NAME_CHARS: usize = 256;
/// A folder tree deeper than this is malformed; parent walks stop here.
const MAX_FOLDER_DEPTH: usize = 64;

/// `api_code` plus a diagnostic line naming the stage.
fn fail(
    stage: &'static str,
    fallback: Error,
    not_found: Error,
) -> impl FnOnce(ApiCallError) -> Error {
    move |error| {
        diag::failed(stage, &error);
        api_code(error, fallback, not_found)
    }
}

/// The user's mailbox: its mail group and every mail set (folders and
/// labels), loaded as the official client's `MailboxModel` does.
pub(crate) struct Mailbox {
    pub group: GeneratedId,
    pub sets: Vec<MailSet>,
}

pub(crate) async fn load_mailbox(sdk: &LoggedInSdk) -> Result<Mailbox> {
    let facade = sdk.mail_facade();
    let mailbox = facade.load_user_mailbox().await.map_err(fail(
        "mailbox load",
        Error::RequestFailed,
        Error::RequestFailed,
    ))?;
    let sets: Vec<MailSet> = facade
        .get_crypto_entity_client()
        .load_all(&mailbox.mailSets.mailSets, ListLoadDirection::ASC)
        .await
        .map_err(fail(
            "mail set load",
            Error::RequestFailed,
            Error::RequestFailed,
        ))?;
    if sets.iter().any(|set| !set._errors.is_empty()) {
        return Err(Error::DecryptionFailed);
    }
    let group = mailbox._ownerGroup.ok_or(Error::IncompleteResponse)?;
    Ok(Mailbox { group, sets })
}

fn same(set: &MailSet, wanted: &IdTupleGenerated) -> bool {
    set._id.as_ref() == Some(wanted)
}

fn find<'a>(sets: &'a [MailSet], wanted: &IdTupleGenerated) -> Option<&'a MailSet> {
    sets.iter().find(|set| same(set, wanted))
}

/// Whether `folder` is Trash, Spam or one of their descendants: the only
/// places the server deletes mail permanently. TS `isSpamOrTrashFolder`.
pub(crate) fn in_trash_or_spam(sets: &[MailSet], folder: &IdTupleGenerated) -> bool {
    let mut current = find(sets, folder);
    for _ in 0..MAX_FOLDER_DEPTH {
        let Some(set) = current else { return false };
        if set.folderType == TRASH_FOLDER_TYPE || set.folderType == SPAM_FOLDER_TYPE {
            return true;
        }
        current = set.parentFolder.as_ref().and_then(|p| find(sets, p));
    }
    false
}

/// The descendants of `folder`, deepest first. TS
/// `FolderSystem.getDescendantFoldersOfParent` sorted as `removeAllEmpty` does.
fn descendants_deepest_first<'a>(
    sets: &'a [MailSet],
    folder: &IdTupleGenerated,
) -> Vec<&'a MailSet> {
    let mut levels: Vec<(usize, &MailSet)> = Vec::new();
    let mut frontier = vec![folder.clone()];
    for level in 1..=MAX_FOLDER_DEPTH {
        let children: Vec<&MailSet> = sets
            .iter()
            .filter(|set| set.folderType != LABEL_FOLDER_TYPE)
            .filter(|set| {
                set.parentFolder
                    .as_ref()
                    .is_some_and(|parent| frontier.contains(parent))
            })
            .collect();
        if children.is_empty() {
            break;
        }
        frontier = children.iter().filter_map(|c| c._id.clone()).collect();
        levels.extend(children.into_iter().map(|c| (level, c)));
    }
    levels.sort_by_key(|(level, _)| std::cmp::Reverse(*level));
    levels.into_iter().map(|(_, set)| set).collect()
}

/// A folder or label name: trimmed, non-empty, at most [`MAX_NAME_CHARS`]
/// characters, no control characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(String);

impl Name {
    /// The trimmed name; anything else is [`Error::InvalidName`].
    pub fn new(name: &str) -> Result<Self> {
        let trimmed = name.trim();
        if trimmed.is_empty()
            || trimmed.chars().count() > MAX_NAME_CHARS
            || trimmed.chars().any(char::is_control)
        {
            return Err(Error::InvalidName);
        }
        Ok(Name(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A label colour as the official client stores it: `#rrggbb`, lower case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Color(String);

impl Color {
    /// `#rrggbb` in any case; anything else is [`Error::InvalidColor`].
    pub fn new(color: &str) -> Result<Self> {
        let hex = color.strip_prefix('#').ok_or(Error::InvalidColor)?;
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidColor);
        }
        Ok(Color(color.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a sibling of `parent` already carries `name`. The official
/// client's folder dialog refuses such a name (`checkFolderName`).
fn name_taken(
    sets: &[MailSet],
    parent: Option<&IdTupleGenerated>,
    name: &str,
    except: Option<&IdTupleGenerated>,
) -> bool {
    sets.iter().any(|set| {
        set.folderType != LABEL_FOLDER_TYPE
            && set.parentFolder.as_ref() == parent
            && set._id.as_ref() != except
            && set.name.trim().eq_ignore_ascii_case(name)
    })
}

/// A fresh session key and its encryption with the mail group's current
/// key, as TS `aes256RandomKey` + `encryptKeyWithVersionedKey`.
async fn new_owned_session_key(
    sdk: &LoggedInSdk,
    group: &GeneratedId,
    fallback: Error,
) -> Result<(GenericAesKey, Vec<u8>, i64)> {
    let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
    let group_key = sdk.get_current_sym_group_key(group).await.map_err(fail(
        "mail group key",
        fallback,
        fallback,
    ))?;
    let session_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer));
    let owner_enc =
        group_key.encrypt_key(&session_key, InitializationVector::generate(&randomizer));
    let version = i64::try_from(owner_enc.version).map_err(|_| fallback)?;
    Ok((session_key, owner_enc.object, version))
}

/// A random key for a service payload whose model is marked encrypted but
/// carries no encrypted value. TS passes `sessionKey: "dummy"` for the same
/// reason (`deleteFolder`); nothing is encrypted with it.
fn throwaway_key() -> GenericAesKey {
    GenericAesKey::Aes256(Aes256Key::generate(&RandomizerFacade::from_core(
        rand_core::OsRng,
    )))
}

// ---------------------------------------------------------------- listings

pub(crate) fn is_label(set: &MailSet) -> bool {
    set.folderType == LABEL_FOLDER_TYPE
}

pub(crate) fn label_row(set: &MailSet) -> Option<Label> {
    Some(Label {
        id: Id::from_tuple(set._id.clone()?),
        name: set.name.clone(),
        color: set.color.clone().unwrap_or_default(),
    })
}

/// The labels a mail carries: its `sets` that are labels.
pub(crate) fn mail_labels(sets: &[IdTupleGenerated], label_ids: &HashSet<String>) -> Vec<Id> {
    sets.iter()
        .filter(|set| label_ids.contains(&id(set)))
        .map(|set| Id::from_tuple(set.clone()))
        .collect()
}

// ----------------------------------------------------------------- folders

/// A rename and/or re-parent of a custom folder, checked before any I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderEdit {
    folder: Id,
    name: Option<Name>,
    /// None keeps the parent; `Some(None)` moves it to the top level.
    parent: Option<Option<Id>>,
}

impl FolderEdit {
    /// At least one change ([`Error::InvalidRequest`] otherwise), and never
    /// the folder as its own parent ([`Error::InvalidParent`]).
    pub fn new(folder: Id, name: Option<Name>, parent: Option<Option<Id>>) -> Result<Self> {
        if name.is_none() && parent.is_none() {
            return Err(Error::InvalidRequest);
        }
        if parent.as_ref().is_some_and(|p| p.as_ref() == Some(&folder)) {
            return Err(Error::InvalidParent);
        }
        Ok(FolderEdit {
            folder,
            name,
            parent,
        })
    }
}

/// What `delete_folder` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderDeletion {
    /// Deleted for good, with its mail (inside Trash or Spam), or because it
    /// and every folder in it were empty.
    Deleted,
    /// Moved under Trash with its mail.
    Trashed,
}

/// What to change on a label, checked before any I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelEdit {
    name: Option<Name>,
    color: Option<Color>,
}

impl LabelEdit {
    /// At least one of the two ([`Error::InvalidRequest`] otherwise).
    pub fn new(name: Option<Name>, color: Option<Color>) -> Result<Self> {
        if name.is_none() && color.is_none() {
            return Err(Error::InvalidRequest);
        }
        Ok(LabelEdit { name, color })
    }
}

/// Labels to add to and remove from mail, checked before any I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelChanges {
    add: Vec<IdTupleGenerated>,
    remove: Vec<IdTupleGenerated>,
}

impl LabelChanges {
    /// Something to do, no label both added and removed, and at most
    /// [`MAX_LABELS_PER_MAIL`] added; [`Error::InvalidRequest`] otherwise.
    pub fn new(add: Vec<Id>, remove: Vec<Id>) -> Result<Self> {
        let add: Vec<IdTupleGenerated> = add.into_iter().map(Id::into_tuple).collect();
        let remove: Vec<IdTupleGenerated> = remove.into_iter().map(Id::into_tuple).collect();
        if (add.is_empty() && remove.is_empty())
            || add.len() > MAX_LABELS_PER_MAIL
            || add.iter().any(|label| remove.contains(label))
        {
            return Err(Error::InvalidRequest);
        }
        Ok(LabelChanges { add, remove })
    }
}

/// One moved id's outcome: `new_id` and `source` come from the server's own
/// report of what it moved. A Tuta mail keeps its id when it moves, so
/// `new_id` equals `id`, and `source` is the folder it left -- what the
/// official client moves back to undo. Both are None for a mail the server
/// did not move (it was already in the destination).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MoveOutcome {
    pub id: Id,
    pub code: Outcome,
    pub new_id: Option<Id>,
    pub source: Option<Id>,
}

/// Whether a folder holds no mail. TS `isEmptyFolder`: one entry is enough.
async fn is_empty_folder(sdk: &LoggedInSdk, folder: &MailSet) -> Result<bool> {
    let entries: Vec<MailSetEntry> = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .load_range(
            &folder.entries,
            // TS `CUSTOM_MIN_ID`. Entry ids are base64url, where the
            // generated-id minimum "------------" sorts high and would find
            // nothing in a folder that holds mail.
            &tutasdk::CustomId(String::new()),
            1,
            ListLoadDirection::ASC,
        )
        .await
        .map_err(fail(
            "folder entries",
            Error::RequestFailed,
            Error::FolderNotFound,
        ))?;
    Ok(entries.is_empty())
}

/// TS `finallyDeleteCustomMailFolder`: `MailFolderService` DELETE. A folder
/// that is already gone counts as deleted; 412 means the server is still
/// working on it.
async fn finally_delete_folder(sdk: &LoggedInSdk, folder: &IdTupleGenerated) -> Result<()> {
    match sdk
        .get_service_executor()
        .delete::<MailFolderService>(
            DeleteMailFolderData {
                _format: 0,
                folders: vec![folder.clone()],
                _errors: Default::default(),
            },
            ExtraServiceParams {
                session_key: Some(throwaway_key()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => Ok(()),
        Err(ApiCallError::ServerResponseError {
            source: HttpError::PreconditionFailedError(_),
        }) => Err(Error::OperationStillActive),
        Err(error) => Err(fail(
            "folder delete",
            Error::FolderFailed,
            Error::FolderNotFound,
        )(error)),
    }
}

/// The session key a stored mail set was encrypted with, as TS
/// `updateLabel` derives it: its owner group key, then `_ownerEncSessionKey`.
async fn mail_set_session_key(sdk: &LoggedInSdk, set: &MailSet) -> Result<GenericAesKey> {
    let group = set._ownerGroup.as_ref().ok_or(Error::IncompleteResponse)?;
    let encrypted = set
        ._ownerEncSessionKey
        .as_ref()
        .ok_or(Error::IncompleteResponse)?;
    let version = set._ownerKeyVersion.unwrap_or(0).unsigned_abs();
    let group_key = sdk
        .mail_facade()
        .get_crypto_entity_client()
        .get_crypto_facade()
        .get_key_loader_facade()
        .load_sym_group_key(group, version, None)
        .await
        .map_err(|error| {
            diag::failed("label key", &error);
            Error::LabelFailed
        })?;
    group_key.decrypt_aes_key(encrypted).map_err(|error| {
        diag::failed("label key", &error);
        Error::DecryptionFailed
    })
}

// ------------------------------------------------------- per-mail batches

/// Unique ids grouped by mail list (the server locks per list), first-seen
/// order, at most `MAIL_BATCH_LIMIT` per group. TS `groupBy(listIdPart)` +
/// `splitInChunks`.
fn list_chunks(mails: &[IdTupleGenerated]) -> Vec<Vec<IdTupleGenerated>> {
    let mut groups: Vec<Vec<IdTupleGenerated>> = Vec::new();
    let mut by_list: HashMap<String, usize> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    for mail in mails {
        if !seen.insert(id(mail)) {
            continue;
        }
        let index = *by_list.entry(mail.list_id.to_string()).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[index].push(mail.clone());
    }
    groups
        .into_iter()
        .flat_map(|group| {
            group
                .chunks(MAIL_BATCH_LIMIT)
                .map(<[IdTupleGenerated]>::to_vec)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Per-id outcome of a batch. Duplicated ids share their outcome.
struct Batch {
    outcomes: HashMap<String, Outcome>,
}

impl Batch {
    fn new(mails: &[IdTupleGenerated]) -> Self {
        Self {
            outcomes: mails
                .iter()
                .map(|m| (id(m), Outcome::NotAttempted))
                .collect(),
        }
    }
    fn settle(&mut self, chunk: &[IdTupleGenerated], outcome: Outcome) {
        for mail in chunk {
            self.outcomes.insert(id(mail), outcome);
        }
    }
    fn outcome(&self, mail: &Id) -> Outcome {
        self.outcomes
            .get(&mail.to_string())
            .copied()
            .unwrap_or(Outcome::NotAttempted)
    }
    fn rows(&self, ids: &[Id]) -> Vec<IdOutcome> {
        ids.iter()
            .map(|mail| IdOutcome {
                id: mail.clone(),
                code: self.outcome(mail),
            })
            .collect()
    }
}

/// A batch of 1 to `MAIL_BATCH_LIMIT` mails.
fn check_batch(ids: &[Id]) -> Result<Vec<IdTupleGenerated>> {
    if ids.is_empty() || ids.len() > MAIL_BATCH_LIMIT {
        return Err(Error::InvalidBatch);
    }
    Ok(ids.iter().map(|mail| mail.tuple().clone()).collect())
}

impl Session {
    /// Create a folder, under `parent` (a folder, never a label) or at the
    /// top level. TS `MailFacade.createMailFolder`: `MailFolderService` POST.
    pub async fn create_folder(&self, name: &Name, parent: Option<&Id>) -> Result<Id> {
        let sdk = &*self.sdk;
        let parent = parent.map(|parent| parent.tuple().clone());
        let mailbox = load_mailbox(sdk).await?;
        if let Some(parent) = &parent {
            // Folders nest under folders, never under labels.
            match find(&mailbox.sets, parent) {
                Some(set) if !is_label(set) => {}
                _ => return Err(Error::FolderNotFound),
            }
        }
        if name_taken(&mailbox.sets, parent.as_ref(), name.as_str(), None) {
            return Err(Error::FolderExists);
        }
        let (session_key, owner_enc, version) =
            new_owned_session_key(sdk, &mailbox.group, Error::FolderFailed).await?;
        let created = sdk
            .get_service_executor()
            .post::<MailFolderService>(
                CreateMailFolderData {
                    _format: 0,
                    folderName: name.as_str().to_string(),
                    ownerEncSessionKey: owner_enc,
                    ownerGroup: Some(mailbox.group),
                    ownerKeyVersion: version,
                    parentFolder: parent,
                    _errors: Default::default(),
                },
                ExtraServiceParams {
                    session_key: Some(session_key),
                    ..Default::default()
                },
            )
            .await
            .map_err(fail(
                "folder create",
                Error::FolderFailed,
                Error::FolderNotFound,
            ))?;
        Ok(Id::from_tuple(created.newFolder))
    }

    /// Rename and/or re-parent a custom folder: the name through an update
    /// of the `MailSet` itself (TS `updateMailFolderName`,
    /// `entityClient.update`), the parent through `MailFolderService` PUT
    /// (TS `updateMailFolderParent`).
    pub async fn rename_folder(&self, edit: &FolderEdit) -> Result<()> {
        let sdk = &*self.sdk;
        let target = edit.folder.tuple();
        let mailbox = load_mailbox(sdk).await?;
        let folder = find(&mailbox.sets, target).ok_or(Error::FolderNotFound)?;
        if folder.folderType != CUSTOM_FOLDER_TYPE {
            return Err(Error::NotCustomFolder);
        }
        let new_parent = match &edit.parent {
            Some(Some(parent)) => {
                let parent = parent.tuple();
                match find(&mailbox.sets, parent) {
                    Some(set) if !is_label(set) => {}
                    _ => return Err(Error::FolderNotFound),
                }
                // A folder cannot move under its own subtree.
                if descendants_deepest_first(&mailbox.sets, target)
                    .iter()
                    .any(|d| same(d, parent))
                {
                    return Err(Error::InvalidParent);
                }
                Some(Some(parent.clone()))
            }
            Some(None) => Some(None),
            None => None,
        };
        let target_parent = match &new_parent {
            Some(parent) => parent.clone(),
            None => folder.parentFolder.clone(),
        };
        let target_name = edit
            .name
            .as_ref()
            .map_or_else(|| folder.name.clone(), |name| name.as_str().to_string());
        if name_taken(
            &mailbox.sets,
            target_parent.as_ref(),
            &target_name,
            Some(target),
        ) {
            return Err(Error::FolderExists);
        }
        if let Some(name) = edit
            .name
            .as_ref()
            .filter(|name| name.as_str() != folder.name)
        {
            let mut renamed = folder.clone();
            renamed.name = name.as_str().to_string();
            sdk.mail_facade()
                .get_crypto_entity_client()
                .update_instance(renamed)
                .await
                .map_err(fail(
                    "folder rename",
                    Error::FolderFailed,
                    Error::FolderNotFound,
                ))?;
        }
        if let Some(parent) = new_parent.filter(|p| *p != folder.parentFolder) {
            sdk.get_service_executor()
                .put::<MailFolderService>(
                    UpdateMailFolderData {
                        _format: 0,
                        folder: target.clone(),
                        newParent: parent,
                    },
                    ExtraServiceParams::default(),
                )
                .await
                .map_err(fail(
                    "folder re-parent",
                    Error::FolderFailed,
                    Error::FolderNotFound,
                ))?;
        }
        Ok(())
    }

    /// Delete a custom folder the way the official client's sidebar does
    /// (`MailView.deleteCustomMailFolder`): inside Trash or Spam it is
    /// deleted for good; elsewhere empty descendants -- and the folder
    /// itself, when it and all of them are empty -- are deleted, and a folder
    /// that still holds mail is moved under Trash instead
    /// (`MailModel.trashFolderAndSubfolders`).
    pub async fn delete_folder(&self, folder_id: &Id) -> Result<FolderDeletion> {
        let sdk = &*self.sdk;
        let target = folder_id.tuple().clone();
        let mailbox = load_mailbox(sdk).await?;
        let folder = find(&mailbox.sets, &target).ok_or(Error::FolderNotFound)?;
        if folder.folderType != CUSTOM_FOLDER_TYPE && folder.folderType != IMPORTED_FOLDER_TYPE {
            return Err(Error::NotCustomFolder);
        }
        if in_trash_or_spam(&mailbox.sets, &target) {
            finally_delete_folder(sdk, &target).await?;
            return Ok(FolderDeletion::Deleted);
        }
        // TS `removeAllEmpty`.
        let mut deleted: HashSet<String> = HashSet::new();
        let mut some_non_empty = false;
        let children_deleted = |parent: &IdTupleGenerated, deleted: &HashSet<String>| {
            mailbox
                .sets
                .iter()
                .filter(|set| set.folderType == CUSTOM_FOLDER_TYPE)
                .filter(|set| set.parentFolder.as_ref() == Some(parent))
                .all(|set| set._id.as_ref().is_some_and(|i| deleted.contains(&id(i))))
        };
        for descendant in descendants_deepest_first(&mailbox.sets, &target) {
            let Some(descendant_id) = descendant._id.as_ref() else {
                continue;
            };
            if is_empty_folder(sdk, descendant).await? && children_deleted(descendant_id, &deleted)
            {
                finally_delete_folder(sdk, descendant_id).await?;
                deleted.insert(id(descendant_id));
            } else {
                some_non_empty = true;
            }
        }
        if !some_non_empty
            && is_empty_folder(sdk, folder).await?
            && children_deleted(&target, &deleted)
        {
            finally_delete_folder(sdk, &target).await?;
            return Ok(FolderDeletion::Deleted);
        }
        let trash = mailbox
            .sets
            .iter()
            .find(|set| set.folderType == TRASH_FOLDER_TYPE)
            .and_then(|set| set._id.clone())
            .ok_or(Error::FolderNotFound)?;
        sdk.get_service_executor()
            .put::<MailFolderService>(
                UpdateMailFolderData {
                    _format: 0,
                    folder: target,
                    newParent: Some(trash),
                },
                ExtraServiceParams::default(),
            )
            .await
            .map_err(fail(
                "folder to trash",
                Error::FolderFailed,
                Error::FolderNotFound,
            ))?;
        Ok(FolderDeletion::Trashed)
    }

    /// Create a label. TS `MailFacade.createLabel`: `ManageLabelService` POST.
    pub async fn create_label(&self, name: &Name, color: &Color) -> Result<Id> {
        let sdk = &*self.sdk;
        let mailbox = load_mailbox(sdk).await?;
        if mailbox
            .sets
            .iter()
            .any(|set| is_label(set) && set.name.trim().eq_ignore_ascii_case(name.as_str()))
        {
            return Err(Error::LabelExists);
        }
        let (session_key, owner_enc, version) =
            new_owned_session_key(sdk, &mailbox.group, Error::LabelFailed).await?;
        let created = sdk
            .get_service_executor()
            .post::<ManageLabelService>(
                ManageLabelServicePostIn {
                    _format: 0,
                    ownerEncSessionKey: owner_enc,
                    ownerKeyVersion: version,
                    ownerGroup: mailbox.group,
                    data: ManageLabelServiceLabelData {
                        _id: None,
                        name: name.as_str().to_string(),
                        color: color.as_str().to_string(),
                        parentLabel: None,
                        _errors: Default::default(),
                    },
                    _errors: Default::default(),
                },
                ExtraServiceParams {
                    session_key: Some(session_key),
                    ..Default::default()
                },
            )
            .await
            .map_err(fail("label create", Error::LabelFailed, Error::LabelFailed))?;
        Ok(Id::from_tuple(created.label))
    }

    /// Rename and/or recolour a label. TS `MailFacade.updateLabel`:
    /// `ManageLabelService` PUT.
    pub async fn update_label(&self, label_id: &Id, edit: &LabelEdit) -> Result<()> {
        let sdk = &*self.sdk;
        let target = label_id.tuple().clone();
        let mailbox = load_mailbox(sdk).await?;
        let label = find(&mailbox.sets, &target)
            .filter(|set| is_label(set))
            .ok_or(Error::LabelNotFound)?;
        let name = edit
            .name
            .as_ref()
            .map_or_else(|| label.name.clone(), |name| name.as_str().to_string());
        let color = edit.color.as_ref().map_or_else(
            || label.color.clone().unwrap_or_default(),
            |color| color.as_str().to_string(),
        );
        if name == label.name && Some(&color) == label.color.as_ref() {
            return Ok(());
        }
        let session_key = mail_set_session_key(sdk, label).await?;
        sdk.get_service_executor()
            .put::<ManageLabelService>(
                ManageLabelServicePutIn {
                    _format: 0,
                    label: target,
                    data: ManageLabelServiceLabelData {
                        _id: None,
                        name,
                        color,
                        parentLabel: label.parentFolder.clone(),
                        _errors: Default::default(),
                    },
                    _errors: Default::default(),
                },
                ExtraServiceParams {
                    session_key: Some(session_key),
                    ..Default::default()
                },
            )
            .await
            .map_err(fail(
                "label update",
                Error::LabelFailed,
                Error::LabelNotFound,
            ))?;
        Ok(())
    }

    /// Delete a label. TS `MailFacade.deleteLabel`: `ManageLabelService`
    /// DELETE. A label that is already gone counts as deleted.
    pub async fn delete_label(&self, label_id: &Id) -> Result<()> {
        let sdk = &*self.sdk;
        let target = label_id.tuple().clone();
        let mailbox = load_mailbox(sdk).await?;
        match find(&mailbox.sets, &target) {
            None => return Ok(()),
            Some(set) if !is_label(set) => return Err(Error::LabelNotFound),
            Some(_) => {}
        }
        match sdk
            .get_service_executor()
            .delete::<ManageLabelService>(
                ManageLabelServiceDeleteIn {
                    _format: 0,
                    label: target,
                },
                ExtraServiceParams::default(),
            )
            .await
        {
            Ok(())
            | Err(ApiCallError::ServerResponseError {
                source: HttpError::NotFoundError,
            }) => Ok(()),
            Err(error) => Err(fail(
                "label delete",
                Error::LabelFailed,
                Error::LabelNotFound,
            )(error)),
        }
    }

    /// Move up to [`MAIL_BATCH_LIMIT`] mails, recording what the server
    /// reports it moved: Tuta mails keep their id across moves, and
    /// `MoveMailPostOut.movedMails` names each moved id with its source
    /// folder -- what the official client's undo moves back
    /// (`MailGuiUtils.runPostMoveActions`).
    pub async fn move_mail(&self, ids: &[Id], destination: &Id) -> Result<Vec<MoveOutcome>> {
        let parsed = check_batch(ids)?;
        let mut batch = Batch::new(&parsed);
        let mut moved: HashMap<String, Id> = HashMap::new();
        for chunk in list_chunks(&parsed) {
            let reply = self
                .sdk
                .get_service_executor()
                .post::<MoveMailService>(
                    MoveMailData {
                        _format: 0,
                        moveReason: None,
                        targetFolder: destination.tuple().clone(),
                        mails: chunk.clone(),
                        excludeMailSet: None,
                    },
                    ExtraServiceParams::default(),
                )
                .await;
            match reply {
                Ok(reply) => {
                    for group in reply.movedMails {
                        for mail in group.mailIds {
                            moved.insert(
                                format!("{}/{}", mail.listId, mail.listElementId),
                                Id::from_tuple(group.sourceFolder.clone()),
                            );
                        }
                    }
                    batch.settle(&chunk, Outcome::Applied);
                }
                Err(error) => {
                    let code = fail("move", Error::RequestFailed, Error::RequestFailed)(error);
                    batch.settle(&chunk, Outcome::Failed(code));
                    break;
                }
            }
        }
        Ok(ids
            .iter()
            .map(|mail| {
                let source = moved.get(&mail.to_string()).cloned();
                MoveOutcome {
                    id: mail.clone(),
                    code: batch.outcome(mail),
                    new_id: source.is_some().then(|| mail.clone()),
                    source,
                }
            })
            .collect())
    }

    /// Delete up to [`MAIL_BATCH_LIMIT`] mails for good from `folder`, which
    /// must be Trash, Spam or a folder inside them. TS
    /// `MailModel.finallyDeleteMails` -> `MailFacade.deleteMails`.
    pub async fn delete(&self, ids: &[Id], folder: &Id) -> Result<Vec<IdOutcome>> {
        let parsed = check_batch(ids)?;
        let folder = folder.tuple();
        let sdk = &*self.sdk;
        let mailbox = load_mailbox(sdk).await?;
        if find(&mailbox.sets, folder).is_none() {
            return Err(Error::FolderNotFound);
        }
        if !in_trash_or_spam(&mailbox.sets, folder) {
            return Err(Error::NotTrashOrSpam);
        }
        let mut batch = Batch::new(&parsed);
        for chunk in list_chunks(&parsed) {
            match sdk
                .get_service_executor()
                .delete::<MailService>(
                    DeleteMailData {
                        _format: 0,
                        mails: chunk.clone(),
                        folder: Some(folder.clone()),
                    },
                    ExtraServiceParams::default(),
                )
                .await
            {
                Ok(()) => batch.settle(&chunk, Outcome::Applied),
                Err(error) => {
                    let code = fail("delete", Error::DeleteFailed, Error::DeleteFailed)(error);
                    batch.settle(&chunk, Outcome::Failed(code));
                    break;
                }
            }
        }
        Ok(batch.rows(ids))
    }

    /// Empty Trash or Spam; returns how many mails it listed just before.
    /// TS `MailViewModel.finallyDeleteAllMailsInSelectedFolder` ->
    /// `MailFacade.clearFolder`: one `MailService` DELETE naming only the
    /// folder; the server deletes its mail in batches itself. A subfolder of
    /// Trash or Spam is emptied by deleting it (`delete_folder`), as there.
    pub async fn empty_folder(&self, folder_id: &Id) -> Result<usize> {
        let sdk = &*self.sdk;
        let target = folder_id.tuple().clone();
        let mailbox = load_mailbox(sdk).await?;
        let folder = find(&mailbox.sets, &target).ok_or(Error::FolderNotFound)?;
        if folder.folderType != TRASH_FOLDER_TYPE && folder.folderType != SPAM_FOLDER_TYPE {
            return Err(Error::NotTrashOrSpam);
        }
        let entries: Vec<MailSetEntry> = sdk
            .mail_facade()
            .get_crypto_entity_client()
            // DESC, as `sync` enumerates: the SDK's ASC walk starts at the
            // generated-id minimum, which skips base64url entry ids.
            .load_all(&folder.entries, ListLoadDirection::DESC)
            .await
            .map_err(fail(
                "folder entries",
                Error::RequestFailed,
                Error::FolderNotFound,
            ))?;
        match sdk
            .get_service_executor()
            .delete::<MailService>(
                DeleteMailData {
                    _format: 0,
                    mails: Vec::new(),
                    folder: Some(target),
                },
                ExtraServiceParams::default(),
            )
            .await
        {
            Ok(()) => Ok(entries.len()),
            Err(ApiCallError::ServerResponseError {
                source: HttpError::PreconditionFailedError(_),
            }) => Err(Error::OperationStillActive),
            Err(error) => Err(fail(
                "empty folder",
                Error::DeleteFailed,
                Error::FolderNotFound,
            )(error)),
        }
    }

    /// Add and remove labels on up to [`MAIL_BATCH_LIMIT`] mails. TS
    /// `MailModel.applyLabels` -> `MailFacade.applyLabels`:
    /// `ApplyLabelService` POST per mail list, in chunks.
    pub async fn apply_labels(&self, ids: &[Id], changes: &LabelChanges) -> Result<Vec<IdOutcome>> {
        let parsed = check_batch(ids)?;
        let sdk = &*self.sdk;
        let mailbox = load_mailbox(sdk).await?;
        if changes
            .add
            .iter()
            .chain(changes.remove.iter())
            .any(|label| !find(&mailbox.sets, label).is_some_and(is_label))
        {
            return Err(Error::LabelNotFound);
        }
        let mut batch = Batch::new(&parsed);
        for chunk in list_chunks(&parsed) {
            match sdk
                .get_service_executor()
                .post::<ApplyLabelService>(
                    ApplyLabelServicePostIn {
                        _format: 0,
                        mails: chunk.clone(),
                        addedLabels: changes.add.clone(),
                        removedLabels: changes.remove.clone(),
                    },
                    ExtraServiceParams::default(),
                )
                .await
            {
                Ok(()) => batch.settle(&chunk, Outcome::Applied),
                Err(error) => {
                    let code =
                        fail("apply labels", Error::LabelFailed, Error::RequestFailed)(error);
                    batch.settle(&chunk, Outcome::Failed(code));
                    break;
                }
            }
        }
        Ok(batch.rows(ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::tuple;

    fn set(element: &str, kind: i64, parent: Option<&str>) -> MailSet {
        MailSet {
            _id: Some(tuple(&format!("sets/{element}")).unwrap()),
            _permissions: GeneratedId("p".into()),
            _format: 0,
            _ownerEncSessionKey: None,
            name: element.to_string(),
            folderType: kind,
            _ownerGroup: None,
            _ownerKeyVersion: None,
            color: None,
            _kdfNonce: None,
            parentFolder: parent.map(|p| tuple(&format!("sets/{p}")).unwrap()),
            entries: GeneratedId("e".into()),
            _errors: Default::default(),
        }
    }

    fn t(element: &str) -> IdTupleGenerated {
        tuple(&format!("sets/{element}")).unwrap()
    }

    fn ids(values: &[&str]) -> Vec<Id> {
        values.iter().map(|v| Id::parse(v).unwrap()).collect()
    }

    #[test]
    fn trash_and_spam_subtrees_allow_final_delete() {
        let sets = vec![
            set("inbox", 1, None),
            set("trash", TRASH_FOLDER_TYPE, None),
            set("spam", SPAM_FOLDER_TYPE, None),
            set("old", CUSTOM_FOLDER_TYPE, Some("trash")),
            set("older", CUSTOM_FOLDER_TYPE, Some("old")),
            set("work", CUSTOM_FOLDER_TYPE, Some("inbox")),
        ];
        assert!(in_trash_or_spam(&sets, &t("trash")));
        assert!(in_trash_or_spam(&sets, &t("spam")));
        assert!(in_trash_or_spam(&sets, &t("older")));
        assert!(!in_trash_or_spam(&sets, &t("work")));
        assert!(!in_trash_or_spam(&sets, &t("inbox")));
        assert!(!in_trash_or_spam(&sets, &t("missing")));
    }

    #[test]
    fn a_parent_cycle_does_not_hang() {
        let sets = vec![
            set("a", CUSTOM_FOLDER_TYPE, Some("b")),
            set("b", CUSTOM_FOLDER_TYPE, Some("a")),
        ];
        assert!(!in_trash_or_spam(&sets, &t("a")));
        assert!(descendants_deepest_first(&sets, &t("a")).len() <= 2 * MAX_FOLDER_DEPTH);
    }

    #[test]
    fn descendants_come_deepest_first_and_skip_labels() {
        let sets = vec![
            set("top", CUSTOM_FOLDER_TYPE, None),
            set("child", CUSTOM_FOLDER_TYPE, Some("top")),
            set("grandchild", CUSTOM_FOLDER_TYPE, Some("child")),
            set("label", LABEL_FOLDER_TYPE, Some("top")),
        ];
        let names: Vec<&str> = descendants_deepest_first(&sets, &t("top"))
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["grandchild", "child"]);
    }

    #[test]
    fn names_and_colours_are_validated() {
        assert_eq!(Name::new("  Work  ").unwrap().as_str(), "Work");
        assert_eq!(Name::new("   "), Err(Error::InvalidName));
        assert_eq!(Name::new("a\u{7}b"), Err(Error::InvalidName));
        assert_eq!(
            Name::new(&"x".repeat(MAX_NAME_CHARS + 1)),
            Err(Error::InvalidName)
        );
        assert_eq!(Color::new("#A1b2C3").unwrap().as_str(), "#a1b2c3");
        assert_eq!(Color::new("a1b2c3"), Err(Error::InvalidColor));
        assert_eq!(Color::new("#a1b2c"), Err(Error::InvalidColor));
        assert_eq!(Color::new("#a1b2cg"), Err(Error::InvalidColor));
    }

    #[test]
    fn sibling_names_collide_case_insensitively() {
        let sets = vec![
            set("Work", CUSTOM_FOLDER_TYPE, None),
            set("Sub", CUSTOM_FOLDER_TYPE, Some("Work")),
            set("Tag", LABEL_FOLDER_TYPE, None),
        ];
        assert!(name_taken(&sets, None, "work", None));
        assert!(!name_taken(&sets, None, "work", Some(&t("Work"))));
        assert!(!name_taken(&sets, None, "sub", None));
        assert!(name_taken(&sets, Some(&t("Work")), "SUB", None));
        // Labels are a separate namespace.
        assert!(!name_taken(&sets, None, "tag", None));
    }

    #[test]
    fn chunks_group_by_list_dedupe_and_cap() {
        let mut mails = Vec::new();
        for n in 0..60 {
            mails.push(tuple(&format!("a/m{n}")).unwrap());
        }
        mails.push(tuple("b/x").unwrap());
        mails.push(tuple("a/m0").unwrap());
        let chunks = list_chunks(&mails);
        let sizes: Vec<usize> = chunks.iter().map(Vec::len).collect();
        assert_eq!(sizes, [MAIL_BATCH_LIMIT, 10, 1]);
        assert!(chunks
            .iter()
            .all(|c| c.iter().all(|m| m.list_id == c[0].list_id)));
    }

    #[test]
    fn batch_rows_keep_input_order_and_mark_the_unattempted() {
        let ids = ids(&["a/1", "b/2", "a/1"]);
        let parsed = check_batch(&ids).unwrap();
        let mut batch = Batch::new(&parsed);
        batch.settle(&parsed[..1], Outcome::Applied);
        let rows = batch.rows(&ids);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].code, Outcome::Applied);
        assert_eq!(rows[1].code, Outcome::NotAttempted);
        assert_eq!(rows[2].code, Outcome::Applied);
        assert_eq!(rows[1].id.to_string(), "b/2");
        let json = serde_json::to_value(&rows).unwrap();
        assert_eq!(json[0]["code"], serde_json::Value::Null);
        assert_eq!(json[1]["code"], "not_attempted");
    }

    #[test]
    fn move_rows_serialize_their_report() {
        let row = MoveOutcome {
            id: Id::parse("a/1").unwrap(),
            code: Outcome::Failed(Error::RequestFailed),
            new_id: None,
            source: None,
        };
        assert_eq!(
            serde_json::to_value(&row).unwrap(),
            serde_json::json!({"id": "a/1", "code": "request_failed", "new_id": null, "source": null})
        );
    }

    #[test]
    fn batches_are_bounded() {
        assert_eq!(check_batch(&[]).err(), Some(Error::InvalidBatch));
        let many: Vec<Id> = (0..=MAIL_BATCH_LIMIT)
            .map(|n| Id::parse(&format!("a/m{n}")).unwrap())
            .collect();
        assert_eq!(check_batch(&many).err(), Some(Error::InvalidBatch));
        assert_eq!(
            check_batch(&many[1..]).map(|b| b.len()),
            Ok(MAIL_BATCH_LIMIT)
        );
    }

    #[test]
    fn folder_edits_need_a_change_and_a_sane_parent() {
        let folder = || Id::parse("sets/f").unwrap();
        assert_eq!(
            FolderEdit::new(folder(), None, None).err(),
            Some(Error::InvalidRequest)
        );
        assert_eq!(
            FolderEdit::new(folder(), None, Some(Some(folder()))).err(),
            Some(Error::InvalidParent)
        );
        let top = FolderEdit::new(folder(), None, Some(None)).unwrap();
        assert_eq!(top.parent, Some(None));
        let named = FolderEdit::new(folder(), Some(Name::new(" New ").unwrap()), None).unwrap();
        assert_eq!(named.name.as_ref().map(Name::as_str), Some("New"));
        assert!(named.parent.is_none());
    }

    #[test]
    fn label_edits_need_a_change() {
        assert_eq!(
            LabelEdit::new(None, None).err(),
            Some(Error::InvalidRequest)
        );
        assert!(LabelEdit::new(None, Some(Color::new("#000000").unwrap())).is_ok());
    }

    #[test]
    fn label_changes_are_validated() {
        let changes = |add: &[&str], remove: &[&str]| LabelChanges::new(ids(add), ids(remove));
        assert_eq!(changes(&[], &[]).err(), Some(Error::InvalidRequest));
        assert_eq!(
            changes(&["l/1"], &["l/1"]).err(),
            Some(Error::InvalidRequest)
        );
        assert_eq!(
            changes(&["l/1", "l/2", "l/3", "l/4", "l/5", "l/6"], &[]).err(),
            Some(Error::InvalidRequest)
        );
        let valid = changes(&["l/1"], &["l/2"]).unwrap();
        assert_eq!((valid.add.len(), valid.remove.len()), (1, 1));
    }

    #[test]
    fn mail_labels_keep_only_labels() {
        let sets = vec![t("inbox"), t("tag")];
        let label_ids: HashSet<String> = [id(&t("tag"))].into_iter().collect();
        assert_eq!(mail_labels(&sets, &label_ids), [Id::from_tuple(t("tag"))]);
    }

    #[test]
    fn api_codes_are_fixed() {
        let server = |source| ApiCallError::ServerResponseError { source };
        let (fallback, gone) = (Error::FolderFailed, Error::FolderNotFound);
        assert_eq!(
            api_code(server(HttpError::NotFoundError), fallback, gone),
            gone
        );
        assert_eq!(
            api_code(server(HttpError::SessionExpiredError), fallback, gone),
            Error::SessionRevoked
        );
        assert_eq!(
            api_code(server(HttpError::LimitReachedError), fallback, gone),
            Error::LimitReached
        );
        assert_eq!(
            api_code(server(HttpError::BadRequestError), fallback, gone),
            fallback
        );
        assert_eq!(
            api_code(ApiCallError::internal("secret".into()), fallback, gone),
            fallback
        );
    }

    #[test]
    fn deletions_serialize_as_the_protocol_names_them() {
        assert_eq!(
            serde_json::to_value(FolderDeletion::Trashed).unwrap(),
            serde_json::json!("trashed")
        );
    }
}
