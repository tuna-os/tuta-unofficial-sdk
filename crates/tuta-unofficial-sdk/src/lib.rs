//! An unofficial, community-maintained Tuta (Tutanota) SDK for Rust.
//!
//! Not affiliated with or endorsed by Tuta GmbH. Tuta's API is undocumented
//! and third-party clients are unsupported; using this crate may conflict
//! with Tuta's terms of service, so check them before you do.
//!
//! All cryptography is the Tuta SDK's own (the `tuta-sdk` crate from
//! tutanota, pinned and prepared by tutabridge, plus a few small patches in
//! `sdk-patches/` that expose what the official client does). This crate
//! composes the official client's requests on top of it.
//!
//! # Overview
//!
//! ```no_run
//! use secrecy::SecretString;
//! use tuta_unofficial_sdk::{Client, Page};
//!
//! # async fn demo() -> tuta_unofficial_sdk::Result<()> {
//! let client = Client::new()?;
//! let password = SecretString::from("correct horse".to_string());
//! let session = client.login("ada@tuta.com", &password, None).await?;
//! for folder in session.folders().await? {
//!     println!("{} {:?} {}", folder.id, folder.role, folder.label);
//! }
//! let page = session.sync(None, Page::new(20, 0)?).await?;
//! if let Some(first) = page.messages.first() {
//!     let message = session.message(&first.header.id).await?;
//!     let mime: Vec<u8> = message.to_mime();
//!     println!("{} bytes", mime.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! - Sessions: [`Client::login`], [`Session::resume`], [`Session::saved`],
//!   [`Session::revoke`], [`Client::revoke`].
//! - Reading: [`Session::folders`], [`Session::labels`], [`Session::sync`],
//!   [`Session::message`] and [`Message::to_mime`].
//! - Changing mail: [`Session::mark_read`], [`Session::move_mail`],
//!   [`Session::delete`], [`Session::empty_folder`],
//!   [`Session::apply_labels`].
//! - Folders and labels: [`Session::create_folder`],
//!   [`Session::rename_folder`], [`Session::delete_folder`],
//!   [`Session::create_label`], [`Session::update_label`],
//!   [`Session::delete_label`].
//! - Sending: [`Session::send`] and [`Session::send_within`]; drafts:
//!   [`drafts::save`], [`drafts::delete`]; contact passwords:
//!   [`contacts::passwords`], [`contacts::store_passwords`].
//! - Importing: [`Session::import`] with an [`ImportMessage`].
//! - Push: [`Session::watch`], a [`futures_core::Stream`] of
//!   [`WatchEvent`]s.
//!
//! Every failure is an [`Error`] with a fixed code ([`Error::code`]); the
//! `tuta-helper` binary in this repository reports the same codes over its
//! JSON protocol.

mod client;
pub mod contacts;
mod delivery;
mod diag;
pub mod drafts;
mod error;
mod ids;
mod import;
mod mail;
mod mailbox_ops;
mod mime;
mod send;
mod thread;
mod transport;
mod watch;

/// The server rejects larger mail-mutation batches with Bad Request; both the
/// SDK and the bridge extensions chunk at this size.
pub const MAIL_BATCH_LIMIT: usize = 50;

pub use client::{Client, SavedSession, Session, DEFAULT_CLIENT_NAME, TUTA_URL};
pub use delivery::{KeyProtocol, RecipientReport};
pub use error::{Error, Result};
pub use ids::Id;
pub use import::{ImportMessage, MAX_IMPORT_BYTES};
pub use mail::{
    Address, Attachment, Folder, FolderRole, IdOutcome, Label, ListedMail, MailHeader, Message,
    Outcome, Page, SyncPage, MAX_PAGE_LIMIT, MAX_PAGE_OFFSET,
};
pub use mailbox_ops::{
    Color, FolderDeletion, FolderEdit, LabelChanges, LabelEdit, MoveOutcome, Name,
    MAX_LABELS_PER_MAIL, MAX_NAME_CHARS,
};
pub use send::{OutgoingAttachment, Recipient, SendOutcome, SendRequest, MAX_BODY_BYTES};
pub use thread::{Action, Thread};
pub use watch::{Watch, WatchEvent};

/// Opt-in diagnostics on stderr: the stage an operation broke in and the
/// SDK's error, redacted (no addresses, ids, tokens, keys or content).
/// Also on when `TUTA_SDK_DEBUG=1` is set.
pub mod diagnostics {
    pub use crate::diag::{enable, enabled, redact};
}
