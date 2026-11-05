# tuta-unofficial-sdk

An unofficial, community-maintained Tuta (Tutanota) SDK for Rust: sign in,
read and decrypt mail, send it end-to-end encrypted (to Tuta recipients by
key, to everyone else behind a password), keep drafts, manage folders and
labels, import mail, keep contact passwords and watch the event bus for
changes. Tuta offers no IMAP, SMTP or JMAP: mail is end-to-end encrypted on
the server, and only Tuta's own client library can sign in and decrypt it.
This SDK wraps that library in a typed async API, and ships `tuta-helper`, a
small JSON-over-stdio program on top of it for applications that would
rather run a separate process.

## Status and disclaimer

**This project is not affiliated with, endorsed by or supported by Tuta GmbH.**
"Tuta" and "Tutanota" are their trademarks, used here only to say what this
software talks to.

Tuta's API is undocumented and third-party clients are unsupported. Using this
SDK may conflict with Tuta's terms of service: read them and decide for
yourself before you use it with an account, and prefer a test account while
developing. The server can change or refuse this client at any time; a pinned
SDK that falls behind the minimum client version Tuta accepts fails with
`client_outdated`, and the fix is to update the pin, never to report a
different client version.

Version 0.1.0 is the first release: the API follows the needs of its first
user, the Hylki mail client's Tuta support, and may still change.

## Features

- Sign-in with password and TOTP; saved, resumable sessions; closing a
  session on the server.
- The folder tree and labels; folder pages with every mail's labels and
  Message-ID; a mail decrypted to its parts or to RFC 5322 MIME.
- Read state, moves (with the server's own undo information), labels,
  permanent deletes from Trash and Spam, emptying Trash and Spam.
- Folders and labels: create, rename, re-parent, recolour, delete, with the
  official client's rules.
- Drafts: save (create or replace) and discard, with their place in a
  conversation.
- Sending: confidential (end-to-end encrypted) to Tuta recipients by their
  public keys and to everyone else behind a password, or ordinary with
  explicit consent; replies and forwards threaded and marked on the parent;
  attachments; a definite or uncertain outcome read from the wire.
- Contact passwords for password-protected recipients, read and stored the
  way Tuta's own apps keep them.
- Import of a MIME message into a folder, as the official desktop importer
  does (Legend and Unlimited plans).
- Push: a stream of folder and mail changes from Tuta's event bus.

## Security model

**All cryptography is the Tuta SDK's.** The SDK is Tuta's own Rust library
(`tuta-sdk` from [tutanota](https://github.com/tutao/tutanota)), at the
release and commit [tutabridge](https://github.com/spartanz51/tutabridge)
pins, with tutabridge's patches. This repository adds no cipher, key
derivation or key exchange of its own: it composes the official client's
service requests on top of the SDK, wraps symmetric keys only with the SDK's
own AES functions, and exposes a few SDK internals through four small
patches:

- `01-recipient-key-data.patch` exposes
  `LoggedInSdk::encrypt_bucket_key_for_internal_recipients`, which loads
  each Tuta recipient's current public key and encrypts a mail's bucket key
  for it through the SDK's own `AsymmetricCryptoFacade` (RSA, or TutaCrypt
  with the sender identity key), as the official client's
  `encryptBucketKeyForInternalRecipient` does. It adds no cryptography.
- `02-service-response-session-key.patch` decrypts a service response
  whose type has no owner key of its own (a created folder, an updated
  draft) with the request's session key, as the official client's
  `ServiceExecutor.decryptResponse` does, instead of failing after the
  server already applied the request.
- `03-entity-patch.patch` adds `CryptoEntityClient::patch_instance`, which
  PATCHes a `sys/PatchList` naming only the changed attributes, as the
  official client's `EntityRestClient.update` writes every update. The
  SDK's own whole-instance PUT would encrypt every value again, final ones
  such as a mail's subject included. It adds `PATCH` to the SDK's
  `HttpMethod` for it.
- `04-secure-external-recipient.patch` exposes
  `LoggedInSdk::secure_external_recipient_key_data`, a port of the official
  client's password-protected recipient path (`addRecipientKeyData`,
  `getExternalGroupKeys`, `createExternalUser`): an Argon2id key from the
  password, the external user found or created, the bucket key wrapped for
  it. It refuses a shared-mailbox or external sender, as the official
  client does. `ContactFacade` gains `create_contact` and
  `set_preshared_password`, and `EntityClient::create_instance` reports a
  refused create as an error instead of panicking. It adds no
  cryptography.

Secrets stay secrets: passwords, session tokens and wrapped keys are held in
`secrecy`/`zeroize` types with no `Debug` form, never go in argv or the
environment of the helper, and never reach the diagnostics, which redact
addresses, ids, tokens and key bytes. A send never falls back to SMTP and
never quietly drops encryption. Recipient keys are not verified (see
[Delivery](#delivery)); each one's version and fingerprint is reported so a
caller can pin them.

### Sources

The `upstream` submodule is used for source only:

- [tutabridge](https://github.com/spartanz51/tutabridge) at
  `da12fd4a479d6885f6643f05690b78205e2adbec` supplies its `tutabridge-tuta`
  mail extensions (mail details, attachments, the event bus client) and the
  SDK preparation script. Its IMAP/SMTP server is not linked or run.
- The [Tuta SDK](https://github.com/tutao/tutanota) is Tuta release
  `362.261020.0`, commit `f5e2d8628f17be558fe63130396ff625bbe69c77` (the
  `upstream/tuta-repo` submodule), with tutabridge's twelve patches for
  optional encrypted values, address normalization, account KDFs, batched
  entity loads, blobs, interactive sessions, owner keys, AEAD reads and
  bucket keys (series and hashes in `upstream/sdk/EXPECTED`), plus ours in
  `sdk-patches/`.

`prepare.sh` runs tutabridge's `sdk-prepare.py`, which prepares and verifies
the pinned SDK in `upstream/sdk/generated`, then writes a copy with our
patches applied to `prepared/`, beside a copy of `tutabridge-tuta`. That
crate's build script verifies the SDK it builds against, so
`prepared/sdk/EXPECTED` lists both patch series (ours as
`unofficial-<name>`) and the content digest of the patched tree; the build
verifies exactly what it compiles. The library builds only from `prepared/`.

## Layout

| Path | What |
| --- | --- |
| `crates/tuta-unofficial-sdk` | The library. |
| `crates/tuta-unofficial-sdk/examples/read_mail.rs` | A small CLI: list the folders, read the newest mail. |
| `crates/tuta-helper` | The `tuta-helper` binary: the JSON protocol below, a thin front end on the library. |
| `sdk-patches/` | Our patches to the Tuta SDK, applied in name order. |
| `prepare.sh` | Prepares the patched SDK in `prepared/` (gitignored). |
| `upstream/` | The tutabridge submodule, with tutanota inside it. |
| `scripts/cargo-sources.sh` | Regenerates `cargo-sources.json` for Flatpak builds. |

## The library

```rust
use secrecy::SecretString;
use tuta_unofficial_sdk::{Client, Page};

async fn demo() -> tuta_unofficial_sdk::Result<()> {
    let client = Client::new()?.client_name("my-app");
    let password = SecretString::from("correct horse".to_string());
    let session = client.login("ada@tuta.com", &password, Some("123456")).await?;
    let saved = session.saved().clone(); // serialize it into a keyring

    for folder in session.folders().await? {
        println!("{} {:?} {}", folder.id, folder.role, folder.label);
    }
    let page = session.sync(None, Page::new(50, 0)?).await?; // the Inbox
    if let Some(newest) = page.messages.first() {
        let message = session.message(&newest.header.id).await?;
        let mime: Vec<u8> = message.to_mime();
        println!("{} bytes", mime.len());
    }
    Ok(())
}
```

The API, all `async` on a tokio runtime:

| Area | API |
| --- | --- |
| Sessions | `Client::new`, `Client::with_url`, `Client::client_name`, `Client::login(email, &SecretString, totp) -> Session`, `Session::resume(&client, SavedSession)`, `Session::saved`, `Session::revoke`, `Client::revoke(&SavedSession)` |
| Reading | `Session::folders`, `labels`, `sync(Option<&Id>, Page) -> SyncPage`, `message(&Id) -> Message`, `Message::to_mime() -> Vec<u8>` |
| Mail | `mark_read(&[Id], bool)`, `move_mail(&[Id], &Id)`, `delete(&[Id], &Id)`, `empty_folder(&Id)`, `apply_labels(&[Id], &LabelChanges)`; per-id `IdOutcome`/`MoveOutcome` rows |
| Folders, labels | `create_folder(&Name, Option<&Id>)`, `rename_folder(&FolderEdit)`, `delete_folder(&Id) -> FolderDeletion`, `create_label(&Name, &Color)`, `update_label(&Id, &LabelEdit)`, `delete_label(&Id)` |
| Sending | `send(SendRequest) -> SendOutcome`, `send_within(SendRequest, Duration)`; `Thread::new(in_reply_to, references, action)` |
| Drafts | `drafts::save(&Session, &DraftRequest) -> Id`, `drafts::delete(&Session, &Id)` |
| Contacts | `contacts::passwords(&Session, &[String])`, `contacts::store_passwords(&Session, &Passwords)` |
| Import | `ImportMessage::parse(bytes, unread)`, `Session::import(&Id, ImportMessage) -> Option<Id>` |
| Push | `Session::watch() -> Watch`, a `futures_core::Stream<Item = Result<WatchEvent>>`; `Watch::close` |
| Diagnostics | `diagnostics::enable(prefix)`, or `TUTA_SDK_DEBUG=1` |

Inputs that can be checked offline are typed and checked when built: `Id`,
`Page`, `Name`, `Color`, `FolderEdit`, `LabelEdit`, `LabelChanges`,
`Thread`, `ImportMessage`, `DraftRequest::check`. Every failure is an
`Error`, a `#[non_exhaustive]` enum whose `code()` is the fixed snake_case
code listed under [Error codes](#error-codes); `Error::from_code` maps a code
back.

**Sends and time limits.** Dropping a `send` future part-way loses the
outcome of a submit that may already have gone out. To bound a send in time,
use `send_within`, which keeps the [outcome rules](#send-outcomes): an
overrun before the submit left is `Timeout` (nothing was sent), after it the
submit's own status decides.

The SDK prints a line of progress to stdout now and then (the helper parks
fd 1 while it runs; an in-process GUI can ignore it).

### Depending on it

The library depends on crates that `prepare.sh` writes into `prepared/`, so
it is not on crates.io. Three ways in:

- **A git dependency on a vendored tag.** Each release also has a
  `vX.Y.Z-vendored` tag: the same source with `prepared/` committed and the
  submodule left out, so Cargo can build it straight from git, without
  Python or the 500 MB tutanota checkout:

  ```toml
  [dependencies]
  tuta-unofficial-sdk = { git = "https://github.com/tuna-os/tuta-unofficial-sdk", tag = "v0.1.0-vendored" }
  ```

  `scripts/vendor.sh` makes such a tag from a release tag. The plain tags
  and `main` do not build as git dependencies: nothing would run
  `prepare.sh`.
- **A path dependency on a submodule.** Add this repository as a submodule,
  run its `prepare.sh` in your build, and depend on
  `crates/tuta-unofficial-sdk` by path.
- **A separate process.** Build `tuta-helper` and talk to it over the
  [protocol](#the-helper-protocol). This keeps the SDK's large dependency
  tree out of your own build and its crashes out of your process.

For a Flatpak build, list `cargo-sources.json` (see
[Packaging](#packaging)) beside your own crate sources, run `sh prepare.sh`
(or use a vendored tag) before `cargo build --offline --locked`, and install
the binary you need.

## The helper protocol

`tuta-helper` is the library behind a JSON protocol on private stdio: a
caller starts it once per operation, writes one request to its stdin, reads
one reply from its stdout, and waits for it to exit; only `watch`, which
holds Tuta's push channel open, streams one line per change instead. The
helper does not listen on a socket, keep a local cache, or speak any mail
protocol. Decrypted mail goes back as headers, a body and attachments.

Installed or linked under the name `hylki-tuta`, the same binary is the
helper the Hylki mail client looks up, and behaves exactly as Hylki's own
`hylki-tuta` did: sessions are named "Hylki" in the account's session list,
and diagnostics follow `HYLKI_TUTA_DEBUG=1` with the `hylki-tuta:` prefix.
Under any other name sessions are named "tuta-helper" and
`TUTA_HELPER_DEBUG=1` turns diagnostics on. The protocol is the same either
way.


One UTF-8 JSON object goes to the helper on stdin, followed by EOF, and one
JSON object comes back on stdout. Passwords, TOTP codes and session tokens
never go in argv or the environment. The SDK prints progress to stdout, so the
helper parks fd 1 on `/dev/null` while SDK code runs; stdout carries exactly
one line. Requests are capped at 36 MiB (room for a 25 MiB `import` or a
send's attachments in base64) and each operation at 90 seconds; a caller
should allow some more for startup (Hylki allows 100 seconds), then kill and
reap the process. The one exception is `watch`, which streams (see [Watch](#watch)).

Every request carries `version: 1` and an `op`:

| Operation | Parameters | Result |
| --- | --- | --- |
| `login` | `email`, `password`, optional `totp` | Resumable `session` |
| `sync` | `session`, optional `folder`, `limit`, `offset` | Folder tree, labels, headers (each with its label ids and `message_id`), and the selected folder's full id snapshot when `offset` is zero |
| `message` | `session`, compound `id` | Decrypted body, original headers, recipients and attachments; its header carries `message_id` too |
| `mark_read` | `session`, `ids`, `is_read` | Per-id outcomes |
| `move` | `session`, `ids`, compound `destination` | Per-id outcomes with `new_id` and `source` |
| `send` | `session`, `sender`, `sender_name`, `to`, `cc`, `bcc`, `reply_tos`, `subject`, `body_html`, `attachments`, `confidential` (bool), `ordinary_confirmed`, optional `passwords` (`{address: password}`), optional `in_reply_to`, `references`, `action` (see [Replies and forwards](#replies-and-forwards)) | Server ids of the sent mail, recipient counts, the delivery mode, each Tuta recipient's key, `secure_external` and `contacts_saved` (see [Delivery](#delivery)); for a reply or forward, `parent_marked` |
| `revoke` | `session` | Empty object; closes the server-side session |
| `list_labels` | `session` | `labels`: `{id, name, color}` each |
| `create_folder` | `session`, `name`, optional compound `parent` | The new folder's `id` |
| `rename_folder` | `session`, compound `id`, optional `name`, optional `parent` (`""` for the top level); at least one of the two | Empty object |
| `delete_folder` | `session`, compound `id` | `outcome`: `deleted` or `trashed` |
| `create_label` | `session`, `name`, `color` (`#rrggbb`) | The new label's `id` |
| `update_label` | `session`, compound `id`, optional `name`, optional `color`; at least one | Empty object |
| `delete_label` | `session`, compound `id` | Empty object |
| `apply_labels` | `session`, `ids`, `add` and `remove` (label ids) | Per-id outcomes |
| `delete` | `session`, `ids`, compound `folder` (Trash, Spam or a folder inside them) | Per-id outcomes |
| `empty_folder` | `session`, compound `id` of Trash or Spam | `deleted`: how many mails it held |
| `save_draft` | `session`, optional compound `draft_id`, `sender`, `sender_name`, `to`, `cc`, `bcc`, `reply_tos`, `subject`, `body_html`, `confidential`, `attachments`, optional `in_reply_to`, `references`, `action` | The draft's `id` |
| `delete_draft` | `session`, compound `id` | Empty object |
| `contact_passwords` | `session`, `addresses` (at most 100) | `recipients`: `{address, external, password}` per distinct address, in request order (see [Delivery](#delivery)) |
| `store_contact_passwords` | `session`, `passwords` (`{address: password}`, at most 100) | Empty object |
| `import` | `session`, compound `folder`, `mime_base64` (the whole RFC 5322 message, standard base64), optional `unread` (default `false`) | The new mail's `id`, or null when the server had not listed it yet |
| `watch` | `session` | A stream of event lines until stdin closes |

A reply is either `{"version":1,"result":{...}}` or
`{"version":1,"error":{"code":"..."}}`. Unknown operations, unknown fields and
other versions are rejected.

Per-id outcomes are `{"outcomes":[{"id","code"}]}` in request order, at most
50 ids: `code` is null when applied, the failure's code for the batch that
failed, and `not_attempted` after it. A move row adds `new_id` and `source`
from the server's own report of what it moved: a Tuta mail keeps its id when
it moves, so `new_id` equals `id`, and `source` is the folder it left -- what
the official client moves back to undo. Both are null for a mail the server
did not move (it was already in the destination).

### Error codes

An error carries a fixed code, never SDK or server text:

- Sign-in: `login_failed`, `second_factor_required`, `second_factor_failed`,
  `invalid_totp`, `resume_failed`, `session_invalid`, `session_revoked`,
  `client_outdated`.
- Transport: `transport_failed`, `request_failed`, `timeout`.
- Content: `decryption_failed`, `unsupported_legacy_body`,
  `attachment_failed`, `body_too_large`.
- Requests: `invalid_request`, `unsupported_version`, `invalid_id`,
  `invalid_page`, `invalid_batch`, `invalid_thread` (a malformed Message-ID
  in `in_reply_to` or `references`, more than 100 references, or an `action`
  with no Message-ID).
- Sending: `invalid_recipient`, `sender_unknown`, `recipient_not_found`,
  `password_required` (a confidential send has a recipient outside Tuta
  without a password; no address is named),
  `secure_external_sender_unsupported` (password-protected delivery from a
  shared mailbox or an external user, which the official client refuses
  too), `ordinary_delivery_requires_consent`, `send_failed`, `send_uncertain`.
- Contacts: `contact_save_failed` when `store_contact_passwords` could not
  write a contact, plus `invalid_batch` and `invalid_recipient` for the
  address lists.
- `revoke_failed` when the server would not close a session.
- Folders and labels: `folder_not_found`, `folder_exists` (a sibling has the
  name, ignoring case), `not_custom_folder` (system folders are never
  renamed or deleted), `invalid_parent`, `invalid_name`, `operation_still_active`
  (the server is still working on the folder), `folder_failed`,
  `label_not_found`, `label_exists`, `invalid_color`, `label_failed`,
  `limit_reached` (the plan allows no more).
- Deleting: `not_trash_or_spam`, `delete_failed`.
- Drafts: `draft_not_found`, `not_a_draft` (the id names a received or sent
  mail), `draft_failed`, plus the sending codes for addresses and attachments.
- Importing: `import_invalid` (not a MIME message: no header at all),
  `import_too_large` (over 25 MiB decoded, over 256 MIME parts, or headers
  and body past the 8 MiB the official importer sends per mail),
  `import_refused` (the account's plan is not Legend or Unlimited, which the
  official client requires before it imports, or the server answered
  `import.disabled`), `import_failed`, plus `folder_not_found`.
- `watch_failed` when the event bus cannot be held.

### Folders, labels and drafts

Each operation is the official client's own: the same services, the same
keys, the same rules.

- A folder or label name is encrypted with a fresh session key, which is
  wrapped with the mail group's current key (`MailFolderService`,
  `ManageLabelService`). A rename updates the folder itself; a re-parent goes
  through `MailFolderService`.
- `delete_folder` behaves like the sidebar's delete: a folder inside Trash or
  Spam is deleted for good (with its mail); elsewhere, empty descendants are
  deleted, then the folder too if it and all of them are empty (`deleted`),
  and otherwise it moves under Trash with its mail (`trashed`).
- Labels are mail sets beside the folders. `sync` lists them under `labels`
  rather than `folders`, names each header's labels, and lists a label's mail
  when its id is the selected `folder`. A mail carries at most five labels.
- `delete` deletes mail for good, and only from Trash, Spam or a folder
  inside them, as the server allows; move it to Trash first. `empty_folder`
  asks the server to empty Trash or Spam in one request; it reports how many
  mails the folder listed just before.
- `save_draft` creates a draft in Drafts, or updates the given one wherever
  it is filed (a template folder works). An update replaces the draft's
  recipients, subject, body and its whole attachment set. `delete_draft`
  discards a draft through Trash, never from Sent. Both refuse any id that is
  not a draft, and both treat a draft that is already gone as done.

### Import

`import` files one message into a folder the way the official desktop
client imports a mail file (tutanota `src/app-kit/mimimi`), so the mail is
stored end-to-end encrypted like any other and reads the same in Tuta's own
app:

1. The message is converted by a port of the official importer's own code
   (`crates/tuta-unofficial-sdk/src/import/mime.rs`, on the same `mail-parser` 0.10.2): one HTML body
   (plain text converted, of a `multipart/alternative` the last part), every
   other part an attachment, the raw header block kept, the sender, the
   recipients, Message-ID, In-Reply-To and References taken over. Its tests
   are upstream's, including the MIME-tools messages it reads from the
   submodule. Where upstream would panic on hostile input, the port does not.
2. The account's plan is read from its customer info, as the official
   client's import button does: only Legend and Unlimited (TS
   `HighestTierPlans`) may import. Any other plan is `import_refused` before
   anything is written; the server answers such an import with a bare 400.
3. `ImportMailService` GET creates an `ImportFileMailState` for the target
   folder.
4. Each attachment goes to the blob store under a fresh file key; the post
   carries the mail's `ImportMailData`, encrypted with a fresh session key
   wrapped by the mail group key, to the blob server the write token names.
5. The state's imported-mail list is read until it names the mail (eight
   tries, 750 ms apart); its mail set entry gives the mail's id. A post that
   failed without a definite refusal is checked the same way, so a mail the
   server did take is never reported as failed.
6. The state is closed as the official client closes one: `Finished` with
   one successful mail, or `Canceled` with one failed mail when the import
   stopped. The API offers no way to delete a state, so each import leaves
   one behind, as every import in the official client does.

The mail is filed as received and read unless `unread` is true. The target
must be a folder: not a label, the IMPORTED set or the scheduled-mail set.
Unlike the official import dialog, the Inbox is allowed; it leaves the
Inbox out only so a bulk import cannot hold up incoming mail. `sync` leaves
the IMPORTED set out of the folder tree, as the official client does: its
mail is listed in the folders it was imported into.

### Watch

`watch` keeps Tuta's event bus websocket open, as the official client does,
and is the one operation that does not answer with exactly one line. Its
request must be a single line ending in a newline, and stdin must stay open:
the helper stops when stdin reaches EOF and then exits 0 without writing
anything more. Without the newline the request is `invalid_request`. No
operation timeout applies. Every line carries `version: 1`:

- `{"event":"ready"}` once the bus first connects.
- `{"event":"mail_changed","folder":"<id>"}` when mail in that folder arrived,
  left or changed (read state, labels). `folder` is `""` when the folder
  could not be told; resync everything then.
- `{"event":"folders_changed"}` when a folder or label was created, renamed,
  moved or deleted. It comes before the `mail_changed` lines of the same
  batch.
- `{"event":"reconnect"}` after the bus dropped and came back. The server
  replays what was missed, but a caller should resync all the same.
- `{"error":{"code":...}}` when the watch cannot go on (`session_revoked`,
  `client_outdated`, `transport_failed`, `watch_failed`); the helper exits
  after it. While the bus reconnects, the session is checked over REST, so
  an expired session ends the watch instead of retrying forever.

Lines name folders only, never a mail's content.

### Delivery

A send goes out in one of two modes, decided from its recipients and
`confidential` before anything is written on the server (no blob, no draft).
A recipient is on Tuta (internal) when its domain is Tuta's or the public-key
service knows the address, and outside Tuta (external) when the service
answers 404. This is the official client's own rule
(`SendMailModel.isConfidential()` is `confidential ||
!containsExternalRecipients()`):

| Recipients | `confidential: true` | `confidential: false` |
| --- | --- | --- |
| All on Tuta | Confidential | Confidential, no consent needed |
| Some or all outside Tuta | Confidential: Tuta recipients by key, the others password-protected; `password_required` unless every one has a password | Ordinary for everyone with `ordinary_confirmed: true`, else `ordinary_delivery_requires_consent` |

- **Confidential** (end-to-end encrypted). A fresh bucket key wraps the
  mail's and attachments' session keys, and the draft is marked
  confidential. Inside the SDK the bucket key is encrypted for each Tuta
  recipient's current public key; a Tuta recipient without a key fails the
  whole send with `recipient_not_found`, never downgraded. Each recipient
  outside Tuta gets the bucket key behind their password: an Argon2id key
  over a fresh salt opens the account's external user for that address,
  which the SDK creates on the first password-protected send to it, and Tuta
  mails the recipient a link to read the message in Tuta's web app. Such a
  send carries the sender's name in the clear for that notification, as the
  official client does. A send whose recipients are all on Tuta with
  TutaCrypt keys also carries its `TutacryptSender` authentication status;
  any password-protected recipient rules that out, as in the official
  client.
- **Ordinary** (encrypted in transit, not end to end) for everyone, only with
  `ordinary_confirmed: true`. Passwords are ignored.

Passwords are trimmed, and addresses match ignoring case. A blank password is
a missing one. A password-protected send from a shared mailbox or by an
external user is `secure_external_sender_unsupported`, as in the official
client.

If a key lookup failed and the mode or a recipient's key depends on it, the
send fails with the lookup's code (`transport_failed` or `send_failed`); an
ordinary send with a recipient outside Tuta goes regardless. The helper
never falls back to SMTP and never quietly drops encryption.

The result carries `confidential` (bool), `recipients`, `secure_external` and
`contacts_saved`. `recipients` lists, for a confidential send, one `{address,
key_version, protocol, fingerprint}` per distinct Tuta recipient, where
`protocol` is `tuta_crypt` or `rsa` and `fingerprint` is the hex SHA-256 over
the public key it was encrypted with (each of RSA, X25519 and Kyber component
as the public-key service serves it, length-prefixed as a big-endian u32);
it is empty for an ordinary send. Key bytes are never reported.
`secure_external` lists the addresses that got the mail password-protected.

After a password-protected send went out, each recipient's password is kept
on their contact's `presharedPassword`, as the official client's
`SendMailModel.updateContacts` keeps it, so Tuta's own apps offer it next
time: a contact holding another password is updated (a PATCH of that field
alone), and an address without a contact gets a new one, named from the
recipient's name or address. `contacts_saved` is false when a write failed;
the mail has gone out either way. The fields are null when a run overran
after the submit.

`contact_passwords` lets a composer fill passwords in: per distinct address,
`external` (true outside Tuta, false on Tuta, null when the lookup failed)
and `password`, the one its contact keeps (null on Tuta or when none is
kept). `store_contact_passwords` keeps passwords on contacts the same way
without sending, for a send that is queued for later; blank ones are skipped,
never cleared. Passwords travel only in requests and replies on the private
pipe: never in diagnostics.

Keys are not verified. The official client only refuses a key that differs
from one the user verified by hand (`KeyVerificationMismatchError`); this
SDK keeps no verified contacts, so the current key from the public-key service is
used, as the official client does for every unverified contact. The
reported version and fingerprint are the hook for pinning keys later (trust
on first use).

Mail sent confidentially to the account's own address is read back by
`message` like any other: the recipient's copy decrypts through the SDK's
bucket-key path.

### Send outcomes

A send reports `send_uncertain` only when its `SendDraftService` request left
the process and no definite answer came back (lost in flight, or a 5xx). The
mail may have gone out and must not be resent. What happened is read from the
wire, not from the SDK's error, which reports a 412, a failed serialization and
an unreadable 200 reply alike. A request that never left, or that the server
refused with a 4xx, is `send_failed` (`session_revoked` for 401 or 440,
`client_outdated` for 474), and its draft is discarded through Trash. An
accepted send whose reply was lost succeeds with null ids; its delivery mode
is still reported.

### Replies and forwards

A `send` or a new `save_draft` takes its place in a conversation the way the
official client's does (`SendMailModel.initAsResponse`,
`MailFacade.createDraft`), from three optional fields:

- `in_reply_to`: the parent's Message-ID, with or without angle brackets.
- `references`: the References chain, whitespace-separated, oldest first.
  Tuta keeps no References of its own, so this only names the parent (its
  newest id) when `in_reply_to` is absent.
- `action`: `"reply"`, `"reply_all"` or `"forward"`. A parent without an
  action is answered as a reply; an action without a parent is
  `invalid_thread`.

Every header (`sync`'s and `message`'s) carries `message_id`: the mail's
own Message-ID as its conversation entry keeps it, without angle brackets,
or null for a draft or when the entry could not be read. Mail between Tuta
accounts has no header block, so this is the only Message-ID it has, and
the one a reply to it names. A `sync` page reads the entries one request
per conversation.

Every id must be printable ASCII without spaces or brackets, at most 998
bytes, and `references` holds at most 100; anything else refuses the whole
request with `invalid_thread` rather than being dropped. The draft is created
with `previousMessageId` set to the parent's bare id and `conversationType`
REPLY (a reply-all too: Tuta has no separate mark for it) or FORWARD, so the
server files it in the parent's conversation. Without the fields it is a new
conversation, as before. A draft's conversation is fixed when it is created;
an update checks the fields and has nowhere to put them.

After a send went out, the mail the server linked it to -- the previous
entry of the new mail's conversation entry, when it carries the given
Message-ID -- has its `replyType` moved on as the official client's
`updatePreviousMail` does: none becomes replied or forwarded, and one
becomes replied-and-forwarded after the other. Only that attribute is
written, encrypted with the parent's session key, as a PATCH. The result's
`parent_marked` says whether the parent ended up marked; it is false when
the account holds no such mail (outside mail never received here, or
deleted) or the write failed, and the send has gone out either way. For mail
the account sent to itself both copies share a Message-ID, and the server
links the sent copy.

## Building and testing

With a Rust toolchain (1.84 or newer), a C compiler, Python 3 and git:

```sh
git clone --recursive https://github.com/tuna-os/tuta-unofficial-sdk
cd tuta-unofficial-sdk
sh prepare.sh
cargo build --locked
cargo test --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt -p tuta-unofficial-sdk -p tuta-helper --check
cargo deny check
```

`git submodule update --init --recursive` fetches the submodules of an
existing clone. `prepare.sh` is a quick no-op when `prepared/` is current;
run it again after updating the submodule or `sdk-patches/`.

The example signs in, lists the folders, reads the newest Inbox mail and
closes its session again:

```sh
TUTA_EMAIL=ada@tuta.com cargo run --example read_mail   # password on stdin
```

### Live tests

The unit tests never touch the network. Two live tests, `#[ignore]`d and
gated on `TUTA_LIVE=1`, run against Tuta's servers with a test account's
`TUTA_LIVE_EMAIL`, `TUTA_LIVE_PASSWORD` and, when it has a second factor,
`TUTA_LIVE_TOTP`:

```sh
TUTA_LIVE=1 TUTA_LIVE_EMAIL=... TUTA_LIVE_PASSWORD=... TUTA_LIVE_TOTP=... \
    cargo test -p tuta-unofficial-sdk --test live -- --ignored
TUTA_LIVE=1 ... cargo test -p tuta-helper --test live -- --ignored
```

The library's signs in once, lists folders and labels, resumes the saved
session, saves, updates and discards a draft, watches the event bus, sends
one confidential mail with an attachment to the account itself, reads the
received copy back (body, attachment, MIME), marks it read, and deletes both
copies for good before closing its session. The helper's signs in once
through the binary, syncs, reads the newest mail through the `hylki-tuta`
name and lists labels, then revokes the session; it sends nothing. A TOTP
code is good for one sign-in: take a fresh one for each.

## Packaging

The Flatpak build has no network, so `cargo-sources.json` lists every crate
from `Cargo.lock` for flatpak-builder. Regenerate it after any `Cargo.lock`
change, or the offline build fails:

```sh
scripts/cargo-sources.sh   # needs curl and uv
```

It runs flatpak-builder-tools' `flatpak-cargo-generator.py` at a pinned
commit, checked against its SHA-256. CI fails when the committed file is
stale.

The binary is built as `tuta-helper`. A package that replaces Hylki's
helper installs it (or a symlink to it) as `hylki-tuta`, for example
`install -Dm755 target/release/tuta-helper /app/bin/tuta-helper` and
`ln -s tuta-helper /app/bin/hylki-tuta`.

## Patches policy

- A patch to the SDK exposes what the official client already does, with a
  pointer to the TypeScript it ports; it adds no cryptography, and it is
  as small as the job allows. Behaviour that can live in this repository's
  own code lives there instead.
- Patches apply in name order (`NN-topic.patch`) to the SDK prepared by
  tutabridge, and `prepare.sh` refuses one that does not apply cleanly.
- Each patch's description stays current in the
  [Security model](#security-model) list.
- When tutabridge moves its SDK pin, every patch is reviewed against the new
  `upstream/sdk/EXPECTED` and rebased or dropped; a patch Tuta merges
  upstream is dropped.

## Debugging

With `TUTA_SDK_DEBUG=1` (or `TUTA_HELPER_DEBUG=1` for the helper,
`HYLKI_TUTA_DEBUG=1` under the `hylki-tuta` name) in the environment, the
library writes diagnostics to stderr, each line prefixed with the program's
name: every HTTP request as method, service path and status (no host, query,
body or ids), and the Debug form of every SDK error with the stage it broke
in (sign-in, recipient resolution, recipient keys, secure external keys,
blob upload, draft create, draft load, attachment keys, send draft, draft
cleanup, the parent's reply mark, contact load, contact create, contact
password, folder and label services, deletes, the event bus). Addresses,
ids, tokens and key bytes are redacted, and no message content or password
is printed. A caller that discards the helper's stderr sees none of it, so
run the helper by hand to see it.

## Known limits

- Two-factor sign-in supports TOTP only; U2F and WebAuthn keys are not
  supported.
- Recipient keys are not verified (see Delivery).
- Password-protected delivery is the official client's, with three
  differences. The notification to the recipient is always in English (the
  official composer lets the sender choose its language). A contact that
  another Tuta app stored with AEAD encryption cannot be written, so its
  password is not updated (`contacts_saved` false). And a new contact is
  created only for a password-protected recipient, never for other
  recipients, which the official client also stores unless the account
  turned automatic contacts off.
- The first password-protected send to an address creates an external user
  for it on the server, and this SDK offers no way to remove one. A later
  send to that address uses it again.
- Password-protected delivery is refused from a shared mailbox and for an
  external (secure-mail) user, as in the official client.
- Stars are not stored on the server.
- Importing (`import`) needs a Legend or Unlimited plan, as in Tuta's own
  app; on any other plan it is refused before anything is written.
- `watch` reports which folders changed, not what changed in them; the caller
  syncs those folders. Missed batches are replayed only while one `watch`
  runs: a new `watch` starts from the present.
- Sessions are not refreshed. Each helper operation resumes the stored
  session, and a revoked or expired one means signing in again.
- The SDK prints some progress to stdout. The helper parks fd 1 while it
  runs; an in-process caller that needs a clean stdout must do the same.

## License

GPL-3.0-or-later (see `LICENSE`), as the Tuta SDK and tutabridge are. The
helper runs as a separate program from its caller.
