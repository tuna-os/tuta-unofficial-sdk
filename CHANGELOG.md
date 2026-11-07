# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (0.x: the API may still change).

## [0.3.0] - 2026-11-07

### Added

- `search`: find mail by `keyword`, `subject`, `sender`, `recipient`,
  received date (`after_ms`, `before_ms`) and read state, in one folder or
  label or in every folder. Tuta has no server-side search on any plan, so
  this is a bounded, resumable scan: each call examines at most 500 mails,
  downloads at most 50 bodies (only for mails a header could not decide),
  stops after 30 seconds or `limit` matches, and returns `next_cursor` to go
  on from. Date bounds come from the entry ids, without loading mail
  outside them (`Session::search`, the `search` module; Kotlin
  `TutaClient.search`, `SearchQuery`, `SearchPage`). (#4)
- `get_mime`: a mail rebuilt as RFC 5322 MIME, base64 on the wire, for
  `.eml` export (Kotlin `TutaClient.getMime`). (#5)
- `cancel_sign_in`: give up a sign-in waiting for its second factor; Tuta
  drops the pending session instead of keeping it until it expires, and a
  session whose code already went through is revoked
  (`Client::cancel_sign_in`, Kotlin `TutaClient.cancelSignIn`).
  `06-cancel-second-factor.patch` adds `Sdk::cancel_second_factor`, the
  official client's unauthenticated `SecondFactorAuthService` DELETE. (#6)
- Golden `.eml` files pin the MIME output (`testdata/mime`).

### Changed

- `Message::to_mime` puts inline images (attachments with a Content-ID) in
  a `multipart/related` beside the HTML body, with `Content-Disposition:
  inline`, and only the other attachments in `multipart/mixed`, as Tuna
  Mail's own MIME builder did. The boundaries are now
  `=_tuta-unofficial-sdk-mixed` and `=_tuta-unofficial-sdk-related`.

## [0.2.1] - 2026-11-07

### Fixed

- A sign-in with a second factor no longer opens a second session for the
  code. `login` without a code used to drop the session Tuta had opened, so
  the retry with the code started another sign-in, which Tuta throttles
  (seen as "could not reach the server"). The `second_factor_required` error
  now carries `pending_session`, and `login` with `pending_session` and
  `totp` completes that session (`Client::sign_in`,
  `Client::complete_sign_in`, `PendingSession`, `SignInError`; Kotlin
  `TutaException.pendingSession`, `TutaClient.login(..., pending)`). A
  refused or malformed code, an outage or throttling hands it back again.

### Added

- `rate_limited`: Tuta throttling (HTTP 429, or too many wrong
  second-factor codes), wherever it used to read as `transport_failed`,
  the watch included.
- `pending_session_expired`: a pending sign-in the server let go.

## [0.2.0] - 2026-11-07

### Added

- `tuta-sdk-android` (`org.tunaos.tuta:tuta-sdk-android`), the helper
  protocol in process for Android and the JVM: `crates/tuta-ffi` exposes it
  through uniffi as `libtuta_ffi` (`request`, `watch` with a listener and a
  stop handle, the error code list), and a Kotlin layer types it
  (`TutaClient`, `TutaSession`, data classes, `TutaException` by family with
  `TutaErrorCode`, `watch` as a `Flow`). The AAR carries arm64-v8a and
  x86_64 libraries built with cargo-ndk, minSdk 24; releases attach it and a
  zipped Maven repository.
- JVM tests of the Kotlin layer against a host-built library, and an
  ignored live test through it.
- `crates/tuta-ffi-bindgen`, `uniffi-bindgen` at the uniffi revision the
  SDK links.
- CI builds the AAR, runs the JVM tests, and attaches the Android assets to
  the release of a tag.
- `05-quiet-type-model-fetch.patch`: the SDK no longer prints to stdout.

### Changed

- `tuta-helper` is also a library: the protocol (`respond`, `watch::serve`)
  is shared by the binary and `tuta-ffi`, with no change on the wire.

## [0.1.0] - 2026-11-05

The first release, extracted from the `hylki-tuta` helper of the Hylki mail
client (`native/tuta` on Hylki's `feat/tuta-native` branch) with its
history.

### Added

- `tuta-unofficial-sdk`, a library with a typed async API: sign-in with
  TOTP, saved and resumed sessions, revoking; folders, labels, folder pages
  and decrypted messages (also as RFC 5322 MIME); read state, moves,
  labels, permanent deletes, emptying Trash and Spam; folder and label
  management; drafts; ordinary, confidential and password-protected
  sending with threading and the uncertain-versus-definite outcome rules
  (`Session::send_within` keeps them under a time limit); contact
  passwords; MIME import; the event bus as a `Stream`.
- `Error`, one enum carrying the helper protocol's fixed codes.
- `tuta-helper`, the JSON-over-stdio front end with hylki-tuta's protocol,
  answering as `hylki-tuta` when started under that name.
- The `read_mail` example, `#[ignore]`d live tests gated on `TUTA_LIVE=1`,
  and offline contract probes of the helper binary.
- CI (tests, clippy, rustfmt, cargo-deny, a current `cargo-sources.json`),
  `scripts/cargo-sources.sh` for Flatpak builds, and `scripts/vendor.sh`
  for the `vX.Y.Z-vendored` tags a Cargo git dependency builds from.

### Changed from hylki-tuta

The protocol is the same, and the replies are byte for byte the same for the
same server answers. Where the helper differs:

- Under its own name the binary is `tuta-helper`: sessions are named
  "tuta-helper" in the account's session list and diagnostics follow
  `TUTA_HELPER_DEBUG=1` with the `tuta-helper:` prefix. Under the name
  `hylki-tuta` both are as before ("Hylki", `HYLKI_TUTA_DEBUG=1`,
  `hylki-tuta:`). `TUTA_SDK_DEBUG=1` also turns diagnostics on.
- `send` and `save_draft` decode their attachments' base64 before the
  session is resumed, so a request with undecodable attachment data is
  `attachment_failed` without contacting the server. hylki-tuta resumed
  first (and for `save_draft` looked up the sender and the draft), so a
  request with a second, server-side fault could report that one instead.
- `sync` with a `folder` that is not a compound id is `folder_not_found`
  without loading the mailbox; hylki-tuta loaded it first and reported
  `request_failed` if that load failed.
- A `revoke` the server refuses also writes a diagnostic line (when
  diagnostics are on).
- `prepared/sdk/EXPECTED` lists our SDK patches as `unofficial-<name>`
  instead of `hylki-<name>`.
