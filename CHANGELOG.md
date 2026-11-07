# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (0.x: the API may still change).

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
