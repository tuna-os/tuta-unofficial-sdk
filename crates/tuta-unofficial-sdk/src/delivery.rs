//! How a send is delivered: confidentially (end-to-end encrypted: Tuta
//! recipients through their public keys, recipients elsewhere through a
//! password) or ordinarily, and the key material each mode hands
//! `SendDraftService`. Mirrors the official client's `MailFacade.sendDraft`.
//!
//! No public-key or passphrase cryptography happens here. Recipient keys are
//! loaded and the bucket key is encrypted for them inside the SDK, through the
//! audited `AsymmetricCryptoFacade` path that Hylki's SDK patch exposes
//! (`sdk-patches/01-recipient-key-data.patch`), and a password-protected
//! recipient's key data is built there too
//! (`sdk-patches/04-secure-external-recipient.patch`); this module only wraps
//! symmetric keys with the SDK's own AES functions, as the ordinary path
//! already did.
//!
//! Key verification: the official client only refuses a key that differs from
//! one the user verified by hand. Hylki has no verified contacts, so the
//! current key from the PublicKeyService is used, as the official client does
//! for every unverified contact. Each recipient's key version and fingerprint
//! is reported back, so a caller can pin keys (trust on first use) later.

use crate::secure_external::Passwords;
use crate::{aggregate_id, diag, RecipientKind, Result, SEND_LANGUAGE};
use crypto_primitives::{
    aes::InitializationVector, key::GenericAesKey, randomizer_facade::RandomizerFacade,
};
use serde_json::{json, Value};
use std::sync::Mutex;
use tutasdk::{
    crypto::asymmetric_crypto_facade::{
        AsymmetricCryptoError, InternalRecipientKey, InternalRecipientKeyError,
    },
    crypto::public_key_provider::PublicKeyLoadingError,
    crypto::secure_external_facade::{SecureExternalRecipient, SecureExternalRecipientError},
    entities::generated::tutanota::{
        AttachmentKeyData, InternalRecipientKeyData, SecureExternalRecipientKeyData, SendDraftData,
        SendDraftParameters,
    },
    tutanota_constants::{CryptoProtocolVersion, EncryptionAuthStatus},
    ApiCallError, GeneratedId, IdTupleGenerated, LoggedInSdk,
};

/// How a send goes out, decided from its recipients before anything is
/// written server-side.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// End-to-end encrypted for every recipient: the Tuta ones (`internal`)
    /// through their public keys, the others (`external`) through the
    /// password each was given. Distinct addresses, request order.
    Confidential {
        internal: Vec<String>,
        external: Vec<String>,
    },
    /// Encrypted in transit only, for everyone. Carries the (internal,
    /// external) counts, or None when a lookup failed but an external
    /// recipient settled the mode anyway.
    Ordinary(Option<(usize, usize)>),
}

/// The official client's rule: a mail is confidential when the user asked
/// for it or when no recipient is external (`SendMailModel.isConfidential()`
/// is `confidential || !containsExternalRecipients()`). So an all-Tuta send
/// is always encrypted end to end and needs no consent, whatever
/// `confidential` says; a confidential send with recipients outside Tuta
/// reaches them password-protected; ordinary delivery reaches every
/// recipient of a mixed send alike.
///
/// `recipients` pairs each distinct address with its kind. Refusals, all
/// definitive and before any server-side write:
/// - confidential, and a recipient outside Tuta has no password:
///   `password_required`, naming nobody (TS `noPreSharedPassword_msg`).
/// - ordinary delivery without `ordinary_confirmed`.
/// - a failed lookup where it decides the mode or a recipient's key: the
///   lookup's own code. An ordinary send to someone outside Tuta needs no
///   key, so a failed lookup does not stop it.
pub(crate) fn plan(
    confidential: bool,
    ordinary_confirmed: bool,
    recipients: &[(String, RecipientKind)],
    passwords: &Passwords,
) -> Result<Plan> {
    let of_kind = |wanted: RecipientKind| -> Vec<String> {
        recipients
            .iter()
            .filter(|(_, kind)| *kind == wanted)
            .map(|(address, _)| address.clone())
            .collect()
    };
    let (internal, external) = (
        of_kind(RecipientKind::Internal),
        of_kind(RecipientKind::External),
    );
    let unknown = recipients.iter().find_map(|(_, kind)| match kind {
        RecipientKind::Unknown(code) => Some(*code),
        _ => None,
    });
    if external.is_empty() || confidential {
        if external
            .iter()
            .any(|address| passwords.get(address).is_none())
        {
            return Err("password_required");
        }
        if let Some(code) = unknown {
            return Err(code);
        }
        return Ok(Plan::Confidential { internal, external });
    }
    if !ordinary_confirmed {
        return Err("ordinary_delivery_requires_consent");
    }
    Ok(Plan::Ordinary(
        unknown
            .is_none()
            .then_some((internal.len(), external.len())),
    ))
}

/// Every address once, first spelling kept: the official client files one
/// key-data entry per recipient, and a To that repeats in Cc is still one.
pub(crate) fn unique_addresses(addresses: &[String]) -> Vec<String> {
    let mut unique: Vec<String> = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.iter().any(|seen| seen.eq_ignore_ascii_case(address)) {
            unique.push(address.clone());
        }
    }
    unique
}

/// The bucket key encrypted for every recipient, by the SDK. Unknown Tuta
/// addresses refuse the whole send (`recipient_not_found`) -- a confidential
/// mail is never downgraded, as in the official client.
pub(crate) async fn recipient_keys(
    sdk: &LoggedInSdk,
    sender_mail_group_id: &GeneratedId,
    bucket_key: &GenericAesKey,
    addresses: &[String],
) -> Result<Vec<InternalRecipientKey>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    sdk.encrypt_bucket_key_for_internal_recipients(sender_mail_group_id, bucket_key, addresses)
        .await
        .map_err(|error| match error {
            // Its Debug form lists addresses: count them instead.
            InternalRecipientKeyError::RecipientsNotFound(missing) => {
                diag::note(&format!("recipient keys: {} not found", missing.len()));
                "recipient_not_found"
            }
            InternalRecipientKeyError::ExternalSender => {
                diag::note("recipient keys: external sender");
                "send_failed"
            }
            InternalRecipientKeyError::Crypto(error) => {
                diag::failed("recipient keys", &error);
                match error {
                    AsymmetricCryptoError::ApiCall(ApiCallError::RestClient { .. })
                    | AsymmetricCryptoError::PublicKeyLoadingError(
                        PublicKeyLoadingError::KeyLoadingError(ApiCallError::RestClient { .. }),
                    ) => "transport_failed",
                    _ => "send_failed",
                }
            }
        })
}

/// The bucket key for every recipient outside Tuta, behind the password the
/// sender gave them, by the SDK: it derives the password key (Argon2id over a
/// fresh salt) and creates the recipient's external user on first use.
/// `plan` has checked every password is there.
pub(crate) async fn secure_external_keys(
    sdk: &LoggedInSdk,
    sender_mail_group_id: &GeneratedId,
    bucket_key: &GenericAesKey,
    addresses: &[String],
    passwords: &Passwords,
) -> Result<Vec<SecureExternalRecipientKeyData>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let recipients: Vec<SecureExternalRecipient> = addresses
        .iter()
        .map(|address| SecureExternalRecipient {
            mail_address: address,
            passphrase: passwords.get(address).unwrap_or_default(),
        })
        .collect();
    sdk.secure_external_recipient_key_data(sender_mail_group_id, bucket_key, &recipients)
        .await
        .map_err(|error| match error {
            // Its Debug form lists addresses: count them instead.
            SecureExternalRecipientError::MissingPassphrase(missing) => {
                diag::note(&format!(
                    "secure external keys: {} without a password",
                    missing.len()
                ));
                "password_required"
            }
            SecureExternalRecipientError::ExternalSender
            | SecureExternalRecipientError::SharedMailboxSender => {
                diag::failed("secure external keys", &error);
                "secure_external_sender_unsupported"
            }
            error => {
                diag::failed("secure external keys", &error);
                match error {
                    SecureExternalRecipientError::ApiCall(ApiCallError::RestClient { .. }) => {
                        "transport_failed"
                    }
                    _ => "send_failed",
                }
            }
        })
}

/// What a recipient's key looked like, for the send reply: never key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecipientReport {
    address: String,
    key_version: i64,
    protocol: &'static str,
    fingerprint: String,
}

impl RecipientReport {
    pub(crate) fn of(key: &InternalRecipientKey) -> Self {
        let protocol = if key.key_data.protocolVersion == CryptoProtocolVersion::TutaCrypt as i64 {
            "tuta_crypt"
        } else {
            "rsa"
        };
        Self {
            address: key.key_data.mailAddress.clone(),
            key_version: key.key_data.recipientKeyVersion,
            protocol,
            fingerprint: key
                .public_key_fingerprint
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    fn to_json(&self) -> Value {
        json!({"address": self.address, "key_version": self.key_version,
            "protocol": self.protocol, "fingerprint": self.fingerprint})
    }
}

/// The mode a submitted send went out in, as the reply reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Delivered {
    pub(crate) confidential: bool,
    pub(crate) recipients: Vec<RecipientReport>,
    /// The recipients outside Tuta that got it password-protected.
    pub(crate) secure_external: Vec<String>,
}

impl Delivered {
    pub(crate) fn to_json(&self) -> Value {
        json!({"confidential": self.confidential,
            "recipients": self.recipients.iter().map(RecipientReport::to_json).collect::<Vec<_>>(),
            "secure_external": self.secure_external})
    }
}

// Recorded just before the submit, so a run that overruns its timeout after
// the submit still reports the mode the mail went out in.
static DELIVERED: Mutex<Option<Delivered>> = Mutex::new(None);

pub(crate) fn record(delivered: &Delivered) {
    *DELIVERED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(delivered.clone());
}

pub(crate) fn recorded() -> Option<Delivered> {
    DELIVERED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// The key material a send hands the server, per mode.
pub(crate) struct MailKeys {
    mail_session_key: Option<Vec<u8>>,
    bucket_enc_mail_session_key: Option<Vec<u8>>,
    attachment_keys: Vec<AttachmentKeyData>,
    internal_recipient_key_data: Vec<InternalRecipientKeyData>,
    secure_external_recipient_key_data: Vec<SecureExternalRecipientKeyData>,
    sender_name_unencrypted: Option<String>,
    session_enc_encryption_auth_status: Option<Vec<u8>>,
}

/// A confidential send's per-recipient key data, as the SDK built it.
pub(crate) struct RecipientKeyData {
    pub(crate) internal: Vec<InternalRecipientKeyData>,
    pub(crate) secure_external: Vec<SecureExternalRecipientKeyData>,
}

/// Ordinary delivery hands the server the clear session keys, exactly as the
/// official client does for a non-confidential draft. There is no bucket.
pub(crate) fn ordinary_keys(
    mail_session_key: &GenericAesKey,
    files: &[(IdTupleGenerated, GenericAesKey)],
) -> MailKeys {
    MailKeys {
        mail_session_key: Some(mail_session_key.as_bytes().to_vec()),
        bucket_enc_mail_session_key: None,
        attachment_keys: files
            .iter()
            .map(|(file, key)| AttachmentKeyData {
                _id: None,
                bucketEncFileSessionKey: None,
                fileSessionKey: Some(key.as_bytes().to_vec()),
                file: file.clone(),
            })
            .collect(),
        internal_recipient_key_data: Vec::new(),
        secure_external_recipient_key_data: Vec::new(),
        sender_name_unencrypted: None,
        session_enc_encryption_auth_status: None,
    }
}

/// Confidential delivery never shows the server a session key: the mail's
/// and every attachment's are wrapped with the bucket key, which only the
/// recipients can unwrap. When every recipient key is TutaCrypt the mail also
/// carries its own authentication status (`TutacryptSender`) encrypted with
/// the mail session key, as `MailFacade.isTutaCryptMail` decides; any
/// password-protected recipient rules that out. The server's notification
/// to such a recipient names the sender, so the mail then carries
/// `sender_name` in the clear, as the official client sends it.
pub(crate) fn confidential_keys(
    bucket_key: &GenericAesKey,
    mail_session_key: &GenericAesKey,
    files: &[(IdTupleGenerated, GenericAesKey)],
    recipients: RecipientKeyData,
    sender_name: &str,
    randomizer: &RandomizerFacade,
) -> Result<MailKeys> {
    let wrap = |key: &GenericAesKey| {
        bucket_key.encrypt_key(key, InitializationVector::generate(randomizer))
    };
    let is_tuta_crypt = recipients.secure_external.is_empty()
        && !recipients.internal.is_empty()
        && recipients
            .internal
            .iter()
            .all(|r| r.protocolVersion == CryptoProtocolVersion::TutaCrypt as i64);
    let session_enc_encryption_auth_status = if is_tuta_crypt {
        let status = (EncryptionAuthStatus::TutacryptSender as i64).to_string();
        Some(
            mail_session_key
                .encrypt_data(
                    status.as_bytes(),
                    InitializationVector::generate(randomizer),
                )
                .map_err(diag::fail("auth status", "send_failed"))?,
        )
    } else {
        None
    };
    let sender_name_unencrypted =
        (!recipients.secure_external.is_empty()).then(|| sender_name.to_string());
    Ok(MailKeys {
        mail_session_key: None,
        bucket_enc_mail_session_key: Some(wrap(mail_session_key)),
        attachment_keys: files
            .iter()
            .map(|(file, key)| AttachmentKeyData {
                _id: None,
                bucketEncFileSessionKey: Some(wrap(key)),
                fileSessionKey: None,
                file: file.clone(),
            })
            .collect(),
        internal_recipient_key_data: recipients.internal,
        secure_external_recipient_key_data: recipients.secure_external,
        sender_name_unencrypted,
        session_enc_encryption_auth_status,
    })
}

/// The submit for a staged draft. Its two copies (top level and
/// `parameters`) carry the same keys, as in the official client; every
/// aggregate gets its own id, since `SendDraftData` is not encrypted and the
/// SDK only fills missing ids in while encrypting.
pub(crate) fn send_payload(
    draft: IdTupleGenerated,
    keys: MailKeys,
    randomizer: &RandomizerFacade,
) -> SendDraftData {
    let attachments = || -> Vec<AttachmentKeyData> {
        keys.attachment_keys
            .iter()
            .map(|key| AttachmentKeyData {
                _id: aggregate_id(randomizer),
                ..key.clone()
            })
            .collect()
    };
    let recipients = || -> Vec<InternalRecipientKeyData> {
        keys.internal_recipient_key_data
            .iter()
            .map(|key| InternalRecipientKeyData {
                _id: aggregate_id(randomizer),
                ..key.clone()
            })
            .collect()
    };
    let secure_externals = || -> Vec<SecureExternalRecipientKeyData> {
        keys.secure_external_recipient_key_data
            .iter()
            .map(|key| SecureExternalRecipientKeyData {
                _id: aggregate_id(randomizer),
                ..key.clone()
            })
            .collect()
    };
    SendDraftData {
        _format: 0,
        language: SEND_LANGUAGE.to_string(),
        mailSessionKey: keys.mail_session_key.clone(),
        bucketEncMailSessionKey: keys.bucket_enc_mail_session_key.clone(),
        // Only a secure-external recipient's notification mail reads it.
        senderNameUnencrypted: keys.sender_name_unencrypted.clone(),
        // Plaintext stays off in both copies: the official client reads the
        // account's sendPlaintextOnly property, but Hylki has no such
        // setting and always composes HTML, so the flag matches the content
        // rather than a server-side switch the user cannot see here.
        plaintext: false,
        calendarMethod: false,
        sessionEncEncryptionAuthStatus: keys.session_enc_encryption_auth_status.clone(),
        sendAt: None,
        allowUndo: false,
        internalRecipientKeyData: recipients(),
        secureExternalRecipientKeyData: secure_externals(),
        attachmentKeyData: attachments(),
        mail: draft.clone(),
        symEncInternalRecipientKeyData: Vec::new(),
        parameters: Some(SendDraftParameters {
            _id: aggregate_id(randomizer),
            language: SEND_LANGUAGE.to_string(),
            mailSessionKey: keys.mail_session_key.clone(),
            bucketEncMailSessionKey: keys.bucket_enc_mail_session_key.clone(),
            senderNameUnencrypted: keys.sender_name_unencrypted.clone(),
            plaintext: false,
            calendarMethod: false,
            sessionEncEncryptionAuthStatus: keys.session_enc_encryption_auth_status.clone(),
            mail: draft,
            internalRecipientKeyData: recipients(),
            secureExternalRecipientKeyData: secure_externals(),
            symEncInternalRecipientKeyData: Vec::new(),
            attachmentKeyData: attachments(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use crypto_primitives::aes::Aes256Key;
    use tutasdk::CustomId;
    use RecipientKind::*;

    fn random_key(randomizer: &RandomizerFacade) -> GenericAesKey {
        GenericAesKey::Aes256(Aes256Key::generate(randomizer))
    }

    fn draft() -> IdTupleGenerated {
        IdTupleGenerated::new(GeneratedId("list".into()), GeneratedId("mail".into()))
    }

    fn file(element: &str) -> IdTupleGenerated {
        IdTupleGenerated::new(GeneratedId("files".into()), GeneratedId(element.into()))
    }

    fn recipient(address: &str, protocol: CryptoProtocolVersion) -> InternalRecipientKeyData {
        InternalRecipientKeyData {
            _id: None,
            mailAddress: address.to_string(),
            pubEncBucketKey: vec![9; 64],
            recipientKeyVersion: 2,
            protocolVersion: protocol as i64,
            senderKeyVersion: Some(1),
        }
    }

    /// Recipients `r0@example.org`, `r1@example.org`, ... of these kinds.
    fn people(kinds: &[RecipientKind]) -> Vec<(String, RecipientKind)> {
        kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| (format!("r{i}@example.org"), *kind))
            .collect()
    }

    fn passwords(json: &str) -> Passwords {
        serde_json::from_str(json).unwrap()
    }

    fn addresses(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn an_all_tuta_send_is_confidential_without_consent() {
        for confidential in [false, true] {
            for confirmed in [false, true] {
                assert_eq!(
                    plan(
                        confidential,
                        confirmed,
                        &people(&[Internal]),
                        &Passwords::default()
                    ),
                    Ok(Plan::Confidential {
                        internal: addresses(&["r0@example.org"]),
                        external: Vec::new(),
                    })
                );
            }
        }
    }

    #[test]
    fn a_confidential_send_reaches_outside_tuta_with_a_password_for_everyone() {
        let with_password = passwords(r#"{"R1@Example.org":" pw ","r2@example.org":"x"}"#);
        for confirmed in [false, true] {
            assert_eq!(
                plan(
                    true,
                    confirmed,
                    &people(&[Internal, External, External]),
                    &with_password
                ),
                Ok(Plan::Confidential {
                    internal: addresses(&["r0@example.org"]),
                    external: addresses(&["r1@example.org", "r2@example.org"]),
                })
            );
        }
        assert_eq!(
            plan(
                true,
                false,
                &people(&[External]),
                &passwords(r#"{"r0@example.org":"pw"}"#)
            ),
            Ok(Plan::Confidential {
                internal: Vec::new(),
                external: addresses(&["r0@example.org"]),
            })
        );
    }

    #[test]
    fn a_confidential_send_without_every_password_is_refused() {
        for given in [
            r#"{}"#,
            r#"{"r1@example.org":"pw"}"#,
            r#"{"r1@example.org":"pw","r2@example.org":"   "}"#,
        ] {
            assert_eq!(
                plan(
                    true,
                    true,
                    &people(&[Internal, External, External]),
                    &passwords(given)
                ),
                Err("password_required"),
                "{given}"
            );
        }
    }

    #[test]
    fn a_mixed_send_is_ordinary_for_everyone_only_with_consent() {
        // Passwords given or not, an ordinary send ignores them.
        let given = passwords(r#"{"r1@example.org":"pw"}"#);
        assert_eq!(
            plan(false, true, &people(&[Internal, External]), &given),
            Ok(Plan::Ordinary(Some((1, 1))))
        );
        assert_eq!(
            plan(false, true, &people(&[External]), &Passwords::default()),
            Ok(Plan::Ordinary(Some((0, 1))))
        );
        assert_eq!(
            plan(false, false, &people(&[Internal, External]), &given),
            Err("ordinary_delivery_requires_consent")
        );
        // A failed lookup leaves the counts unknown, not the send.
        assert_eq!(
            plan(
                false,
                true,
                &people(&[External, Unknown("transport_failed")]),
                &Passwords::default()
            ),
            Ok(Plan::Ordinary(None))
        );
    }

    #[test]
    fn an_undecidable_confidential_send_refuses_with_the_lookup_code() {
        assert_eq!(
            plan(
                false,
                true,
                &people(&[Internal, Unknown("transport_failed")]),
                &Passwords::default()
            ),
            Err("transport_failed")
        );
        assert_eq!(
            plan(
                true,
                false,
                &people(&[Unknown("send_failed")]),
                &Passwords::default()
            ),
            Err("send_failed")
        );
        // Confidential with someone outside Tuta: an unknown recipient might
        // need a password or a key, so the send cannot go.
        assert_eq!(
            plan(
                true,
                true,
                &people(&[External, Unknown("transport_failed")]),
                &passwords(r#"{"r0@example.org":"pw"}"#)
            ),
            Err("transport_failed")
        );
    }

    #[test]
    fn repeated_recipients_get_one_key_entry() {
        let addresses = [
            "ada@tuta.com".to_string(),
            "bo@tuta.com".to_string(),
            "Ada@Tuta.com".to_string(),
        ];
        assert_eq!(
            unique_addresses(&addresses),
            ["ada@tuta.com", "bo@tuta.com"]
        );
    }

    #[test]
    fn confidential_keys_hide_every_session_key_behind_the_bucket() {
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let bucket_key = random_key(&randomizer);
        let mail_session_key = random_key(&randomizer);
        let files = [
            (file("a"), random_key(&randomizer)),
            (file("b"), random_key(&randomizer)),
        ];
        let keys = confidential_keys(
            &bucket_key,
            &mail_session_key,
            &files,
            internal_only(vec![recipient(
                "ada@tuta.com",
                CryptoProtocolVersion::TutaCrypt,
            )]),
            "Me",
            &randomizer,
        )
        .unwrap();
        let payload = send_payload(draft(), keys, &randomizer);
        let parameters = payload.parameters.as_ref().unwrap();
        for (session, bucket_enc) in [
            (&payload.mailSessionKey, &payload.bucketEncMailSessionKey),
            (
                &parameters.mailSessionKey,
                &parameters.bucketEncMailSessionKey,
            ),
        ] {
            assert!(session.is_none());
            let unwrapped = bucket_key
                .decrypt_aes_key(bucket_enc.as_ref().unwrap())
                .unwrap();
            assert_eq!(unwrapped.as_bytes(), mail_session_key.as_bytes());
        }
        for attachment_keys in [&payload.attachmentKeyData, &parameters.attachmentKeyData] {
            assert_eq!(attachment_keys.len(), 2);
            for (data, (file, key)) in attachment_keys.iter().zip(&files) {
                assert_eq!(&data.file, file);
                assert!(data.fileSessionKey.is_none());
                let unwrapped = bucket_key
                    .decrypt_aes_key(data.bucketEncFileSessionKey.as_ref().unwrap())
                    .unwrap();
                assert_eq!(unwrapped.as_bytes(), key.as_bytes());
            }
        }
        for recipients in [
            &payload.internalRecipientKeyData,
            &parameters.internalRecipientKeyData,
        ] {
            assert_eq!(recipients.len(), 1);
            assert_eq!(recipients[0].mailAddress, "ada@tuta.com");
            assert_eq!(recipients[0].pubEncBucketKey, vec![9; 64]);
        }
        // All TutaCrypt: the mail carries "sent by me" under its own key.
        for status in [
            &payload.sessionEncEncryptionAuthStatus,
            &parameters.sessionEncEncryptionAuthStatus,
        ] {
            let decrypted = mail_session_key
                .decrypt_data(status.as_ref().unwrap())
                .unwrap();
            assert_eq!(decrypted, b"4");
        }
        assert!(payload.secureExternalRecipientKeyData.is_empty());
        assert!(payload.symEncInternalRecipientKeyData.is_empty());
        assert!(payload.senderNameUnencrypted.is_none());
    }

    #[test]
    fn a_legacy_rsa_recipient_drops_the_auth_status() {
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let keys = confidential_keys(
            &random_key(&randomizer),
            &random_key(&randomizer),
            &[],
            internal_only(vec![
                recipient("ada@tuta.com", CryptoProtocolVersion::TutaCrypt),
                recipient("old@tutanota.de", CryptoProtocolVersion::Rsa),
            ]),
            "Me",
            &randomizer,
        )
        .unwrap();
        let payload = send_payload(draft(), keys, &randomizer);
        assert!(payload.sessionEncEncryptionAuthStatus.is_none());
        assert!(payload
            .parameters
            .unwrap()
            .sessionEncEncryptionAuthStatus
            .is_none());
    }

    fn internal_only(internal: Vec<InternalRecipientKeyData>) -> RecipientKeyData {
        RecipientKeyData {
            internal,
            secure_external: Vec::new(),
        }
    }

    fn secure_external(address: &str) -> SecureExternalRecipientKeyData {
        SecureExternalRecipientKeyData {
            _id: None,
            mailAddress: address.to_string(),
            passwordVerifier: vec![1; 32],
            salt: Some(vec![2; 16]),
            saltHash: Some(vec![3; 32]),
            pwEncCommunicationKey: Some(vec![4; 64]),
            ownerEncBucketKey: vec![5; 64],
            kdfVersion: 1,
            ownerKeyVersion: 0,
            userGroupKeyVersion: 0,
        }
    }

    #[test]
    fn a_password_protected_recipient_names_the_sender_and_drops_the_auth_status() {
        // TS `isTutaCryptMail`: a secure external recipient makes the mail
        // non-TutaCrypt even when every Tuta recipient's key is TutaCrypt.
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let bucket_key = random_key(&randomizer);
        let mail_session_key = random_key(&randomizer);
        let keys = confidential_keys(
            &bucket_key,
            &mail_session_key,
            &[(file("a"), random_key(&randomizer))],
            RecipientKeyData {
                internal: vec![recipient("ada@tuta.com", CryptoProtocolVersion::TutaCrypt)],
                secure_external: vec![secure_external("ext@example.org")],
            },
            "Me Myself",
            &randomizer,
        )
        .unwrap();
        let payload = send_payload(draft(), keys, &randomizer);
        let parameters = payload.parameters.as_ref().unwrap();
        assert!(payload.sessionEncEncryptionAuthStatus.is_none());
        assert!(parameters.sessionEncEncryptionAuthStatus.is_none());
        assert_eq!(payload.senderNameUnencrypted.as_deref(), Some("Me Myself"));
        assert_eq!(
            parameters.senderNameUnencrypted.as_deref(),
            Some("Me Myself")
        );
        for (externals, internals) in [
            (
                &payload.secureExternalRecipientKeyData,
                &payload.internalRecipientKeyData,
            ),
            (
                &parameters.secureExternalRecipientKeyData,
                &parameters.internalRecipientKeyData,
            ),
        ] {
            assert_eq!(externals.len(), 1);
            assert_eq!(internals.len(), 1);
            let external = &externals[0];
            assert_eq!(external.mailAddress, "ext@example.org");
            assert_eq!(external.ownerEncBucketKey, vec![5; 64]);
            let id = external._id.as_ref().expect("aggregate without an id");
            assert_eq!(URL_SAFE_NO_PAD.decode(id.as_str()).unwrap().len(), 4);
        }
        // Still confidential: no session key in the clear.
        assert!(payload.mailSessionKey.is_none());
        assert!(payload.attachmentKeyData[0].fileSessionKey.is_none());
        assert_eq!(
            bucket_key
                .decrypt_aes_key(payload.bucketEncMailSessionKey.as_ref().unwrap())
                .unwrap(),
            mail_session_key
        );

        // Only password-protected recipients: no auth status either.
        let keys = confidential_keys(
            &bucket_key,
            &mail_session_key,
            &[],
            RecipientKeyData {
                internal: Vec::new(),
                secure_external: vec![secure_external("ext@example.org")],
            },
            "Me",
            &randomizer,
        )
        .unwrap();
        let payload = send_payload(draft(), keys, &randomizer);
        assert!(payload.sessionEncEncryptionAuthStatus.is_none());
        assert!(payload.internalRecipientKeyData.is_empty());
        assert_eq!(payload.senderNameUnencrypted.as_deref(), Some("Me"));
    }

    #[test]
    fn ordinary_keys_are_clear_with_no_bucket() {
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let mail_session_key = random_key(&randomizer);
        let file_key = random_key(&randomizer);
        let keys = ordinary_keys(&mail_session_key, &[(file("a"), file_key.clone())]);
        let payload = send_payload(draft(), keys, &randomizer);
        let parameters = payload.parameters.as_ref().unwrap();
        for (session, bucket_enc, status) in [
            (
                &payload.mailSessionKey,
                &payload.bucketEncMailSessionKey,
                &payload.sessionEncEncryptionAuthStatus,
            ),
            (
                &parameters.mailSessionKey,
                &parameters.bucketEncMailSessionKey,
                &parameters.sessionEncEncryptionAuthStatus,
            ),
        ] {
            assert_eq!(session.as_deref(), Some(mail_session_key.as_bytes()));
            assert!(bucket_enc.is_none());
            assert!(status.is_none());
        }
        assert_eq!(
            payload.attachmentKeyData[0].fileSessionKey.as_deref(),
            Some(file_key.as_bytes())
        );
        assert!(payload.attachmentKeyData[0]
            .bucketEncFileSessionKey
            .is_none());
        assert!(payload.internalRecipientKeyData.is_empty());
        assert!(!payload.plaintext);
        assert_eq!(parameters.language, SEND_LANGUAGE);
    }

    #[test]
    fn every_send_payload_aggregate_carries_an_id() {
        // SendDraftData is not encrypted, so the SDK never fills a missing
        // aggregate id in, and its serializer refuses the submit before it
        // is sent ("Invalid value: ... TypeId(1788) _id", seen live).
        let randomizer = RandomizerFacade::from_core(rand_core::OsRng);
        let files = [
            (file("a"), random_key(&randomizer)),
            (file("b"), random_key(&randomizer)),
        ];
        let keys = confidential_keys(
            &random_key(&randomizer),
            &random_key(&randomizer),
            &files,
            internal_only(vec![
                recipient("ada@tuta.com", CryptoProtocolVersion::TutaCrypt),
                recipient("bo@tuta.com", CryptoProtocolVersion::TutaCrypt),
            ]),
            "Me",
            &randomizer,
        )
        .unwrap();
        let payload = send_payload(draft(), keys, &randomizer);
        let parameters = payload.parameters.as_ref().unwrap();
        let ids: Vec<&CustomId> = std::iter::once(&parameters._id)
            .chain(payload.attachmentKeyData.iter().map(|k| &k._id))
            .chain(parameters.attachmentKeyData.iter().map(|k| &k._id))
            .chain(payload.internalRecipientKeyData.iter().map(|k| &k._id))
            .chain(parameters.internalRecipientKeyData.iter().map(|k| &k._id))
            .map(|id| id.as_ref().expect("aggregate without an id"))
            .collect();
        assert_eq!(ids.len(), 9);
        for id in &ids {
            // Four random bytes, base64url without padding, as the SDK mints.
            assert_eq!(URL_SAFE_NO_PAD.decode(id.as_str()).unwrap().len(), 4);
        }
        // The file references survive, in order, in both copies.
        let files = |keys: &[AttachmentKeyData]| -> Vec<String> {
            keys.iter().map(|k| k.file.element_id.to_string()).collect()
        };
        assert_eq!(files(&payload.attachmentKeyData), ["a", "b"]);
        assert_eq!(files(&parameters.attachmentKeyData), ["a", "b"]);
    }

    #[test]
    fn the_reply_reports_key_versions_and_fingerprints_never_keys() {
        let key = InternalRecipientKey {
            key_data: recipient("ada@tuta.com", CryptoProtocolVersion::TutaCrypt),
            public_key_fingerprint: vec![0xab; 32],
        };
        let delivered = Delivered {
            confidential: true,
            recipients: vec![RecipientReport::of(&key)],
            secure_external: vec!["ext@example.org".to_string()],
        };
        let reply = delivered.to_json();
        assert_eq!(reply["confidential"], json!(true));
        assert_eq!(reply["secure_external"], json!(["ext@example.org"]));
        let row = &reply["recipients"][0];
        assert_eq!(row["address"], json!("ada@tuta.com"));
        assert_eq!(row["key_version"], json!(2));
        assert_eq!(row["protocol"], json!("tuta_crypt"));
        assert_eq!(row["fingerprint"], json!("ab".repeat(32)));
        assert_eq!(row.as_object().unwrap().len(), 4);
        let rsa = InternalRecipientKey {
            key_data: recipient("old@tutanota.de", CryptoProtocolVersion::Rsa),
            public_key_fingerprint: vec![1; 32],
        };
        assert_eq!(RecipientReport::of(&rsa).protocol, "rsa");
    }
}
