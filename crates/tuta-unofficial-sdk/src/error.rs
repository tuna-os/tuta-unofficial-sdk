//! The one error type: a fixed code per failure, never SDK or server text.
//!
//! Every variant maps to the stable snake_case code the helper protocol
//! reports (`Error::code`), so a caller can match on the enum in process or
//! on the code over the wire and see the same thing. Diagnostics about what
//! actually went wrong go to stderr when they are switched on (see
//! [`crate::diagnostics`]), redacted, never into the error.

use serde::{Serialize, Serializer};
use std::fmt;
use tutasdk::ApiCallError;
use tutasdk::{login::LoginError, rest_error::HttpError, tutanota_constants::SecondFactorType};

/// A result with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

macro_rules! codes {
    ($($(#[doc = $doc:literal])* $variant:ident => $code:literal,)*) => {
        /// What went wrong, as a fixed code (see [`Error::code`]).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Error {
            $($(#[doc = $doc])* $variant,)*
        }

        impl Error {
            /// Every error, in declaration order.
            pub const ALL: &'static [Error] = &[$(Error::$variant,)*];

            /// The fixed snake_case code, as the helper protocol reports it.
            pub const fn code(self) -> &'static str {
                match self {
                    $(Error::$variant => $code,)*
                }
            }

            /// The error a code names, if any.
            pub fn from_code(code: &str) -> Option<Self> {
                match code {
                    $($code => Some(Error::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

codes! {
    // Sign-in.
    /// The server refused the address or the password.
    LoginFailed => "login_failed",
    /// The account needs a TOTP code and none was given.
    SecondFactorRequired => "second_factor_required",
    /// The server refused the TOTP code.
    SecondFactorFailed => "second_factor_failed",
    /// The TOTP code is not six digits.
    InvalidTotp => "invalid_totp",
    /// The account's only second factor is a U2F key, which is not supported.
    UnsupportedU2f => "unsupported_u2f",
    /// The account's only second factor is a WebAuthn key, which is not supported.
    UnsupportedWebauthn => "unsupported_webauthn",
    /// The account offers no second factor this crate supports.
    UnsupportedSecondFactor => "unsupported_second_factor",
    /// A saved session could not be resumed for a reason other than the ones below.
    ResumeFailed => "resume_failed",
    /// The saved session material is corrupt.
    SessionInvalid => "session_invalid",
    /// The server no longer honours the session: sign in again.
    SessionRevoked => "session_revoked",
    /// The server refuses this client version: the pinned SDK needs an update.
    ClientOutdated => "client_outdated",
    /// A sign-in's pending session is gone (expired or cancelled on the
    /// server): start the sign-in over.
    PendingSessionExpired => "pending_session_expired",
    // Transport.
    /// No connection, an outage, or throttling.
    TransportFailed => "transport_failed",
    /// A read the server did not answer usefully.
    RequestFailed => "request_failed",
    /// The operation overran its time limit.
    Timeout => "timeout",
    /// Tuta is throttling this client or account (HTTP 429, or too many
    /// failed second-factor attempts): wait, then try again.
    RateLimited => "rate_limited",
    // Content.
    /// A mail, folder or attachment could not be decrypted.
    DecryptionFailed => "decryption_failed",
    /// A mail stored in the legacy body format, which is not supported.
    UnsupportedLegacyBody => "unsupported_legacy_body",
    /// An attachment could not be read, encrypted or uploaded.
    AttachmentFailed => "attachment_failed",
    /// The body is over the official client's 1 MiB limit.
    BodyTooLarge => "body_too_large",
    /// The server's reply lacked a field it always carries.
    IncompleteResponse => "incomplete_response",
    // Requests.
    /// The request is malformed.
    InvalidRequest => "invalid_request",
    /// The helper protocol version is not one this build speaks.
    UnsupportedVersion => "unsupported_version",
    /// An id is not a compound `list/element` id.
    InvalidId => "invalid_id",
    /// A sync page is out of range.
    InvalidPage => "invalid_page",
    /// A batch is empty or over its limit.
    InvalidBatch => "invalid_batch",
    /// A Message-ID, References chain or reply action is malformed.
    InvalidThread => "invalid_thread",
    // Sending.
    /// An address is not one.
    InvalidRecipient => "invalid_recipient",
    /// The sender is not one of the account's addresses.
    SenderUnknown => "sender_unknown",
    /// A Tuta recipient has no public key.
    RecipientNotFound => "recipient_not_found",
    /// A confidential send has a recipient outside Tuta without a password.
    PasswordRequired => "password_required",
    /// Password-protected delivery from a shared mailbox or an external user.
    SecureExternalSenderUnsupported => "secure_external_sender_unsupported",
    /// Ordinary delivery was not confirmed.
    OrdinaryDeliveryRequiresConsent => "ordinary_delivery_requires_consent",
    /// The send definitely did not go out.
    SendFailed => "send_failed",
    /// The send may have gone out: never resend it.
    SendUncertain => "send_uncertain",
    // Contacts and sessions.
    /// A contact could not be written.
    ContactSaveFailed => "contact_save_failed",
    /// The server would not close the session.
    RevokeFailed => "revoke_failed",
    // Folders and labels.
    /// No such folder.
    FolderNotFound => "folder_not_found",
    /// A sibling folder has the name, ignoring case.
    FolderExists => "folder_exists",
    /// System folders are never renamed or deleted.
    NotCustomFolder => "not_custom_folder",
    /// The new parent is the folder itself or inside it.
    InvalidParent => "invalid_parent",
    /// A folder or label name is blank, too long or has control characters.
    InvalidName => "invalid_name",
    /// The server is still working on the folder.
    OperationStillActive => "operation_still_active",
    /// A folder write failed.
    FolderFailed => "folder_failed",
    /// No such label.
    LabelNotFound => "label_not_found",
    /// A label has the name, ignoring case.
    LabelExists => "label_exists",
    /// A label colour is not `#rrggbb`.
    InvalidColor => "invalid_color",
    /// A label write failed.
    LabelFailed => "label_failed",
    /// The account's plan allows no more.
    LimitReached => "limit_reached",
    // Deleting.
    /// Mail is deleted for good only from Trash, Spam or a folder in them.
    NotTrashOrSpam => "not_trash_or_spam",
    /// A delete failed.
    DeleteFailed => "delete_failed",
    // Drafts.
    /// No such draft.
    DraftNotFound => "draft_not_found",
    /// The id names a received or sent mail.
    NotADraft => "not_a_draft",
    /// A draft write failed.
    DraftFailed => "draft_failed",
    // Importing.
    /// Not a MIME message: no header at all.
    ImportInvalid => "import_invalid",
    /// Over 25 MiB decoded, over 256 parts, or over 8 MiB of headers and body.
    ImportTooLarge => "import_too_large",
    /// The account's plan may not import, or the server has import disabled.
    ImportRefused => "import_refused",
    /// The import failed.
    ImportFailed => "import_failed",
    // Watching.
    /// The event bus could not be held.
    WatchFailed => "watch_failed",
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

/// The fixed code for a failed SDK call. Session, version and transport
/// classes keep their shared codes; a missing instance reports `not_found`;
/// everything else reports the operation's own `fallback`.
pub(crate) fn api_code(error: ApiCallError, fallback: Error, not_found: Error) -> Error {
    match error {
        ApiCallError::RestClient { .. } => Error::TransportFailed,
        ApiCallError::ServerResponseError { source } => match source {
            HttpError::InvalidSoftwareVersionError => Error::ClientOutdated,
            HttpError::SessionExpiredError
            | HttpError::NotAuthenticatedError
            | HttpError::AccessExpiredError
            | HttpError::AccessDeactivatedError
            | HttpError::AccessBlockedError => Error::SessionRevoked,
            HttpError::NotFoundError => not_found,
            HttpError::RequestTimeoutError => Error::Timeout,
            HttpError::LimitReachedError => Error::LimitReached,
            HttpError::TooManyRequestsError { .. } => Error::RateLimited,
            HttpError::ConnectionError
            | HttpError::InternalServerError
            | HttpError::BadGatewayError
            | HttpError::ServiceUnavailableError { .. }
            | HttpError::LockedError => Error::TransportFailed,
            _ => fallback,
        },
        ApiCallError::InternalSdkError { .. } => fallback,
    }
}

/// Which code a failed resume reports.
pub(crate) fn resume_error(error: LoginError) -> Error {
    match error {
        // The server no longer honors this token: revoked, expired, or logged
        // out elsewhere. The user signs in again; retrying changes nothing.
        LoginError::InvalidAccessToken { .. } => Error::SessionRevoked,
        // Our stored material is corrupt, not the server's state.
        LoginError::InvalidPassphrase { .. } | LoginError::InvalidKey { .. } => {
            Error::SessionInvalid
        }
        LoginError::ApiCall { source } => match source {
            ApiCallError::RestClient { .. } => Error::TransportFailed,
            ApiCallError::ServerResponseError { source } => server_error(source),
            ApiCallError::InternalSdkError { .. } => Error::ResumeFailed,
        },
    }
}

fn server_error(error: HttpError) -> Error {
    match error {
        // No automatic reauthentication: a refused client version is not an
        // invalid password. The fix is an app update, not a retry.
        HttpError::InvalidSoftwareVersionError => Error::ClientOutdated,
        HttpError::SessionExpiredError
        | HttpError::NotAuthenticatedError
        | HttpError::NotAuthorizedError
        | HttpError::AccessExpiredError
        | HttpError::AccessDeactivatedError
        | HttpError::AccessBlockedError => Error::SessionRevoked,
        HttpError::RequestTimeoutError => Error::Timeout,
        HttpError::TooManyRequestsError { .. } => Error::RateLimited,
        HttpError::ConnectionError
        | HttpError::InternalServerError
        | HttpError::BadGatewayError
        | HttpError::ServiceUnavailableError { .. }
        | HttpError::LockedError => Error::TransportFailed,
        _ => Error::ResumeFailed,
    }
}

/// Which code a failed sign-in reports. Only a server that answered can
/// have refused the address or the password; no connection, an outage or
/// a refused client version must not read as a wrong password.
pub(crate) fn initiate_error(error: LoginError) -> Error {
    match error {
        LoginError::ApiCall {
            source: ApiCallError::RestClient { .. },
        } => Error::TransportFailed,
        LoginError::ApiCall {
            source: ApiCallError::ServerResponseError { source },
        } => match source {
            HttpError::InvalidSoftwareVersionError => Error::ClientOutdated,
            HttpError::RequestTimeoutError => Error::Timeout,
            HttpError::TooManyRequestsError { .. } => Error::RateLimited,
            HttpError::ConnectionError
            | HttpError::InternalServerError
            | HttpError::BadGatewayError
            | HttpError::ServiceUnavailableError { .. } => Error::TransportFailed,
            _ => Error::LoginFailed,
        },
        _ => Error::LoginFailed,
    }
}

/// Which code a failed second-factor step reports, for a sign-in whose
/// session the server opened and is waiting on. `check` is the status
/// request (GET), `submit` the code itself (POST), as the official
/// client's `SecondFactorAuthDialog` reads them: a refused code is
/// `second_factor_failed`, a session the server no longer knows is
/// `pending_session_expired`, too many attempts are `rate_limited`.
pub(crate) fn second_factor_error(error: LoginError, submit: bool) -> Error {
    match error {
        LoginError::InvalidAccessToken { .. }
        | LoginError::InvalidPassphrase { .. }
        | LoginError::InvalidKey { .. } => Error::SessionInvalid,
        LoginError::ApiCall { source } => match source {
            ApiCallError::RestClient { .. } => Error::TransportFailed,
            ApiCallError::ServerResponseError { source } => match source {
                HttpError::InvalidSoftwareVersionError => Error::ClientOutdated,
                HttpError::RequestTimeoutError => Error::Timeout,
                HttpError::TooManyRequestsError { .. } | HttpError::AccessBlockedError => {
                    Error::RateLimited
                }
                HttpError::NotFoundError
                | HttpError::SessionExpiredError
                | HttpError::AccessExpiredError
                | HttpError::AccessDeactivatedError => Error::PendingSessionExpired,
                // Only the status check reads 401 as a dead session; for the
                // code itself it is the official client's "wrong code".
                HttpError::NotAuthenticatedError if !submit => Error::PendingSessionExpired,
                HttpError::ConnectionError
                | HttpError::InternalServerError
                | HttpError::BadGatewayError
                | HttpError::ServiceUnavailableError { .. }
                | HttpError::LockedError => Error::TransportFailed,
                _ => Error::SecondFactorFailed,
            },
            ApiCallError::InternalSdkError { .. } => Error::SecondFactorFailed,
        },
    }
}

/// Whether a sign-in that failed with `code` in its second-factor step can
/// still be retried on the same pending session: a wrong or missing code, an
/// outage or throttling can; a dead, blocked or corrupt session cannot.
pub(crate) fn keeps_pending(code: Error) -> bool {
    matches!(
        code,
        Error::SecondFactorRequired
            | Error::SecondFactorFailed
            | Error::InvalidTotp
            | Error::TransportFailed
            | Error::Timeout
            | Error::RateLimited
    )
}

/// Which code to report when none of the offered challenges is TOTP: name
/// the blocking factor honestly so the UI can say what the account actually
/// needs. A mix, or a type this crate predates, stays generic.
pub(crate) fn unsupported_factor_code(challenge_types: &[i64]) -> Error {
    let mut kinds = challenge_types.to_vec();
    kinds.sort_unstable();
    kinds.dedup();
    match kinds.as_slice() {
        [only] if *only == SecondFactorType::U2f as i64 => Error::UnsupportedU2f,
        [only] if *only == SecondFactorType::Webauthn as i64 => Error::UnsupportedWebauthn,
        _ => Error::UnsupportedSecondFactor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tutasdk::bindings::rest_client::RestClientError;

    fn server(code: HttpError) -> LoginError {
        LoginError::ApiCall {
            source: ApiCallError::ServerResponseError { source: code },
        }
    }

    #[test]
    fn every_code_is_unique_and_round_trips() {
        let mut seen = std::collections::HashSet::new();
        for error in Error::ALL {
            assert!(seen.insert(error.code()), "{error:?}");
            assert_eq!(Error::from_code(error.code()), Some(*error));
            assert_eq!(error.to_string(), error.code());
            assert_eq!(
                serde_json::to_value(error).unwrap(),
                serde_json::json!(error.code())
            );
        }
        assert_eq!(Error::from_code("not_attempted"), None);
    }

    #[test]
    fn resume_distinguishes_revoked_outage_and_refused_version() {
        let token = || LoginError::InvalidAccessToken {
            error_message: String::new(),
        };
        assert_eq!(resume_error(token()), Error::SessionRevoked);
        assert_eq!(
            resume_error(server(HttpError::SessionExpiredError)),
            Error::SessionRevoked
        );
        assert_eq!(
            resume_error(server(HttpError::NotAuthenticatedError)),
            Error::SessionRevoked
        );
        assert_eq!(
            resume_error(server(HttpError::InvalidSoftwareVersionError)),
            Error::ClientOutdated
        );
        assert_eq!(
            resume_error(LoginError::ApiCall {
                source: ApiCallError::RestClient {
                    source: RestClientError::NetworkError,
                },
            }),
            Error::TransportFailed
        );
        assert_eq!(
            resume_error(server(HttpError::ServiceUnavailableError {
                suspension_time_sec: None,
            })),
            Error::TransportFailed
        );
        assert_eq!(
            resume_error(server(HttpError::RequestTimeoutError)),
            Error::Timeout
        );
        assert_eq!(
            resume_error(server(HttpError::BadRequestError)),
            Error::ResumeFailed
        );
    }

    #[test]
    fn a_sign_in_without_a_server_is_not_a_wrong_password() {
        assert_eq!(
            initiate_error(LoginError::ApiCall {
                source: ApiCallError::RestClient {
                    source: RestClientError::NetworkError,
                },
            }),
            Error::TransportFailed
        );
        assert_eq!(
            initiate_error(server(HttpError::InvalidSoftwareVersionError)),
            Error::ClientOutdated
        );
        assert_eq!(
            initiate_error(server(HttpError::NotAuthenticatedError)),
            Error::LoginFailed
        );
    }

    #[test]
    fn throttling_is_rate_limited_not_an_outage() {
        let throttled = || {
            server(HttpError::TooManyRequestsError {
                suspension_time_sec: None,
            })
        };
        assert_eq!(initiate_error(throttled()), Error::RateLimited);
        assert_eq!(resume_error(throttled()), Error::RateLimited);
        assert_eq!(second_factor_error(throttled(), true), Error::RateLimited);
        assert_eq!(second_factor_error(throttled(), false), Error::RateLimited);
        assert_eq!(
            api_code(
                ApiCallError::ServerResponseError {
                    source: HttpError::TooManyRequestsError {
                        suspension_time_sec: None
                    }
                },
                Error::FolderFailed,
                Error::FolderNotFound
            ),
            Error::RateLimited
        );
    }

    #[test]
    fn second_factor_failures_read_as_the_official_client_reads_them() {
        // The code itself: 401 and 400 are a wrong code.
        assert_eq!(
            second_factor_error(server(HttpError::NotAuthenticatedError), true),
            Error::SecondFactorFailed
        );
        assert_eq!(
            second_factor_error(server(HttpError::BadRequestError), true),
            Error::SecondFactorFailed
        );
        assert_eq!(
            second_factor_error(server(HttpError::AccessBlockedError), true),
            Error::RateLimited
        );
        // A session the server forgot, whichever request noticed.
        for submit in [true, false] {
            for gone in [
                HttpError::NotFoundError,
                HttpError::SessionExpiredError,
                HttpError::AccessExpiredError,
            ] {
                assert_eq!(
                    second_factor_error(server(gone), submit),
                    Error::PendingSessionExpired
                );
            }
        }
        assert_eq!(
            second_factor_error(server(HttpError::NotAuthenticatedError), false),
            Error::PendingSessionExpired
        );
        assert_eq!(
            second_factor_error(
                LoginError::ApiCall {
                    source: ApiCallError::RestClient {
                        source: RestClientError::NetworkError,
                    },
                },
                true
            ),
            Error::TransportFailed
        );
        assert_eq!(
            second_factor_error(
                LoginError::InvalidAccessToken {
                    error_message: String::new()
                },
                false
            ),
            Error::SessionInvalid
        );
    }

    #[test]
    fn only_a_retryable_second_factor_failure_keeps_the_pending_session() {
        for code in [
            Error::SecondFactorRequired,
            Error::SecondFactorFailed,
            Error::InvalidTotp,
            Error::TransportFailed,
            Error::Timeout,
            Error::RateLimited,
        ] {
            assert!(keeps_pending(code), "{code}");
        }
        for code in [
            Error::PendingSessionExpired,
            Error::SessionInvalid,
            Error::ClientOutdated,
            Error::LoginFailed,
        ] {
            assert!(!keeps_pending(code), "{code}");
        }
    }

    #[test]
    fn corrupt_local_material_is_not_a_revoked_session() {
        assert_eq!(
            resume_error(LoginError::InvalidPassphrase {
                error_message: String::new(),
            }),
            Error::SessionInvalid
        );
        assert_eq!(
            resume_error(LoginError::InvalidKey {
                error_message: String::new(),
            }),
            Error::SessionInvalid
        );
    }

    #[test]
    fn blocking_second_factor_is_named_honestly() {
        assert_eq!(unsupported_factor_code(&[0]), Error::UnsupportedU2f);
        assert_eq!(unsupported_factor_code(&[0, 0]), Error::UnsupportedU2f);
        assert_eq!(unsupported_factor_code(&[2]), Error::UnsupportedWebauthn);
        assert_eq!(
            unsupported_factor_code(&[0, 2]),
            Error::UnsupportedSecondFactor
        );
        assert_eq!(
            unsupported_factor_code(&[7]),
            Error::UnsupportedSecondFactor
        );
        assert_eq!(unsupported_factor_code(&[]), Error::UnsupportedSecondFactor);
    }
}
