//! Signing in, resuming and closing sessions.

use crate::{
    diag,
    error::{
        api_code, initiate_error, keeps_pending, resume_error, second_factor_error,
        unsupported_factor_code,
    },
    transport, Error, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, fmt, sync::Arc, sync::Mutex, time::Duration};
use tutasdk::{
    bindings::{
        file_client::{FileClient, FileClientError},
        rest_client::RestClient,
    },
    crypto::sha256,
    entities::generated::sys::CloseSessionServicePost,
    login::{CredentialType, Credentials, LoginError},
    net::native_rest_client::NativeRestClient,
    rest_error::HttpError,
    services::{generated::sys::CloseSessionService, ExtraServiceParams},
    tutanota_constants::SecondFactorType,
    util::BASE64_EXT,
    ApiCallError, CustomId, GeneratedId, IdTupleCustom, LoggedInSdk, Sdk,
};

/// Tuta's production API.
pub const TUTA_URL: &str = "https://app.tuta.com";

/// The client name a session carries when none is set: Tuta lists it in the
/// account's session overview.
pub const DEFAULT_CLIENT_NAME: &str = "tuta-unofficial-sdk";

/// How often a pending second factor is re-checked after the TOTP code was
/// accepted, one second apart.
const SECOND_FACTOR_POLLS: u32 = 30;

/// A connection to Tuta's API, not yet signed in. Cheap to create; each one
/// owns its own HTTP client.
pub struct Client {
    sdk: Sdk,
    base_url: String,
    client_name: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("client_name", &self.client_name)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct MemoryFiles(Mutex<HashMap<String, Vec<u8>>>);

#[async_trait::async_trait]
impl FileClient for MemoryFiles {
    async fn persist_content(
        &self,
        name: String,
        content: Vec<u8>,
    ) -> std::result::Result<(), FileClientError> {
        self.0
            .lock()
            .map_err(|_| FileClientError::Unknown)?
            .insert(name, content);
        Ok(())
    }
    async fn read_content(&self, name: String) -> std::result::Result<Vec<u8>, FileClientError> {
        self.0
            .lock()
            .map_err(|_| FileClientError::Unknown)?
            .get(&name)
            .cloned()
            .ok_or(FileClientError::NotFound)
    }
}

impl Client {
    /// A client for Tuta's production API ([`TUTA_URL`]).
    pub fn new() -> Result<Self> {
        Self::with_url(TUTA_URL)
    }

    /// A client for another API origin (a test server).
    pub fn with_url(base_url: &str) -> Result<Self> {
        let native = NativeRestClient::try_new()
            .map_err(diag::fail("transport setup", Error::TransportFailed))?;
        let rest: Arc<dyn RestClient> = Arc::new(transport::Traced(Arc::new(native)));
        Ok(Client {
            sdk: Sdk::new(base_url.to_string(), rest, Arc::new(MemoryFiles::default())),
            base_url: base_url.to_string(),
            client_name: DEFAULT_CLIENT_NAME.to_string(),
        })
    }

    /// The name new sessions carry in the account's session list.
    pub fn client_name(mut self, name: &str) -> Self {
        self.client_name = name.to_string();
        self
    }

    /// Sign in with an address and password, plus a six-digit TOTP code when
    /// the account has a second factor. U2F and WebAuthn are not supported.
    ///
    /// A failure in the second-factor step drops the session the server
    /// opened for it; [`Client::sign_in`] hands it back for a retry instead.
    pub async fn login(
        &self,
        email: &str,
        password: &SecretString,
        totp: Option<&str>,
    ) -> Result<Session> {
        self.sign_in(email, password, totp)
            .await
            .map_err(|failure| failure.code)
    }

    /// Sign in as [`Client::login`] does, but when the account wants a
    /// second factor and the code is missing, malformed or refused, or the
    /// step failed in a way worth retrying, the failure carries the
    /// [`PendingSession`] the server opened: complete it with
    /// [`Client::complete_sign_in`] rather than signing in again, which
    /// would open another session (and Tuta throttles sign-ins).
    pub async fn sign_in(
        &self,
        email: &str,
        password: &SecretString,
        totp: Option<&str>,
    ) -> Result<Session, SignInError> {
        let initiated = self
            .sdk
            .initiate_session(email, password.expose_secret(), &self.client_name)
            .await
            .map_err(|error| {
                diag::failed("sign-in", &error);
                initiate_error(error)
            })?;
        if initiated.challenges.is_empty() {
            return self
                .finish(PendingSession(SavedSession::from_credentials(
                    initiated.credentials,
                )))
                .await;
        }
        let offers_totp = initiated
            .challenges
            .iter()
            .any(|c| c.r#type == SecondFactorType::Totp as i64);
        if !offers_totp {
            let types: Vec<i64> = initiated.challenges.iter().map(|c| c.r#type).collect();
            return Err(unsupported_factor_code(&types).into());
        }
        let pending = PendingSession(SavedSession::from_credentials(initiated.credentials));
        match totp {
            None => Err(SignInError::pending(Error::SecondFactorRequired, pending)),
            Some(code) => self.second_factor(pending, code, false).await,
        }
    }

    /// Finish a sign-in that is waiting for its second factor, on the
    /// session the server already opened for it. A wrong code can be
    /// retried on the same session again; `pending_session_expired` means
    /// the server let it go: sign in again.
    pub async fn complete_sign_in(
        &self,
        pending: PendingSession,
        totp: &str,
    ) -> Result<Session, SignInError> {
        self.second_factor(pending, totp, true).await
    }

    /// Give up a sign-in that is waiting for its second factor, closing the
    /// session the server opened for it rather than leaving it to expire:
    /// the official client's cancel (an unauthenticated
    /// `SecondFactorAuthService` DELETE, `06-cancel-second-factor.patch`).
    /// A session whose code already went in, so that nothing is pending any
    /// more, is revoked instead. Idempotent: a session the server already
    /// let go counts as closed.
    ///
    /// Fails with `transport_failed` (also while a code is being checked at
    /// the same moment), `rate_limited`, `timeout`, `client_outdated`,
    /// `session_invalid` for a malformed pending session, or
    /// `revoke_failed`.
    pub async fn cancel_sign_in(&self, pending: PendingSession) -> Result<()> {
        let token = pending.0.access_token().to_string();
        match self.sdk.cancel_second_factor(&token).await {
            Ok(()) => Ok(()),
            Err(LoginError::ApiCall {
                source:
                    ApiCallError::ServerResponseError {
                        source:
                            HttpError::NotFoundError
                            | HttpError::NotAuthenticatedError
                            | HttpError::SessionExpiredError
                            | HttpError::AccessExpiredError
                            | HttpError::AccessDeactivatedError,
                    },
            }) => match self.revoke(&pending.0).await {
                // Gone is gone.
                Err(Error::SessionRevoked) => Ok(()),
                revoked => revoked,
            },
            Err(LoginError::ApiCall { source }) => {
                diag::failed("sign-in cancel", &source);
                Err(api_code(source, Error::RevokeFailed, Error::RevokeFailed))
            }
            Err(error) => {
                diag::failed("sign-in cancel", &error);
                Err(Error::SessionInvalid)
            }
        }
    }

    /// Submit `code` for `pending`, wait for the server to accept it, and
    /// sign in. With `check`, ask first whether the session still waits for
    /// its second factor: one that is already through (a retry after the
    /// code went in but the sign-in did not finish) goes straight on.
    async fn second_factor(
        &self,
        pending: PendingSession,
        code: &str,
        check: bool,
    ) -> Result<Session, SignInError> {
        let Some(code) = totp_code(code) else {
            return Err(SignInError::pending(Error::InvalidTotp, pending));
        };
        let failed = |stage: &str, error: LoginError, submit: bool, pending: PendingSession| {
            diag::failed(stage, &error);
            SignInError::after(second_factor_error(error, submit), pending)
        };
        let token = pending.0.access_token().to_string();
        let waiting = if check {
            match self.sdk.is_second_factor_pending(&token).await {
                Ok(waiting) => waiting,
                Err(error) => return Err(failed("second factor check", error, false, pending)),
            }
        } else {
            true
        };
        if waiting {
            if let Err(error) = self
                .sdk
                .authenticate_with_second_factor_totp(&token, code)
                .await
            {
                return Err(failed("second factor", error, true, pending));
            }
            for _ in 0..SECOND_FACTOR_POLLS {
                match self.sdk.is_second_factor_pending(&token).await {
                    Ok(false) => break,
                    Ok(true) => tokio::time::sleep(Duration::from_secs(1)).await,
                    Err(error) => return Err(failed("second factor poll", error, false, pending)),
                }
            }
        }
        self.finish(pending).await
    }

    /// Log in on a session the server has opened and authenticated.
    async fn finish(&self, pending: PendingSession) -> Result<Session, SignInError> {
        match self.sdk.login(pending.0.credentials()).await {
            Ok(logged_in) => Ok(Session {
                sdk: logged_in,
                saved: pending.0,
                base_url: self.base_url.clone(),
            }),
            Err(error) => {
                diag::failed("session login", &error);
                // Only an outage or throttling is worth retrying on the same
                // session; anything else reads as a refused sign-in.
                let code = match resume_error(error) {
                    code @ (Error::TransportFailed
                    | Error::RateLimited
                    | Error::Timeout
                    | Error::ClientOutdated) => code,
                    _ => Error::LoginFailed,
                };
                Err(SignInError::after(code, pending))
            }
        }
    }

    /// Resume a saved session: [`Session::resume`].
    pub async fn resume(&self, saved: SavedSession) -> Result<Session> {
        let logged_in = self.sdk.login(saved.credentials()).await.map_err(|error| {
            diag::failed("session resume", &error);
            resume_error(error)
        })?;
        Ok(Session {
            sdk: logged_in,
            saved,
            base_url: self.base_url.clone(),
        })
    }

    /// Close a saved session on the server without keeping it open here.
    /// Idempotent: a session that is already dead needs no closing.
    pub async fn revoke(&self, saved: &SavedSession) -> Result<()> {
        let token = saved.access_token.expose_secret().to_string();
        let session_id = session_id_from_token(&token).ok_or(Error::SessionInvalid)?;
        let logged_in = match self.sdk.login(saved.credentials()).await {
            Ok(logged_in) => logged_in,
            Err(
                LoginError::InvalidAccessToken { .. }
                | LoginError::InvalidPassphrase { .. }
                | LoginError::InvalidKey { .. },
            ) => return Ok(()),
            Err(error) => return Err(resume_error(error)),
        };
        close_session(&logged_in, token, session_id).await
    }
}

/// A signed-in session. All mail operations hang off it; see the crate
/// docs for the list.
pub struct Session {
    pub(crate) sdk: Arc<LoggedInSdk>,
    pub(crate) saved: SavedSession,
    pub(crate) base_url: String,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// Resume a saved session over `client`. Sessions are not refreshed: a
    /// revoked or expired one is [`Error::SessionRevoked`], and the fix is
    /// to sign in again.
    pub async fn resume(client: &Client, saved: SavedSession) -> Result<Session> {
        client.resume(saved).await
    }

    /// What to store to resume this session later. It holds the access
    /// token and the wrapped passphrase key: keep it in a keyring.
    pub fn saved(&self) -> &SavedSession {
        &self.saved
    }

    /// The signed-in address.
    pub fn login(&self) -> &str {
        &self.saved.login
    }

    /// Close this session on the server. Idempotent: a session the server
    /// already forgot counts as closed.
    pub async fn revoke(self) -> Result<()> {
        let token = self.saved.access_token.expose_secret().to_string();
        let session_id = session_id_from_token(&token).ok_or(Error::SessionInvalid)?;
        close_session(&self.sdk, token, session_id).await
    }
}

async fn close_session(
    sdk: &LoggedInSdk,
    access_token: String,
    session_id: IdTupleCustom,
) -> Result<()> {
    let closed = CloseSessionServicePost {
        _format: 0,
        accessToken: access_token,
        sessionId: session_id,
    };
    match sdk
        .get_service_executor()
        .post::<CloseSessionService>(closed, ExtraServiceParams::default())
        .await
    {
        Ok(()) => Ok(()),
        // Raced with an expiry or a second client: gone is gone.
        Err(ApiCallError::ServerResponseError {
            source:
                HttpError::NotFoundError
                | HttpError::NotAuthenticatedError
                | HttpError::SessionExpiredError,
        }) => Ok(()),
        Err(error) => {
            diag::failed("session close", &error);
            Err(Error::RevokeFailed)
        }
    }
}

/// A session as stored between runs: `{login, user_id, access_token,
/// encrypted_passphrase_key}` when serialized, the helper protocol's
/// `session` object. Deliberately not `Debug`; the token and key are held
/// as secrets and zeroed on drop.
pub struct SavedSession {
    login: String,
    user_id: String,
    access_token: SecretString,
    encrypted_passphrase_key: SecretBox<Vec<u8>>,
}

impl SavedSession {
    fn credentials(&self) -> Credentials {
        Credentials {
            login: self.login.clone(),
            user_id: GeneratedId(self.user_id.clone()),
            access_token: self.access_token.expose_secret().to_string(),
            encrypted_passphrase_key: self.encrypted_passphrase_key.expose_secret().clone(),
            credential_type: CredentialType::Internal,
        }
    }

    fn from_credentials(c: Credentials) -> Self {
        SavedSession {
            login: c.login,
            user_id: c.user_id.to_string(),
            access_token: SecretString::from(c.access_token),
            encrypted_passphrase_key: SecretBox::new(Box::new(c.encrypted_passphrase_key)),
        }
    }

    /// The signed-in address.
    pub fn login(&self) -> &str {
        &self.login
    }

    /// The account's user id.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub(crate) fn access_token(&self) -> &str {
        self.access_token.expose_secret()
    }
}

impl Clone for SavedSession {
    fn clone(&self) -> Self {
        SavedSession {
            login: self.login.clone(),
            user_id: self.user_id.clone(),
            access_token: self.access_token.clone(),
            encrypted_passphrase_key: SecretBox::new(Box::new(
                self.encrypted_passphrase_key.expose_secret().clone(),
            )),
        }
    }
}

#[derive(Serialize)]
struct SavedSessionRef<'a> {
    login: &'a str,
    user_id: &'a str,
    access_token: &'a str,
    encrypted_passphrase_key: &'a [u8],
}

#[derive(Deserialize)]
struct SavedSessionOwned {
    login: String,
    user_id: String,
    access_token: String,
    encrypted_passphrase_key: Vec<u8>,
}

impl Serialize for SavedSession {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        SavedSessionRef {
            login: &self.login,
            user_id: &self.user_id,
            access_token: self.access_token.expose_secret(),
            encrypted_passphrase_key: self.encrypted_passphrase_key.expose_secret(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SavedSession {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let owned = SavedSessionOwned::deserialize(deserializer)?;
        Ok(SavedSession {
            login: owned.login,
            user_id: owned.user_id,
            access_token: SecretString::from(owned.access_token),
            encrypted_passphrase_key: SecretBox::new(Box::new(owned.encrypted_passphrase_key)),
        })
    }
}

/// A sign-in waiting for its second factor: the session the server opened
/// for it, serialized exactly like a [`SavedSession`] (the helper
/// protocol's `pending_session`). It is a credential: keep it in memory
/// only, and drop it when the address or password changes. An abandoned
/// one expires on the server. Deliberately not `Debug`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PendingSession(SavedSession);

impl PendingSession {
    /// The address the sign-in is for, as it was entered.
    pub fn login(&self) -> &str {
        self.0.login()
    }
}

/// A failed sign-in: its [`Error`] code and, when the second factor can be
/// retried on the same session, the [`PendingSession`] to retry it on.
pub struct SignInError {
    pub code: Error,
    pub pending: Option<PendingSession>,
}

impl SignInError {
    /// A failure that always keeps the session (`second_factor_required`,
    /// a malformed code).
    fn pending(code: Error, pending: PendingSession) -> Self {
        SignInError {
            code,
            pending: Some(pending),
        }
    }

    /// A failure after the session was opened: kept only if a retry on it
    /// makes sense.
    fn after(code: Error, pending: PendingSession) -> Self {
        SignInError {
            code,
            pending: keeps_pending(code).then_some(pending),
        }
    }
}

impl From<Error> for SignInError {
    fn from(code: Error) -> Self {
        SignInError {
            code,
            pending: None,
        }
    }
}

impl fmt::Debug for SignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignInError")
            .field("code", &self.code)
            .field("pending", &self.pending.is_some())
            .finish()
    }
}

/// A TOTP code as the server takes it: exactly six ASCII digits.
fn totp_code(code: &str) -> Option<u32> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

// First bytes of an access token: the session list id. Mirrors the SDK's own
// session id parsing, which lives behind a private function.
const GENERATED_ID_BYTES: usize = 9;

fn session_id_from_token(token: &str) -> Option<IdTupleCustom> {
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    if bytes.len() < GENERATED_ID_BYTES {
        return None;
    }
    let (list_id_bytes, element_id_bytes) = bytes.split_at(GENERATED_ID_BYTES);
    Some(IdTupleCustom {
        list_id: GeneratedId(BASE64_EXT.encode(list_id_bytes)),
        element_id: CustomId(URL_SAFE_NO_PAD.encode(sha256(element_id_bytes))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_comes_from_the_token_prefix() {
        assert_eq!(session_id_from_token("!!!not-base64!!!"), None);
        assert_eq!(session_id_from_token("dG9v"), None);
        let raw: Vec<u8> = (0..16).collect();
        let token = URL_SAFE_NO_PAD.encode(&raw);
        let parsed = session_id_from_token(&token).unwrap();
        assert_eq!(
            BASE64_EXT.decode(parsed.list_id.to_string()).unwrap(),
            raw[..9]
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(parsed.element_id.to_string())
                .unwrap(),
            sha256(&raw[9..])
        );
    }

    #[test]
    fn a_saved_session_round_trips_the_protocol_shape() {
        let json = serde_json::json!({"login": "a@tuta.com", "user_id": "u",
            "access_token": "t", "encrypted_passphrase_key": [1, 2, 3]});
        let saved: SavedSession = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(saved.login(), "a@tuta.com");
        assert_eq!(saved.user_id(), "u");
        assert_eq!(saved.access_token(), "t");
        assert_eq!(serde_json::to_value(&saved).unwrap(), json);
        assert_eq!(serde_json::to_value(saved.clone()).unwrap(), json);
        let credentials = saved.credentials();
        assert_eq!(credentials.encrypted_passphrase_key, vec![1, 2, 3]);
        assert_eq!(credentials.credential_type, CredentialType::Internal);
        // Every field is required.
        assert!(serde_json::from_value::<SavedSession>(
            serde_json::json!({"login": "a", "user_id": "u", "access_token": "t"})
        )
        .is_err());
    }

    #[test]
    fn a_totp_code_is_six_digits() {
        assert_eq!(totp_code("012345"), Some(12345));
        for bad in ["", "12345", "1234567", "12345a", " 12345", "１２３４５６"] {
            assert_eq!(totp_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_pending_session_is_shaped_like_a_saved_one() {
        let json = serde_json::json!({"login": "a@tuta.com", "user_id": "u",
            "access_token": "t", "encrypted_passphrase_key": [1, 2]});
        let pending: PendingSession = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(pending.login(), "a@tuta.com");
        assert_eq!(serde_json::to_value(&pending).unwrap(), json);
        assert!(
            serde_json::from_value::<PendingSession>(serde_json::json!({"login": "a"})).is_err()
        );
    }

    #[test]
    fn a_sign_in_failure_keeps_its_session_only_when_a_retry_can_use_it() {
        let pending = || {
            serde_json::from_value::<PendingSession>(serde_json::json!({
            "login": "a", "user_id": "u", "access_token": "t", "encrypted_passphrase_key": []}))
            .unwrap()
        };
        assert!(SignInError::pending(Error::SecondFactorRequired, pending())
            .pending
            .is_some());
        assert!(SignInError::after(Error::SecondFactorFailed, pending())
            .pending
            .is_some());
        assert!(SignInError::after(Error::RateLimited, pending())
            .pending
            .is_some());
        assert!(SignInError::after(Error::PendingSessionExpired, pending())
            .pending
            .is_none());
        assert!(SignInError::after(Error::LoginFailed, pending())
            .pending
            .is_none());
        assert!(SignInError::from(Error::LoginFailed).pending.is_none());
        let debug = format!("{:?}", SignInError::pending(Error::InvalidTotp, pending()));
        assert_eq!(debug, "SignInError { code: InvalidTotp, pending: true }");
    }
}
