//! Signing in, resuming and closing sessions.

use crate::{
    diag,
    error::{initiate_error, resume_error, unsupported_factor_code},
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
    pub async fn login(
        &self,
        email: &str,
        password: &SecretString,
        totp: Option<&str>,
    ) -> Result<Session> {
        let initiated = self
            .sdk
            .initiate_session(email, password.expose_secret(), &self.client_name)
            .await
            .map_err(|error| {
                diag::failed("sign-in", &error);
                initiate_error(error)
            })?;
        if !initiated.challenges.is_empty() {
            let offers_totp = initiated
                .challenges
                .iter()
                .any(|c| c.r#type == SecondFactorType::Totp as i64);
            if !offers_totp {
                let types: Vec<i64> = initiated.challenges.iter().map(|c| c.r#type).collect();
                return Err(unsupported_factor_code(&types));
            }
            let code = totp.ok_or(Error::SecondFactorRequired)?;
            if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidTotp);
            }
            self.sdk
                .authenticate_with_second_factor_totp(
                    &initiated.credentials.access_token,
                    code.parse().map_err(|_| Error::InvalidTotp)?,
                )
                .await
                .map_err(diag::fail("second factor", Error::SecondFactorFailed))?;
            for _ in 0..SECOND_FACTOR_POLLS {
                if !self
                    .sdk
                    .is_second_factor_pending(&initiated.credentials.access_token)
                    .await
                    .map_err(diag::fail("second factor poll", Error::SecondFactorFailed))?
                {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        let logged_in = self
            .sdk
            .login(initiated.credentials.clone())
            .await
            .map_err(diag::fail("session login", Error::LoginFailed))?;
        Ok(Session {
            sdk: logged_in,
            saved: SavedSession::from_credentials(initiated.credentials),
            base_url: self.base_url.clone(),
        })
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
}
