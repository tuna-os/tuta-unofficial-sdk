use super::key::RsaX25519PublicKeys;
use crate::crypto::key::PublicKey::{RsaX25519, TutaCrypt};
use crate::crypto::key::{AsymmetricKeyPair, KeyLoadError, PublicKey};
use crate::crypto::kyber::KyberKeyError;
#[cfg_attr(test, mockall_double::double)]
use crate::crypto::public_key_provider::PublicKeyProvider;
use crate::crypto::public_key_provider::{PublicKeyIdentifier, PublicKeyLoadingError};
use crate::crypto::rsa::{RSAEncryptionError, RSAKeyError, RSAX25519KeyPair};
use crate::crypto::tuta_crypt::{TutaCryptError, TutaCryptMessage, TutaCryptPublicKeys};
use crate::crypto::x25519::{X25519KeyPair, X25519PublicKey};
use crate::entities::generated::sys::{PubEncKeyData, PublicKeyPutIn};
use crate::entities::generated::tutanota::InternalRecipientKeyData;
#[cfg_attr(test, mockall_double::double)]
use crate::key_loader_facade::KeyLoaderFacade;
use crate::rest_error::HttpError;
use crate::services::generated::sys::PublicKeyService;
#[cfg_attr(test, mockall_double::double)]
use crate::services::service_executor::ServiceExecutor;
use crate::services::ExtraServiceParams;
use crate::tutanota_constants::CryptoProtocolVersion;
use crate::tutanota_constants::EncryptionAuthStatus;
use crate::tutanota_constants::{PublicKeyIdentifierType, SYSTEM_GROUP_MAIL_ADDRESS};
use crate::util::{convert_version_to_i64, convert_version_to_u64};
use crate::ApiCallError;
use crate::GeneratedId;
use crypto_primitives::aes::Aes256Key;
use crypto_primitives::aes::{AesEncryptError, InitializationVector};
use crypto_primitives::key::GenericAesKey;
use crypto_primitives::key::KeyDecryptError;
use crypto_primitives::randomizer_facade::RandomizerFacade;
use crypto_primitives::sha::sha256;
use crypto_primitives::versioned::{Versioned, VersionedAesKey};
use std::sync::Arc;
use util::array::ArrayCastingError;
use zeroize::Zeroizing;

fn get_sender_ecc_key(public_key: Versioned<PublicKey>) -> Option<X25519PublicKey> {
	match public_key.object {
		RsaX25519(x) => Some(x.x25519_public_key),
		TutaCrypt(x) => {
			let TutaCryptPublicKeys {
				x25519_public_key,
				kyber_public_key: _,
			} = x;
			Some(x25519_public_key)
		},
		PublicKey::Rsa(_) => None,
	}
}

pub struct DecapsulatedAesKey {
	pub decrypted_aes_key: GenericAesKey,
	pub sender_identity_pub_key: Option<X25519PublicKey>, // for authentication: None for rsa only
}

pub struct PubEncSymKey {
	pub_enc_sym_key_bytes: Vec<u8>,
	crypto_protocol_version: CryptoProtocolVersion,
	sender_key_version: Option<u64>,
	recipient_key_version: u64,
}

/// One internal recipient's share of a confidential mail: the bucket key
/// encrypted with the recipient's current public key, ready for
/// `SendDraftData.internalRecipientKeyData` (the caller assigns the aggregate
/// `_id`), plus a fingerprint of the key it was encrypted with.
pub struct InternalRecipientKey {
	pub key_data: InternalRecipientKeyData,
	/// See `public_key_fingerprint`.
	pub public_key_fingerprint: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum InternalRecipientKeyError {
	/// No public key exists for these addresses (the TS client's
	/// `RecipientsNotFoundError`). No key data is built for anyone then.
	#[error("recipients not found")]
	RecipientsNotFound(Vec<String>),
	/// External (secure-mail) users encrypt symmetrically for internal
	/// recipients; that path is not offered here.
	#[error("external sender")]
	ExternalSender,
	#[error("recipient key encryption failed")]
	Crypto(#[from] AsymmetricCryptoError),
}

/// SHA-256 over a public encryption key, for callers that pin recipient keys
/// (trust on first use). It covers each component as the PublicKeyService
/// serves it -- RSA, X25519, Kyber, in that order -- each prefixed with its
/// length as a big-endian u32, an absent component counting as empty. This is
/// not Tuta's identity-key fingerprint, which covers the signing key instead.
#[must_use]
pub fn public_key_fingerprint(public_key: &PublicKey) -> Vec<u8> {
	let (rsa, ecc, kyber) = match public_key {
		PublicKey::Rsa(rsa) => (rsa.serialize(), Vec::new(), Vec::new()),
		PublicKey::RsaX25519(keys) => (
			keys.rsa_public_key.serialize(),
			keys.x25519_public_key.as_bytes().to_vec(),
			Vec::new(),
		),
		PublicKey::TutaCrypt(keys) => (
			Vec::new(),
			keys.x25519_public_key.as_bytes().to_vec(),
			keys.kyber_public_key.serialize(),
		),
	};
	let mut material = Vec::new();
	for part in [rsa, ecc, kyber] {
		let length = u32::try_from(part.len()).expect("public key component over 4 GiB");
		material.extend_from_slice(&length.to_be_bytes());
		material.extend_from_slice(&part);
	}
	sha256(&material)
}

#[derive(thiserror::Error, Debug)]
#[error("AsymmetricCryptoError")]
pub enum AsymmetricCryptoError {
	InvalidCryptoProtocolVersion(CryptoProtocolVersion),
	UnexpectedAsymmetricKeyPairType(String),
	UnexpectedPublicKeyPairType(String),
	UnexpectedSymmetricKeyType(String),
	RsaEncrypt(#[from] RSAEncryptionError),
	TutaCrypt(#[from] TutaCryptError),
	ArrayCasting(#[from] ArrayCastingError),
	KeyDecrypting(#[from] KeyDecryptError),
	KeyLoading(#[from] KeyLoadError),
	KeyParsing(String),
	RsaKey(#[from] RSAKeyError),
	KyberKey(#[from] KyberKeyError),
	AesEncrypt(#[from] AesEncryptError),
	ApiCall(#[from] ApiCallError),
	AuthenticationError(EncryptionAuthStatus),
	PublicKeyLoadingError(#[from] PublicKeyLoadingError),
}

pub struct AsymmetricCryptoFacade {
	key_loader_facade: Arc<KeyLoaderFacade>,
	randomizer_facade: RandomizerFacade,
	service_executor: Arc<ServiceExecutor>,
	public_key_provider: Arc<PublicKeyProvider>,
}

#[cfg_attr(test, mockall::automock)]
impl AsymmetricCryptoFacade {
	#[must_use]
	pub fn new(
		key_loader_facade: Arc<KeyLoaderFacade>,
		randomizer_facade: RandomizerFacade,
		service_executor: Arc<ServiceExecutor>,
		public_key_provider: Arc<PublicKeyProvider>,
	) -> Self {
		Self {
			key_loader_facade,
			randomizer_facade,
			service_executor,
			public_key_provider,
		}
	}

	/// Verifies whether the key that the public key service returns is the same as the one used for encryption.
	/// When we have key verification we should stop verifying against the PublicKeyService but against the verified key.
	///
	/// @param identifier the identifier to load the public key to verify that it matches the one used in the protocol run.
	/// @param sender_identity_pub_key the sender_identity_pub_key that was used to encrypt/authenticate the data.
	/// @param sender_key_version the version of the sender_identity_pub_key.
	#[allow(clippy::needless_lifetimes)] // explicit lifetime needed for automock
	pub async fn authenticate_sender<'a>(
		&self,
		identifier: PublicKeyIdentifier,
		sender_identity_pub_key: Versioned<&'a X25519PublicKey>,
	) -> Result<EncryptionAuthStatus, AsymmetricCryptoError> {
		let pub_keys = self
			.public_key_provider
			.load_versioned_pub_key(&identifier, sender_identity_pub_key.version)
			.await?;

		Ok(match get_sender_ecc_key(pub_keys) {
			Some(X25519PublicKey(bytes)) if bytes == sender_identity_pub_key.object.as_bytes() => {
				EncryptionAuthStatus::TutacryptAuthenticationSucceeded
			},
			_ => EncryptionAuthStatus::TutacryptAuthenticationFailed,
		})
	}

	/// Decrypts the pubEncSymKey with the recipientKeyPair and authenticates it if the protocol supports authentication.
	/// If the protocol does not support authentication this method will only decrypt.
	/// @param recipientKeyPair the recipientKeyPair. Must match the cryptoProtocolVersion and must be of the required recipientKeyVersion.
	/// @param pubEncKeyData the encrypted symKey with the metadata (versions, group identifier etc.) for decryption and authentication.
	/// @param senderIdentifier the identifier for the sender's key group
	/// @throws CryptoError in case the authentication fails.
	pub async fn decrypt_sym_key_with_key_pair_and_authenticate(
		&self,
		recipient_key_pair: AsymmetricKeyPair,
		pub_enc_key_data: PubEncKeyData,
		sender_identifier: PublicKeyIdentifier,
	) -> Result<DecapsulatedAesKey, AsymmetricCryptoError> {
		let crypto_protocol_version =
			CryptoProtocolVersion::try_from(pub_enc_key_data.protocolVersion).unwrap();
		let decapsulated_aes_key = Self::decrypt_sym_key_with_key_pair(
			recipient_key_pair,
			&crypto_protocol_version,
			&pub_enc_key_data.pubEncSymKey,
		)?;
		if crypto_protocol_version == CryptoProtocolVersion::TutaCrypt {
			let sender_identity_pub_key_from_tuta_crypt_message = decapsulated_aes_key
				.sender_identity_pub_key
				.as_ref()
				.unwrap();
			let encryption_auth_status = self
				.authenticate_sender(
					sender_identifier,
					Versioned {
						object: sender_identity_pub_key_from_tuta_crypt_message,
						version: convert_version_to_u64(pub_enc_key_data.senderKeyVersion.unwrap()),
					},
				)
				.await?;
			if encryption_auth_status != EncryptionAuthStatus::TutacryptAuthenticationSucceeded {
				//the provided public key could not be authenticated
				return Err(AsymmetricCryptoError::AuthenticationError(
					encryption_auth_status,
				));
			}
		}
		Ok(decapsulated_aes_key)
	}

	/// Decrypts the pub_enc_sym_key with the recipientKeyPair.
	/// @param pub_enc_sym_key the asymmetrically encrypted session key
	/// @param crypto_protocol_version asymmetric protocol to decrypt pub_enc_sym_key (RSA or TutaCrypt)
	/// @param recipient_key_pair the recipientKeyPair. Must match the crypto_protocol_version.
	pub fn decrypt_sym_key_with_key_pair(
		recipient_key_pair: AsymmetricKeyPair,
		crypto_protocol_version: &CryptoProtocolVersion,
		pub_enc_sym_key: &[u8],
	) -> Result<DecapsulatedAesKey, AsymmetricCryptoError> {
		match crypto_protocol_version {
			CryptoProtocolVersion::Rsa => match recipient_key_pair {
				AsymmetricKeyPair::RSAX25519KeyPair(RSAX25519KeyPair {
					rsa_key_pair: key_pair,
					..
				})
				| AsymmetricKeyPair::RSAKeyPair(key_pair) => {
					let sym_key_bytes =
						Zeroizing::new(key_pair.private_key.decrypt(pub_enc_sym_key)?);
					let decrypted_aes_key = GenericAesKey::from_bytes(sym_key_bytes.as_slice())?;
					Ok(DecapsulatedAesKey {
						decrypted_aes_key,
						sender_identity_pub_key: None,
					})
				},
				_ => Err(AsymmetricCryptoError::UnexpectedAsymmetricKeyPairType(
					format!("{:? }", recipient_key_pair),
				)),
			},
			CryptoProtocolVersion::TutaCrypt => match recipient_key_pair {
				AsymmetricKeyPair::TutaCryptKeyPairs(key_pair) => {
					let decapsulated_sym_key =
						TutaCryptMessage::deserialize(pub_enc_sym_key)?.decapsulate(&key_pair)?;
					Ok(DecapsulatedAesKey {
						decrypted_aes_key: decapsulated_sym_key.decrypted_sym_key_bytes.into(),
						sender_identity_pub_key: Some(decapsulated_sym_key.sender_identity_pub_key),
					})
				},
				_ => Err(AsymmetricCryptoError::UnexpectedAsymmetricKeyPairType(
					format!("{:? }", recipient_key_pair),
				)),
			},
			_ => Err(AsymmetricCryptoError::InvalidCryptoProtocolVersion(
				crypto_protocol_version.to_owned(),
			)),
		}
	}

	/// Loads the recipient_key_pair in the required version and decrypts the pub_enc_sym_key with it.
	pub async fn load_key_pair_and_decrypt_sym_key(
		&self,
		recipient_key_pair_group_id: &GeneratedId,
		recipient_key_version: u64,
		crypto_protocol_version: &CryptoProtocolVersion,
		pub_enc_sym_key: &[u8],
	) -> Result<DecapsulatedAesKey, AsymmetricCryptoError> {
		let key_pair = self
			.key_loader_facade
			.load_key_pair(recipient_key_pair_group_id, recipient_key_version)
			.await?;
		Self::decrypt_sym_key_with_key_pair(key_pair, crypto_protocol_version, pub_enc_sym_key)
	}

	/// Encrypts the symKey asymmetrically with the provided public keys.
	/// @param symKey the symmetric key  to be encrypted
	/// @param recipientPublicKeys the public key(s) of the recipient in the current version
	/// @param senderGroupId the group id of the sender. will only be used in case we also need the sender's key pair, e.g. with TutaCrypt.
	pub async fn asym_encrypt_sym_key(
		&self,
		sym_key: GenericAesKey,
		versioned_recipient_public_keys: Versioned<PublicKey>,
		sender_group_id: &GeneratedId,
	) -> Result<PubEncSymKey, AsymmetricCryptoError> {
		let recipient_public_key = versioned_recipient_public_keys.object;

		match recipient_public_key {
			PublicKey::RsaX25519(RsaX25519PublicKeys {
				rsa_public_key: rsa_pub_key,
				x25519_public_key: _,
			})
			| PublicKey::Rsa(rsa_pub_key) => {
				let pub_enc_sym_key_bytes =
					rsa_pub_key.encrypt(&self.randomizer_facade, sym_key.as_bytes())?;
				Ok(PubEncSymKey {
					pub_enc_sym_key_bytes,
					crypto_protocol_version: CryptoProtocolVersion::Rsa,
					sender_key_version: None,
					recipient_key_version: versioned_recipient_public_keys.version,
				})
			},
			PublicKey::TutaCrypt(tuta_crypt_keys) => {
				let sender_key_pair: Versioned<AsymmetricKeyPair> = self
					.key_loader_facade
					.load_current_key_pair(sender_group_id)
					.await?;
				let sender_x25519_key_pair = self
					.get_or_make_sender_identity_key_pair(sender_key_pair.object, sender_group_id)
					.await?;
				match sym_key {
					GenericAesKey::Aes128(_) => {
						Err(AsymmetricCryptoError::UnexpectedSymmetricKeyType(format!(
							"{:? }",
							sym_key
						)))
					},
					GenericAesKey::Aes256(aes256_sym_key) => Ok(self
						.tuta_crypt_encrypt_sym_key_impl(
							Versioned {
								object: tuta_crypt_keys,
								version: versioned_recipient_public_keys.version,
							},
							aes256_sym_key,
							Versioned {
								object: sender_x25519_key_pair,
								version: sender_key_pair.version,
							},
						)?),
				}
			},
		}
	}

	/// Encrypts `bucket_key` for every internal recipient of a confidential
	/// mail: the internal-recipient arm of TS `MailFacade.addRecipientKeyData`
	/// plus `CryptoFacade.encryptBucketKeyForInternalRecipient`. Each
	/// recipient's current public key comes from the PublicKeyService through
	/// the `PublicKeyProvider`, and `asym_encrypt_sym_key` encrypts the bucket
	/// key with it -- RSA for legacy keys, TutaCrypt (authenticated with the
	/// sender group's identity key, created first if the group has none) for
	/// PQ keys.
	///
	/// Like the TS client, every unknown recipient is collected before
	/// failing, and no key data is built once one is missing. The TS client
	/// additionally verifies keys of contacts the user verified manually;
	/// there are none here, so the service's current key is used, as the TS
	/// client does for every unverified contact. The returned fingerprints let
	/// a caller pin keys itself.
	///
	/// @param sender_group_id the user group, or a shared mailbox's mail group
	///        when sending from one (TS `isSharedMailboxSender`).
	pub async fn encrypt_bucket_key_for_internal_recipients(
		&self,
		bucket_key: &GenericAesKey,
		recipient_mail_addresses: &[String],
		sender_group_id: &GeneratedId,
	) -> Result<Vec<InternalRecipientKey>, InternalRecipientKeyError> {
		let mut not_found = Vec::new();
		let mut keys = Vec::with_capacity(recipient_mail_addresses.len());
		for address in recipient_mail_addresses {
			if address == SYSTEM_GROUP_MAIL_ADDRESS {
				not_found.push(address.clone());
				continue;
			}
			let identifier = PublicKeyIdentifier {
				identifier: address.clone(),
				identifier_type: PublicKeyIdentifierType::MailAddress,
			};
			let public_key = match self
				.public_key_provider
				.load_current_pub_key(&identifier)
				.await
			{
				Ok(public_key) => public_key,
				Err(PublicKeyLoadingError::KeyLoadingError(
					ApiCallError::ServerResponseError {
						source: HttpError::NotFoundError,
					},
				)) => {
					not_found.push(address.clone());
					continue;
				},
				Err(error) => return Err(AsymmetricCryptoError::from(error).into()),
			};
			if !not_found.is_empty() {
				continue;
			}
			let public_key_fingerprint = public_key_fingerprint(&public_key.object);
			let encrypted = self
				.asym_encrypt_sym_key(bucket_key.clone(), public_key, sender_group_id)
				.await?;
			keys.push(InternalRecipientKey {
				key_data: InternalRecipientKeyData {
					_id: None,
					mailAddress: address.clone(),
					pubEncBucketKey: encrypted.pub_enc_sym_key_bytes,
					recipientKeyVersion: convert_version_to_i64(encrypted.recipient_key_version),
					protocolVersion: encrypted.crypto_protocol_version as i64,
					senderKeyVersion: encrypted.sender_key_version.map(convert_version_to_i64),
				},
				public_key_fingerprint,
			});
		}
		if !not_found.is_empty() {
			return Err(InternalRecipientKeyError::RecipientsNotFound(not_found));
		}
		Ok(keys)
	}

	/// Encrypts the symKey asymmetrically with the provided public keys using the TutaCrypt protocol.
	/// @param symKey the key to be encrypted
	/// @param recipientPublicKeys MUST be a tuta_crypt key pair
	/// @param senderX25519KeyPair the sender's key pair (needed for authentication)
	/// @throws ProgrammingError if the recipientPublicKeys are not suitable for TutaCrypt
	pub fn tuta_crypt_encrypt_sym_key(
		&self,
		sym_key: Aes256Key,
		recipient_public_keys: Versioned<PublicKey>,
		sender_x25519_key_pair: Versioned<X25519KeyPair>,
	) -> Result<PubEncSymKey, AsymmetricCryptoError> {
		let recipient_public_key = recipient_public_keys.object;
		match recipient_public_key {
			PublicKey::RsaX25519(_) | PublicKey::Rsa(_) => {
				Err(AsymmetricCryptoError::UnexpectedPublicKeyPairType(format!(
					"{:? }",
					recipient_public_key
				)))
			},
			PublicKey::TutaCrypt(tuta_crypt_pub_keys) => self.tuta_crypt_encrypt_sym_key_impl(
				Versioned {
					object: tuta_crypt_pub_keys,
					version: recipient_public_keys.version,
				},
				sym_key,
				sender_x25519_key_pair,
			),
		}
	}

	fn tuta_crypt_encrypt_sym_key_impl(
		&self,
		recipient_public_key: Versioned<TutaCryptPublicKeys>,
		sym_key: Aes256Key,
		sender_x25519_key_pair: Versioned<X25519KeyPair>,
	) -> Result<PubEncSymKey, AsymmetricCryptoError> {
		let ephemeral_key_pair = X25519KeyPair::generate(&self.randomizer_facade);
		let encapsulation_iv = InitializationVector::generate(&self.randomizer_facade);
		let pub_enc_sym_key_bytes = TutaCryptMessage::encapsulate(
			&sender_x25519_key_pair.object,
			&ephemeral_key_pair,
			&recipient_public_key.object.x25519_public_key,
			&recipient_public_key.object.kyber_public_key,
			&sym_key,
			encapsulation_iv,
		)?
		.serialize();
		Ok(PubEncSymKey {
			pub_enc_sym_key_bytes,
			crypto_protocol_version: CryptoProtocolVersion::TutaCrypt,
			sender_key_version: Some(sender_x25519_key_pair.version),
			recipient_key_version: recipient_public_key.version,
		})
	}

	/// Returns the SenderIdentityKeyPair that is either already on the KeyPair that is being passed in,
	/// or creates a new one and writes it to the respective Group.
	/// @param senderKeyPair
	/// @param keyGroupId Id for the Group that Public Key Service might write a new IdentityKeyPair for.
	///        This is necessary as a User might send an E-Mail from a shared mailbox,
	///        for which the KeyPair should be created.
	async fn get_or_make_sender_identity_key_pair(
		&self,
		sender_key_pair: AsymmetricKeyPair,
		key_group_id: &GeneratedId,
	) -> Result<X25519KeyPair, AsymmetricCryptoError> {
		match sender_key_pair {
			AsymmetricKeyPair::TutaCryptKeyPairs(tuta_crypt_pairs) => {
				Ok(tuta_crypt_pairs.x25519_keys)
			},
			AsymmetricKeyPair::RSAX25519KeyPair(rsa_x25519_pairs) => {
				Ok(rsa_x25519_pairs.x25519_key_pair)
			},
			AsymmetricKeyPair::RSAKeyPair(_rsa_pair) => {
				// there is no x25519 key pair yet, so we have to generate and upload one
				let sym_group_key: VersionedAesKey = self
					.key_loader_facade
					.get_current_sym_group_key(key_group_id)
					.await?;
				let new_identity_key_pair = X25519KeyPair::generate(&self.randomizer_facade);
				let sym_enc_priv_x25519_key = sym_group_key.object.encrypt_data(
					new_identity_key_pair.private_key.as_bytes(),
					InitializationVector::generate(&self.randomizer_facade),
				)?;

				let data = PublicKeyPutIn {
					_format: 0,
					pubEccKey: new_identity_key_pair.public_key.as_bytes().to_vec(),
					symEncPrivEccKey: sym_enc_priv_x25519_key,
					keyGroup: key_group_id.to_owned(),
				};
				self.service_executor
					.put::<PublicKeyService>(data, ExtraServiceParams::default())
					.await?;
				Ok(new_identity_key_pair)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::crypto::asymmetric_crypto_facade::AsymmetricCryptoFacade;
	use crate::crypto::public_key_provider::{MockPublicKeyProvider, PublicKeyIdentifier};
	use crate::key_loader_facade::MockKeyLoaderFacade;
	use crate::services::service_executor::MockServiceExecutor;
	use crate::tutanota_constants::PublicKeyIdentifierType;
	use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
	use std::sync::Arc;

	fn make_asymmetric_crypto_facade(
		service_executor: MockServiceExecutor,
		public_key_provider: MockPublicKeyProvider,
	) -> AsymmetricCryptoFacade {
		let key_loader_facade = MockKeyLoaderFacade::default();
		AsymmetricCryptoFacade::new(
			Arc::new(key_loader_facade),
			make_thread_rng_facade(),
			Arc::new(service_executor),
			Arc::new(public_key_provider),
		)
	}

	fn setup_authentication_test() -> (
		u64,
		PublicKeyIdentifier,
		MockServiceExecutor,
		MockPublicKeyProvider,
	) {
		let sender_key_version = 0u64;
		let public_key_identifier = PublicKeyIdentifier {
			identifier: String::from("sender_id"),
			identifier_type: PublicKeyIdentifierType::GroupId,
		};

		let service_executor = MockServiceExecutor::default();
		let public_key_provider = MockPublicKeyProvider::default();
		(
			sender_key_version,
			public_key_identifier,
			service_executor,
			public_key_provider,
		)
	}

	mod authenticate_sender {
		use crate::crypto::asymmetric_crypto_facade::tests::{
			make_asymmetric_crypto_facade, setup_authentication_test,
		};
		use crate::crypto::key::PublicKey;
		use crate::crypto::kyber::KyberPublicKey;
		use crate::crypto::rsa::RSAPublicKey;
		use crate::crypto::tuta_crypt::TutaCryptPublicKeys;
		use crate::crypto::X25519PublicKey;
		use crate::services::generated::sys::PublicKeyService;
		use crate::tutanota_constants::EncryptionAuthStatus;
		use crate::util::test_utils::{
			get_kyber_pub_key_bytes, get_rsa_pub_key_bytes, get_x25519_pub_key_bytes,
		};
		use crypto_primitives::versioned::Versioned;
		use mockall::predicate::eq;

		#[tokio::test]
		async fn should_return_tutacrypt_authentication_succeeded_if_the_key_matches() {
			let (
				sender_key_version,
				public_key_identifier,
				mut service_executor,
				mut public_key_provider,
			) = setup_authentication_test();
			let pub_key = get_x25519_pub_key_bytes();
			let kyber_public_key = get_kyber_pub_key_bytes();
			let sender_identity_pub_key = X25519PublicKey::from_bytes(&pub_key.as_slice()).unwrap();

			service_executor.expect_get::<PublicKeyService>().never();
			service_executor.expect_put::<PublicKeyService>().never();
			public_key_provider
				.expect_load_versioned_pub_key()
				.with(eq(public_key_identifier.clone()), eq(sender_key_version))
				.returning(move |_, _| {
					Ok(Versioned {
						object: PublicKey::TutaCrypt(TutaCryptPublicKeys {
							x25519_public_key: X25519PublicKey::from_bytes(
								pub_key.clone().as_slice(),
							)
							.unwrap(),
							kyber_public_key: KyberPublicKey::from_bytes(
								&kyber_public_key.as_slice(),
							)
							.unwrap(),
						}),
						version: sender_key_version,
					})
				});

			let asymmetric_crypto_facade =
				make_asymmetric_crypto_facade(service_executor, public_key_provider);

			let result = asymmetric_crypto_facade
				.authenticate_sender(
					public_key_identifier,
					Versioned {
						object: &sender_identity_pub_key,
						version: sender_key_version,
					},
				)
				.await
				.unwrap();
			assert_eq!(
				result,
				EncryptionAuthStatus::TutacryptAuthenticationSucceeded,
			);
		}

		#[tokio::test]
		async fn should_return_tutacrypt_authentication_failed_if_sender_does_not_have_an_x25519_identity_key_in_the_requested_version(
		) {
			let (
				sender_key_version,
				public_key_identifier,
				mut service_executor,
				mut public_key_provider,
			) = setup_authentication_test();
			let pub_x25519_key = get_x25519_pub_key_bytes();
			let pub_rsa_key = get_rsa_pub_key_bytes();
			let sender_identity_pub_key = X25519PublicKey::from_bytes(&pub_x25519_key).unwrap();

			service_executor.expect_get::<PublicKeyService>().never();
			service_executor.expect_put::<PublicKeyService>().never();
			public_key_provider
				.expect_load_versioned_pub_key()
				.with(eq(public_key_identifier.clone()), eq(sender_key_version))
				.returning(move |_, _| {
					Ok(Versioned {
						object: PublicKey::Rsa(
							RSAPublicKey::deserialize(&pub_rsa_key.clone()).unwrap(),
						),
						version: sender_key_version,
					})
				});

			let asymmetric_crypto_facade =
				make_asymmetric_crypto_facade(service_executor, public_key_provider);
			let result = asymmetric_crypto_facade
				.authenticate_sender(
					public_key_identifier,
					Versioned {
						object: &sender_identity_pub_key,
						version: sender_key_version,
					},
				)
				.await
				.unwrap();

			assert_eq!(result, EncryptionAuthStatus::TutacryptAuthenticationFailed,);
		}

		#[tokio::test]
		async fn should_return_tutacrypt_authentication_failed_if_the_key_does_not_match() {
			let (
				sender_key_version,
				public_key_identifier,
				mut service_executor,
				mut public_key_provider,
			) = setup_authentication_test();

			let bad_pub_x25519_key = get_x25519_pub_key_bytes();
			let good_pub_x25519_key = vec![5; 32];

			let kyber_pub_key = get_kyber_pub_key_bytes();
			let sender_identity_pub_key =
				X25519PublicKey::from_bytes(good_pub_x25519_key.as_slice()).unwrap();

			service_executor.expect_get::<PublicKeyService>().never();
			service_executor.expect_put::<PublicKeyService>().never();
			public_key_provider
				.expect_load_versioned_pub_key()
				.with(eq(public_key_identifier.clone()), eq(sender_key_version))
				.returning(move |_, _| {
					Ok(Versioned {
						object: PublicKey::TutaCrypt(TutaCryptPublicKeys {
							x25519_public_key: X25519PublicKey::from_bytes(
								bad_pub_x25519_key.as_slice(),
							)
							.unwrap(), // not matching the sender_identity_pub_key
							kyber_public_key: KyberPublicKey::from_bytes(&kyber_pub_key.as_slice())
								.unwrap(),
						}),
						version: sender_key_version,
					})
				});

			let asymmetric_crypto_facade =
				make_asymmetric_crypto_facade(service_executor, public_key_provider);

			let result = asymmetric_crypto_facade
				.authenticate_sender(
					public_key_identifier,
					Versioned {
						object: &sender_identity_pub_key,
						version: sender_key_version,
					},
				)
				.await
				.unwrap();

			assert_eq!(result, EncryptionAuthStatus::TutacryptAuthenticationFailed,);
		}
	}

	mod decrypt_sym_key_with_key_pair_and_authenticate {
		use crate::crypto::asymmetric_crypto_facade::tests::make_asymmetric_crypto_facade;
		use crate::crypto::asymmetric_crypto_facade::tests::setup_authentication_test;
		use crate::crypto::asymmetric_crypto_facade::AsymmetricCryptoError;
		use crate::crypto::key::{AsymmetricKeyPair, PublicKey};
		use crate::crypto::kyber::KyberPublicKey;
		use crate::crypto::rsa::RSAKeyPair;
		use crate::crypto::tuta_crypt::{TutaCryptMessage, TutaCryptPublicKeys};
		use crate::crypto::x25519::X25519KeyPair;
		use crate::crypto::{Aes256Key, TutaCryptKeyPairs, X25519PublicKey};
		use crate::entities::generated::sys::PubEncKeyData;
		use crate::services::generated::sys::PublicKeyService;
		use crate::tutanota_constants::CryptoProtocolVersion;
		use crate::tutanota_constants::PublicKeyIdentifierType;
		use crate::util::test_utils::{get_kyber_pub_key_bytes, get_x25519_pub_key_bytes};
		use crypto_primitives::aes::InitializationVector;
		use crypto_primitives::key::GenericAesKey;
		use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
		use crypto_primitives::versioned::Versioned;
		use mockall::predicate::eq;

		#[tokio::test]
		async fn error_if_authentication_fails() {
			let (
				sender_key_version,
				sender_identifier,
				mut service_executor,
				mut public_key_provider,
			) = setup_authentication_test();

			service_executor.expect_get::<PublicKeyService>().never();
			service_executor.expect_put::<PublicKeyService>().never();
			public_key_provider
				.expect_load_versioned_pub_key()
				.with(eq(sender_identifier.clone()), eq(sender_key_version))
				.returning(move |_, _| {
					Ok(Versioned {
						object: PublicKey::TutaCrypt(TutaCryptPublicKeys {
							x25519_public_key: X25519PublicKey::from_bytes(
								get_x25519_pub_key_bytes().as_slice(), // not matching the sender_identity_pub_key
							)
							.unwrap(),
							kyber_public_key: KyberPublicKey::from_bytes(
								get_kyber_pub_key_bytes().as_slice(),
							)
							.unwrap(),
						}),
						version: sender_key_version,
					})
				});

			let asymmetric_crypto_facade =
				make_asymmetric_crypto_facade(service_executor, public_key_provider);

			let randomizer_facade = make_thread_rng_facade();
			let recipient_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);

			let pub_enc_sym_key = TutaCryptMessage::encapsulate(
				&X25519KeyPair::generate(&randomizer_facade),
				&X25519KeyPair::generate(&randomizer_facade),
				&recipient_key_pair.x25519_keys.public_key.clone(),
				&recipient_key_pair.kyber_keys.public_key.clone(),
				&Aes256Key::generate(&randomizer_facade),
				InitializationVector::generate(&randomizer_facade),
			)
			.unwrap();

			let recipient_identifier = String::from("recipient_identifier");
			let recipient_identifier_type = PublicKeyIdentifierType::MailAddress;
			let pub_enc_key_data = PubEncKeyData {
				_id: Default::default(),
				pubEncSymKey: pub_enc_sym_key.serialize(),
				protocolVersion: CryptoProtocolVersion::TutaCrypt as i64,
				recipientIdentifier: recipient_identifier,
				recipientIdentifierType: recipient_identifier_type as i64,
				recipientKeyVersion: 0,
				senderKeyVersion: Some(sender_key_version as i64),
				senderIdentifier: Some(sender_identifier.identifier.clone()),
				senderIdentifierType: Some(sender_identifier.identifier_type.clone() as i64),
				symKeyMac: None,
			};

			let result = asymmetric_crypto_facade
				.decrypt_sym_key_with_key_pair_and_authenticate(
					AsymmetricKeyPair::TutaCryptKeyPairs(recipient_key_pair),
					pub_enc_key_data,
					sender_identifier,
				)
				.await;
			assert!(result.is_err());
			assert!(matches!(
				result.err().unwrap(),
				AsymmetricCryptoError::AuthenticationError { .. }
			));
		}

		#[tokio::test]
		async fn should_not_try_authentication_when_protocol_is_not_tuta_crypt() {
			let (_sender_key_version, sender_identifier, mut service_executor, public_key_provider) =
				setup_authentication_test();

			service_executor.expect_get::<PublicKeyService>().never();

			let asymmetric_crypto_facade =
				make_asymmetric_crypto_facade(service_executor, public_key_provider);

			let randomizer_facade = make_thread_rng_facade();
			let recipient_key_pair = RSAKeyPair::generate(&randomizer_facade);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let pub_enc_sym_key = recipient_key_pair
				.public_key
				.encrypt(&randomizer_facade, sym_key.as_bytes())
				.unwrap();
			let pub_enc_key_data: PubEncKeyData = PubEncKeyData {
				_id: Default::default(),
				pubEncSymKey: pub_enc_sym_key,
				recipientIdentifier: "".to_string(),
				recipientIdentifierType: 0,
				recipientKeyVersion: 0,
				protocolVersion: CryptoProtocolVersion::Rsa as i64,
				senderKeyVersion: None,
				senderIdentifier: Some(sender_identifier.identifier.clone()),
				senderIdentifierType: Some(sender_identifier.identifier_type.clone() as i64),
				symKeyMac: None,
			};

			let result = asymmetric_crypto_facade
				.decrypt_sym_key_with_key_pair_and_authenticate(
					AsymmetricKeyPair::RSAKeyPair(recipient_key_pair),
					pub_enc_key_data,
					sender_identifier,
				)
				.await
				.unwrap();

			assert_eq!(result.sender_identity_pub_key, None);
			assert_eq!(result.decrypted_aes_key, GenericAesKey::Aes256(sym_key));
		}
	}

	mod decrypt_sym_key_with_key_pair {
		use crate::crypto::asymmetric_crypto_facade::{
			AsymmetricCryptoError, AsymmetricCryptoFacade,
		};
		use crate::crypto::key::AsymmetricKeyPair;
		use crate::crypto::rsa::RSAKeyPair;
		use crate::crypto::tuta_crypt::TutaCryptMessage;
		use crate::crypto::x25519::X25519KeyPair;
		use crate::crypto::{Aes256Key, TutaCryptKeyPairs};
		use crate::tutanota_constants::CryptoProtocolVersion;
		use crypto_primitives::aes::InitializationVector;
		use crypto_primitives::key::GenericAesKey;
		use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;

		#[tokio::test]
		async fn error_when_the_protocol_version_is_symmetric() {
			let result = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::RSAKeyPair(RSAKeyPair::generate(&make_thread_rng_facade())),
				&CryptoProtocolVersion::SymmetricEncryption,
				&[1, 2, 3],
			);
			assert!(result.is_err());
			assert!(matches!(
				result.err().unwrap(),
				AsymmetricCryptoError::InvalidCryptoProtocolVersion { .. }
			));
		}

		#[tokio::test]
		async fn should_call_rsa_decryption_when_the_protocol_version_is_set_to_rsa() {
			let randomizer_facade = make_thread_rng_facade();
			let recipient_key_pair = RSAKeyPair::generate(&randomizer_facade);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let pub_enc_sym_key = recipient_key_pair
				.public_key
				.encrypt(&randomizer_facade, sym_key.as_bytes())
				.unwrap();

			let result = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::RSAKeyPair(recipient_key_pair),
				&CryptoProtocolVersion::Rsa,
				&pub_enc_sym_key,
			)
			.unwrap();

			assert_eq!(result.sender_identity_pub_key, None);
			assert_eq!(result.decrypted_aes_key, GenericAesKey::Aes256(sym_key));
		}

		#[tokio::test]
		async fn error_when_crypto_protocol_version_does_not_match_key_pair_rsa() {
			let result = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::TutaCryptKeyPairs(TutaCryptKeyPairs::generate(
					&make_thread_rng_facade(),
				)),
				&CryptoProtocolVersion::Rsa,
				&[1, 2, 3],
			);
			assert!(result.is_err());
			assert!(matches!(
				result.err().unwrap(),
				AsymmetricCryptoError::UnexpectedAsymmetricKeyPairType { .. }
			));
		}

		#[tokio::test]
		async fn error_when_crypto_protocol_version_does_not_match_key_pair_tuta_crypt() {
			let result = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::RSAKeyPair(RSAKeyPair::generate(&make_thread_rng_facade())),
				&CryptoProtocolVersion::TutaCrypt,
				&[1, 2, 3],
			);
			assert!(result.is_err());
			assert!(matches!(
				result.err().unwrap(),
				AsymmetricCryptoError::UnexpectedAsymmetricKeyPairType { .. }
			));
		}

		#[tokio::test]
		async fn should_call_tuta_crypt_decryption_when_the_protocol_version_is_set_to_tuta_crypt()
		{
			let randomizer_facade = make_thread_rng_facade();
			let recipient_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);

			let sender_x25519_key_pair = X25519KeyPair::generate(&randomizer_facade);
			let sym_key = Aes256Key::generate(&randomizer_facade);
			let pub_enc_sym_key = TutaCryptMessage::encapsulate(
				&sender_x25519_key_pair,
				&X25519KeyPair::generate(&randomizer_facade),
				&recipient_key_pair.x25519_keys.public_key.clone(),
				&recipient_key_pair.kyber_keys.public_key.clone(),
				&sym_key,
				InitializationVector::generate(&randomizer_facade),
			)
			.unwrap();

			let result = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::TutaCryptKeyPairs(recipient_key_pair),
				&CryptoProtocolVersion::TutaCrypt,
				&pub_enc_sym_key.serialize(),
			)
			.unwrap();

			assert_eq!(
				result.sender_identity_pub_key,
				Some(sender_x25519_key_pair.public_key)
			);
			assert_eq!(result.decrypted_aes_key, GenericAesKey::Aes256(sym_key));
		}
	}

	mod encrypt_pub_sym_key {
		use crate::crypto::asymmetric_crypto_facade::AsymmetricCryptoFacade;
		use crate::crypto::key::RsaX25519PublicKeys;
		use crate::crypto::key::{AsymmetricKeyPair, PublicKey};
		use crate::crypto::public_key_provider::MockPublicKeyProvider;
		use crate::crypto::rsa::RSAKeyPair;
		use crate::crypto::rsa::RSAX25519KeyPair;
		use crate::crypto::tuta_crypt::TutaCryptPublicKeys;
		use crate::crypto::{Aes256Key, TutaCryptKeyPairs};
		use crate::entities::generated::sys::PublicKeyPutIn;
		use crate::key_loader_facade::MockKeyLoaderFacade;
		use crate::services::generated::sys::PublicKeyService;
		use crate::services::service_executor::MockServiceExecutor;
		use crate::tutanota_constants::CryptoProtocolVersion;
		use crate::ExtraServiceParams;
		use crate::GeneratedId;
		use crate::GenericAesKey;
		use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
		use crypto_primitives::versioned::Versioned;
		use mockall::predicate::eq;
		use std::sync::Arc;

		#[tokio::test]
		async fn encrypt_the_sym_key_with_the_recipient_tuta_crypt_public_key() {
			let sender_key_version = 1u64;
			let sender_group_id = GeneratedId::test_random();

			let mut service_executor = MockServiceExecutor::default();
			let public_key_provider = MockPublicKeyProvider::default();
			service_executor.expect_get::<PublicKeyService>().never();

			let mut key_loader_facade = MockKeyLoaderFacade::default();

			let randomizer_facade = make_thread_rng_facade();
			let sender_key_pair = AsymmetricKeyPair::TutaCryptKeyPairs(
				TutaCryptKeyPairs::generate(&randomizer_facade),
			);
			key_loader_facade
				.expect_load_current_key_pair()
				.with(eq(sender_group_id.clone()))
				.returning(move |_| {
					Ok(Versioned {
						object: sender_key_pair.clone(),
						version: sender_key_version,
					})
				});

			let asymmetric_crypto_facade = AsymmetricCryptoFacade::new(
				Arc::new(key_loader_facade),
				make_thread_rng_facade(),
				Arc::new(service_executor),
				Arc::new(public_key_provider),
			);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let recipient_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);
			let recipient_key_version = 3u64;
			let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
				version: recipient_key_version,
				object: PublicKey::TutaCrypt(TutaCryptPublicKeys {
					kyber_public_key: recipient_key_pair.kyber_keys.public_key,
					x25519_public_key: recipient_key_pair.x25519_keys.public_key,
				}),
			};

			let pub_enc_sym_key = asymmetric_crypto_facade
				.asym_encrypt_sym_key(
					GenericAesKey::Aes256(sym_key),
					versioned_recipient_public_keys,
					&sender_group_id,
				)
				.await
				.unwrap();

			assert_eq!(
				pub_enc_sym_key.crypto_protocol_version,
				CryptoProtocolVersion::TutaCrypt
			);
			assert_eq!(pub_enc_sym_key.sender_key_version, Some(sender_key_version));
			assert_eq!(pub_enc_sym_key.recipient_key_version, recipient_key_version);
			assert!(pub_enc_sym_key.pub_enc_sym_key_bytes.len() > 1000); // tutaCrypt tests will check that this is a valid tuta_crypt_message
		}

		#[tokio::test]
		async fn recipient_has_tuta_crypt_public_key_and_sender_has_only_rsa_key_pair_then_put_sender_x25519_key(
		) {
			let sender_key_version = 1u64;
			let sender_group_id = GeneratedId::test_random();
			let sender_group_id_clone = sender_group_id.clone();

			let mut service_executor = MockServiceExecutor::default();
			let public_key_provider = MockPublicKeyProvider::default();
			service_executor.expect_get::<PublicKeyService>().never();
			service_executor
				.expect_put::<PublicKeyService>()
				.withf(
					move |put_in: &PublicKeyPutIn, _params: &ExtraServiceParams| {
						put_in.keyGroup == sender_group_id_clone
					},
				)
				.returning(|_, _| Ok(()))
				.once();

			let mut key_loader_facade = MockKeyLoaderFacade::default();

			let randomizer_facade = make_thread_rng_facade();
			let sender_key_pair =
				AsymmetricKeyPair::RSAKeyPair(RSAKeyPair::generate(&randomizer_facade));
			key_loader_facade
				.expect_load_current_key_pair()
				.with(eq(sender_group_id.clone()))
				.returning(move |_| {
					Ok(Versioned {
						object: sender_key_pair.clone(),
						version: sender_key_version,
					})
				});

			let current_sym_sender_group_key = Aes256Key::generate(&randomizer_facade);
			key_loader_facade
				.expect_get_current_sym_group_key()
				.with(eq(sender_group_id.clone()))
				.returning(move |_| {
					Ok(Versioned {
						version: sender_key_version,
						object: GenericAesKey::Aes256(current_sym_sender_group_key.clone()),
					})
				})
				.once();

			let asymmetric_crypto_facade = AsymmetricCryptoFacade::new(
				Arc::new(key_loader_facade),
				make_thread_rng_facade(),
				Arc::new(service_executor),
				Arc::new(public_key_provider),
			);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let recipient_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);
			let recipient_key_version = 3u64;
			let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
				version: recipient_key_version,
				object: PublicKey::TutaCrypt(TutaCryptPublicKeys {
					kyber_public_key: recipient_key_pair.kyber_keys.public_key,
					x25519_public_key: recipient_key_pair.x25519_keys.public_key,
				}),
			};
			let pub_enc_sym_key = asymmetric_crypto_facade
				.asym_encrypt_sym_key(
					GenericAesKey::Aes256(sym_key),
					versioned_recipient_public_keys,
					&sender_group_id,
				)
				.await
				.unwrap();

			assert_eq!(
				pub_enc_sym_key.crypto_protocol_version,
				CryptoProtocolVersion::TutaCrypt
			);
			assert_eq!(pub_enc_sym_key.sender_key_version, Some(sender_key_version));
			assert_eq!(pub_enc_sym_key.recipient_key_version, recipient_key_version);
			assert!(pub_enc_sym_key.pub_enc_sym_key_bytes.len() > 1000); // tutaCrypt tests will check that this is a valid tuta_crypt_message
		}

		#[tokio::test]
		async fn encrypt_rsa() {
			let sender_group_id = GeneratedId::test_random();

			let mut service_executor = MockServiceExecutor::default();
			let public_key_provider = MockPublicKeyProvider::default();
			service_executor.expect_put::<PublicKeyService>().never();
			service_executor.expect_get::<PublicKeyService>().never();

			let key_loader_facade = MockKeyLoaderFacade::default();

			let randomizer_facade = make_thread_rng_facade();

			let asymmetric_crypto_facade = AsymmetricCryptoFacade::new(
				Arc::new(key_loader_facade),
				make_thread_rng_facade(),
				Arc::new(service_executor),
				Arc::new(public_key_provider),
			);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let recipient_key_pair = RSAKeyPair::generate(&randomizer_facade);
			let recipient_key_version = 3u64;
			let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
				version: recipient_key_version,
				object: PublicKey::Rsa(recipient_key_pair.public_key),
			};

			let pub_enc_sym_key = asymmetric_crypto_facade
				.asym_encrypt_sym_key(
					GenericAesKey::Aes256(sym_key),
					versioned_recipient_public_keys,
					&sender_group_id,
				)
				.await
				.unwrap();

			assert_eq!(
				pub_enc_sym_key.crypto_protocol_version,
				CryptoProtocolVersion::Rsa
			);
			assert_eq!(pub_enc_sym_key.sender_key_version, None);
			assert_eq!(pub_enc_sym_key.recipient_key_version, recipient_key_version);
			assert!(pub_enc_sym_key.pub_enc_sym_key_bytes.len() > 1); // rsa tests will check that this is a valid ciphertext
		}

		#[tokio::test]
		async fn encrypt_symetric_key_with_an_rsa_x25519_combo_key_behaves_like_rsa() {
			let sender_group_id = GeneratedId::test_random();

			let mut service_executor = MockServiceExecutor::default();
			let public_key_provider = MockPublicKeyProvider::default();
			service_executor.expect_put::<PublicKeyService>().never();
			service_executor.expect_get::<PublicKeyService>().never();

			let key_loader_facade = MockKeyLoaderFacade::default();

			let randomizer_facade = make_thread_rng_facade();

			let asymmetric_crypto_facade = AsymmetricCryptoFacade::new(
				Arc::new(key_loader_facade),
				make_thread_rng_facade(),
				Arc::new(service_executor),
				Arc::new(public_key_provider),
			);

			let sym_key = Aes256Key::generate(&randomizer_facade);
			let recipient_key_pair = RSAX25519KeyPair::generate(&randomizer_facade);
			let recipient_key_version = 3u64;
			let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
				version: recipient_key_version,
				object: PublicKey::RsaX25519(RsaX25519PublicKeys {
					rsa_public_key: recipient_key_pair.rsa_key_pair.public_key,
					x25519_public_key: recipient_key_pair.x25519_key_pair.public_key,
				}),
			};

			let pub_enc_sym_key = asymmetric_crypto_facade
				.asym_encrypt_sym_key(
					GenericAesKey::Aes256(sym_key),
					versioned_recipient_public_keys,
					&sender_group_id,
				)
				.await
				.unwrap();

			assert_eq!(
				pub_enc_sym_key.crypto_protocol_version,
				CryptoProtocolVersion::Rsa
			);
			assert_eq!(pub_enc_sym_key.sender_key_version, None);
			assert_eq!(pub_enc_sym_key.recipient_key_version, recipient_key_version);
			assert!(pub_enc_sym_key.pub_enc_sym_key_bytes.len() > 1); // rsa tests will check that this is a valid ciphertext
		}

		mod tuta_crypt_encrypt_sym_key {
			use crate::crypto::asymmetric_crypto_facade::tests::make_asymmetric_crypto_facade;
			use crate::crypto::asymmetric_crypto_facade::AsymmetricCryptoError;
			use crate::crypto::key::PublicKey;
			use crate::crypto::key::RsaX25519PublicKeys;
			use crate::crypto::public_key_provider::MockPublicKeyProvider;
			use crate::crypto::rsa::RSAKeyPair;
			use crate::crypto::rsa::RSAX25519KeyPair;
			use crate::crypto::x25519::X25519KeyPair;
			use crate::crypto::Aes256Key;
			use crate::services::generated::sys::PublicKeyService;
			use crate::services::service_executor::MockServiceExecutor;
			use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
			use crypto_primitives::versioned::Versioned;

			#[tokio::test]
			async fn error_when_passing_an_rsa_public_key() {
				let sender_key_version = 1u64;

				let mut service_executor = MockServiceExecutor::default();
				let public_key_provider = MockPublicKeyProvider::default();
				service_executor.expect_get::<PublicKeyService>().never();
				let randomizer_facade = make_thread_rng_facade();

				let asymmetric_crypto_facade =
					make_asymmetric_crypto_facade(service_executor, public_key_provider);

				let sym_key = Aes256Key::generate(&randomizer_facade);
				let recipient_key_pair = RSAKeyPair::generate(&randomizer_facade);
				let recipient_key_version = 3u64;
				let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
					version: recipient_key_version,
					object: PublicKey::Rsa(recipient_key_pair.public_key),
				};

				let result = asymmetric_crypto_facade.tuta_crypt_encrypt_sym_key(
					sym_key,
					versioned_recipient_public_keys,
					Versioned {
						version: sender_key_version,
						object: X25519KeyPair::generate(&randomizer_facade),
					},
				);

				assert!(result.is_err());
				assert!(matches!(
					result.err().unwrap(),
					AsymmetricCryptoError::UnexpectedPublicKeyPairType { .. }
				));
			}

			#[tokio::test]
			async fn error_when_passing_an_rsa_x25519_public_key() {
				let sender_key_version = 1u64;

				let mut service_executor = MockServiceExecutor::default();
				let public_key_provider = MockPublicKeyProvider::default();
				service_executor.expect_get::<PublicKeyService>().never();
				let randomizer_facade = make_thread_rng_facade();

				let asymmetric_crypto_facade =
					make_asymmetric_crypto_facade(service_executor, public_key_provider);

				let sym_key = Aes256Key::generate(&randomizer_facade);
				let recipient_key_pair = RSAX25519KeyPair::generate(&randomizer_facade);
				let recipient_key_version = 3u64;
				let versioned_recipient_public_keys: Versioned<PublicKey> = Versioned {
					version: recipient_key_version,
					object: PublicKey::RsaX25519(RsaX25519PublicKeys {
						rsa_public_key: recipient_key_pair.rsa_key_pair.public_key,
						x25519_public_key: recipient_key_pair.x25519_key_pair.public_key,
					}),
				};

				let result = asymmetric_crypto_facade.tuta_crypt_encrypt_sym_key(
					sym_key,
					versioned_recipient_public_keys,
					Versioned {
						version: sender_key_version,
						object: X25519KeyPair::generate(&randomizer_facade),
					},
				);

				assert!(result.is_err());
				assert!(matches!(
					result.err().unwrap(),
					AsymmetricCryptoError::UnexpectedPublicKeyPairType { .. }
				));
			}
		}
	}

	mod encrypt_bucket_key_for_internal_recipients {
		use crate::crypto::asymmetric_crypto_facade::{
			public_key_fingerprint, AsymmetricCryptoError, AsymmetricCryptoFacade,
			InternalRecipientKeyError,
		};
		use crate::crypto::key::{AsymmetricKeyPair, PublicKey};
		use crate::crypto::public_key_provider::{MockPublicKeyProvider, PublicKeyLoadingError};
		use crate::crypto::rsa::RSAKeyPair;
		use crate::crypto::tuta_crypt::TutaCryptPublicKeys;
		use crate::crypto::{Aes256Key, TutaCryptKeyPairs};
		use crate::key_loader_facade::MockKeyLoaderFacade;
		use crate::rest_error::HttpError;
		use crate::services::generated::sys::PublicKeyService;
		use crate::services::service_executor::MockServiceExecutor;
		use crate::tutanota_constants::{
			CryptoProtocolVersion, PublicKeyIdentifierType, SYSTEM_GROUP_MAIL_ADDRESS,
		};
		use crate::ApiCallError;
		use crate::GeneratedId;
		use crate::GenericAesKey;
		use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
		use crypto_primitives::versioned::Versioned;
		use mockall::predicate::eq;
		use std::sync::Arc;

		fn not_found() -> PublicKeyLoadingError {
			PublicKeyLoadingError::KeyLoadingError(ApiCallError::ServerResponseError {
				source: HttpError::NotFoundError,
			})
		}

		fn facade(
			key_loader_facade: MockKeyLoaderFacade,
			public_key_provider: MockPublicKeyProvider,
		) -> AsymmetricCryptoFacade {
			let mut service_executor = MockServiceExecutor::default();
			service_executor.expect_get::<PublicKeyService>().never();
			service_executor.expect_put::<PublicKeyService>().never();
			AsymmetricCryptoFacade::new(
				Arc::new(key_loader_facade),
				make_thread_rng_facade(),
				Arc::new(service_executor),
				Arc::new(public_key_provider),
			)
		}

		fn serve_key(
			public_key_provider: &mut MockPublicKeyProvider,
			address: &'static str,
			key: Versioned<PublicKey>,
		) {
			public_key_provider
				.expect_load_current_pub_key()
				.withf(move |identifier| {
					identifier.identifier == address
						&& identifier.identifier_type == PublicKeyIdentifierType::MailAddress
				})
				.returning(move |_| Ok(key.clone()))
				.once();
		}

		#[tokio::test]
		async fn tuta_crypt_recipients_can_decrypt_the_bucket_key_and_authenticate_the_sender() {
			let randomizer_facade = make_thread_rng_facade();
			let sender_group_id = GeneratedId::test_random();
			let sender_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);
			let sender_identity = sender_key_pair.x25519_keys.public_key.clone();
			let mut key_loader_facade = MockKeyLoaderFacade::default();
			key_loader_facade
				.expect_load_current_key_pair()
				.with(eq(sender_group_id.clone()))
				.returning(move |_| {
					Ok(Versioned {
						object: AsymmetricKeyPair::TutaCryptKeyPairs(sender_key_pair.clone()),
						version: 1,
					})
				});
			let recipient_key_pair = TutaCryptKeyPairs::generate(&randomizer_facade);
			let recipient_public_key = PublicKey::TutaCrypt(TutaCryptPublicKeys {
				x25519_public_key: recipient_key_pair.x25519_keys.public_key.clone(),
				kyber_public_key: recipient_key_pair.kyber_keys.public_key.clone(),
			});
			let mut public_key_provider = MockPublicKeyProvider::default();
			serve_key(
				&mut public_key_provider,
				"bob@tuta.com",
				Versioned::new(recipient_public_key.clone(), 3),
			);
			let bucket_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer_facade));

			let keys = facade(key_loader_facade, public_key_provider)
				.encrypt_bucket_key_for_internal_recipients(
					&bucket_key,
					&["bob@tuta.com".to_string()],
					&sender_group_id,
				)
				.await
				.unwrap();

			assert_eq!(keys.len(), 1);
			let key_data = &keys[0].key_data;
			assert_eq!(key_data.mailAddress, "bob@tuta.com");
			assert_eq!(
				key_data.protocolVersion,
				CryptoProtocolVersion::TutaCrypt as i64
			);
			assert_eq!(key_data.recipientKeyVersion, 3);
			assert_eq!(key_data.senderKeyVersion, Some(1));
			assert_eq!(
				keys[0].public_key_fingerprint,
				public_key_fingerprint(&recipient_public_key)
			);
			let decapsulated = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::TutaCryptKeyPairs(recipient_key_pair),
				&CryptoProtocolVersion::TutaCrypt,
				&key_data.pubEncBucketKey,
			)
			.unwrap();
			assert_eq!(
				decapsulated.decrypted_aes_key.as_bytes(),
				bucket_key.as_bytes()
			);
			assert_eq!(decapsulated.sender_identity_pub_key, Some(sender_identity));
		}

		#[tokio::test]
		async fn legacy_rsa_recipients_get_an_rsa_encrypted_bucket_key() {
			let randomizer_facade = make_thread_rng_facade();
			let mut key_loader_facade = MockKeyLoaderFacade::default();
			key_loader_facade.expect_load_current_key_pair().never();
			let recipient_key_pair = RSAKeyPair::generate(&randomizer_facade);
			let recipient_public_key = PublicKey::Rsa(recipient_key_pair.public_key.clone());
			let mut public_key_provider = MockPublicKeyProvider::default();
			serve_key(
				&mut public_key_provider,
				"old@tutanota.de",
				Versioned::new(recipient_public_key.clone(), 0),
			);
			let bucket_key = GenericAesKey::Aes256(Aes256Key::generate(&randomizer_facade));

			let keys = facade(key_loader_facade, public_key_provider)
				.encrypt_bucket_key_for_internal_recipients(
					&bucket_key,
					&["old@tutanota.de".to_string()],
					&GeneratedId::test_random(),
				)
				.await
				.unwrap();

			let key_data = &keys[0].key_data;
			assert_eq!(key_data.protocolVersion, CryptoProtocolVersion::Rsa as i64);
			assert_eq!(key_data.recipientKeyVersion, 0);
			assert_eq!(key_data.senderKeyVersion, None);
			assert_eq!(
				keys[0].public_key_fingerprint,
				public_key_fingerprint(&recipient_public_key)
			);
			let decrypted = AsymmetricCryptoFacade::decrypt_sym_key_with_key_pair(
				AsymmetricKeyPair::RSAKeyPair(recipient_key_pair),
				&CryptoProtocolVersion::Rsa,
				&key_data.pubEncBucketKey,
			)
			.unwrap();
			assert_eq!(
				decrypted.decrypted_aes_key.as_bytes(),
				bucket_key.as_bytes()
			);
		}

		#[tokio::test]
		async fn every_unknown_recipient_is_reported_and_nothing_is_encrypted() {
			let randomizer_facade = make_thread_rng_facade();
			let mut key_loader_facade = MockKeyLoaderFacade::default();
			key_loader_facade.expect_load_current_key_pair().never();
			let known = TutaCryptKeyPairs::generate(&randomizer_facade);
			let mut public_key_provider = MockPublicKeyProvider::default();
			public_key_provider
				.expect_load_current_pub_key()
				.withf(|identifier| identifier.identifier != "known@tuta.com")
				.returning(|_| Err(not_found()))
				.times(2);
			serve_key(
				&mut public_key_provider,
				"known@tuta.com",
				Versioned::new(
					PublicKey::TutaCrypt(TutaCryptPublicKeys {
						x25519_public_key: known.x25519_keys.public_key.clone(),
						kyber_public_key: known.kyber_keys.public_key.clone(),
					}),
					1,
				),
			);
			let addresses = [
				"gone@tuta.com".to_string(),
				"known@tuta.com".to_string(),
				SYSTEM_GROUP_MAIL_ADDRESS.to_string(),
				"never@tuta.com".to_string(),
			];

			let result = facade(key_loader_facade, public_key_provider)
				.encrypt_bucket_key_for_internal_recipients(
					&GenericAesKey::Aes256(Aes256Key::generate(&randomizer_facade)),
					&addresses,
					&GeneratedId::test_random(),
				)
				.await;

			match result {
				Err(InternalRecipientKeyError::RecipientsNotFound(missing)) => assert_eq!(
					missing,
					["gone@tuta.com", SYSTEM_GROUP_MAIL_ADDRESS, "never@tuta.com"]
				),
				_ => panic!("expected RecipientsNotFound"),
			}
		}

		#[tokio::test]
		async fn a_failed_key_lookup_is_an_error_not_a_missing_recipient() {
			let mut public_key_provider = MockPublicKeyProvider::default();
			public_key_provider
				.expect_load_current_pub_key()
				.returning(|_| {
					Err(PublicKeyLoadingError::KeyLoadingError(
						ApiCallError::ServerResponseError {
							source: HttpError::TooManyRequestsError {
								suspension_time_sec: None,
							},
						},
					))
				})
				.once();

			let result = facade(MockKeyLoaderFacade::default(), public_key_provider)
				.encrypt_bucket_key_for_internal_recipients(
					&GenericAesKey::Aes256(Aes256Key::generate(&make_thread_rng_facade())),
					&["busy@tuta.com".to_string()],
					&GeneratedId::test_random(),
				)
				.await;

			assert!(matches!(
				result,
				Err(InternalRecipientKeyError::Crypto(
					AsymmetricCryptoError::PublicKeyLoadingError(_)
				))
			));
		}
	}
}
