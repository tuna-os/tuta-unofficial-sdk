//! Password-protected ("secure external") recipients of a confidential mail:
//! the external-recipient arm of TS `MailFacade.addRecipientKeyData`, with
//! `getExternalGroupKeys` and `createExternalUser`.
//!
//! A recipient outside Tuta reads a confidential mail through an external
//! user that the sender's account owns. The user's group keys are wrapped
//! with the sender's user group key, so only the sender's account can find
//! them again, and with a key derived from a passphrase the sender shares
//! with the recipient out of band. Each mail carries a fresh salt, the
//! passphrase verifier and the external user group key under the passphrase
//! key, plus the bucket key under the external mail group key.

use crate::crypto::argon2_id::generate_key_from_passphrase;
use crate::crypto::key::KeyLoadError;
use crate::crypto::sha256;
use crate::entities::generated::sys::{
	ExternalUserReference, Group, GroupRoot, RootInstance, User,
};
use crate::entities::generated::tutanota::{
	CreateExternalUserGroupData, ExternalUserData, SecureExternalRecipientKeyData,
};
use crate::entities::Entity;
use crate::groups::GroupType;
#[cfg_attr(test, mockall_double::double)]
use crate::key_loader_facade::KeyLoaderFacade;
use crate::login::login_facade::KdfType;
use crate::rest_error::HttpError;
use crate::services::generated::tutanota::ExternalUserService;
#[cfg_attr(test, mockall_double::double)]
use crate::services::service_executor::ServiceExecutor;
use crate::services::ExtraServiceParams;
use crate::tutanota_constants::AccountType;
use crate::type_model_provider::TypeModelProvider;
#[cfg_attr(test, mockall_double::double)]
use crate::typed_entity_client::TypedEntityClient;
#[cfg_attr(test, mockall_double::double)]
use crate::user_facade::UserFacade;
use crate::util::convert_version_to_i64;
use crate::{ApiCallError, CustomId, GeneratedId, IdTupleCustom};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_primitives::aes::{Aes256Key, AesEncryptError, InitializationVector};
use crypto_primitives::key::{GenericAesKey, KeyDecryptError};
use crypto_primitives::randomizer_facade::RandomizerFacade;
use crypto_primitives::versioned::VersionedAesKey;
use std::sync::Arc;

/// One password-protected recipient: the address as the mail names it and
/// the passphrase the sender shares with them.
pub struct SecureExternalRecipient<'a> {
	pub mail_address: &'a str,
	pub passphrase: &'a str,
}

#[derive(thiserror::Error, Debug)]
pub enum SecureExternalRecipientError {
	/// These recipients have no passphrase. TS collects them with the
	/// not-found recipients; no key data is built for anyone then.
	#[error("recipients without a passphrase")]
	MissingPassphrase(Vec<String>),
	/// An external (secure-mail) user cannot provision further external
	/// users.
	#[error("external sender")]
	ExternalSender,
	/// TS refuses secure external recipients from a shared mailbox: the
	/// external user would hang off the sender's own user group.
	#[error("shared mailbox sender")]
	SharedMailboxSender,
	/// The external user's stored groups are not what TS creates.
	#[error("malformed external user: {0}")]
	MalformedExternalUser(&'static str),
	#[error("api call failed")]
	ApiCall(#[from] ApiCallError),
	#[error("key loading failed")]
	KeyLoad(#[from] KeyLoadError),
	#[error("key decryption failed")]
	KeyDecrypt(#[from] KeyDecryptError),
	#[error("encryption failed")]
	AesEncrypt(#[from] AesEncryptError),
}

/// The external user's current keys, as `getExternalGroupKeys` returns them.
struct ExternalGroupKeys {
	user_group_key: VersionedAesKey,
	mail_group_key: VersionedAesKey,
}

pub struct SecureExternalFacade {
	user_facade: Arc<UserFacade>,
	key_loader_facade: Arc<KeyLoaderFacade>,
	typed_entity_client: Arc<TypedEntityClient>,
	service_executor: Arc<ServiceExecutor>,
	type_model_provider: Arc<TypeModelProvider>,
	randomizer_facade: RandomizerFacade,
}

impl SecureExternalFacade {
	#[must_use]
	pub fn new(
		user_facade: Arc<UserFacade>,
		key_loader_facade: Arc<KeyLoaderFacade>,
		typed_entity_client: Arc<TypedEntityClient>,
		service_executor: Arc<ServiceExecutor>,
		type_model_provider: Arc<TypeModelProvider>,
		randomizer_facade: RandomizerFacade,
	) -> Self {
		Self {
			user_facade,
			key_loader_facade,
			typed_entity_client,
			service_executor,
			type_model_provider,
			randomizer_facade,
		}
	}

	/// Builds `SendDraftData.secureExternalRecipientKeyData` for each
	/// recipient (the caller assigns the aggregate `_id`), creating the
	/// external user first where the account has none for that address.
	///
	/// Refused, before anything is loaded or created, for an external user
	/// and for a shared mailbox (`sender_mail_group_id` other than the user's
	/// own mail group), as TS refuses both, and when any recipient lacks a
	/// passphrase. The passphrase key is Argon2id (TS `DEFAULT_KDF_TYPE`) over
	/// a fresh 16-byte salt.
	pub async fn secure_external_recipient_key_data(
		&self,
		sender_mail_group_id: &GeneratedId,
		bucket_key: &GenericAesKey,
		recipients: &[SecureExternalRecipient<'_>],
	) -> Result<Vec<SecureExternalRecipientKeyData>, SecureExternalRecipientError> {
		if self.user_facade.get_user().accountType == AccountType::EXTERNAL as i64 {
			return Err(SecureExternalRecipientError::ExternalSender);
		}
		let own_mail_group_id = self
			.user_facade
			.get_membership_by_group_type(GroupType::Mail)?
			.group;
		if own_mail_group_id != *sender_mail_group_id {
			return Err(SecureExternalRecipientError::SharedMailboxSender);
		}
		let missing: Vec<String> = recipients
			.iter()
			.filter(|recipient| recipient.passphrase.is_empty())
			.map(|recipient| recipient.mail_address.to_string())
			.collect();
		if !missing.is_empty() {
			return Err(SecureExternalRecipientError::MissingPassphrase(missing));
		}

		let mut key_data = Vec::with_capacity(recipients.len());
		for recipient in recipients {
			let salt: [u8; 16] = self.randomizer_facade.generate_random_array();
			let passphrase_key =
				GenericAesKey::Aes256(generate_key_from_passphrase(recipient.passphrase, salt));
			// TS `createAuthVerifier`: the raw hash, not its base64url form.
			let verifier = sha256(passphrase_key.as_bytes());
			let external_keys = self
				.external_group_keys(recipient.mail_address, &passphrase_key, &verifier)
				.await?;
			let owner_enc_bucket_key = external_keys
				.mail_group_key
				.encrypt_key(bucket_key, self.iv());
			let pw_enc_communication_key =
				passphrase_key.encrypt_key(&external_keys.user_group_key.object, self.iv());
			key_data.push(SecureExternalRecipientKeyData {
				_id: None,
				mailAddress: recipient.mail_address.to_string(),
				passwordVerifier: verifier,
				salt: Some(salt.to_vec()),
				saltHash: Some(sha256(&salt)),
				pwEncCommunicationKey: Some(pw_enc_communication_key),
				ownerEncBucketKey: owner_enc_bucket_key.object,
				kdfVersion: KdfType::Argon2id as i64,
				ownerKeyVersion: convert_version_to_i64(owner_enc_bucket_key.version),
				userGroupKeyVersion: convert_version_to_i64(external_keys.user_group_key.version),
			});
		}
		Ok(key_data)
	}

	fn iv(&self) -> InitializationVector {
		InitializationVector::generate(&self.randomizer_facade)
	}

	/// TS `getExternalGroupKeys`: the account's external user for the
	/// address, through `GroupRoot.externalUserReferences` keyed by the
	/// lower-cased address, or a new one.
	async fn external_group_keys(
		&self,
		mail_address: &str,
		passphrase_key: &GenericAesKey,
		verifier: &[u8],
	) -> Result<ExternalGroupKeys, SecureExternalRecipientError> {
		let user_group_id = self.user_facade.get_user_group_id();
		let group_root = self.load_group_root(&user_group_id).await?;
		let cleaned_address = mail_address.trim().to_lowercase();
		let reference_id = IdTupleCustom::new(
			group_root.externalUserReferences,
			CustomId(BASE64_URL_SAFE_NO_PAD.encode(cleaned_address.as_bytes())),
		);
		let reference = match self
			.typed_entity_client
			.load::<ExternalUserReference, IdTupleCustom>(&reference_id)
			.await
		{
			Ok(reference) => reference,
			Err(ApiCallError::ServerResponseError {
				source: HttpError::NotFoundError,
			}) => {
				return self
					.create_external_user(&cleaned_address, passphrase_key, verifier)
					.await;
			},
			Err(error) => return Err(error.into()),
		};

		let external_user = self
			.typed_entity_client
			.load::<User, GeneratedId>(&reference.user)
			.await?;
		let external_mail_group_id = external_user
			.memberships
			.iter()
			.find(|membership| membership.groupType == Some(GroupType::Mail as i64))
			.ok_or(SecureExternalRecipientError::MalformedExternalUser(
				"no mail group membership",
			))?
			.group
			.clone();
		let external_mail_group = self
			.typed_entity_client
			.load::<Group, GeneratedId>(&external_mail_group_id)
			.await?;
		let external_user_group = self
			.typed_entity_client
			.load::<Group, GeneratedId>(&reference.userGroup)
			.await?;
		let internal_user_enc_user_key = external_user_group.adminGroupEncGKey.as_ref().ok_or(
			SecureExternalRecipientError::MalformedExternalUser("user group without admin key"),
		)?;
		let user_enc_mail_key = external_mail_group.adminGroupEncGKey.as_ref().ok_or(
			SecureExternalRecipientError::MalformedExternalUser("mail group without admin key"),
		)?;

		// The external user group is administered by our user group, at the
		// version recorded on it.
		let internal_user_group_key = self
			.key_loader_facade
			.load_sym_group_key(
				&user_group_id,
				admin_key_version(&external_user_group)?,
				None,
			)
			.await?;
		let user_group_key = VersionedAesKey::new(
			internal_user_group_key.decrypt_aes_key(internal_user_enc_user_key)?,
			key_version(external_user_group.groupKeyVersion)?,
		);
		// We are no member of the external user group, so its key at the
		// version the mail group needs is loaded from the current one.
		let required_user_group_key = self
			.key_loader_facade
			.load_sym_group_key(
				&reference.userGroup,
				admin_key_version(&external_mail_group)?,
				Some(user_group_key.clone()),
			)
			.await?;
		let mail_group_key = VersionedAesKey::new(
			required_user_group_key.decrypt_aes_key(user_enc_mail_key)?,
			key_version(external_mail_group.groupKeyVersion)?,
		);
		Ok(ExternalGroupKeys {
			user_group_key,
			mail_group_key,
		})
	}

	/// TS `entityClient.loadRoot(GroupRootTypeRef, userGroupId)`.
	async fn load_group_root(
		&self,
		user_group_id: &GeneratedId,
	) -> Result<GroupRoot, SecureExternalRecipientError> {
		let root_id = self
			.type_model_provider
			.resolve_client_type_ref(&GroupRoot::type_ref())
			.ok_or_else(|| ApiCallError::internal("no type model for GroupRoot".to_string()))?
			.root_id
			.clone();
		let root_instance = self
			.typed_entity_client
			.load::<RootInstance, IdTupleCustom>(&IdTupleCustom::new(
				user_group_id.clone(),
				root_id,
			))
			.await?;
		Ok(self
			.typed_entity_client
			.load::<GroupRoot, GeneratedId>(&root_instance.reference)
			.await?)
	}

	/// TS `createExternalUser`: fresh user and mail group keys for the
	/// external user, its user group key wrapped with the passphrase key and
	/// with our user group key, the info session keys also with our mail
	/// group key, posted to the `ExternalUserService`.
	async fn create_external_user(
		&self,
		cleaned_address: &str,
		passphrase_key: &GenericAesKey,
		verifier: &[u8],
	) -> Result<ExternalGroupKeys, SecureExternalRecipientError> {
		let internal_user_group_key =
			self.user_facade
				.get_current_user_group_key()
				.ok_or(KeyLoadError {
					reason: "the user group key is not unlocked".to_string(),
				})?;
		let internal_mail_group_key = self
			.key_loader_facade
			.get_current_sym_group_key(
				&self
					.user_facade
					.get_membership_by_group_type(GroupType::Mail)?
					.group,
			)
			.await?;

		let user_group_key = VersionedAesKey::new(self.fresh_key(), 0);
		let mail_group_key = VersionedAesKey::new(self.fresh_key(), 0);
		let user_group_info_session_key = self.fresh_key();
		let mail_group_info_session_key = self.fresh_key();
		let tutanota_properties_session_key = self.fresh_key();
		let mailbox_session_key = self.fresh_key();
		let entropy: [u8; 32] = self.randomizer_facade.generate_random_array();

		let internal_user_enc_user_group_key =
			internal_user_group_key.encrypt_key(&user_group_key.object, self.iv());
		let user_group_data = CreateExternalUserGroupData {
			// A data transfer type is not encrypted, so nothing would fill
			// the aggregate id in.
			_id: Some(CustomId(
				BASE64_URL_SAFE_NO_PAD.encode(self.randomizer_facade.generate_random_array::<4>()),
			)),
			mailAddress: cleaned_address.to_string(),
			externalPwEncUserGroupKey: passphrase_key
				.encrypt_key(&user_group_key.object, self.iv()),
			internalUserEncUserGroupKey: internal_user_enc_user_group_key.object,
			internalUserGroupKeyVersion: convert_version_to_i64(
				internal_user_enc_user_group_key.version,
			),
		};
		let data = ExternalUserData {
			_format: 0,
			verifier: verifier.to_vec(),
			userGroupData: user_group_data,
			kdfVersion: KdfType::Argon2id as i64,
			externalUserEncEntropy: user_group_key.object.encrypt_data(&entropy, self.iv())?,
			externalUserEncUserGroupInfoSessionKey: user_group_key
				.encrypt_key(&user_group_info_session_key, self.iv())
				.object,
			externalUserEncMailGroupKey: user_group_key
				.encrypt_key(&mail_group_key.object, self.iv())
				.object,
			externalUserEncTutanotaPropertiesSessionKey: user_group_key
				.encrypt_key(&tutanota_properties_session_key, self.iv())
				.object,
			externalMailEncMailGroupInfoSessionKey: mail_group_key
				.encrypt_key(&mail_group_info_session_key, self.iv())
				.object,
			externalMailEncMailBoxSessionKey: mail_group_key
				.encrypt_key(&mailbox_session_key, self.iv())
				.object,
			internalMailEncUserGroupInfoSessionKey: internal_mail_group_key
				.encrypt_key(&user_group_info_session_key, self.iv())
				.object,
			internalMailEncMailGroupInfoSessionKey: internal_mail_group_key
				.encrypt_key(&mail_group_info_session_key, self.iv())
				.object,
			internalMailGroupKeyVersion: convert_version_to_i64(internal_mail_group_key.version),
		};
		self.service_executor
			.post::<ExternalUserService>(data, ExtraServiceParams::default())
			.await?;
		Ok(ExternalGroupKeys {
			user_group_key,
			mail_group_key,
		})
	}

	fn fresh_key(&self) -> GenericAesKey {
		GenericAesKey::Aes256(Aes256Key::generate(&self.randomizer_facade))
	}
}

fn key_version(version: i64) -> Result<u64, SecureExternalRecipientError> {
	u64::try_from(version)
		.map_err(|_| SecureExternalRecipientError::MalformedExternalUser("negative key version"))
}

/// TS `parseKeyVersion(group.adminGroupKeyVersion ?? "0")`.
fn admin_key_version(group: &Group) -> Result<u64, SecureExternalRecipientError> {
	key_version(group.adminGroupKeyVersion.unwrap_or(0))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::entities::generated::sys::GroupMembership;
	use crate::key_loader_facade::MockKeyLoaderFacade;
	use crate::services::service_executor::MockServiceExecutor;
	use crate::typed_entity_client::MockTypedEntityClient;
	use crate::user_facade::MockUserFacade;
	use crate::util::test_utils::{create_test_entity, mock_type_model_provider};
	use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
	use mockall::predicate::eq;
	use std::sync::Mutex;

	const PASSPHRASE: &str = "correct horse battery staple";

	struct Account {
		user_group_id: GeneratedId,
		mail_group_id: GeneratedId,
		user_group_key: VersionedAesKey,
		mail_group_key: VersionedAesKey,
	}

	fn random_key() -> GenericAesKey {
		GenericAesKey::Aes256(Aes256Key::generate(&make_thread_rng_facade()))
	}

	fn account() -> Account {
		Account {
			user_group_id: GeneratedId::test_random(),
			mail_group_id: GeneratedId::test_random(),
			user_group_key: VersionedAesKey::new(random_key(), 3),
			mail_group_key: VersionedAesKey::new(random_key(), 2),
		}
	}

	fn user_facade(account: &Account, account_type: AccountType) -> MockUserFacade {
		let mut user_facade = MockUserFacade::default();
		let user = User {
			accountType: account_type as i64,
			..create_test_entity()
		};
		user_facade.expect_get_user().return_const(Arc::new(user));
		let mail_group_id = account.mail_group_id.clone();
		user_facade
			.expect_get_membership_by_group_type()
			.withf(|group_type| *group_type == GroupType::Mail)
			.returning(move |_| {
				Ok(GroupMembership {
					group: mail_group_id.clone(),
					groupType: Some(GroupType::Mail as i64),
					..create_test_entity()
				})
			});
		user_facade
			.expect_get_user_group_id()
			.return_const(account.user_group_id.clone());
		user_facade
			.expect_get_current_user_group_key()
			.return_const(Some(account.user_group_key.clone()));
		user_facade
	}

	/// The account's group root, with `externalUserReferences` as its list.
	fn serve_group_root(
		entities: &mut MockTypedEntityClient,
		account: &Account,
		references: &GeneratedId,
	) {
		let group_root_id = GeneratedId::test_random();
		let root_instance = RootInstance {
			reference: group_root_id.clone(),
			..create_test_entity()
		};
		let root_id = mock_type_model_provider()
			.resolve_client_type_ref(&GroupRoot::type_ref())
			.unwrap()
			.root_id
			.clone();
		entities
			.expect_load::<RootInstance, IdTupleCustom>()
			.with(eq(IdTupleCustom::new(
				account.user_group_id.clone(),
				root_id,
			)))
			.return_const(Ok(root_instance));
		entities
			.expect_load::<GroupRoot, GeneratedId>()
			.with(eq(group_root_id))
			.return_const(Ok(GroupRoot {
				externalUserReferences: references.clone(),
				..create_test_entity()
			}));
	}

	fn facade(
		user_facade: MockUserFacade,
		key_loader_facade: MockKeyLoaderFacade,
		entities: MockTypedEntityClient,
		service_executor: MockServiceExecutor,
	) -> SecureExternalFacade {
		SecureExternalFacade::new(
			Arc::new(user_facade),
			Arc::new(key_loader_facade),
			Arc::new(entities),
			Arc::new(service_executor),
			Arc::new(mock_type_model_provider()),
			make_thread_rng_facade(),
		)
	}

	fn reference_id(references: &GeneratedId, address: &str) -> IdTupleCustom {
		IdTupleCustom::new(references.clone(), CustomId::from_custom_string(address))
	}

	/// What a recipient does with the key data: derive the passphrase key
	/// from the salt, check it against the verifier, unwrap the external user
	/// group key with it.
	fn passphrase_key_of(data: &SecureExternalRecipientKeyData) -> GenericAesKey {
		let salt: [u8; 16] = data.salt.clone().unwrap().try_into().unwrap();
		let key = GenericAesKey::Aes256(generate_key_from_passphrase(PASSPHRASE, salt));
		assert_eq!(data.passwordVerifier, sha256(key.as_bytes()));
		assert_eq!(data.saltHash.as_deref(), Some(sha256(&salt).as_slice()));
		assert_eq!(data.kdfVersion, KdfType::Argon2id as i64);
		key
	}

	#[tokio::test]
	async fn an_existing_external_user_gets_the_bucket_key_under_its_mail_group_key() {
		let account = account();
		let references = GeneratedId::test_random();
		let external_user_id = GeneratedId::test_random();
		let external_user_group_id = GeneratedId::test_random();
		let external_mail_group_id = GeneratedId::test_random();
		let external_user_group_key = random_key();
		let external_mail_group_key = random_key();
		let randomizer = make_thread_rng_facade();

		let mut entities = MockTypedEntityClient::default();
		serve_group_root(&mut entities, &account, &references);
		// The address is looked up trimmed and lower-cased, as TS does.
		entities
			.expect_load::<ExternalUserReference, IdTupleCustom>()
			.with(eq(reference_id(&references, "ext@example.org")))
			.return_const(Ok(ExternalUserReference {
				user: external_user_id.clone(),
				userGroup: external_user_group_id.clone(),
				..create_test_entity()
			}));
		entities
			.expect_load::<User, GeneratedId>()
			.with(eq(external_user_id))
			.return_const(Ok(User {
				memberships: vec![GroupMembership {
					group: external_mail_group_id.clone(),
					groupType: Some(GroupType::Mail as i64),
					..create_test_entity()
				}],
				..create_test_entity()
			}));
		entities
			.expect_load::<Group, GeneratedId>()
			.with(eq(external_mail_group_id))
			.return_const(Ok(Group {
				adminGroupEncGKey: Some(external_user_group_key.encrypt_key(
					&external_mail_group_key,
					InitializationVector::generate(&randomizer),
				)),
				adminGroupKeyVersion: Some(0),
				groupKeyVersion: 4,
				..create_test_entity()
			}));
		entities
			.expect_load::<Group, GeneratedId>()
			.with(eq(external_user_group_id.clone()))
			.return_const(Ok(Group {
				adminGroupEncGKey: Some(account.user_group_key.object.encrypt_key(
					&external_user_group_key,
					InitializationVector::generate(&randomizer),
				)),
				adminGroupKeyVersion: Some(3),
				groupKeyVersion: 0,
				..create_test_entity()
			}));

		let mut key_loader_facade = MockKeyLoaderFacade::default();
		let internal_key = account.user_group_key.object.clone();
		key_loader_facade
			.expect_load_sym_group_key()
			.withf({
				let user_group_id = account.user_group_id.clone();
				move |group, version, current| {
					*group == user_group_id && *version == 3 && current.is_none()
				}
			})
			.returning(move |_, _, _| Ok(internal_key.clone()))
			.once();
		let current_external_key = external_user_group_key.clone();
		key_loader_facade
			.expect_load_sym_group_key()
			.withf({
				let external_user_group_key = external_user_group_key.clone();
				move |group, version, current| {
					*group == external_user_group_id
						&& *version == 0 && current.as_ref().is_some_and(|key| {
						key.object == external_user_group_key && key.version == 0
					})
				}
			})
			.returning(move |_, _, _| Ok(current_external_key.clone()))
			.once();
		let mut service_executor = MockServiceExecutor::default();
		service_executor
			.expect_post::<ExternalUserService>()
			.never();

		let bucket_key = random_key();
		let key_data = facade(
			user_facade(&account, AccountType::PAID),
			key_loader_facade,
			entities,
			service_executor,
		)
		.secure_external_recipient_key_data(
			&account.mail_group_id,
			&bucket_key,
			&[SecureExternalRecipient {
				mail_address: " Ext@Example.org ",
				passphrase: PASSPHRASE,
			}],
		)
		.await
		.unwrap();

		assert_eq!(key_data.len(), 1);
		let data = &key_data[0];
		assert_eq!(data.mailAddress, " Ext@Example.org ");
		assert!(data._id.is_none());
		let passphrase_key = passphrase_key_of(data);
		let unwrapped_user_key = passphrase_key
			.decrypt_aes_key(data.pwEncCommunicationKey.as_ref().unwrap())
			.unwrap();
		assert_eq!(unwrapped_user_key, external_user_group_key);
		assert_eq!(data.userGroupKeyVersion, 0);
		let unwrapped_bucket_key = external_mail_group_key
			.decrypt_aes_key(&data.ownerEncBucketKey)
			.unwrap();
		assert_eq!(unwrapped_bucket_key, bucket_key);
		assert_eq!(data.ownerKeyVersion, 4);
	}

	#[tokio::test]
	async fn a_new_external_user_is_created_with_keys_only_the_sender_and_recipient_can_open() {
		let account = account();
		let references = GeneratedId::test_random();
		let mut entities = MockTypedEntityClient::default();
		serve_group_root(&mut entities, &account, &references);
		entities
			.expect_load::<ExternalUserReference, IdTupleCustom>()
			.with(eq(reference_id(&references, "new@example.org")))
			.returning(|_| {
				Err(ApiCallError::ServerResponseError {
					source: HttpError::NotFoundError,
				})
			});
		entities.expect_load::<User, GeneratedId>().never();
		entities.expect_load::<Group, GeneratedId>().never();

		let mut key_loader_facade = MockKeyLoaderFacade::default();
		let mail_group_key = account.mail_group_key.clone();
		key_loader_facade
			.expect_get_current_sym_group_key()
			.with(eq(account.mail_group_id.clone()))
			.returning(move |_| Ok(mail_group_key.clone()))
			.once();
		key_loader_facade.expect_load_sym_group_key().never();

		let posted: Arc<Mutex<Option<ExternalUserData>>> = Arc::default();
		let mut service_executor = MockServiceExecutor::default();
		service_executor
			.expect_post::<ExternalUserService>()
			.returning({
				let posted = posted.clone();
				move |data, _| {
					*posted.lock().unwrap() = Some(data);
					Ok(())
				}
			})
			.once();

		let bucket_key = random_key();
		let key_data = facade(
			user_facade(&account, AccountType::FREE),
			key_loader_facade,
			entities,
			service_executor,
		)
		.secure_external_recipient_key_data(
			&account.mail_group_id,
			&bucket_key,
			&[SecureExternalRecipient {
				mail_address: "New@Example.org",
				passphrase: PASSPHRASE,
			}],
		)
		.await
		.unwrap();

		let data = &key_data[0];
		let passphrase_key = passphrase_key_of(data);
		let created = posted.lock().unwrap().take().unwrap();
		let group_data = &created.userGroupData;
		assert_eq!(group_data.mailAddress, "new@example.org");
		assert!(group_data._id.is_some());
		assert_eq!(created.verifier, data.passwordVerifier);
		assert_eq!(created.kdfVersion, KdfType::Argon2id as i64);
		// The recipient opens the external user group key with the
		// passphrase, the sender with its own user group key.
		let user_group_key = passphrase_key
			.decrypt_aes_key(&group_data.externalPwEncUserGroupKey)
			.unwrap();
		assert_eq!(
			account
				.user_group_key
				.object
				.decrypt_aes_key(&group_data.internalUserEncUserGroupKey)
				.unwrap(),
			user_group_key
		);
		assert_eq!(group_data.internalUserGroupKeyVersion, 3);
		assert_eq!(
			passphrase_key
				.decrypt_aes_key(data.pwEncCommunicationKey.as_ref().unwrap())
				.unwrap(),
			user_group_key
		);
		assert_eq!(data.userGroupKeyVersion, 0);
		let mail_group_key = user_group_key
			.decrypt_aes_key(&created.externalUserEncMailGroupKey)
			.unwrap();
		assert_eq!(
			mail_group_key
				.decrypt_aes_key(&data.ownerEncBucketKey)
				.unwrap(),
			bucket_key
		);
		assert_eq!(data.ownerKeyVersion, 0);
		// The group infos are readable by the sender's mail group too.
		let user_info_key = user_group_key
			.decrypt_aes_key(&created.externalUserEncUserGroupInfoSessionKey)
			.unwrap();
		assert_eq!(
			account
				.mail_group_key
				.object
				.decrypt_aes_key(&created.internalMailEncUserGroupInfoSessionKey)
				.unwrap(),
			user_info_key
		);
		let mail_info_key = mail_group_key
			.decrypt_aes_key(&created.externalMailEncMailGroupInfoSessionKey)
			.unwrap();
		assert_eq!(
			account
				.mail_group_key
				.object
				.decrypt_aes_key(&created.internalMailEncMailGroupInfoSessionKey)
				.unwrap(),
			mail_info_key
		);
		assert_eq!(created.internalMailGroupKeyVersion, 2);
		mail_group_key
			.decrypt_aes_key(&created.externalMailEncMailBoxSessionKey)
			.unwrap();
		user_group_key
			.decrypt_aes_key(&created.externalUserEncTutanotaPropertiesSessionKey)
			.unwrap();
		assert_eq!(
			user_group_key
				.decrypt_data(&created.externalUserEncEntropy)
				.unwrap()
				.len(),
			32
		);
	}

	fn untouched() -> (
		MockKeyLoaderFacade,
		MockTypedEntityClient,
		MockServiceExecutor,
	) {
		let mut key_loader_facade = MockKeyLoaderFacade::default();
		key_loader_facade.expect_load_sym_group_key().never();
		key_loader_facade.expect_get_current_sym_group_key().never();
		let mut entities = MockTypedEntityClient::default();
		entities
			.expect_load::<RootInstance, IdTupleCustom>()
			.never();
		let mut service_executor = MockServiceExecutor::default();
		service_executor
			.expect_post::<ExternalUserService>()
			.never();
		(key_loader_facade, entities, service_executor)
	}

	#[tokio::test]
	async fn shared_mailboxes_and_external_senders_are_refused_before_any_request() {
		let account = account();
		let recipient = [SecureExternalRecipient {
			mail_address: "ext@example.org",
			passphrase: PASSPHRASE,
		}];
		let (key_loader_facade, entities, service_executor) = untouched();
		let shared = facade(
			user_facade(&account, AccountType::PAID),
			key_loader_facade,
			entities,
			service_executor,
		)
		.secure_external_recipient_key_data(&GeneratedId::test_random(), &random_key(), &recipient)
		.await;
		assert!(matches!(
			shared,
			Err(SecureExternalRecipientError::SharedMailboxSender)
		));

		let (key_loader_facade, entities, service_executor) = untouched();
		let external = facade(
			user_facade(&account, AccountType::EXTERNAL),
			key_loader_facade,
			entities,
			service_executor,
		)
		.secure_external_recipient_key_data(&account.mail_group_id, &random_key(), &recipient)
		.await;
		assert!(matches!(
			external,
			Err(SecureExternalRecipientError::ExternalSender)
		));
	}

	#[tokio::test]
	async fn every_recipient_without_a_passphrase_is_named_and_nothing_is_built() {
		let account = account();
		let (key_loader_facade, entities, service_executor) = untouched();
		let result = facade(
			user_facade(&account, AccountType::PAID),
			key_loader_facade,
			entities,
			service_executor,
		)
		.secure_external_recipient_key_data(
			&account.mail_group_id,
			&random_key(),
			&[
				SecureExternalRecipient {
					mail_address: "a@example.org",
					passphrase: "",
				},
				SecureExternalRecipient {
					mail_address: "b@example.org",
					passphrase: PASSPHRASE,
				},
				SecureExternalRecipient {
					mail_address: "c@example.org",
					passphrase: "",
				},
			],
		)
		.await;
		match result {
			Err(SecureExternalRecipientError::MissingPassphrase(missing)) => {
				assert_eq!(missing, ["a@example.org", "c@example.org"]);
			},
			other => panic!("{:?}", other.map(|data| data.len())),
		}
	}
}
