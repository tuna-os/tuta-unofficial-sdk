#[cfg_attr(test, mockall_double::double)]
use crate::crypto::asymmetric_crypto_facade::AsymmetricCryptoFacade;
use crate::crypto::asymmetric_crypto_facade::{AsymmetricCryptoError, DecapsulatedAesKey};
use crate::crypto::key::KeyLoadError;
use crate::crypto::rsa::RSAEncryptionError;
use crate::crypto::tuta_crypt::TutaCryptError;
use crate::crypto::x25519::X25519PublicKey;
use crate::crypto::Aes256Key;
use crate::element_value::{ElementValue, ParsedEntity};
use crate::entities::entity_facade::{
	BUCKET_KEY_FIELD, ID_FIELD, OWNER_ENC_SESSION_KEY_FIELD, OWNER_GROUP_FIELD,
	OWNER_KEY_VERSION_FIELD, PERMISSIONS_FIELD,
};
use crate::entities::generated::sys::{BucketKey, Permission};
use crate::entities::Entity;
#[cfg_attr(test, mockall_double::double)]
use crate::entity_client::EntityClient;
use crate::instance_mapper::InstanceMapper;
#[cfg_attr(test, mockall_double::double)]
use crate::key_loader_facade::KeyLoaderFacade;
use crate::metamodel::TypeModel;
use crate::tutanota_constants::{CryptoProtocolVersion, PermissionType};
#[cfg_attr(test, mockall_double::double)]
use crate::user_facade::UserFacade;
use crate::util::convert_version_to_u64;
use crate::IdTupleGenerated;
use crate::{GeneratedId, ListLoadDirection};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_primitives::aes::InitializationVector;
use crypto_primitives::key::{GenericAesKey, KeyDecryptError};
use crypto_primitives::randomizer_facade::RandomizerFacade;
use num_enum::TryFromPrimitive;
use std::sync::Arc;
use util::array::ArrayCastingError;

#[derive(uniffi::Object)]
pub struct CryptoFacade {
	key_loader_facade: Arc<KeyLoaderFacade>,
	instance_mapper: Arc<InstanceMapper>,
	randomizer_facade: RandomizerFacade,
	asymmetric_crypto_facade: Arc<AsymmetricCryptoFacade>,
	user_facade: Arc<UserFacade>,
	entity_client: Arc<EntityClient>,
}

/// Session key that encrypts an entity and the same key encrypted with the owner group.
/// owner_enc_session_key is stored on entities to avoid public key encryption on subsequent loads.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct ResolvedSessionKey {
	pub session_key: GenericAesKey,
	pub owner_enc_session_key: Vec<u8>,
	pub owner_key_version: u64,
	// the sender's x25519 key that was used to decrypt the PQ message, in case TutaCrypt was used.
	pub sender_identity_pub_key: Option<X25519PublicKey>,
}

#[cfg_attr(test, mockall::automock)]
impl CryptoFacade {
	#[must_use]
	pub fn new(
		key_loader_facade: Arc<KeyLoaderFacade>,
		instance_mapper: Arc<InstanceMapper>,
		randomizer_facade: RandomizerFacade,
		asymmetric_crypto_facade: Arc<AsymmetricCryptoFacade>,
		user_facade: Arc<UserFacade>,
		entity_client: Arc<EntityClient>,
	) -> Self {
		Self {
			key_loader_facade,
			instance_mapper,
			randomizer_facade,
			asymmetric_crypto_facade,
			user_facade,
			entity_client,
		}
	}

	#[must_use]
	pub fn get_key_loader_facade(&self) -> &Arc<KeyLoaderFacade> {
		&self.key_loader_facade
	}

	/// Returns the session key from `entity` and resolves the bucket key fields contained inside
	/// if present
	pub async fn resolve_session_key(
		&self,
		entity: &ParsedEntity,
		model: &TypeModel,
	) -> Result<Option<ResolvedSessionKey>, SessionKeyResolutionError> {
		if !model.marked_encrypted() {
			return Ok(None);
		}

		// Derive the session key from the bucket key
		if let Ok(bucket_key_attribute_id) =
			model.get_attribute_id_by_attribute_name(BUCKET_KEY_FIELD)
		{
			if let Some(bucket_key_value) = entity.get(bucket_key_attribute_id.as_str()) {
				match bucket_key_value {
					ElementValue::Array(array) if array.is_empty() => {},
					ElementValue::Array(_) => {
						let resolved_key = self.resolve_bucket_key(entity, model).await?;
						return Ok(Some(resolved_key));
					},
					_ => {
						return Err(SessionKeyResolutionError {
							reason: "bucketKey is invalid!".to_string(),
						})
					},
				}
			}
		}

		// Extract the session key data from the owner group of the entity
		let EntityOwnerKeyData {
			owner_enc_session_key: Some(owner_enc_session_key),
			owner_key_version: Some(owner_key_version),
			owner_group: Some(owner_group),
		} = EntityOwnerKeyData::extract_owner_key_data(entity, model)?
		else {
			return Err(SessionKeyResolutionError {
				reason: "instance missing owner key/group data".to_string(),
			});
		};

		// The user might not be member of the owner group of this entity
		// example: GroupInfo entity from another customer (Shared Calendars)
		let has_group = self.user_facade.has_group(owner_group);

		if has_group {
			let group_key: GenericAesKey = self
				.key_loader_facade
				.load_sym_group_key(owner_group, owner_key_version, None)
				.await?;

			let session_key = group_key.decrypt_aes_key(owner_enc_session_key)?;
			// TODO: performance: should we reuse owner_enc_session_key?
			Ok(Some(ResolvedSessionKey {
				session_key,
				owner_enc_session_key: owner_enc_session_key.clone(),
				owner_key_version,
				sender_identity_pub_key: None,
			}))
		} else {
			let mut permission_id: Option<GeneratedId> = None;

			if let Ok(permissions_attribute_id) =
				model.get_attribute_id_by_attribute_name(PERMISSIONS_FIELD)
			{
				if let Some(permissions_value) = entity.get(permissions_attribute_id.as_str()) {
					match permissions_value {
						ElementValue::IdGeneratedId(id) => permission_id = Some(id.clone()),
						_ => {
							return Err(SessionKeyResolutionError {
								reason: "Missing permissions for entity".to_string(),
							})
						},
					}
				}
			}

			if permission_id.is_none() {
				return Err(SessionKeyResolutionError {
					reason: "Missing permissions for entity".to_string(),
				});
			}

			let permissions = self
				.entity_client
				.load_all(
					&Permission::type_ref(),
					&(permission_id.unwrap()),
					ListLoadDirection::ASC,
				)
				.await
				.map_err(|e| SessionKeyResolutionError {
					reason: e.to_string(),
				})?
				.into_iter()
				.map(|e| self.instance_mapper.parse_entity::<Permission>(e))
				.collect::<Result<Vec<Permission>, _>>()
				.map_err(|error| SessionKeyResolutionError {
					reason: format!("Failed to parse permission into proper types: {}", error),
				})?;

			let resolved_session_key = self.try_symmetric_permission(permissions).await?;
			Ok(Some(ResolvedSessionKey {
				session_key: resolved_session_key,
				owner_enc_session_key: owner_enc_session_key.clone(),
				owner_key_version,
				sender_identity_pub_key: None,
			}))
		}
	}

	async fn try_symmetric_permission(
		&self,
		permissions: Vec<Permission>,
	) -> Result<GenericAesKey, SessionKeyResolutionError> {
		let symmetric_permission = permissions.iter().find(|&p| {
			let Ok(permission_type) = PermissionType::try_from_primitive(p.r#type) else {
				return false;
			};

			let has_group = p._ownerGroup.is_some()
				&& self.user_facade.has_group(p._ownerGroup.as_ref().unwrap());
			(permission_type == PermissionType::PublicSymmetric
				|| permission_type == PermissionType::Symmetric)
				&& has_group
		});

		if symmetric_permission.is_some() {
			let s_permission = symmetric_permission.unwrap().clone();
			let group_key: GenericAesKey = self
				.key_loader_facade
				.load_sym_group_key(
					&s_permission._ownerGroup.unwrap(),
					s_permission._ownerKeyVersion.unwrap_or(0).unsigned_abs(),
					None,
				)
				.await?;

			let Some(owner_enc_session_key) = s_permission._ownerEncSessionKey else {
				return Err(SessionKeyResolutionError {
					reason: "Missing ownerEncSessionKey".to_string(),
				});
			};

			let session_key = group_key.decrypt_aes_key(owner_enc_session_key.as_slice())?;
			return Ok(session_key);
		}

		Err(SessionKeyResolutionError {
			reason: "Missing symmetricPermission".to_string(),
		})
	}

	/// Resolves the bucket key fields inside `entity` and returns the session key
	async fn resolve_bucket_key(
		&self,
		entity: &ParsedEntity,
		type_model: &TypeModel,
	) -> Result<ResolvedSessionKey, SessionKeyResolutionError> {
		let bucket_key_attribute_id = type_model
            .get_attribute_id_by_attribute_name(BUCKET_KEY_FIELD)
            .map_err(|err| SessionKeyResolutionError {
                reason: format!(
                    "{BUCKET_KEY_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
                    type_model.id,
                    err
                ),
            })?;

		let bucket_key_map =
			if let Some(ElementValue::Array(bucket_keys)) = entity.get(&bucket_key_attribute_id) {
				if let Some(ElementValue::Dict(bucket_key_map)) = bucket_keys.first() {
					bucket_key_map
				} else {
					return Err(SessionKeyResolutionError {
						reason: format!("{BUCKET_KEY_FIELD} is empty"),
					});
				}
			} else {
				return Err(SessionKeyResolutionError {
					reason: format!("{BUCKET_KEY_FIELD} is not a array type"),
				});
			};

		let bucket_key: BucketKey =
			match self.instance_mapper.parse_entity(bucket_key_map.to_owned()) {
				Ok(n) => n,
				Err(e) => {
					return Err(SessionKeyResolutionError {
						reason: format!("{BUCKET_KEY_FIELD} could not be deserialized: {e}"),
					})
				},
			};

		let owner_key_data = EntityOwnerKeyData::extract_owner_key_data(entity, type_model)?;
		let Some(owner_group) = owner_key_data.owner_group else {
			return Err(SessionKeyResolutionError {
				reason: "entity has no ownerGroup".to_owned(),
			});
		};

		let id_attribute_id: String = type_model
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.map_err(|err| SessionKeyResolutionError {
				reason: format!(
					"{ID_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
					type_model.id, err
				),
			})?;
		let instance_id = parse_generated_id_field(entity.get(&id_attribute_id))?;

		let bucket = self
			.decrypt_bucket(&bucket_key)
			.await
			.map_err(DecryptBucketError::into_resolution_error)?;

		// The entity's own entry, matched on its element id, the last one winning.
		let Some(session_key) = bucket
			.instance_keys
			.iter()
			.rev()
			.find(|key| &key.instance_id == instance_id)
			.map(|key| key.session_key.clone())
		else {
			return Err(SessionKeyResolutionError {
				reason: "no session key found in bucket key for this instance".to_string(),
			});
		};

		// TODO: authenticate
		let versioned_owner_group_key = self
			.key_loader_facade
			.get_current_sym_group_key(owner_group)
			.await?;

		let owner_enc_session_key = versioned_owner_group_key.object.encrypt_key(
			&session_key,
			InitializationVector::generate(&self.randomizer_facade),
		);
		Ok(ResolvedSessionKey {
			session_key,
			owner_enc_session_key,
			owner_key_version: versioned_owner_group_key.version,
			sender_identity_pub_key: bucket.sender_identity_pub_key,
		})
	}

	/// Decapsulates the bucket key and decrypts every session key the bucket
	/// carries, in bucket order, without choosing one: the callers select.
	/// A `groupEncBucketKey` (secure external) is reported, not implemented.
	async fn decrypt_bucket(
		&self,
		bucket_key: &BucketKey,
	) -> Result<DecryptedBucket, DecryptBucketError> {
		let DecapsulatedAesKey {
			decrypted_aes_key: bucket_aes_key,
			sender_identity_pub_key,
		} = if let (Some(key_group), Some(pub_enc_bucket_key)) =
			(&bucket_key.keyGroup, &bucket_key.pubEncBucketKey)
		{
			let protocol_version = CryptoProtocolVersion::try_from(bucket_key.protocolVersion)
				.map_err(|_| {
					DecryptBucketError::Resolution(SessionKeyResolutionError {
						reason: "unknown crypto protocol version on bucket key".to_string(),
					})
				})?;
			self.asymmetric_crypto_facade
				.load_key_pair_and_decrypt_sym_key(
					key_group,
					convert_version_to_u64(bucket_key.recipientKeyVersion),
					&protocol_version,
					pub_enc_bucket_key,
				)
				.await
				.map_err(|e| DecryptBucketError::Resolution(e.into()))?
		} else if bucket_key.groupEncBucketKey.is_some() {
			return Err(DecryptBucketError::GroupReferenceUnsupported);
		} else {
			return Err(DecryptBucketError::Resolution(SessionKeyResolutionError {
				reason: "encrypted bucket key not set on bucket key".to_string(),
			}));
		};

		let mut instance_keys = Vec::with_capacity(bucket_key.bucketEncSessionKeys.len());
		for entry in &bucket_key.bucketEncSessionKeys {
			let session_key = bucket_aes_key
				.decrypt_aes_key(entry.symEncSessionKey.as_slice())
				.map_err(|e| DecryptBucketError::Resolution(e.into()))?;
			instance_keys.push(BucketInstanceKey {
				instance_list: entry.instanceList.clone(),
				instance_id: entry.instanceId.clone(),
				session_key,
			});
		}
		Ok(DecryptedBucket {
			instance_keys,
			sender_identity_pub_key,
		})
	}

	/// The session keys a bucket names for children of the entity that
	/// carries it, as TS `resolveWithBucketKey` feeds the attachments'
	/// `OwnerEncSessionKeyProvider`: one decapsulation, one key per requested
	/// id in the requested order, each matched on its full id and wrapped
	/// with the current key of `owner_group`, the parent's owner group. The
	/// children are not authenticated. Nothing is written or cached.
	pub async fn resolve_bucket_instance_keys(
		&self,
		bucket_key: &BucketKey,
		owner_group: &GeneratedId,
		requested: &[IdTupleGenerated],
	) -> Result<Vec<ResolvedSessionKey>, BucketKeyError> {
		if requested.is_empty() {
			return Ok(Vec::new());
		}
		let bucket = self.decrypt_bucket(bucket_key).await?;

		let mut session_keys = Vec::with_capacity(requested.len());
		for id in requested {
			let mut matches = bucket
				.instance_keys
				.iter()
				.filter(|key| key.instance_list == id.list_id && key.instance_id == id.element_id);
			let Some(first) = matches.next() else {
				return Err(BucketKeyError::NoEntry);
			};
			if matches.next().is_some() {
				return Err(BucketKeyError::AmbiguousEntries);
			}
			session_keys.push(first.session_key.clone());
		}

		let owner_group_key = self
			.key_loader_facade
			.get_current_sym_group_key(owner_group)
			.await
			.map_err(|e| BucketKeyError::Resolution(e.into()))?;
		Ok(session_keys
			.into_iter()
			.map(|session_key| {
				let owner_enc_session_key = owner_group_key.object.encrypt_key(
					&session_key,
					InitializationVector::generate(&self.randomizer_facade),
				);
				ResolvedSessionKey {
					session_key,
					owner_enc_session_key,
					owner_key_version: owner_group_key.version,
					sender_identity_pub_key: None,
				}
			})
			.collect())
	}
}

/// Every session key a bucket carries, decrypted once.
struct DecryptedBucket {
	instance_keys: Vec<BucketInstanceKey>,
	sender_identity_pub_key: Option<X25519PublicKey>,
}

/// One entry of a bucket: the instance it names and its decrypted key.
struct BucketInstanceKey {
	instance_list: GeneratedId,
	instance_id: GeneratedId,
	session_key: GenericAesKey,
}

enum DecryptBucketError {
	GroupReferenceUnsupported,
	Resolution(SessionKeyResolutionError),
}

impl DecryptBucketError {
	fn into_resolution_error(self) -> SessionKeyResolutionError {
		match self {
			Self::GroupReferenceUnsupported => SessionKeyResolutionError {
				reason: "groupEncBucketKey (secure external) is not supported".to_string(),
			},
			Self::Resolution(error) => error,
		}
	}
}

impl From<DecryptBucketError> for BucketKeyError {
	fn from(error: DecryptBucketError) -> Self {
		match error {
			DecryptBucketError::GroupReferenceUnsupported => Self::GroupReferenceUnsupported,
			DecryptBucketError::Resolution(error) => Self::Resolution(error),
		}
	}
}

/// Resolves the id field of an entity into a generated id
fn parse_generated_id_field(
	id_field: Option<&ElementValue>,
) -> Result<&GeneratedId, SessionKeyResolutionError> {
	match id_field {
		Some(ElementValue::IdGeneratedId(id)) => Ok(id),
		Some(ElementValue::IdTupleGeneratedElementId(IdTupleGenerated { element_id, .. })) => {
			Ok(element_id)
		},
		None => Err(SessionKeyResolutionError {
			reason: "no id present on instance".to_string(),
		}),
		Some(actual) => Err(SessionKeyResolutionError {
			reason: format!(
				"unexpected {} type for id on instance",
				actual.type_variant_name()
			),
		}),
	}
}

struct EntityOwnerKeyData<'a> {
	owner_enc_session_key: Option<&'a Vec<u8>>,
	owner_key_version: Option<u64>,
	owner_group: Option<&'a GeneratedId>,
}

impl<'a> EntityOwnerKeyData<'a> {
	fn extract_owner_key_data(
		entity: &'a ParsedEntity,
		type_model: &TypeModel,
	) -> Result<EntityOwnerKeyData<'a>, SessionKeyResolutionError> {
		macro_rules! get_nullable_field {
			($entity:expr, $field:expr, $type:tt) => {
				match $entity.get($field) {
					Some(ElementValue::$type(q)) => Ok(Some(q)),
					None | Some(ElementValue::Null) => Ok(None), // none = not present on type, null = present on type but null
					Some(actual) => Err(SessionKeyResolutionError { reason: format!("field `{}` is not the expected type, got {} instead", $field, actual.type_variant_name()) }),
				}
			};
		}

		let owner_enc_session_key_attribute_id: String = type_model
            .get_attribute_id_by_attribute_name(OWNER_ENC_SESSION_KEY_FIELD)
            .map_err(|err| SessionKeyResolutionError {
                reason: format!(
                    "{OWNER_ENC_SESSION_KEY_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
                    type_model.id,
                    err
                ),
            })?;

		let owner_enc_session_key =
			get_nullable_field!(entity, &owner_enc_session_key_attribute_id, Bytes)?;

		let owner_key_version_attribute_id: String = type_model
            .get_attribute_id_by_attribute_name(OWNER_KEY_VERSION_FIELD)
            .map_err(|err| SessionKeyResolutionError {
                reason: format!(
                    "{OWNER_KEY_VERSION_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
                    type_model.id,
                    err
                ),
            })?;

		let owner_key_version_i64 =
			get_nullable_field!(entity, &owner_key_version_attribute_id, Number)?.copied();

		let owner_key_version_attribute_id: String = type_model
            .get_attribute_id_by_attribute_name(OWNER_GROUP_FIELD)
            .map_err(|err| SessionKeyResolutionError {
                reason: format!(
                    "{OWNER_GROUP_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
                    type_model.id,
                    err
                ),
            })?;

		let owner_key_version: Option<u64> = owner_key_version_i64.map(convert_version_to_u64);
		let owner_group =
			get_nullable_field!(entity, &owner_key_version_attribute_id, IdGeneratedId)?;

		Ok(EntityOwnerKeyData {
			owner_enc_session_key,
			owner_key_version,
			owner_group,
		})
	}
}

#[derive(thiserror::Error, Debug, Clone)]
#[error("Session key resolution failure: {reason}")]
pub struct SessionKeyResolutionError {
	reason: String,
}

/// Used to map various errors to `SessionKeyResolutionError`
trait SessionKeyResolutionErrorSubtype: ToString {}

impl<T: SessionKeyResolutionErrorSubtype> From<T> for SessionKeyResolutionError {
	fn from(value: T) -> Self {
		Self {
			reason: value.to_string(),
		}
	}
}

impl SessionKeyResolutionErrorSubtype for KeyLoadError {}

impl SessionKeyResolutionErrorSubtype for KeyDecryptError {}

impl SessionKeyResolutionErrorSubtype for ArrayCastingError {}

impl SessionKeyResolutionErrorSubtype for TutaCryptError {}

impl SessionKeyResolutionErrorSubtype for RSAEncryptionError {}
impl SessionKeyResolutionErrorSubtype for AsymmetricCryptoError {}

/// Why a bucket could not name a session key for a requested instance. The
/// messages name the case, never an instance.
#[derive(thiserror::Error, Debug)]
pub enum BucketKeyError {
	#[error("no bucket entry for a requested instance")]
	NoEntry,
	#[error("more than one bucket entry for a requested instance")]
	AmbiguousEntries,
	#[error("groupEncBucketKey (secure external) is not supported")]
	GroupReferenceUnsupported,
	#[error(transparent)]
	Resolution(#[from] SessionKeyResolutionError),
}

#[must_use]
pub fn create_auth_verifier(user_passphrase_key: Aes256Key) -> String {
	let sha_user_passphrase = crypto_primitives::sha::sha256(user_passphrase_key.as_bytes());
	BASE64_URL_SAFE_NO_PAD.encode(sha_user_passphrase)
}

#[cfg(test)]
mod test {
	use crate::bindings::file_client::MockFileClient;
	use crate::bindings::rest_client::MockRestClient;
	use crate::crypto::asymmetric_crypto_facade::{DecapsulatedAesKey, MockAsymmetricCryptoFacade};
	use crate::crypto::crypto_facade::{BucketKeyError, CryptoFacade};
	use crate::crypto::x25519::X25519KeyPair;
	use crate::element_value::ParsedEntity;
	use crate::entities::generated::sys::{BucketKey, GroupInfo, InstanceSessionKey, Permission};
	use crate::entities::generated::tutanota::Mail;
	use crate::entities::Entity;
	use crate::entity_client::MockEntityClient;
	use crate::instance_mapper::InstanceMapper;
	use crate::key_loader_facade::MockKeyLoaderFacade;
	use crate::metamodel::TypeModel;
	use crate::tutanota_constants::{CryptoProtocolVersion, PermissionType};
	use crate::user_facade::MockUserFacade;
	use crate::util::test_utils::{create_test_entity, typed_entity_to_parsed_entity};
	use crate::GeneratedId;
	use crate::IdTupleGenerated;
	use crate::TypeModelProvider;
	use crypto_primitives::aes::{Aes256Key, InitializationVector};
	use crypto_primitives::key::GenericAesKey;
	use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
	use crypto_primitives::randomizer_facade::RandomizerFacade;
	use crypto_primitives::versioned::VersionedAesKey;
	use mockall::predicate::eq;
	use std::ops::Deref;
	use std::sync::Arc;

	#[tokio::test]
	async fn test_tuta_crypt_bucket_key_resolves() {
		let randomizer_facade = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer_facade);

		let sender_keypair = X25519KeyPair::generate(&randomizer_facade);

		let protocol_version = CryptoProtocolVersion::TutaCrypt;
		let raw_mail = make_raw_mail(
			&constants,
			constants.pub_enc_bucket_key.clone(),
			protocol_version.clone() as i64,
		);
		let mail_type_model = get_mail_type_model();

		let mut asymmetric_crypto_facade = MockAsymmetricCryptoFacade::default();

		asymmetric_crypto_facade
			.expect_load_key_pair_and_decrypt_sym_key()
			.with(
				eq(constants.key_group),
				eq(constants.recipient_key_version),
				eq(protocol_version),
				eq(constants.pub_enc_bucket_key.clone()),
			)
			.returning(move |_, _, _, _| {
				Ok(DecapsulatedAesKey {
					decrypted_aes_key: constants.bucket_key_generic.clone(),
					sender_identity_pub_key: Some(sender_keypair.public_key.clone()),
				})
			});

		let crypto_facade = make_crypto_facade(
			randomizer_facade.clone(),
			constants.group_key.clone(),
			constants.sender_key_version,
			Some(asymmetric_crypto_facade),
			vec![],
			None,
		);

		let key = crypto_facade
			.resolve_session_key(&raw_mail, &mail_type_model)
			.await
			.expect("should not have errored")
			.expect("where is the key");

		assert_eq!(
			constants.mail_session_key.as_bytes(),
			key.session_key.as_bytes()
		);
	}

	#[tokio::test]
	async fn test_rsa_bucket_key_resolves() {
		let randomizer_facade = make_thread_rng_facade();

		let constants = BucketKeyConstants::new(&randomizer_facade);
		let crypto_protocol_version = CryptoProtocolVersion::Rsa;
		let raw_mail = make_raw_mail(
			&constants,
			constants.pub_enc_bucket_key.clone(),
			crypto_protocol_version.clone() as i64,
		);

		let mut asymmetric_crypto_facade = MockAsymmetricCryptoFacade::default();
		asymmetric_crypto_facade
			.expect_load_key_pair_and_decrypt_sym_key()
			.with(
				eq(constants.key_group),
				eq(constants.recipient_key_version),
				eq(crypto_protocol_version),
				eq(constants.pub_enc_bucket_key.clone()),
			)
			.returning(move |_, _, _, _| {
				Ok(DecapsulatedAesKey {
					decrypted_aes_key: constants.bucket_key_generic.clone(),
					sender_identity_pub_key: None,
				})
			});

		let crypto_facade = make_crypto_facade(
			randomizer_facade.clone(),
			constants.group_key.clone(),
			constants.sender_key_version,
			Some(asymmetric_crypto_facade),
			vec![],
			None,
		);

		let mail_type_model = get_mail_type_model();
		let key = crypto_facade
			.resolve_session_key(&raw_mail, &mail_type_model)
			.await
			.expect("should not have errored")
			.expect("where is the key");

		assert_eq!(
			constants.mail_session_key.as_bytes(),
			key.session_key.as_bytes()
		);
	}

	#[tokio::test]
	async fn owner_enc_session_key_is_returned_if_no_bucket_key() {
		let randomizer_facade = make_thread_rng_facade();

		let constants = BucketKeyConstants::new(&randomizer_facade);
		let session_key = GenericAesKey::from(Aes256Key::generate(&randomizer_facade));
		let owner_enc_session_key = constants.group_key.encrypt_key(
			&session_key,
			InitializationVector::generate(&randomizer_facade),
		);

		let mail = Mail {
			_id: Some(IdTupleGenerated {
				list_id: constants.instance_list.clone(),
				element_id: constants.instance_id.clone(),
			}),
			_ownerGroup: Some(constants.key_group.clone()),
			bucketKey: None,
			_ownerEncSessionKey: Some(owner_enc_session_key.clone()),
			_ownerKeyVersion: Some(constants.recipient_key_version as i64),
			..create_test_entity()
		};

		let raw_mail = typed_entity_to_parsed_entity(mail);

		let asymmetric_crypto_facade = MockAsymmetricCryptoFacade::default();

		let crypto_facade = make_crypto_facade(
			randomizer_facade.clone(),
			constants.group_key.clone(),
			constants.sender_key_version,
			Some(asymmetric_crypto_facade),
			vec![],
			None,
		);

		let mail_type_model = get_mail_type_model();
		let key = crypto_facade
			.resolve_session_key(&raw_mail, &mail_type_model)
			.await
			.expect("should not have errored")
			.expect("where is the key");

		assert_eq!(session_key.as_bytes(), key.session_key.as_bytes());
	}

	#[tokio::test]
	async fn resolve_session_key_using_permission() {
		let randomizer_facade = make_thread_rng_facade();

		let constants = BucketKeyConstants::new(&randomizer_facade);
		let permission_constants = BucketKeyConstants::new(&randomizer_facade);
		let session_key = GenericAesKey::from(Aes256Key::generate(&randomizer_facade));
		let owner_enc_session_key = constants.group_key.encrypt_key(
			&session_key,
			InitializationVector::generate(&randomizer_facade),
		);

		let permission_list = permission_constants.instance_list.clone();
		let permission_id = permission_constants.instance_id.clone();
		let permission_owner_group = permission_constants.key_group.clone();
		let permission_owner_key_version = permission_constants.recipient_key_version;
		let permission_owner_enc_session_key = permission_constants.group_key.encrypt_key(
			&session_key,
			InitializationVector::generate(&randomizer_facade),
		);

		let mock_calendar_group_info = GroupInfo {
			_id: Some(IdTupleGenerated {
				list_id: constants.instance_list.clone(),
				element_id: constants.instance_id.clone(),
			}),
			_ownerGroup: Some(constants.key_group.clone()),
			_ownerEncSessionKey: Some(owner_enc_session_key.clone()),
			_ownerKeyVersion: Some(constants.recipient_key_version as i64),
			_permissions: permission_id.clone(),
			..create_test_entity()
		};

		let mock_permission = Permission {
			_id: Some(IdTupleGenerated {
				list_id: permission_list,
				element_id: permission_id,
			}),
			_ownerGroup: Some(permission_owner_group.clone()),
			_ownerEncSessionKey: Some(permission_owner_enc_session_key.clone()),
			_ownerKeyVersion: Some(permission_owner_key_version as i64),
			r#type: PermissionType::Symmetric.into(),
			..create_test_entity()
		};

		let raw_permission = typed_entity_to_parsed_entity(mock_permission);
		let raw_calendar = typed_entity_to_parsed_entity(mock_calendar_group_info.clone());

		let asymmetric_crypto_facade = MockAsymmetricCryptoFacade::default();

		let crypto_facade = make_crypto_facade(
			randomizer_facade.clone(),
			permission_constants.group_key.clone(),
			permission_constants.sender_key_version,
			Some(asymmetric_crypto_facade),
			vec![permission_owner_group],
			Some(raw_permission),
		);

		let group_info_type_model = get_group_info_model();
		let key = crypto_facade
			.resolve_session_key(&raw_calendar, &group_info_type_model)
			.await
			.expect("should not have errored")
			.expect("where is the key");

		assert_eq!(
			mock_calendar_group_info._ownerEncSessionKey.unwrap(),
			key.owner_enc_session_key
		);
		assert_eq!(session_key.as_bytes(), key.session_key.as_bytes());
	}

	fn get_mail_type_model() -> TypeModel {
		let provider = TypeModelProvider::new_test(
			Arc::new(MockRestClient::default()),
			Arc::new(MockFileClient::default()),
			"http://localhost:9000".to_string(),
		);
		let mail_type_ref = Mail::type_ref();
		provider
			.resolve_server_type_ref(&mail_type_ref)
			.unwrap()
			.clone()
			.deref()
			.clone()
	}

	fn get_group_info_model() -> TypeModel {
		let provider = TypeModelProvider::new_test(
			Arc::new(MockRestClient::default()),
			Arc::new(MockFileClient::default()),
			"http://localhost:9000".to_string(),
		);
		let group_info = GroupInfo::type_ref();
		provider
			.resolve_server_type_ref(&group_info)
			.unwrap()
			.clone()
			.deref()
			.clone()
	}

	fn make_raw_mail(
		constants: &BucketKeyConstants,
		pub_enc_bucket_key: Vec<u8>,
		protocol_version: i64,
	) -> ParsedEntity {
		let bucket_key_data = make_bucket_key(
			constants.recipient_key_version,
			pub_enc_bucket_key,
			&constants.instance_id,
			&constants.instance_list,
			&constants.key_group,
			constants.bucket_enc_session_key.clone(),
			protocol_version,
		);

		let mail = Mail {
			_id: Some(IdTupleGenerated {
				list_id: constants.instance_list.clone(),
				element_id: constants.instance_id.clone(),
			}),
			_ownerGroup: Some(constants.key_group.clone()),
			bucketKey: Some(bucket_key_data),
			..create_test_entity()
		};

		typed_entity_to_parsed_entity(mail)
	}

	struct BucketKeyConstants {
		group_key: GenericAesKey,
		mail_session_key: GenericAesKey,
		instance_id: GeneratedId,
		instance_list: GeneratedId,
		key_group: GeneratedId,
		bucket_key: Aes256Key,
		bucket_key_generic: GenericAesKey,
		bucket_enc_session_key: Vec<u8>,
		sender_key_version: u64,
		recipient_key_version: u64,
		pub_enc_bucket_key: Vec<u8>,
	}

	impl BucketKeyConstants {
		fn new(randomizer_facade: &RandomizerFacade) -> Self {
			let group_key = GenericAesKey::from(Aes256Key::generate(randomizer_facade));
			let bucket_key = Aes256Key::generate(randomizer_facade);
			let mail_session_key = GenericAesKey::from(Aes256Key::generate(randomizer_facade));
			let instance_id = GeneratedId::test_random();
			let instance_list = GeneratedId::test_random();
			let key_group = GeneratedId::test_random();
			let bucket_key_generic = GenericAesKey::from(bucket_key.clone());

			let bucket_enc_session_key_iv = InitializationVector::generate(randomizer_facade);
			let bucket_enc_session_key =
				bucket_key_generic.encrypt_key(&mail_session_key, bucket_enc_session_key_iv);
			let sender_key_version = 1;
			let recipient_key_version = sender_key_version;
			let pub_enc_bucket_key = vec![1, 6, 8, 2];

			Self {
				group_key,
				bucket_key,
				mail_session_key,
				instance_id,
				instance_list,
				key_group,
				bucket_key_generic,
				bucket_enc_session_key,
				sender_key_version,
				recipient_key_version,
				pub_enc_bucket_key,
			}
		}
	}

	fn make_crypto_facade(
		randomizer_facade: RandomizerFacade,
		group_key: GenericAesKey,
		sender_key_version: u64,
		asymmetric_crypto_facade: Option<MockAsymmetricCryptoFacade>,
		has_groups: Vec<GeneratedId>,
		permission: Option<ParsedEntity>,
	) -> CryptoFacade {
		let mut key_loader = MockKeyLoaderFacade::default();
		let mut user_facade = MockUserFacade::default();
		let group_key_clone = group_key.clone();
		let mut entity_client = MockEntityClient::default();

		if permission.is_some() {
			entity_client
				.expect_load_all()
				.return_const(Ok(vec![permission.unwrap()]));
		}

		key_loader
			.expect_get_current_sym_group_key()
			.returning(move |_| {
				Ok(VersionedAesKey {
					version: sender_key_version,
					object: group_key_clone.clone(),
				})
			});

		key_loader
			.expect_load_sym_group_key()
			.returning(move |_, _, _| Ok(group_key.clone()));

		let asymmetric_crypto_facade = asymmetric_crypto_facade.unwrap_or_default();

		let type_model_provider = Arc::new(TypeModelProvider::new_test(
			Arc::new(MockRestClient::default()),
			Arc::new(MockFileClient::default()),
			"localhost:9000".to_string(),
		));

		if has_groups.is_empty() {
			user_facade.expect_has_group().return_const(true);
		} else {
			user_facade
				.expect_has_group()
				.returning(move |group_id: &GeneratedId| has_groups.contains(group_id));
		}

		CryptoFacade {
			key_loader_facade: Arc::new(key_loader),
			instance_mapper: Arc::new(InstanceMapper::new(type_model_provider)),
			randomizer_facade,
			asymmetric_crypto_facade: Arc::new(asymmetric_crypto_facade),
			user_facade: Arc::new(user_facade),
			entity_client: Arc::new(entity_client),
		}
	}

	fn make_bucket_key(
		recipient_key_version: u64,
		pub_enc_bucket_key: Vec<u8>,
		instance_id: &GeneratedId,
		instance_list: &GeneratedId,
		key_group: &GeneratedId,
		bucket_enc_session_key: Vec<u8>,
		protocol_version: i64,
	) -> BucketKey {
		let recipient_key_version_i64 = recipient_key_version as i64;
		BucketKey {
			groupEncBucketKey: None,
			protocolVersion: protocol_version,
			pubEncBucketKey: Some(pub_enc_bucket_key),
			recipientKeyVersion: recipient_key_version_i64,
			senderKeyVersion: None,
			bucketEncSessionKeys: vec![InstanceSessionKey {
				encryptionAuthStatus: None,
				instanceId: instance_id.clone(),
				instanceList: instance_list.clone(),
				symEncSessionKey: bucket_enc_session_key.clone(),
				symKeyVersion: recipient_key_version_i64,
				..create_test_entity()
			}],
			keyGroup: Some(key_group.clone()),
			..create_test_entity()
		}
	}

	/// A bucket entry for `(list, element)` whose session key is `sk`.
	fn bucket_entry(
		list: &GeneratedId,
		element: &GeneratedId,
		bucket_key: &GenericAesKey,
		sk: &GenericAesKey,
	) -> InstanceSessionKey {
		let randomizer = make_thread_rng_facade();
		InstanceSessionKey {
			encryptionAuthStatus: None,
			instanceId: element.clone(),
			instanceList: list.clone(),
			symEncSessionKey: bucket_key
				.encrypt_key(sk, InitializationVector::generate(&randomizer)),
			symKeyVersion: 1,
			..create_test_entity()
		}
	}

	/// A TutaCrypt bucket naming the mail of `constants` plus every `(id, key)`
	/// child, and a facade whose decapsulation returns the bucket key and
	/// counts its calls.
	fn bucket_with_children(
		constants: &BucketKeyConstants,
		children: &[(IdTupleGenerated, GenericAesKey)],
	) -> (BucketKey, Arc<std::sync::atomic::AtomicUsize>, CryptoFacade) {
		let randomizer = make_thread_rng_facade();
		let mut bucket = make_bucket_key(
			constants.recipient_key_version,
			constants.pub_enc_bucket_key.clone(),
			&constants.instance_id,
			&constants.instance_list,
			&constants.key_group,
			constants.bucket_enc_session_key.clone(),
			CryptoProtocolVersion::TutaCrypt as i64,
		);
		for (id, key) in children {
			bucket.bucketEncSessionKeys.push(bucket_entry(
				&id.list_id,
				&id.element_id,
				&constants.bucket_key_generic,
				key,
			));
		}
		let decapsulations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
		let counter = decapsulations.clone();
		let bucket_key = constants.bucket_key_generic.clone();
		let mut asymmetric_crypto_facade = MockAsymmetricCryptoFacade::default();
		asymmetric_crypto_facade
			.expect_load_key_pair_and_decrypt_sym_key()
			.returning(move |_, _, _, _| {
				counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
				Ok(DecapsulatedAesKey {
					decrypted_aes_key: bucket_key.clone(),
					sender_identity_pub_key: None,
				})
			});
		let facade = make_crypto_facade(
			randomizer,
			constants.group_key.clone(),
			constants.sender_key_version,
			Some(asymmetric_crypto_facade),
			vec![],
			None,
		);
		(bucket, decapsulations, facade)
	}

	fn child(key: GenericAesKey) -> (IdTupleGenerated, GenericAesKey) {
		(
			IdTupleGenerated {
				list_id: GeneratedId::test_random(),
				element_id: GeneratedId::test_random(),
			},
			key,
		)
	}

	#[tokio::test]
	async fn bucket_instance_keys_come_from_one_decapsulation_wrapped_for_the_parent_group() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let first = child(GenericAesKey::from(Aes256Key::generate(&randomizer)));
		let second = child(GenericAesKey::from(Aes256Key::generate(&randomizer)));
		let (bucket, decapsulations, facade) =
			bucket_with_children(&constants, &[first.clone(), second.clone()]);

		let keys = facade
			.resolve_bucket_instance_keys(
				&bucket,
				&constants.key_group,
				&[second.0.clone(), first.0.clone()],
			)
			.await
			.unwrap();

		assert_eq!(decapsulations.load(std::sync::atomic::Ordering::SeqCst), 1);
		assert_eq!(keys.len(), 2);
		// Requested order, not bucket order.
		assert_eq!(keys[0].session_key.as_bytes(), second.1.as_bytes());
		assert_eq!(keys[1].session_key.as_bytes(), first.1.as_bytes());
		for key in &keys {
			assert_eq!(key.owner_key_version, constants.sender_key_version);
			assert!(key.sender_identity_pub_key.is_none());
			let unwrapped = constants
				.group_key
				.decrypt_aes_key(&key.owner_enc_session_key)
				.unwrap();
			assert_eq!(unwrapped.as_bytes(), key.session_key.as_bytes());
		}
		// The parent's own key is unchanged and is not a child's.
		let parent = facade
			.resolve_session_key(
				&make_raw_mail(
					&constants,
					constants.pub_enc_bucket_key.clone(),
					CryptoProtocolVersion::TutaCrypt as i64,
				),
				&get_mail_type_model(),
			)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(
			parent.session_key.as_bytes(),
			constants.mail_session_key.as_bytes()
		);
	}

	#[tokio::test]
	async fn bucket_instance_keys_match_the_full_id_not_the_element_alone() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let file = child(GenericAesKey::from(Aes256Key::generate(&randomizer)));
		let (bucket, _, facade) = bucket_with_children(&constants, &[file.clone()]);

		let other_list = IdTupleGenerated {
			list_id: GeneratedId::test_random(),
			element_id: file.0.element_id.clone(),
		};
		let error = facade
			.resolve_bucket_instance_keys(&bucket, &constants.key_group, &[other_list])
			.await
			.unwrap_err();
		assert!(matches!(error, BucketKeyError::NoEntry), "{error}");

		let other_element = IdTupleGenerated {
			list_id: file.0.list_id.clone(),
			element_id: GeneratedId::test_random(),
		};
		let error = facade
			.resolve_bucket_instance_keys(&bucket, &constants.key_group, &[other_element])
			.await
			.unwrap_err();
		assert!(matches!(error, BucketKeyError::NoEntry), "{error}");
	}

	#[tokio::test]
	async fn bucket_instance_keys_refuse_a_duplicated_entry_and_a_missing_one_entirely() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let file = child(GenericAesKey::from(Aes256Key::generate(&randomizer)));
		let twin = (
			file.0.clone(),
			GenericAesKey::from(Aes256Key::generate(&randomizer)),
		);
		let (bucket, _, facade) = bucket_with_children(&constants, &[file.clone(), twin]);

		let error = facade
			.resolve_bucket_instance_keys(&bucket, &constants.key_group, &[file.0.clone()])
			.await
			.unwrap_err();
		assert!(matches!(error, BucketKeyError::AmbiguousEntries), "{error}");

		// One known id and one unknown: nothing is returned.
		let (bucket, _, facade) = bucket_with_children(&constants, &[file.clone()]);
		let unknown = child(GenericAesKey::from(Aes256Key::generate(&randomizer))).0;
		let error = facade
			.resolve_bucket_instance_keys(&bucket, &constants.key_group, &[file.0, unknown])
			.await
			.unwrap_err();
		assert!(matches!(error, BucketKeyError::NoEntry), "{error}");
	}

	#[tokio::test]
	async fn bucket_instance_keys_without_a_request_do_not_decapsulate() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let (bucket, decapsulations, facade) = bucket_with_children(&constants, &[]);

		let keys = facade
			.resolve_bucket_instance_keys(&bucket, &constants.key_group, &[])
			.await
			.unwrap();

		assert!(keys.is_empty());
		assert_eq!(decapsulations.load(std::sync::atomic::Ordering::SeqCst), 0);
	}

	fn group_reference_bucket(constants: &BucketKeyConstants) -> BucketKey {
		let mut bucket = make_bucket_key(
			constants.recipient_key_version,
			constants.pub_enc_bucket_key.clone(),
			&constants.instance_id,
			&constants.instance_list,
			&constants.key_group,
			constants.bucket_enc_session_key.clone(),
			CryptoProtocolVersion::Rsa as i64,
		);
		bucket.pubEncBucketKey = None;
		bucket.groupEncBucketKey = Some(vec![1, 2, 3]);
		bucket
	}

	#[tokio::test]
	async fn a_group_reference_bucket_is_an_error_on_both_paths() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let bucket = group_reference_bucket(&constants);
		let facade = make_crypto_facade(
			randomizer,
			constants.group_key.clone(),
			constants.sender_key_version,
			None,
			vec![],
			None,
		);

		let error = facade
			.resolve_bucket_instance_keys(
				&bucket,
				&constants.key_group,
				&[child(constants.mail_session_key.clone()).0],
			)
			.await
			.unwrap_err();
		assert!(
			matches!(error, BucketKeyError::GroupReferenceUnsupported),
			"{error}"
		);

		let mail = Mail {
			_id: Some(IdTupleGenerated {
				list_id: constants.instance_list.clone(),
				element_id: constants.instance_id.clone(),
			}),
			_ownerGroup: Some(constants.key_group.clone()),
			bucketKey: Some(bucket),
			..create_test_entity()
		};
		let error = facade
			.resolve_session_key(&typed_entity_to_parsed_entity(mail), &get_mail_type_model())
			.await
			.unwrap_err();
		assert!(error.to_string().contains("groupEncBucketKey"), "{error}");
	}

	#[tokio::test]
	async fn an_unknown_protocol_version_is_an_error_on_both_paths() {
		let randomizer = make_thread_rng_facade();
		let constants = BucketKeyConstants::new(&randomizer);
		let mut bucket = make_bucket_key(
			constants.recipient_key_version,
			constants.pub_enc_bucket_key.clone(),
			&constants.instance_id,
			&constants.instance_list,
			&constants.key_group,
			constants.bucket_enc_session_key.clone(),
			99,
		);
		bucket.groupEncBucketKey = None;
		let facade = make_crypto_facade(
			randomizer,
			constants.group_key.clone(),
			constants.sender_key_version,
			None,
			vec![],
			None,
		);

		let error = facade
			.resolve_bucket_instance_keys(
				&bucket,
				&constants.key_group,
				&[child(constants.mail_session_key.clone()).0],
			)
			.await
			.unwrap_err();
		assert!(
			matches!(error, BucketKeyError::Resolution(_))
				&& error.to_string().contains("protocol version"),
			"{error}"
		);

		let mail = Mail {
			_id: Some(IdTupleGenerated {
				list_id: constants.instance_list.clone(),
				element_id: constants.instance_id.clone(),
			}),
			_ownerGroup: Some(constants.key_group.clone()),
			bucketKey: Some(bucket),
			..create_test_entity()
		};
		let error = facade
			.resolve_session_key(&typed_entity_to_parsed_entity(mail), &get_mail_type_model())
			.await
			.unwrap_err();
		assert!(error.to_string().contains("protocol version"), "{error}");
	}
}
