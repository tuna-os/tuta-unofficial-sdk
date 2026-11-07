#[cfg_attr(test, mockall_double::double)]
use crate::crypto_entity_client::CryptoEntityClient;
use crate::entities::generated::sys::{Patch, PatchList, RootInstance};
use crate::entities::generated::tutanota::ContactList;
use crate::entities::Entity;
use crate::groups::GroupType;
#[cfg_attr(test, mockall_double::double)]
use crate::key_loader_facade::KeyLoaderFacade;
use crate::type_model_provider::TypeModelProvider;
#[cfg_attr(test, mockall_double::double)]
use crate::user_facade::UserFacade;
use crate::util::{convert_version_to_i64, convert_version_to_u64};
use crate::{entities::generated::tutanota::Contact, GeneratedId};
use crate::{ApiCallError, Arc, CustomId, IdTupleCustom, IdTupleGenerated, ListLoadDirection};
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use base64::Engine;
use crypto_primitives::aes::{Aes256Key, InitializationVector};
use crypto_primitives::key::GenericAesKey;
use crypto_primitives::randomizer_facade::RandomizerFacade;

/// TS `PatchOperationType.REPLACE_VALUE`.
const PATCH_REPLACE: i64 = 2;

#[derive(uniffi::Object)]
pub struct ContactFacade {
	crypto_entity_client: Arc<CryptoEntityClient>,
	type_model_provider: Arc<TypeModelProvider>,
	user_facade: Arc<UserFacade>,
	key_loader_facade: Arc<KeyLoaderFacade>,
	randomizer_facade: RandomizerFacade,
}

#[cfg_attr(test, mockall::automock)]
impl ContactFacade {
	#[must_use]
	pub fn new(
		crypto_entity_client: Arc<CryptoEntityClient>,
		type_model_provider: Arc<TypeModelProvider>,
		user_facade: Arc<UserFacade>,
		key_loader_facade: Arc<KeyLoaderFacade>,
		randomizer_facade: RandomizerFacade,
	) -> Self {
		ContactFacade {
			crypto_entity_client,
			type_model_provider,
			user_facade,
			key_loader_facade,
			randomizer_facade,
		}
	}

	async fn fetch_contact_lists(&self) -> Result<ContactList, ApiCallError> {
		let user_group_id = self.user_facade.get_user_group_id();
		let Some(type_root) = self
			.type_model_provider
			.resolve_client_type_ref(&ContactList::type_ref())
		else {
			return Err(ApiCallError::InternalSdkError {
				error_message: "Failed to resolve type_root for ContactList".to_string(),
			});
		};

		let root_instance_id = IdTupleCustom {
			list_id: user_group_id,
			element_id: type_root.root_id.clone(),
		};

		let root_instance = self
			.crypto_entity_client
			.load::<RootInstance, IdTupleCustom>(&root_instance_id)
			.await?;

		let contact_list = self
			.crypto_entity_client
			.load::<ContactList, GeneratedId>(&root_instance.reference)
			.await?;

		Ok(contact_list)
	}

	async fn fetch_contacts(
		&self,
		contact_list: &GeneratedId,
	) -> Result<Vec<Contact>, ApiCallError> {
		let contacts: Vec<Contact> = self
			.crypto_entity_client
			.load_all(contact_list, ListLoadDirection::ASC)
			.await?;

		Ok(contacts)
	}

	pub async fn load_all_user_contacts(&self) -> Result<Vec<Contact>, ApiCallError> {
		let contact_list = self.fetch_contact_lists().await?;
		let contacts = self.fetch_contacts(&contact_list.contacts).await?;

		Ok(contacts)
	}

	/// Stores `contact` as a new contact in the user's contact list, as TS
	/// `EntityClient.setup(contactListId, contact)` does with the AES-CBC
	/// scheme: a fresh session key, wrapped with the contact group's current
	/// key, encrypts the contact. Its id, permissions and owner fields are
	/// set here. Returns the new contact's id.
	pub async fn create_contact(&self, contact: Contact) -> Result<IdTupleGenerated, ApiCallError> {
		let mut contact = contact;
		let contact_list = self.fetch_contact_lists().await?;
		let contact_group_id = self
			.user_facade
			.get_membership_by_group_type(GroupType::Contact)?
			.group;
		let group_key = self
			.key_loader_facade
			.get_current_sym_group_key(&contact_group_id)
			.await
			.map_err(|error| ApiCallError::internal_with_err(error, "contact group key"))?;
		let session_key = GenericAesKey::Aes256(Aes256Key::generate(&self.randomizer_facade));
		let owner_enc_session_key = group_key.encrypt_key(
			&session_key,
			InitializationVector::generate(&self.randomizer_facade),
		);
		// A POST names only the list; the server assigns the element id.
		contact._id = Some(IdTupleGenerated::new(
			contact_list.contacts.clone(),
			GeneratedId::min_id(),
		));
		contact._permissions = GeneratedId::min_id();
		contact._format = 0;
		contact._ownerGroup = Some(contact_group_id);
		contact._ownerEncSessionKey = Some(owner_enc_session_key.object);
		contact._ownerKeyVersion = Some(convert_version_to_i64(owner_enc_session_key.version));
		contact._kdfNonce = None;
		let created = self
			.crypto_entity_client
			.create_instance(contact, Some(session_key))
			.await?;
		let element_id = created.generatedId.ok_or_else(|| {
			ApiCallError::internal("the server returned no id for the contact".to_string())
		})?;
		Ok(IdTupleGenerated::new(contact_list.contacts, element_id))
	}

	/// Replaces a stored contact's `presharedPassword` alone, as the PATCH TS
	/// `EntityClient.update` sends after `SendMailModel.updateContacts`
	/// changed it. The value is encrypted with the contact's own session key,
	/// unwrapped from its owner key. A contact written with AEAD (it carries
	/// a KDF nonce) is refused: this SDK writes no AEAD values.
	pub async fn set_preshared_password(
		&self,
		contact: &Contact,
		password: &str,
	) -> Result<(), ApiCallError> {
		if contact._kdfNonce.is_some() {
			return Err(ApiCallError::internal(
				"AEAD instance writes are not supported".to_string(),
			));
		}
		let id = contact
			._id
			.as_ref()
			.ok_or_else(|| ApiCallError::internal("contact without an id".to_string()))?;
		let (Some(owner_group), Some(owner_enc_session_key)) =
			(&contact._ownerGroup, &contact._ownerEncSessionKey)
		else {
			return Err(ApiCallError::internal(
				"contact without an owner key".to_string(),
			));
		};
		let owner_key = self
			.key_loader_facade
			.load_sym_group_key(
				owner_group,
				convert_version_to_u64(contact._ownerKeyVersion.unwrap_or(0)),
				None,
			)
			.await
			.map_err(|error| ApiCallError::internal_with_err(error, "contact owner key"))?;
		let session_key = owner_key
			.decrypt_aes_key(owner_enc_session_key)
			.map_err(|error| ApiCallError::internal_with_err(error, "contact session key"))?;
		let encrypted = session_key
			.encrypt_data(
				password.as_bytes(),
				InitializationVector::generate(&self.randomizer_facade),
			)
			.map_err(|error| ApiCallError::internal_with_err(error, "contact password"))?;
		let attribute_path = self
			.type_model_provider
			.resolve_client_type_ref(&Contact::type_ref())
			.and_then(|model| {
				model
					.get_attribute_id_by_attribute_name("presharedPassword")
					.ok()
			})
			.ok_or_else(|| ApiCallError::internal("no presharedPassword attribute".to_string()))?;
		let patches = PatchList {
			_id: Some(self.aggregate_id()),
			patches: vec![Patch {
				_id: Some(self.aggregate_id()),
				patchOperation: PATCH_REPLACE,
				attributePath: attribute_path,
				value: Some(BASE64_STANDARD.encode(encrypted)),
			}],
		};
		self.crypto_entity_client
			.patch_instance::<Contact>(id, patches)
			.await
	}

	/// A PatchList is not encrypted, so nothing fills its aggregate ids in.
	fn aggregate_id(&self) -> CustomId {
		CustomId(BASE64_URL_SAFE_NO_PAD.encode(self.randomizer_facade.generate_random_array::<4>()))
	}
}

#[cfg(test)]
mod contact_facade_integration_tests {
	use super::ContactFacade;
	use crate::crypto_entity_client::MockCryptoEntityClient;
	use crate::entities::generated::base::PersistenceResourcePostReturn;
	use crate::entities::generated::sys::PatchList;
	use crate::entities::generated::sys::{GroupMembership, RootInstance, User};
	use crate::entities::generated::tutanota::{Contact, ContactList};
	use crate::key_loader_facade::MockKeyLoaderFacade;
	use crate::tutanota_constants::GroupType;
	use crate::user_facade::MockUserFacade;
	use crate::util::test_utils::{
		create_mock_contact, create_test_entity, mock_type_model_provider,
	};
	use crate::{Arc, CustomId, GeneratedId, IdTupleCustom, IdTupleGenerated, ListLoadDirection};
	use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
	use base64::Engine;
	use crypto_primitives::aes::{Aes256Key, InitializationVector};
	use crypto_primitives::key::GenericAesKey;
	use crypto_primitives::randomizer_facade::test_util::make_thread_rng_facade;
	use crypto_primitives::versioned::VersionedAesKey;
	use mockall::predicate;
	use std::sync::Mutex;

	fn random_key() -> GenericAesKey {
		GenericAesKey::Aes256(Aes256Key::generate(&make_thread_rng_facade()))
	}

	#[tokio::test]
	async fn a_new_contact_is_owned_by_the_contact_group_under_a_fresh_session_key() {
		let user_group = GeneratedId::test_random();
		let contact_group = GeneratedId::test_random();
		let contact_list_id = GeneratedId::test_random();
		let contacts_list = GeneratedId::test_random();
		let group_key = VersionedAesKey::new(random_key(), 5);

		let mut user_facade = MockUserFacade::default();
		user_facade
			.expect_get_user_group_id()
			.return_const(user_group.clone());
		let membership_group = contact_group.clone();
		user_facade
			.expect_get_membership_by_group_type()
			.withf(|group_type| *group_type == super::GroupType::Contact)
			.returning(move |_| {
				Ok(GroupMembership {
					group: membership_group.clone(),
					..create_test_entity()
				})
			});
		let mut entities = MockCryptoEntityClient::default();
		let contact_list_root = CustomId("CHR1dGFub3RhAACZ".to_string());
		entities
			.expect_load::<RootInstance, IdTupleCustom>()
			.with(predicate::eq(IdTupleCustom::new(
				user_group.clone(),
				contact_list_root,
			)))
			.return_const(Ok(RootInstance {
				reference: contact_list_id.clone(),
				..create_test_entity()
			}));
		entities
			.expect_load::<ContactList, GeneratedId>()
			.with(predicate::eq(contact_list_id))
			.return_const(Ok(ContactList {
				contacts: contacts_list.clone(),
				..create_test_entity()
			}));
		let created: Arc<Mutex<Option<(Contact, GenericAesKey)>>> = Arc::default();
		let new_id = GeneratedId::test_random();
		entities.expect_create_instance::<Contact>().returning({
			let created = created.clone();
			let new_id = new_id.clone();
			move |contact, key| {
				*created.lock().unwrap() = Some((contact, key.unwrap()));
				Ok(PersistenceResourcePostReturn {
					generatedId: Some(new_id.clone()),
					..create_test_entity()
				})
			}
		});
		let mut key_loader_facade = MockKeyLoaderFacade::default();
		let current_key = group_key.clone();
		key_loader_facade
			.expect_get_current_sym_group_key()
			.with(predicate::eq(contact_group.clone()))
			.returning(move |_| Ok(current_key.clone()));
		let facade = ContactFacade {
			crypto_entity_client: Arc::new(entities),
			type_model_provider: Arc::new(mock_type_model_provider()),
			user_facade: Arc::new(user_facade),
			key_loader_facade: Arc::new(key_loader_facade),
			randomizer_facade: make_thread_rng_facade(),
		};

		let id = facade
			.create_contact(Contact {
				firstName: "Ada".to_string(),
				presharedPassword: Some("secret".to_string()),
				..create_test_entity()
			})
			.await
			.unwrap();

		assert_eq!(id, IdTupleGenerated::new(contacts_list.clone(), new_id));
		let (contact, session_key) = created.lock().unwrap().take().unwrap();
		assert_eq!(contact._id.unwrap().list_id, contacts_list);
		assert_eq!(contact._ownerGroup, Some(contact_group));
		assert_eq!(contact._ownerKeyVersion, Some(5));
		assert_eq!(
			group_key
				.object
				.decrypt_aes_key(&contact._ownerEncSessionKey.unwrap())
				.unwrap(),
			session_key
		);
		assert_eq!(contact.presharedPassword.as_deref(), Some("secret"));
		assert_eq!(contact.firstName, "Ada");
	}

	fn stored_contact(
		group: &GeneratedId,
		group_key: &GenericAesKey,
		session_key: &GenericAesKey,
	) -> Contact {
		Contact {
			_id: Some(IdTupleGenerated::new(
				GeneratedId::test_random(),
				GeneratedId::test_random(),
			)),
			_ownerGroup: Some(group.clone()),
			_ownerEncSessionKey: Some(group_key.encrypt_key(
				session_key,
				InitializationVector::generate(&make_thread_rng_facade()),
			)),
			_ownerKeyVersion: Some(1),
			_kdfNonce: None,
			..create_test_entity()
		}
	}

	#[tokio::test]
	async fn a_changed_password_is_patched_alone_under_the_contact_session_key() {
		let group = GeneratedId::test_random();
		let group_key = random_key();
		let session_key = random_key();
		let contact = stored_contact(&group, &group_key, &session_key);
		let mut key_loader_facade = MockKeyLoaderFacade::default();
		let owner_key = group_key.clone();
		key_loader_facade
			.expect_load_sym_group_key()
			.withf({
				let group = group.clone();
				move |id, version, current| *id == group && *version == 1 && current.is_none()
			})
			.returning(move |_, _, _| Ok(owner_key.clone()));
		let patched: Arc<Mutex<Option<(IdTupleGenerated, PatchList)>>> = Arc::default();
		let mut entities = MockCryptoEntityClient::default();
		entities.expect_patch_instance::<Contact>().returning({
			let patched = patched.clone();
			move |id, patches| {
				*patched.lock().unwrap() = Some((id.clone(), patches));
				Ok(())
			}
		});
		let facade = ContactFacade {
			crypto_entity_client: Arc::new(entities),
			type_model_provider: Arc::new(mock_type_model_provider()),
			user_facade: Arc::new(MockUserFacade::default()),
			key_loader_facade: Arc::new(key_loader_facade),
			randomizer_facade: make_thread_rng_facade(),
		};

		facade
			.set_preshared_password(&contact, "new secret")
			.await
			.unwrap();

		let (id, patches) = patched.lock().unwrap().take().unwrap();
		assert_eq!(Some(id), contact._id);
		assert_eq!(patches.patches.len(), 1);
		let patch = &patches.patches[0];
		assert_eq!(patch.patchOperation, 2);
		assert_eq!(patch.attributePath, "79");
		let ciphertext = BASE64_STANDARD
			.decode(patch.value.as_ref().unwrap())
			.unwrap();
		assert_eq!(
			session_key.decrypt_data(&ciphertext).unwrap(),
			b"new secret"
		);
		for id in [&patches._id, &patch._id] {
			let id = id.as_ref().unwrap();
			assert_eq!(BASE64_URL_SAFE_NO_PAD.decode(id.as_str()).unwrap().len(), 4);
		}
	}

	#[tokio::test]
	async fn an_aead_contact_is_not_written() {
		let group = GeneratedId::test_random();
		let contact = Contact {
			_kdfNonce: Some(vec![7; 32]),
			..stored_contact(&group, &random_key(), &random_key())
		};
		let mut key_loader_facade = MockKeyLoaderFacade::default();
		key_loader_facade.expect_load_sym_group_key().never();
		let mut entities = MockCryptoEntityClient::default();
		entities.expect_patch_instance::<Contact>().never();
		let facade = ContactFacade {
			crypto_entity_client: Arc::new(entities),
			type_model_provider: Arc::new(mock_type_model_provider()),
			user_facade: Arc::new(MockUserFacade::default()),
			key_loader_facade: Arc::new(key_loader_facade),
			randomizer_facade: make_thread_rng_facade(),
		};
		assert!(facade
			.set_preshared_password(&contact, "secret")
			.await
			.is_err());
	}

	fn create_mock_user(
		user_group: &GeneratedId,
		contact_list_id: &GeneratedId,
		contact_list_list_id: &GeneratedId,
	) -> User {
		User {
			memberships: vec![
				GroupMembership {
					groupType: Some(GroupType::Contact as i64),
					group: contact_list_id.to_owned(),
					..create_test_entity()
				},
				GroupMembership {
					groupType: Some(GroupType::ContactList as i64),
					group: contact_list_list_id.to_owned(),
					..create_test_entity()
				},
			],
			userGroup: GroupMembership {
				group: user_group.to_owned(),
				..create_test_entity()
			},
			..create_test_entity()
		}
	}

	#[tokio::test]
	pub async fn test_fetch_contacts_entity_list() {
		let mut mock_crypto_entity_client = MockCryptoEntityClient::default();
		let mut mock_user_facade: MockUserFacade = MockUserFacade::default();
		let mock_type_model_provider = mock_type_model_provider();

		let user_group = GeneratedId::test_random();
		let contact_list_id = GeneratedId::test_random();

		// Custom Id Took from type_models/tutanota.json
		let type_model_id = CustomId("CHR1dGFub3RhAACZ".to_string());
		let root_instance_id: IdTupleCustom = IdTupleCustom {
			list_id: user_group.clone(),
			element_id: type_model_id,
		};

		let root_instance = RootInstance {
			_id: Some(root_instance_id.clone()),
			_ownerGroup: Some(user_group.clone()),
			reference: contact_list_id.clone(),
			..create_test_entity()
		};

		let contact_list = ContactList {
			_id: Some(contact_list_id.clone()),
			contacts: GeneratedId::test_random(),
			..create_test_entity()
		};

		mock_crypto_entity_client
			.expect_load::<RootInstance, IdTupleCustom>()
			.with(predicate::eq(root_instance_id))
			.return_const(Ok(root_instance));

		mock_crypto_entity_client
			.expect_load::<ContactList, GeneratedId>()
			.with(predicate::eq(contact_list_id.clone()))
			.return_const(Ok(contact_list.clone()));

		let mock_user = create_mock_user(&user_group, &contact_list_id, &contact_list_id);
		mock_user_facade
			.expect_get_user_group_id()
			.return_const(mock_user.userGroup.group);

		let contact_facade = ContactFacade {
			crypto_entity_client: Arc::new(mock_crypto_entity_client),
			type_model_provider: Arc::new(mock_type_model_provider),
			user_facade: Arc::new(mock_user_facade),
			key_loader_facade: Arc::new(MockKeyLoaderFacade::default()),
			randomizer_facade: make_thread_rng_facade(),
		};

		let loaded_contact_list = contact_facade.fetch_contact_lists().await;

		assert_eq!(loaded_contact_list.unwrap(), contact_list);
	}

	#[tokio::test]
	pub async fn test_fetch_contacts() {
		let mut mock_crypto_entity_client = MockCryptoEntityClient::default();
		let mut mock_user_facade = MockUserFacade::default();
		let mock_type_model_provider = mock_type_model_provider();

		let user_group = GeneratedId::test_random();
		let contact_list_id = GeneratedId::test_random();
		let contact_list_list_id = GeneratedId::test_random();

		let mock_user = create_mock_user(&user_group, &contact_list_id, &contact_list_list_id);
		mock_user_facade.expect_get_user().return_const(mock_user);

		let contacts = vec![
			create_mock_contact(
				&contact_list_id,
				&GeneratedId::test_random(),
				Some("John"),
				None,
			),
			create_mock_contact(
				&contact_list_id,
				&GeneratedId::test_random(),
				Some("Jane"),
				None,
			),
			create_mock_contact(
				&contact_list_id,
				&GeneratedId::test_random(),
				Some("Isis"),
				None,
			),
		];

		mock_crypto_entity_client
			.expect_load_all::<Contact>()
			.with(
				predicate::eq(contact_list_id.clone()),
				predicate::eq(ListLoadDirection::ASC),
			)
			.return_const(Ok(contacts));

		let contact_facade = ContactFacade {
			crypto_entity_client: Arc::new(mock_crypto_entity_client),
			type_model_provider: Arc::new(mock_type_model_provider),
			user_facade: Arc::new(mock_user_facade),
			key_loader_facade: Arc::new(MockKeyLoaderFacade::default()),
			randomizer_facade: make_thread_rng_facade(),
		};

		let contacts = contact_facade.fetch_contacts(&contact_list_id).await;

		assert_eq!(contacts.unwrap().len(), 3);
	}
}
