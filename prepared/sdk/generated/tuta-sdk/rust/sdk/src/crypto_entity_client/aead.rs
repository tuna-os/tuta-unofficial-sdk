use super::CryptoEntityClient;
use crate::element_value::{ElementValue, ParsedEntity};
use crate::entities::entity_facade::{
	EntityDecryptionKeys, EntityDecryptionRequirements, BUCKET_KEY_FIELD, OWNER_GROUP_FIELD,
};
use crate::metamodel::TypeModel;
use crate::ApiCallError;

impl CryptoEntityClient {
	/// Group-key attributes do not require an owner-encrypted session key.
	pub(super) async fn process_entity_with_group_keys(
		&self,
		model: &TypeModel,
		entity: ParsedEntity,
		inherited_session_key: Option<crate::crypto::crypto_facade::ResolvedSessionKey>,
	) -> Result<ParsedEntity, ApiCallError> {
		let requirements =
			EntityDecryptionRequirements::with_resolver(model, &entity, &|reference| {
				self.entity_client.resolve_server_type_ref(reference)
			})?;
		// Bucket-key resolution also establishes sender identity and caches keys for
		// attachments. Preserve that work even if every attribute is group-encrypted.
		let has_bucket_key = model
			.get_attribute_id_by_attribute_name(BUCKET_KEY_FIELD)
			.ok()
			.and_then(|id| entity.get(&id))
			.is_some_and(
				|value| matches!(value, ElementValue::Array(values) if !values.is_empty()),
			);
		let mut keys = EntityDecryptionKeys::default();
		if requirements.session_key || has_bucket_key {
			keys.session_key = match inherited_session_key {
				Some(key) if !has_bucket_key => Some(key),
				_ => self
					.crypto_facade
					.resolve_session_key(&entity, model)
					.await
					.map_err(|e| {
						ApiCallError::internal_with_err(
							e,
							"Failed to resolve required attribute session key",
						)
					})?,
			};
			if keys.session_key.is_none() {
				return Err(ApiCallError::internal(
					"Missing required attribute session key".into(),
				));
			}
		}
		if !requirements.group_key_versions.is_empty() {
			let owner_id = model.get_attribute_id_by_attribute_name(OWNER_GROUP_FIELD)?;
			let Some(ElementValue::IdGeneratedId(owner)) = entity.get(&owner_id) else {
				return Err(ApiCallError::internal("Missing AEAD owner group".into()));
			};
			for version in requirements.group_key_versions {
				let key = self
					.key_loader_facade
					.load_sym_group_key(owner, version, None)
					.await
					.map_err(|e| {
						ApiCallError::internal_with_err(
							e,
							&format!("Failed to load AEAD group key version {version}"),
						)
					})?;
				keys.group_keys.insert(version, key);
			}
		}
		let sender_identity = keys
			.session_key
			.as_ref()
			.and_then(|key| key.sender_identity_pub_key.clone());
		let mut decrypted = self
			.entity_facade
			.decrypt_and_map_with_keys(model, entity, keys)?;
		if let Some(status) = self
			.get_encryption_auth_status_or_none(model, &mut decrypted, sender_identity)
			.await?
		{
			let id = model.get_attribute_id_by_attribute_name("encryptionAuthStatus")?;
			decrypted.insert(id, ElementValue::Number(status));
		}
		Ok(decrypted)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::bindings::{file_client::MockFileClient, rest_client::MockRestClient};
	use crate::crypto::crypto_facade::{ResolvedSessionKey, SessionKeyResolutionError};
	use crate::crypto::key::KeyLoadError;
	use crate::crypto::{
		asymmetric_crypto_facade::MockAsymmetricCryptoFacade, crypto_facade::MockCryptoFacade,
	};
	use crate::entities::generated::sys::BucketKey;
	use crate::entities::{entity_facade::MockEntityFacade, generated::tutanota::Mail, Entity};
	use crate::entity_client::MockEntityClient;
	use crate::instance_mapper::InstanceMapper;
	use crate::key_loader_facade::MockKeyLoaderFacade;
	use crate::type_model_provider::TypeModelProvider;
	use crate::GeneratedId;
	use crypto_primitives::key::GenericAesKey;
	use std::sync::Arc;

	fn provider() -> Arc<TypeModelProvider> {
		Arc::new(TypeModelProvider::new_test(
			Arc::new(MockRestClient::new()),
			Arc::new(MockFileClient::new()),
			"localhost".into(),
		))
	}

	/// A Mail model without aggregates and without the sender authentication step.
	fn plain_model(provider: &TypeModelProvider) -> TypeModel {
		let mut model = (*provider.resolve_server_type_ref(&Mail::type_ref()).unwrap()).clone();
		model.id = 99999.into();
		model.associations.clear();
		model
	}

	fn session_key() -> ResolvedSessionKey {
		ResolvedSessionKey {
			session_key: GenericAesKey::from_bytes(&[0x11; 32]).unwrap(),
			owner_enc_session_key: vec![1, 2, 3],
			owner_key_version: 0,
			sender_identity_pub_key: None,
		}
	}

	fn client(
		entity_client: MockEntityClient,
		crypto_facade: MockCryptoFacade,
		entity_facade: MockEntityFacade,
		key_loader: MockKeyLoaderFacade,
	) -> CryptoEntityClient {
		CryptoEntityClient::new(
			Arc::new(entity_client),
			Arc::new(entity_facade),
			Arc::new(crypto_facade),
			Arc::new(InstanceMapper::new(provider())),
			Arc::new(MockAsymmetricCryptoFacade::default()),
			Arc::new(key_loader),
		)
	}

	/// Passes the entity through once it is given a session key and no group key.
	fn facade_expecting_only_a_session_key() -> MockEntityFacade {
		let mut facade = MockEntityFacade::default();
		facade
			.expect_decrypt_and_map_with_keys()
			.withf(|_, _, keys| keys.session_key.is_some() && keys.group_keys.is_empty())
			.returning(|_, entity, _| Ok(entity));
		facade
	}

	#[tokio::test]
	async fn loads_ciphertext_group_versions_without_requesting_a_session_key() {
		let provider = Arc::new(TypeModelProvider::new_test(
			Arc::new(MockRestClient::new()),
			Arc::new(MockFileClient::new()),
			"localhost".into(),
		));
		let mut model = (*provider.resolve_server_type_ref(&Mail::type_ref()).unwrap()).clone();
		model.id = 99999.into(); // No mail sender-authentication step in this key-loading test.
		model.associations.clear();
		let mut subject = model.values[&105.into()].clone();
		subject.id = 106.into();
		model.values.insert(106.into(), subject);
		let entity = ParsedEntity::from([
			("105".into(), ElementValue::Bytes(vec![2, 0, 7])),
			("106".into(), ElementValue::Bytes(vec![2, 0, 8])),
			(
				"587".into(),
				ElementValue::IdGeneratedId(GeneratedId("owner".into())),
			),
			("1839".into(), ElementValue::Bytes(vec![0x22; 32])),
		]);
		let mut loader = MockKeyLoaderFacade::default();
		for version in [7, 8] {
			loader
				.expect_load_sym_group_key()
				.withf(move |owner, requested, current| {
					owner.as_str() == "owner" && *requested == version && current.is_none()
				})
				.times(1)
				.returning(move |_, _, _| {
					Ok(GenericAesKey::from_bytes(&[version as u8; 32]).unwrap())
				});
		}
		let mut facade = MockEntityFacade::default();
		facade
			.expect_decrypt_and_map_with_keys()
			.times(1)
			.withf(|_, _, keys| {
				keys.session_key.is_none()
					&& keys.group_keys.len() == 2
					&& keys.group_keys.contains_key(&7)
					&& keys.group_keys.contains_key(&8)
			})
			.returning(|_, entity, _| Ok(entity));
		let client = CryptoEntityClient::new(
			Arc::new(MockEntityClient::default()),
			Arc::new(facade),
			Arc::new(MockCryptoFacade::default()),
			Arc::new(InstanceMapper::new(provider)),
			Arc::new(MockAsymmetricCryptoFacade::default()),
			Arc::new(loader),
		);
		client
			.process_entity_with_group_keys(&model, entity, None)
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn a_session_key_attribute_uses_the_inherited_key_or_resolves_one() {
		let model = plain_model(&provider());
		let entity = ParsedEntity::from([
			("105".into(), ElementValue::Bytes(vec![3; 53])),
			("1839".into(), ElementValue::Bytes(vec![0x22; 32])),
		]);

		// An inherited key is used as is.
		let mut crypto_facade = MockCryptoFacade::default();
		crypto_facade.expect_resolve_session_key().times(0);
		client(
			MockEntityClient::default(),
			crypto_facade,
			facade_expecting_only_a_session_key(),
			MockKeyLoaderFacade::default(),
		)
		.process_entity_with_group_keys(&model, entity.clone(), Some(session_key()))
		.await
		.unwrap();

		// Without one, it is resolved from the entity.
		let mut crypto_facade = MockCryptoFacade::default();
		crypto_facade
			.expect_resolve_session_key()
			.times(1)
			.returning(|_, _| Ok(Some(session_key())));
		client(
			MockEntityClient::default(),
			crypto_facade,
			facade_expecting_only_a_session_key(),
			MockKeyLoaderFacade::default(),
		)
		.process_entity_with_group_keys(&model, entity.clone(), None)
		.await
		.unwrap();

		// Nothing is decrypted when no key can be resolved.
		for (resolution, message) in [
			(Ok(None), "Missing required attribute session key"),
			(
				Err(SessionKeyResolutionError::from(KeyLoadError {
					reason: "offline".into(),
				})),
				"Failed to resolve required attribute session key",
			),
		] {
			let mut crypto_facade = MockCryptoFacade::default();
			crypto_facade
				.expect_resolve_session_key()
				.times(1)
				.return_once(move |_, _| resolution);
			let error = client(
				MockEntityClient::default(),
				crypto_facade,
				MockEntityFacade::default(),
				MockKeyLoaderFacade::default(),
			)
			.process_entity_with_group_keys(&model, entity.clone(), None)
			.await
			.unwrap_err();
			assert!(error.to_string().contains(message), "{error}");
		}
	}

	#[tokio::test]
	async fn a_bucket_key_is_resolved_even_with_an_inherited_key() {
		let provider = provider();
		let mut model = (*provider.resolve_server_type_ref(&Mail::type_ref()).unwrap()).clone();
		model.id = 99999.into();
		model.associations.retain(|id, _| *id == 1310.into());
		let entity = ParsedEntity::from([
			("105".into(), ElementValue::Bytes(vec![3; 53])),
			("1839".into(), ElementValue::Bytes(vec![0x22; 32])),
			(
				"1310".into(),
				ElementValue::Array(vec![ElementValue::Dict(ParsedEntity::new())]),
			),
		]);
		let bucket_key_model = provider
			.resolve_server_type_ref(&BucketKey::type_ref())
			.unwrap();
		let mut entity_client = MockEntityClient::default();
		entity_client
			.expect_resolve_server_type_ref()
			.returning(move |_| Ok(bucket_key_model.clone()));
		let mut crypto_facade = MockCryptoFacade::default();
		crypto_facade
			.expect_resolve_session_key()
			.times(1)
			.returning(|_, _| Ok(Some(session_key())));

		client(
			entity_client,
			crypto_facade,
			facade_expecting_only_a_session_key(),
			MockKeyLoaderFacade::default(),
		)
		.process_entity_with_group_keys(&model, entity, Some(session_key()))
		.await
		.unwrap();
	}

	#[tokio::test]
	async fn group_keys_need_the_owner_group_and_name_the_failing_version() {
		let model = plain_model(&provider());
		let mut entity = ParsedEntity::from([
			("105".into(), ElementValue::Bytes(vec![2, 0, 7])),
			("1839".into(), ElementValue::Bytes(vec![0x22; 32])),
		]);
		let error = client(
			MockEntityClient::default(),
			MockCryptoFacade::default(),
			MockEntityFacade::default(),
			MockKeyLoaderFacade::default(),
		)
		.process_entity_with_group_keys(&model, entity.clone(), None)
		.await
		.unwrap_err();
		assert!(error.to_string().contains("Missing AEAD owner group"));

		entity.insert(
			"587".into(),
			ElementValue::IdGeneratedId(GeneratedId("owner".into())),
		);
		let mut loader = MockKeyLoaderFacade::default();
		loader
			.expect_load_sym_group_key()
			.times(1)
			.returning(|_, _, _| {
				Err(KeyLoadError {
					reason: "offline".into(),
				})
			});
		let error = client(
			MockEntityClient::default(),
			MockCryptoFacade::default(),
			MockEntityFacade::default(),
			loader,
		)
		.process_entity_with_group_keys(&model, entity, None)
		.await
		.unwrap_err();
		assert!(error.to_string().contains("AEAD group key version 7"));
	}
}
