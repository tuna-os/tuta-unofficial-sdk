use super::BlobFacade;
use crate::bindings::rest_client::{
	encode_query_params, HttpMethod, RestClientError, RestClientOptions,
};
use crate::blobs::blob_access_token_facade::ReadTokenKey;
use crate::entities::generated::storage::{BlobGetIn, BlobId, BlobServerAccessInfo};
use crate::entities::Entity;
use crate::metamodel::ElementType;
use crate::rest_error::HttpError;
use crate::tutanota_constants::ArchiveDataType;
use crate::util::BASE64_EXT;
use crate::{ApiCallError, CustomId, GeneratedId, IdTupleGenerated, TypeRef};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::collections::HashMap;
use std::future::Future;

/// Maximum number of blob ids per blob service request.
const BLOB_DOWNLOAD_LIMIT: usize = 100;

impl BlobFacade {
	/// Loads one encrypted blob element from an archive owned by the current
	/// user. Returns the JSON response; the caller parses and decrypts it.
	pub async fn load_blob_element(
		&self,
		type_ref: &TypeRef,
		id: &IdTupleGenerated,
	) -> Result<Vec<u8>, ApiCallError> {
		let model = self
			.type_model_provider
			.resolve_client_type_ref(type_ref)
			.ok_or_else(|| ApiCallError::internal(format!("Unknown blob type {type_ref}")))?;
		if model.element_type != ElementType::BlobElement {
			return Err(ApiCallError::internal(
				"Expected a blob element type".to_owned(),
			));
		}
		let path = format!(
			"/rest/{}/{}/{}",
			type_ref.app,
			model.name.to_lowercase(),
			id.list_id
		);
		let path = path.as_str();
		self.with_read_token(
			&ReadTokenKey::Archive(id.list_id.clone()),
			|info| async move {
				self.read_from_servers(
					&info,
					path,
					model.version,
					vec![("ids".to_owned(), id.element_id.to_string())],
				)
				.await
			},
		)
		.await
	}

	/// Downloads encrypted blobs authorized by a referencing instance, in batches of 100.
	/// This does not require ownership of the archive containing those blobs.
	pub async fn download_blobs(
		&self,
		archive: &GeneratedId,
		instance: &IdTupleGenerated,
		data_type: ArchiveDataType,
		ids: &[GeneratedId],
	) -> Result<HashMap<GeneratedId, Vec<u8>>, ApiCallError> {
		if ids.is_empty() {
			return Ok(HashMap::new());
		}
		let key = ReadTokenKey::Instance {
			archive: archive.clone(),
			list: instance.list_id.clone(),
			element: instance.element_id.clone(),
			data_type,
		};
		self.with_read_token(&key, |info| async move {
			self.download_blob_chunks(&info, archive, ids).await
		})
		.await
	}

	async fn download_blob_chunks(
		&self,
		info: &BlobServerAccessInfo,
		archive: &GeneratedId,
		ids: &[GeneratedId],
	) -> Result<HashMap<GeneratedId, Vec<u8>>, ApiCallError> {
		let type_ref = BlobGetIn::type_ref();
		let version = self
			.type_model_provider
			.resolve_client_type_ref(&type_ref)
			.ok_or_else(|| ApiCallError::internal("Missing BlobGetIn model".to_owned()))?
			.version;
		let mut result = HashMap::new();
		for chunk in ids.chunks(BLOB_DOWNLOAD_LIMIT) {
			let request = BlobGetIn {
				_format: 0,
				archiveId: archive.clone(),
				blobId: None,
				blobIds: chunk
					.iter()
					.map(|id| BlobId {
						_id: Some(CustomId(
							URL_SAFE_NO_PAD
								.encode(self.randomizer_facade.generate_random_array::<4>()),
						)),
						blobId: id.clone(),
					})
					.collect(),
			};
			let parsed = self
				.instance_mapper
				.serialize_entity(request)
				.map_err(|e| ApiCallError::internal_with_err(e, "Cannot map BlobGetIn"))?;
			let raw = self.json_serializer.serialize(&type_ref, parsed)?;
			let body = serde_json::to_string(&raw)
				.map_err(|e| ApiCallError::internal_with_err(e, "Invalid BlobGetIn"))?;
			let response = self
				.read_from_servers(
					info,
					super::BLOB_SERVICE_REST_PATH,
					version,
					vec![("_body".to_owned(), body)],
				)
				.await?;
			let downloaded = parse_multiple_blobs_response(&response)?;
			for id in chunk {
				if !downloaded.contains_key(id) {
					return Err(ApiCallError::internal(format!(
						"Missing requested blob {id}"
					)));
				}
			}
			if downloaded.keys().any(|id| !chunk.contains(id)) {
				return Err(ApiCallError::internal(
					"Unrequested blob in response".to_owned(),
				));
			}
			result.extend(downloaded);
		}
		Ok(result)
	}

	/// Mirrors doBlobRequestWithRetry: on 403, evicts the token and repeats the
	/// complete read once.
	async fn with_read_token<T, F, R>(&self, key: &ReadTokenKey, read: F) -> Result<T, ApiCallError>
	where
		F: Fn(BlobServerAccessInfo) -> R,
		R: Future<Output = Result<T, ApiCallError>>,
	{
		let read_once = || async {
			let info = self
				.blob_access_token_facade
				.request_read_token(key)
				.await?;
			read(info).await
		};
		match read_once().await {
			Err(ApiCallError::ServerResponseError {
				source: HttpError::NotAuthorizedError,
			}) => {
				self.blob_access_token_facade.evict_read_token(key);
				read_once().await
			},
			result => result,
		}
	}

	/// Mirrors tryServers: fail over only for errors specific to one blob server.
	async fn read_from_servers(
		&self,
		info: &BlobServerAccessInfo,
		path: &str,
		version: u64,
		mut params: Vec<(String, String)>,
	) -> Result<Vec<u8>, ApiCallError> {
		params.extend(self.auth_headers_provider.provide_headers(version));
		params.push(("blobAccessToken".to_owned(), info.blobAccessToken.clone()));
		let query = encode_query_params(params);
		let mut last_error = ApiCallError::internal("No blob servers available".to_owned());
		for server in &info.servers {
			let response = self
				.rest_client
				.request_binary(
					format!("{}{path}{query}", server.url),
					HttpMethod::GET,
					RestClientOptions {
						body: None,
						headers: HashMap::new(),
						suspension_behavior: None,
					},
				)
				.await;
			let error: ApiCallError = match response {
				Ok(response) if response.status == 200 => {
					return response.body.ok_or_else(|| {
						ApiCallError::internal("Missing blob response body".to_owned())
					})
				},
				Ok(response) => {
					HttpError::from_http_response(response.status, &response.headers)?.into()
				},
				Err(error) => error.into(),
			};
			match error {
				err @ ApiCallError::ServerResponseError {
					source:
						HttpError::ConnectionError
						| HttpError::InternalServerError
						| HttpError::NotFoundError,
				}
				| err @ ApiCallError::RestClient {
					source: RestClientError::NetworkError | RestClientError::FailedHandshake,
				} => last_error = err,
				err => return Err(err),
			}
		}
		Err(last_error)
	}
}

/// count:i32 followed by count * (id:9, hash:6, size:i32, payload:size), big endian.
/// Validate lengths before allocation. Payload authentication belongs to decryption.
fn parse_multiple_blobs_response(
	data: &[u8],
) -> Result<HashMap<GeneratedId, Vec<u8>>, ApiCallError> {
	fn invalid() -> ApiCallError {
		ApiCallError::internal("Invalid binary blob response".to_owned())
	}
	let (count, mut remaining) = data.split_at_checked(4).ok_or_else(invalid)?;
	let count = usize::try_from(i32::from_be_bytes(count.try_into().map_err(|_| invalid())?))
		.map_err(|_| invalid())?;
	if count > remaining.len() / 19 {
		return Err(invalid());
	}
	let mut result = HashMap::new();
	for _ in 0..count {
		let (header, rest) = remaining.split_at_checked(19).ok_or_else(invalid)?;
		let id = GeneratedId(BASE64_EXT.encode(&header[..9]));
		let size = usize::try_from(i32::from_be_bytes(
			header[15..19].try_into().map_err(|_| invalid())?,
		))
		.map_err(|_| invalid())?;
		let (payload, rest) = rest.split_at_checked(size).ok_or_else(invalid)?;
		if result.insert(id, payload.to_vec()).is_some() {
			return Err(invalid());
		}
		remaining = rest;
	}
	if !remaining.is_empty() {
		return Err(invalid());
	}
	Ok(result)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::bindings::{
		file_client::MockFileClient,
		rest_client::{MockRestClient, RestResponse},
	};
	use crate::blobs::blob_access_token_facade::MockBlobAccessTokenFacade;
	use crate::entities::generated::storage::{BlobServerAccessInfo, BlobServerUrl};
	use crate::entities::generated::tutanota::{Mail, MailDetailsBlob};
	use crate::instance_mapper::InstanceMapper;
	use crate::json_serializer::JsonSerializer;
	use crate::type_model_provider::TypeModelProvider;
	use crate::util::test_utils::create_test_entity;
	use crate::HeadersProvider;
	use crypto_primitives::randomizer_facade::RandomizerFacade;
	use std::sync::{Arc, Mutex};

	fn info() -> BlobServerAccessInfo {
		BlobServerAccessInfo {
			blobAccessToken: "token".into(),
			servers: vec![
				BlobServerUrl {
					url: "https://first".into(),
					..create_test_entity()
				},
				BlobServerUrl {
					url: "https://second".into(),
					..create_test_entity()
				},
			],
			..create_test_entity()
		}
	}

	fn facade(rest: MockRestClient, token: MockBlobAccessTokenFacade) -> BlobFacade {
		let provider = Arc::new(TypeModelProvider::new_test(
			Arc::new(MockRestClient::new()),
			Arc::new(MockFileClient::new()),
			"http://test".into(),
		));
		BlobFacade::new(
			token,
			Arc::new(rest),
			RandomizerFacade::from_core(rand_core::OsRng),
			Arc::new(HeadersProvider::new(Some("session-token".to_owned()))),
			Arc::new(InstanceMapper::new(provider.clone())),
			Arc::new(JsonSerializer::new(provider.clone())),
			provider,
		)
	}

	fn id() -> IdTupleGenerated {
		IdTupleGenerated::new(GeneratedId("archive".into()), GeneratedId("element".into()))
	}

	fn wire(entries: &[(GeneratedId, Vec<u8>)]) -> Vec<u8> {
		let mut out = (entries.len() as u32).to_be_bytes().to_vec();
		for (id, bytes) in entries {
			out.extend(BASE64_EXT.decode(id.as_str()).unwrap());
			out.extend([0; 6]);
			out.extend((bytes.len() as u32).to_be_bytes());
			out.extend(bytes);
		}
		out
	}

	#[test]
	fn binary_parser_checks_framing_before_allocation() {
		let id = GeneratedId(BASE64_EXT.encode([1; 9]));
		let good = wire(&[(id.clone(), vec![1, 2, 3])]);
		assert_eq!(
			parse_multiple_blobs_response(&good).unwrap()[&id],
			vec![1, 2, 3]
		);
		assert!(parse_multiple_blobs_response(&[0; 4]).unwrap().is_empty());
		let mut trailing = good.clone();
		trailing.push(0);
		let mut oversized = good.clone();
		oversized[19..23].copy_from_slice(&u32::MAX.to_be_bytes());
		let duplicate = wire(&[(id.clone(), vec![]), (id, vec![])]);
		for bad in [
			vec![],
			vec![0; 3],
			vec![255; 4],
			vec![0, 0, 0, 1],
			vec![0, 0, 0, 0, 1],
			good[..good.len() - 1].to_vec(),
			trailing,
			oversized,
			duplicate,
		] {
			assert!(parse_multiple_blobs_response(&bad).is_err());
		}
	}

	#[tokio::test]
	async fn blob_element_retries_transient_server_then_returns_body() {
		let mut token = MockBlobAccessTokenFacade::default();
		token
			.expect_request_read_token()
			.times(1)
			.returning(|_| Ok(info()));
		let mut rest = MockRestClient::new();
		rest.expect_request_binary()
			.times(1)
			.withf(|url, _, _| url.starts_with("https://first/"))
			.returning(|_, _, _| {
				Ok(RestResponse {
					status: 404,
					headers: HashMap::new(),
					body: None,
				})
			});
		rest.expect_request_binary()
			.times(1)
			.withf(|url, _, _| url.starts_with("https://second/"))
			.returning(|_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: HashMap::new(),
					body: Some(b"[]".to_vec()),
				})
			});
		assert_eq!(
			facade(rest, token)
				.load_blob_element(&MailDetailsBlob::type_ref(), &id())
				.await
				.unwrap(),
			b"[]"
		);
	}

	#[tokio::test]
	async fn permanent_errors_and_empty_bodies_do_not_retry() {
		for status in [401, 474, 200] {
			let mut token = MockBlobAccessTokenFacade::default();
			token
				.expect_request_read_token()
				.times(1)
				.returning(|_| Ok(info()));
			let mut rest = MockRestClient::new();
			rest.expect_request_binary()
				.times(1)
				.returning(move |_, _, _| {
					Ok(RestResponse {
						status,
						headers: HashMap::new(),
						body: None,
					})
				});
			assert!(facade(rest, token)
				.load_blob_element(&MailDetailsBlob::type_ref(), &id())
				.await
				.is_err());
		}
	}

	#[tokio::test]
	async fn blob_element_rejects_a_type_that_is_not_a_blob_element() {
		let error = facade(MockRestClient::new(), MockBlobAccessTokenFacade::default())
			.load_blob_element(&Mail::type_ref(), &id())
			.await
			.unwrap_err();
		assert!(error.to_string().contains("Expected a blob element type"));
	}

	#[tokio::test]
	async fn binary_download_uses_instance_scope_and_chunks_at_100() {
		let mut token = MockBlobAccessTokenFacade::default();
		token
			.expect_request_read_token()
			.times(1)
			.withf(|key| {
				*key == ReadTokenKey::Instance {
					archive: GeneratedId("archive".into()),
					list: GeneratedId("files".into()),
					element: GeneratedId("file".into()),
					data_type: ArchiveDataType::Attachments,
				}
			})
			.returning(|_| Ok(info()));
		let sizes = Arc::new(Mutex::new(Vec::new()));
		let seen = sizes.clone();
		let mut rest = MockRestClient::new();
		rest.expect_request_binary()
			.times(2)
			.returning(move |url, method, options| {
				assert!(url.contains("/rest/storage/blobservice?"));
				assert_eq!(method, HttpMethod::GET);
				assert!(options.body.is_none());
				let query: HashMap<_, _> =
					form_urlencoded::parse(url.split_once('?').unwrap().1.as_bytes())
						.into_owned()
						.collect();
				assert!(options.headers.is_empty());
				assert_eq!(query["blobAccessToken"], "token");
				assert_eq!(query["accessToken"], "session-token");
				assert!(query.contains_key("v") && query.contains_key("cv"));
				let raw: serde_json::Value = serde_json::from_str(&query["_body"]).unwrap();
				let ids = raw["193"].as_array().unwrap();
				seen.lock().unwrap().push(ids.len());
				let mut entries = Vec::new();
				for item in ids {
					assert!(item["145"].is_string());
					entries.push((GeneratedId(item["146"].as_str().unwrap().into()), vec![42]));
				}
				Ok(RestResponse {
					status: 200,
					headers: HashMap::new(),
					body: Some(wire(&entries)),
				})
			});
		let ids: Vec<_> = (0..101)
			.map(|i| GeneratedId(BASE64_EXT.encode([i; 9])))
			.collect();
		let facade = facade(rest, token);
		let result = facade
			.download_blobs(
				&GeneratedId("archive".into()),
				&IdTupleGenerated::new(GeneratedId("files".into()), GeneratedId("file".into())),
				ArchiveDataType::Attachments,
				&ids,
			)
			.await
			.unwrap();
		assert_eq!(*sizes.lock().unwrap(), vec![100, 1]);
		assert_eq!(result.len(), 101);
		assert!(facade
			.download_blobs(
				&GeneratedId("unused".into()),
				&id(),
				ArchiveDataType::Attachments,
				&[]
			)
			.await
			.unwrap()
			.is_empty());
	}

	#[tokio::test]
	async fn binary_download_rejects_missing_or_unrequested_blobs() {
		let requested = GeneratedId(BASE64_EXT.encode([1; 9]));
		for entries in [
			vec![],
			vec![
				(requested.clone(), vec![1]),
				(GeneratedId(BASE64_EXT.encode([2; 9])), vec![2]),
			],
		] {
			let mut token = MockBlobAccessTokenFacade::default();
			token
				.expect_request_read_token()
				.times(1)
				.returning(|_| Ok(info()));
			let body = wire(&entries);
			let mut rest = MockRestClient::new();
			rest.expect_request_binary()
				.times(1)
				.returning(move |_, _, _| {
					Ok(RestResponse {
						status: 200,
						headers: HashMap::new(),
						body: Some(body.clone()),
					})
				});
			assert!(facade(rest, token)
				.download_blobs(
					&id().list_id,
					&id(),
					ArchiveDataType::Attachments,
					std::slice::from_ref(&requested)
				)
				.await
				.is_err());
		}
	}

	#[tokio::test]
	async fn binary_refresh_restarts_the_complete_archive_read_once() {
		let mut token = MockBlobAccessTokenFacade::default();
		token
			.expect_request_read_token()
			.times(2)
			.returning(|_| Ok(info()));
		token.expect_evict_read_token().times(1).return_const(());
		let sizes = Arc::new(Mutex::new(Vec::new()));
		let seen = sizes.clone();
		let mut rest = MockRestClient::new();
		rest.expect_request_binary()
			.times(4)
			.returning(move |url, _, options| {
				assert!(options.body.is_none());
				let query: HashMap<_, _> =
					form_urlencoded::parse(url.split_once('?').unwrap().1.as_bytes())
						.into_owned()
						.collect();
				let raw: serde_json::Value = serde_json::from_str(&query["_body"]).unwrap();
				let ids = raw["193"].as_array().unwrap();
				let mut seen = seen.lock().unwrap();
				seen.push(ids.len());
				if seen.len() == 2 {
					return Ok(RestResponse {
						status: 403,
						headers: HashMap::new(),
						body: None,
					});
				}
				let entries: Vec<_> = ids
					.iter()
					.map(|item| (GeneratedId(item["146"].as_str().unwrap().into()), vec![42]))
					.collect();
				Ok(RestResponse {
					status: 200,
					headers: HashMap::new(),
					body: Some(wire(&entries)),
				})
			});
		let ids: Vec<_> = (0..101)
			.map(|i| GeneratedId(BASE64_EXT.encode([i; 9])))
			.collect();
		let result = facade(rest, token)
			.download_blobs(&id().list_id, &id(), ArchiveDataType::Attachments, &ids)
			.await
			.unwrap();
		assert_eq!(result.len(), 101);
		assert_eq!(*sizes.lock().unwrap(), vec![100, 1, 100, 1]);
	}

	#[tokio::test]
	async fn binary_download_fails_over_to_the_next_server() {
		let mut token = MockBlobAccessTokenFacade::default();
		token
			.expect_request_read_token()
			.times(1)
			.returning(|_| Ok(info()));
		let blob = GeneratedId(BASE64_EXT.encode([1; 9]));
		let body = wire(&[(blob.clone(), vec![42])]);
		let mut rest = MockRestClient::new();
		let mut sequence = mockall::Sequence::new();
		rest.expect_request_binary()
			.times(1)
			.in_sequence(&mut sequence)
			.withf(|url, _, _| url.starts_with("https://first/"))
			.returning(|_, _, _| {
				Ok(RestResponse {
					status: 500,
					headers: HashMap::new(),
					body: None,
				})
			});
		rest.expect_request_binary()
			.times(1)
			.in_sequence(&mut sequence)
			.withf(|url, _, _| url.starts_with("https://second/"))
			.returning(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: HashMap::new(),
					body: Some(body.clone()),
				})
			});

		let result = facade(rest, token)
			.download_blobs(
				&id().list_id,
				&id(),
				ArchiveDataType::Attachments,
				std::slice::from_ref(&blob),
			)
			.await
			.unwrap();
		assert_eq!(result[&blob], vec![42]);
	}

	#[tokio::test]
	async fn binary_download_returns_the_last_error_when_every_server_fails() {
		let mut token = MockBlobAccessTokenFacade::default();
		token
			.expect_request_read_token()
			.times(1)
			.returning(|_| Ok(info()));
		let mut rest = MockRestClient::new();
		let mut sequence = mockall::Sequence::new();
		rest.expect_request_binary()
			.times(1)
			.in_sequence(&mut sequence)
			.withf(|url, _, _| url.starts_with("https://first/"))
			.returning(|_, _, _| Err(RestClientError::NetworkError));
		rest.expect_request_binary()
			.times(1)
			.in_sequence(&mut sequence)
			.withf(|url, _, _| url.starts_with("https://second/"))
			.returning(|_, _, _| {
				Ok(RestResponse {
					status: 500,
					headers: HashMap::new(),
					body: None,
				})
			});
		let blob = GeneratedId(BASE64_EXT.encode([1; 9]));

		let error = facade(rest, token)
			.download_blobs(
				&id().list_id,
				&id(),
				ArchiveDataType::Attachments,
				std::slice::from_ref(&blob),
			)
			.await
			.unwrap_err();
		assert!(matches!(
			error,
			ApiCallError::ServerResponseError {
				source: HttpError::InternalServerError
			}
		));
	}
}
