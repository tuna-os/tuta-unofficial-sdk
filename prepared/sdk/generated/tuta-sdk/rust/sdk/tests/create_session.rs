use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tutasdk::bindings::rest_client::{
	HttpMethod, RestClient, RestClientError, RestClientOptions, RestResponse,
};
use tutasdk::bindings::test_file_client::TestFileClient;
use tutasdk::bindings::test_rest_client::TestRestClient;
use tutasdk::net::native_rest_client::NativeRestClient;
use tutasdk::Sdk;

#[cfg_attr(
	not(feature = "test-with-local-http-server"),
	ignore = "require local http server."
)]
#[tokio::test]
async fn sdk_can_create_new_session() -> Result<(), Box<dyn Error>> {
	let rest_client = Arc::new(NativeRestClient::try_new().unwrap());
	let file_client = Arc::new(TestFileClient::default());

	// this test expect local server with matching model versions to be live at: http://localhost:9000
	let sdk = Sdk::new(
		"http://localhost:9000".to_string(),
		rest_client.clone(),
		file_client,
	);

	sdk.create_session("map-free@tutanota.de", "map")
		.await
		.map(|_| ())?;

	Ok(())
}

/// Answers the salt service with the given KDF version, refuses the session
/// service, and records the requests it receives.
struct SaltServer {
	type_models: TestRestClient,
	kdf_version: &'static str,
	requests: Mutex<Vec<(String, String)>>,
}

impl SaltServer {
	fn new(kdf_version: &'static str) -> Arc<Self> {
		Arc::new(Self {
			type_models: TestRestClient::new("http://test"),
			kdf_version,
			requests: Mutex::new(vec![]),
		})
	}

	fn requests(&self) -> Vec<(String, String)> {
		self.requests.lock().unwrap().clone()
	}
}

#[async_trait::async_trait]
impl RestClient for SaltServer {
	async fn request_binary(
		&self,
		url: String,
		method: HttpMethod,
		options: RestClientOptions,
	) -> Result<RestResponse, RestClientError> {
		let response = |status, body: Option<serde_json::Value>| RestResponse {
			status,
			headers: HashMap::new(),
			body: body.map(|body| serde_json::to_vec(&body).unwrap()),
		};
		if url.contains("/saltservice") || url.contains("/sessionservice") {
			let body = String::from_utf8(options.body.clone().unwrap_or_default()).unwrap();
			self.requests.lock().unwrap().push((url.clone(), body));
		}
		if url.contains("/saltservice") {
			let salt = serde_json::json!({
				"421": "0",
				"422": "BwcHBwcHBwcHBwcHBwcHBw==",
				"2133": self.kdf_version,
			});
			Ok(response(200, Some(salt)))
		} else if url.contains("/sessionservice") {
			Ok(response(404, None))
		} else {
			self.type_models.request_binary(url, method, options).await
		}
	}
}

fn sdk_with(server: Arc<SaltServer>) -> Sdk {
	Sdk::new(
		"http://test".to_string(),
		server,
		Arc::new(TestFileClient::default()),
	)
}

#[tokio::test]
async fn create_session_uses_the_normalized_address() {
	let server = SaltServer::new("1");

	let _ = sdk_with(server.clone())
		.create_session(" Map-Free@Tutanota.de ", "map")
		.await;

	let requests = server.requests();
	// The salt request carries its data url-encoded in the query.
	assert!(requests[0].0.contains("map-free%40tutanota.de"));
	assert!(requests[1].1.contains("map-free@tutanota.de"));
	assert!(!requests[1].1.contains("Map-Free"));
}

#[tokio::test]
async fn create_session_refuses_a_bcrypt_account_without_creating_a_session() {
	let server = SaltServer::new("0");

	let result = sdk_with(server.clone())
		.create_session("map-free@tutanota.de", "map")
		.await;

	assert!(result.is_err());
	assert!(!server
		.requests()
		.iter()
		.any(|(url, _)| url.contains("/sessionservice")));
}
