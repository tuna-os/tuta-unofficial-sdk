//! Interactive session creation against an in-memory server, never a real account.
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tutasdk::bindings::rest_client::{
	HttpMethod, RestClient, RestClientError, RestClientOptions, RestResponse,
};
use tutasdk::bindings::test_file_client::TestFileClient;
use tutasdk::bindings::test_rest_client::TestRestClient;
use tutasdk::Sdk;

const ACCESS_TOKEN: &str = "ZC2NIBDACUABAdJhibIwclzaPU3fEu-NzQ";

/// Serves an Argon2 salt, creates sessions (with one pending challenge when
/// asked), accepts second factors, and records the bodies it is posted.
/// Any other request is recorded and answered with 404.
struct SessionServer {
	type_models: TestRestClient,
	salt: Vec<u8>,
	with_challenge: bool,
	posts: Mutex<Vec<serde_json::Value>>,
	other_requests: Mutex<Vec<String>>,
}

#[async_trait]
impl RestClient for SessionServer {
	async fn request_binary(
		&self,
		url: String,
		method: HttpMethod,
		options: RestClientOptions,
	) -> Result<RestResponse, RestClientError> {
		let body = if url.contains("/saltservice") {
			Some(serde_json::json!({
				"421": "0",
				"422": STANDARD.encode(&self.salt),
				"2133": "1",
			}))
		} else if url.ends_with("/sessionservice") && method == HttpMethod::POST {
			self.record(&options);
			let challenges = if self.with_challenge {
				vec![serde_json::json!({"1188": "challenge", "1189": "1", "1190": [], "1247": []})]
			} else {
				vec![]
			};
			Some(serde_json::json!({
				"1220": "0",
				"1221": ACCESS_TOKEN,
				"1222": challenges,
				"1223": ["user"],
			}))
		} else if url.ends_with("/secondfactorauthservice") && method == HttpMethod::POST {
			self.record(&options);
			None
		} else if url.contains("/secondfactorauthservice?") {
			Some(serde_json::json!({"1237": "0", "1238": "0"}))
		} else if url.ends_with("/applicationtypesservice") {
			return self.type_models.request_binary(url, method, options).await;
		} else {
			self.other_requests.lock().unwrap().push(url);
			return Ok(RestResponse {
				status: 404,
				headers: HashMap::new(),
				body: None,
			});
		};
		Ok(RestResponse {
			status: 200,
			headers: HashMap::new(),
			body: body.map(|body| serde_json::to_vec(&body).unwrap()),
		})
	}
}

impl SessionServer {
	fn record(&self, options: &RestClientOptions) {
		let body = serde_json::from_slice(options.body.as_ref().unwrap()).unwrap();
		self.posts.lock().unwrap().push(body);
	}

	fn posts(&self) -> Vec<serde_json::Value> {
		self.posts.lock().unwrap().clone()
	}

	fn other_requests(&self) -> Vec<String> {
		self.other_requests.lock().unwrap().clone()
	}
}

fn sdk_with_server(with_challenge: bool) -> (Sdk, Arc<SessionServer>) {
	sdk_with_salt(vec![7; 16], with_challenge)
}

fn sdk_with_salt(salt: Vec<u8>, with_challenge: bool) -> (Sdk, Arc<SessionServer>) {
	let server = Arc::new(SessionServer {
		type_models: TestRestClient::new("http://test"),
		salt,
		with_challenge,
		posts: Mutex::new(vec![]),
		other_requests: Mutex::new(vec![]),
	});
	let sdk = Sdk::new(
		"http://test".into(),
		server.clone(),
		Arc::new(TestFileClient::default()),
	);
	(sdk, server)
}

#[tokio::test]
async fn initiate_session_returns_credentials_and_pending_challenges() {
	for with_challenge in [false, true] {
		let (sdk, server) = sdk_with_server(with_challenge);

		let result = sdk
			.initiate_session(" USER@example.test ", "test password", "Test client")
			.await
			.unwrap();

		assert_eq!(result.credentials.login, " USER@example.test ");
		assert_eq!(result.challenges.len(), usize::from(with_challenge));
		let posts = server.posts();
		assert_eq!(posts.len(), 1);
		assert_eq!(posts[0]["1215"], "Test client");
		assert_eq!(posts[0]["1213"], "user@example.test");
		// The access key sent to the server is a 256-bit key.
		let access_key = STANDARD.decode(posts[0]["1216"].as_str().unwrap()).unwrap();
		assert_eq!(access_key.len(), 32);
	}
}

#[tokio::test]
async fn a_salt_of_the_wrong_length_is_refused_before_creating_a_session() {
	let (sdk, server) = sdk_with_salt(vec![7; 15], false);

	let error = sdk
		.initiate_session("user@example.test", "test password", "Test client")
		.await
		.err()
		.unwrap();

	assert!(error.to_string().contains("salt has wrong length"));
	assert!(server.posts().is_empty());
}

#[tokio::test]
async fn create_session_refuses_a_pending_second_factor() {
	let (sdk, server) = sdk_with_server(true);

	let error = sdk
		.create_session("user@example.test", "test password")
		.await
		.err()
		.unwrap();

	assert!(error.to_string().contains("a second factor is required"));
	assert_eq!(server.posts().len(), 1);
	assert!(server.other_requests().is_empty());
}

#[tokio::test]
async fn create_session_without_a_challenge_logs_in_with_the_new_session() {
	let (sdk, server) = sdk_with_server(false);

	// The in-memory server has no session entity, so the login that follows
	// fails, but only after asking for the session it was just given.
	let error = sdk
		.create_session("user@example.test", "test password")
		.await
		.err()
		.unwrap();

	assert!(!error.to_string().contains("second factor"));
	assert_eq!(server.posts().len(), 1);
	assert_eq!(
		server.other_requests(),
		["http://test/rest/sys/Session/O1qC702-1J-0/3u3i8Lr9_7TnDDdAVw7w3TypTD2k1L00vIUTMF0SIPY"]
	);
}

#[tokio::test]
async fn totp_is_validated_then_posted_to_the_second_factor_service() {
	let (sdk, server) = sdk_with_server(false);

	// A TOTP code has at most six digits: refused before any request.
	assert!(sdk
		.authenticate_with_second_factor_totp(ACCESS_TOKEN, 1_000_000)
		.await
		.is_err());
	assert!(server.posts().is_empty());

	sdk.authenticate_with_second_factor_totp(ACCESS_TOKEN, 123)
		.await
		.unwrap();
	let posts = server.posts();
	assert_eq!(posts[0]["1230"], "1");
	assert_eq!(posts[0]["1243"], "123");
	assert_eq!(
		posts[0]["1232"],
		serde_json::json!([[
			"O1qC702-1J-0",
			"3u3i8Lr9_7TnDDdAVw7w3TypTD2k1L00vIUTMF0SIPY"
		]])
	);

	assert!(!sdk.is_second_factor_pending(ACCESS_TOKEN).await.unwrap());
}
