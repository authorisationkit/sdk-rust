//! Integration tests for the generated HTTP client, exercised against `wiremock`.
//!
//! The request methods are generated, so these tests are not about whether a
//! URL is spelled right — the OpenAPI document decides that. They cover the
//! part that is hand-written and could silently do nothing: the
//! [`progenitor_client::ClientHooks`] implementation in `src/hooks.rs`.
//!
//! That risk is real rather than theoretical. Progenitor selects between the
//! default hooks (implemented for `&Client`) and ours (implemented for
//! `Client`) by auto-ref specialization, and if ours ever stopped being
//! selected the client would still compile and still work — it would just
//! stop sending the API key, stop marking writes idempotent, and stop
//! retrying. Every assertion here exists to make that failure loud.

use std::time::Duration;

use authorisationkit::{Client, Error};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_KEY: &str = "test-api-key";

/// Build a client pointed at the mock server. Retries are disabled by default
/// so individual tests stay fast and focused; the retry-specific tests
/// re-enable them with a tiny backoff.
fn test_client(server: &MockServer) -> Client {
    Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .disable_retries()
        .build()
        .expect("client build")
}

fn sample_consumer() -> serde_json::Value {
    json!({
        "id": "00000000-0000-0000-0000-000000000000",
        "registration_type": "Plain",
        "email": "test@example.com",
        "created_at": "2024-01-02T03:04:05",
        "confirmed": true,
    })
}

// ---------------------------------------------------------------------------
// The generated transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generated_method_hits_the_documented_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/provide/register"))
        .and(query_param("redirect_url", "https://app.example.com/cb"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": "11111111-2222-3333-4444-555555555555",
            "redirect": "https://api.authkit.tech/abc123",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = test_client(&server)
        .get_registration_code("https://app.example.com/cb")
        .await
        .expect("get_registration_code")
        .into_inner();

    // `code` is a generated newtype over `Uuid`, not a string — the document
    // says so, so the SDK does too.
    assert_eq!(
        response.code.to_string(),
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(response.redirect, "https://api.authkit.tech/abc123");
}

#[tokio::test]
async fn generated_response_types_decode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .mount(&server)
        .await;

    let consumer = test_client(&server)
        .get_consumer(&Uuid::nil())
        .await
        .expect("get_consumer")
        .into_inner();

    assert_eq!(consumer.email, "test@example.com");
    assert!(consumer.confirmed);
}

/// The OAuth endpoints had no Rust coverage at all before generation. This is
/// the cheapest proof they arrived with everything else.
#[tokio::test]
async fn oauth_endpoints_are_present() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "x": "eA", "y": "eB",
                "kid": "k1", "use": "sig", "alg": "ES256",
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let jwks = test_client(&server)
        .get_jwks()
        .await
        .expect("get_jwks")
        .into_inner();

    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid, "k1");
}

// ---------------------------------------------------------------------------
// The `pre` hook: credentials and headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_key_is_sent_on_every_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .and(header("api_key", TEST_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    test_client(&server)
        .get_consumer(&Uuid::nil())
        .await
        .expect("api_key must reach the server");
}

#[tokio::test]
async fn default_user_agent_is_sent() {
    let server = MockServer::start().await;
    let expected = concat!("authorisationkit-rust/", env!("CARGO_PKG_VERSION"));
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .and(header("user-agent", expected))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    test_client(&server)
        .get_consumer(&Uuid::nil())
        .await
        .expect("ok");
}

#[tokio::test]
async fn custom_user_agent_overrides_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .and(header("user-agent", "myapp/9.9.9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .user_agent("myapp/9.9.9")
        .disable_retries()
        .build()
        .expect("client build");

    client.get_consumer(&Uuid::nil()).await.expect("ok");
}

#[tokio::test]
async fn writes_carry_an_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/consumers/logout"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    test_client(&server)
        .logout_consumer(&Uuid::nil())
        .await
        .expect("logout");
}

#[tokio::test]
async fn deletes_carry_an_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/oauth/grants"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    test_client(&server)
        .disconnect_consumer_grant(&Uuid::nil(), &Uuid::nil())
        .await
        .expect("disconnect");
}

#[tokio::test]
async fn reads_do_not_carry_an_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .mount(&server)
        .await;

    test_client(&server)
        .get_consumer(&Uuid::nil())
        .await
        .expect("ok");

    let received = server.received_requests().await.expect("requests");
    let request = received.first().expect("at least one request");
    assert!(
        request.headers.get("idempotency-key").is_none(),
        "GET requests must not include Idempotency-Key"
    );
}

/// A retried write must look to the server like the write it already saw, so
/// the key is minted once per call and replayed — not regenerated per attempt,
/// which would defeat the point of sending one.
#[tokio::test]
async fn retries_replay_the_same_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/consumers/logout"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/consumers/logout"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .max_retries(3)
        .min_retry_backoff(Duration::from_millis(1))
        .max_retry_backoff(Duration::from_millis(5))
        .build()
        .expect("client build");

    client
        .logout_consumer(&Uuid::nil())
        .await
        .expect("succeeds after retries");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 3, "expected initial + 2 retries");

    let keys: Vec<_> = received
        .iter()
        .map(|r| {
            r.headers
                .get("idempotency-key")
                .expect("every attempt carries one")
                .to_str()
                .expect("valid header")
                .to_owned()
        })
        .collect();
    assert_eq!(
        keys.iter().collect::<std::collections::HashSet<_>>().len(),
        1,
        "all attempts must reuse one key, got {keys:?}"
    );
}

// ---------------------------------------------------------------------------
// The `exec` hook: retries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retries_5xx_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .max_retries(3)
        .min_retry_backoff(Duration::from_millis(1))
        .max_retry_backoff(Duration::from_millis(5))
        .build()
        .expect("client build");

    let consumer = client
        .get_consumer(&Uuid::nil())
        .await
        .expect("succeeds after retries")
        .into_inner();
    assert_eq!(consumer.email, "test@example.com");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 3, "expected initial + 2 retries");
}

#[tokio::test]
async fn does_not_retry_4xx() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "nope"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .max_retries(3)
        .min_retry_backoff(Duration::from_millis(1))
        .build()
        .expect("client build");

    client
        .get_consumer(&Uuid::nil())
        .await
        .expect_err("404 is the answer, not a hiccup");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 1, "a 404 must not be retried");
}

#[tokio::test]
async fn disable_retries_does_not_retry_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    test_client(&server)
        .get_consumer(&Uuid::nil())
        .await
        .expect_err("expected error");
}

#[tokio::test]
async fn retries_are_bounded_by_max_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(server.uri())
        .max_retries(2)
        .min_retry_backoff(Duration::from_millis(1))
        .max_retry_backoff(Duration::from_millis(2))
        .build()
        .expect("client build");

    client
        .get_consumer(&Uuid::nil())
        .await
        .expect_err("always 503");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 3, "expected initial + 2 retries, then stop");
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// The generated methods return `progenitor_client::Error`; `?` in a function
/// returning [`Error`] converts it. This is the shape callers actually write.
async fn fetch_consumer(client: &Client) -> Result<String, Error> {
    Ok(client.get_consumer(&Uuid::nil()).await?.into_inner().email)
}

#[tokio::test]
async fn api_error_carries_status_and_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": { "code": 400, "reason": "consumer not found" }
        })))
        .mount(&server)
        .await;

    let err = fetch_consumer(&test_client(&server))
        .await
        .expect_err("expected error");

    match err {
        Error::Api {
            status, message, ..
        } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(message, "consumer not found");
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

/// An empty `reason` is not a message — the caller would render a blank string
/// to a user. The status's canonical reason is at least true.
#[tokio::test]
async fn api_error_falls_back_to_canonical_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": { "code": 500, "reason": "" }
        })))
        .mount(&server)
        .await;

    let err = fetch_consumer(&test_client(&server))
        .await
        .expect_err("expected error");

    match err {
        Error::Api {
            status, message, ..
        } => {
            assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(message, "Internal Server Error");
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

/// A body that does not match the documented error schema surfaces as
/// [`Error::Decode`], not [`Error::Api`].
///
/// Progenitor discards the status code when a documented response fails to
/// deserialize, so there is nothing to build an `Api` error from. It is worth
/// knowing this is where a misbehaving proxy's HTML error page lands.
#[tokio::test]
async fn malformed_error_body_surfaces_as_decode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("<html>gateway</html>"))
        .mount(&server)
        .await;

    let err = fetch_consumer(&test_client(&server))
        .await
        .expect_err("expected error");

    assert!(
        matches!(err, Error::Decode { .. }),
        "expected Error::Decode, got {err:?}"
    );
}

/// A status the document does not list still produces a usable error, but a
/// thinner one.
///
/// Progenitor hands back the raw `reqwest::Response` for anything undocumented,
/// and reading its body needs an `await` that a `From` conversion cannot make —
/// so the status survives and the message does not. Worth knowing before
/// matching on `message`: `/consumer` documents 200, 400 and 500, so a 404 from
/// a proxy in front of the API lands here rather than in the branch above.
#[tokio::test]
async fn undocumented_status_still_reports_its_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": 404, "reason": "consumer not found" }
        })))
        .mount(&server)
        .await;

    let err = fetch_consumer(&test_client(&server))
        .await
        .expect_err("expected error");

    match err {
        Error::Api {
            status, message, ..
        } => {
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(
                message.contains("undocumented"),
                "expected the message to say so, got {message:?}"
            );
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn request_id_propagated_into_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("x-request-id", "req-abc-123")
                .set_body_json(json!({"error": {"code": 400, "reason": "not found"}})),
        )
        .mount(&server)
        .await;

    let err = fetch_consumer(&test_client(&server))
        .await
        .expect_err("expected error");

    match err {
        Error::Api { request_id, .. } => {
            assert_eq!(request_id.as_deref(), Some("req-abc-123"));
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn invalid_api_key_returns_config_error() {
    let err = Client::with_api_key("bad\nkey").expect_err("expected error");
    match err {
        Error::Config(msg) => assert!(msg.contains("api_key")),
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

#[test]
fn missing_api_key_returns_config_error() {
    let err = Client::builder().build().expect_err("expected error");
    match err {
        Error::Config(msg) => assert!(msg.contains("api_key")),
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

#[test]
fn debug_redacts_api_key() {
    let client = Client::with_api_key("super-secret-do-not-leak").expect("client");
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains("super-secret-do-not-leak"),
        "api key leaked into Debug: {rendered}"
    );
    assert!(rendered.contains("***"));
}

/// The generated client formats `{baseurl}/consumer`, so a base URL keeping its
/// trailing slash would request `//consumer`.
#[tokio::test]
async fn trailing_slash_in_base_url_is_stripped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .api_key(TEST_KEY)
        .base_url(format!("{}/", server.uri()))
        .disable_retries()
        .build()
        .expect("client build");

    client.get_consumer(&Uuid::nil()).await.expect("ok");
}
