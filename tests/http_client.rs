//! Integration tests for the HTTP client, exercised against `wiremock`.
//!
//! These tests cover the SDK-specific surface that the unit tests can't:
//! status-code handling, error-body parsing, request-id propagation,
//! header injection (api_key, user-agent, idempotency-key), and the
//! retry middleware.

use std::time::Duration;

use authorisationkit::{Client, ConsumerId, Error, SessionId};
use serde_json::json;
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_KEY: &str = "test-api-key";

/// Build a client pointed at the mock server. Retries are disabled by
/// default so individual tests stay fast and focused; the retry-specific
/// test re-enables them with a tiny backoff.
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

#[tokio::test]
async fn register_returns_typed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/provide/register"))
        .and(query_param("redirect_url", "https://app.example.com/cb"))
        .and(header("api_key", TEST_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": "abc123",
            "redirect": "https://api.authkit.tech/abc123",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let resp = client
        .register("https://app.example.com/cb")
        .await
        .expect("register");
    assert_eq!(resp.code, "abc123");
    assert_eq!(resp.redirect, "https://api.authkit.tech/abc123");
}

#[tokio::test]
async fn get_consumer_decodes_naive_datetime() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let consumer = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect("get_consumer");
    assert_eq!(consumer.email, "test@example.com");
    assert!(consumer.confirmed);
}

#[tokio::test]
async fn api_error_with_message_body_is_parsed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "consumer not found"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect_err("expected error");
    match err {
        Error::Api {
            status, message, ..
        } => {
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert_eq!(message, "consumer not found");
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn api_error_with_oauth_body_is_parsed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_token",
            "error_description": "the token is expired"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect_err("expected error");
    match err {
        Error::Api {
            status, message, ..
        } => {
            assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
            assert_eq!(message, "the token is expired");
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn api_error_falls_back_to_canonical_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("not json"))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect_err("expected error");
    match err {
        Error::Api {
            status,
            message,
            body,
            ..
        } => {
            assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(message, "Internal Server Error");
            assert_eq!(body.as_deref(), Some("not json"));
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
            ResponseTemplate::new(404)
                .insert_header("x-request-id", "req-abc-123")
                .set_body_json(json!({"message": "not found"})),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect_err("expected error");
    match err {
        Error::Api { request_id, .. } => {
            assert_eq!(request_id.as_deref(), Some("req-abc-123"));
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
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

    let client = test_client(&server);
    let _ = client.get_consumer(uuid::Uuid::nil()).await.expect("ok");
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
    let _ = client.get_consumer(uuid::Uuid::nil()).await.expect("ok");
}

#[tokio::test]
async fn logout_uses_post_with_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/consumers/logout"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let _ = client
        .logout_consumer(uuid::Uuid::nil())
        .await
        .expect("logout");
}

#[tokio::test]
async fn resend_confirmation_uses_post_with_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/consumers/resend-confirmation"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sent": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let resp = client
        .resend_confirmation(uuid::Uuid::nil())
        .await
        .expect("resend");
    assert!(resp.sent);
}

#[tokio::test]
async fn get_requests_do_not_send_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let _ = client.get_consumer(uuid::Uuid::nil()).await.expect("ok");

    // Inspect the recorded request and assert no Idempotency-Key header.
    let received = server.received_requests().await.expect("requests");
    let req = received.first().expect("at least one request");
    assert!(
        req.headers.get("idempotency-key").is_none(),
        "GET requests must not include Idempotency-Key"
    );
}

#[tokio::test]
async fn retry_on_5xx_then_succeed() {
    let server = MockServer::start().await;

    // First two attempts fail with 503; third attempt succeeds.
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
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect("succeeds after retries");
    assert_eq!(consumer.email, "test@example.com");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 3, "expected initial + 2 retries");
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

    let client = test_client(&server); // disables retries
    let err = client
        .get_consumer(uuid::Uuid::nil())
        .await
        .expect_err("expected error");
    matches!(err, Error::Api { .. });
}

#[tokio::test]
async fn invalid_api_key_returns_config_error() {
    let err = Client::new("bad\nkey").expect_err("expected error");
    match err {
        Error::Config(msg) => assert!(msg.contains("api_key")),
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

#[tokio::test]
async fn debug_redacts_api_key() {
    let client = Client::new("super-secret-do-not-leak").expect("client");
    let dbg = format!("{client:?}");
    assert!(!dbg.contains("super-secret-do-not-leak"));
    assert!(dbg.contains("***"));
}

#[tokio::test]
async fn register_accepts_parsed_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/provide/register"))
        .and(query_param(
            "redirect_url",
            "https://app.example.com/cb?token=abc",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": "abc",
            "redirect": "https://api.authkit.tech/abc",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let url = url::Url::parse("https://app.example.com/cb?token=abc").expect("valid url");
    // `Url` (owned) flows through `impl IntoUrl`. `&Url` is not supported
    // by `reqwest::IntoUrl` upstream — clone or pass by value.
    client.register(url).await.expect("register");
}

#[tokio::test]
async fn register_rejects_malformed_url_locally() {
    // No mock — the SDK must reject before any HTTP attempt.
    let server = MockServer::start().await;
    let client = test_client(&server);

    let err = client
        .register("not a url")
        .await
        .expect_err("expected error");
    // reqwest::IntoUrl parse failures arrive as Error::Transport in our
    // mapping. We don't try to introspect the inner reqwest::Error
    // further — just confirm we never made a network call.
    matches!(err, Error::Transport(_));
    let received = server.received_requests().await.expect("requests");
    assert!(
        received.is_empty(),
        "SDK should not contact the server for a malformed redirect URL"
    );
}

#[tokio::test]
async fn get_consumer_accepts_consumer_id_newtype() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/consumer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let id: ConsumerId = uuid::Uuid::nil().into();
    let consumer = client.get_consumer(id).await.expect("get_consumer");
    // Round-trip: the deserialized id is also a ConsumerId, not a raw Uuid.
    let _: ConsumerId = consumer.id;
}

#[tokio::test]
async fn logout_consumer_accepts_session_id_newtype() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/consumers/logout"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_consumer()))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let session: SessionId = uuid::Uuid::nil().into();
    client.logout_consumer(session).await.expect("logout");
}

#[tokio::test]
async fn list_consumer_grants_decodes_a_connected_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth/grants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "client_id": "11111111-1111-1111-1111-111111111111",
            "client_name": "Claude",
            "scopes": ["email_read", "email_change"],
            // Naive form, as the server emits it.
            "granted_at": "2026-07-01T09:00:00",
            "last_used_at": "2026-07-31T12:30:00"
        }])))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let grants = client
        .list_consumer_grants(uuid::Uuid::nil())
        .await
        .expect("list_consumer_grants");

    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].client_name, "Claude");
    assert_eq!(grants[0].scopes, vec!["email_read", "email_change"]);
    assert!(grants[0].granted_at < grants[0].last_used_at);
}

#[tokio::test]
async fn list_consumer_grants_handles_no_connected_clients() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth/grants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let client = test_client(&server);
    assert!(client
        .list_consumer_grants(uuid::Uuid::nil())
        .await
        .expect("list_consumer_grants")
        .is_empty());
}

#[tokio::test]
async fn disconnect_consumer_grant_accepts_an_empty_body() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/oauth/grants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let client = test_client(&server);
    client
        .disconnect_consumer_grant(uuid::Uuid::nil(), uuid::Uuid::nil())
        .await
        .expect("disconnect_consumer_grant");
}

#[tokio::test]
async fn disconnect_consumer_grant_surfaces_an_unknown_grant() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/oauth/grants"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "No grant for this consumer and client"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    assert!(client
        .disconnect_consumer_grant(uuid::Uuid::nil(), uuid::Uuid::nil())
        .await
        .is_err());
}
