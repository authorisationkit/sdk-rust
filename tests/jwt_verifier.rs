//! Integration tests for [`authorisationkit::JwtVerifier`].
//!
//! These tests use `wiremock` to stub the OAuth Authorization Server
//! metadata + JWKS endpoints. They verify the SDK-specific surface that
//! matters: cache freshness, single-flight under concurrency, force-
//! refetch on unknown `kid`, and the typed error mapping for upstream
//! HTTP failures.
//!
//! End-to-end signed-token verification is intentionally out of scope:
//! the actual ECDSA verification is implemented by `jsonwebtoken` and
//! tested upstream. We construct fake tokens with valid headers (real
//! `kid`, real RFC 7515 P-256 JWK coordinates) but garbage signatures so
//! `verify()` consistently progresses through the fetch + cache code
//! before failing at signature verification — exactly the call site we
//! want to exercise.

use std::sync::Arc;

use authorisationkit::{JwtError, JwtVerifier};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ISSUER: &str = "https://issuer.example.com";
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server/test-org";
const JWKS_PATH: &str = "/.well-known/jwks.json";

// RFC 7515 Appendix A.3 P-256 test vector public coordinates. These are
// real points on the curve so `DecodingKey::from_ec_components` accepts
// them; signature verification still fails because our test tokens are
// not actually signed by the matching private key.
const RFC7515_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn jwks_with(kids: &[&str]) -> serde_json::Value {
    let keys: Vec<_> = kids
        .iter()
        .map(|kid| {
            json!({
                "kty": "EC",
                "crv": "P-256",
                "kid": kid,
                "x": RFC7515_X,
                "y": RFC7515_Y,
                "alg": "ES256",
                "use": "sig",
            })
        })
        .collect();
    json!({ "keys": keys })
}

fn metadata_body(jwks_url: &str) -> serde_json::Value {
    json!({
        "issuer": TEST_ISSUER,
        "jwks_uri": jwks_url,
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"],
    })
}

/// Build a fake JWT with a valid header (`kid` set) and bogus signature.
/// `verify()` will progress all the way through metadata + JWKS fetch and
/// key construction, then fail at signature verification — which is what
/// the cache-behavior tests want to exercise.
fn fake_jwt(kid: &str) -> String {
    let header = json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
    let payload = json!({
        "iss": TEST_ISSUER,
        "sub": "user-1",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "scope": "",
        "exp": 9_999_999_999_i64,
        "iat": 0,
        "jti": "jti-1",
    });
    let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let s = BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]); // 64 zero bytes
    format!("{h}.{p}.{s}")
}

fn metadata_url(server: &MockServer) -> String {
    format!("{}{METADATA_PATH}", server.uri())
}

fn jwks_url(server: &MockServer) -> String {
    format!("{}{JWKS_PATH}", server.uri())
}

#[tokio::test]
async fn cold_cache_fetches_metadata_and_jwks_once_each() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body(&jwks_url(&server))))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with(&["k1"])))
        .expect(1)
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");
    // Signature will fail because the token isn't actually signed; we only
    // care that the fetch + cache code ran.
    let _ = verifier.verify(&fake_jwt("k1")).await;
    // Mock expectations verified on drop.
}

#[tokio::test]
async fn warm_cache_does_not_refetch() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body(&jwks_url(&server))))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with(&["k1"])))
        .expect(1)
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");
    let token = fake_jwt("k1");
    for _ in 0..5 {
        let _ = verifier.verify(&token).await;
    }
}

#[tokio::test]
async fn concurrent_verifies_single_flight_jwks() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(metadata_body(&jwks_url(&server)))
                // Small delay so concurrent callers actually pile up.
                .set_delay(std::time::Duration::from_millis(20)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_with(&["k1"]))
                .set_delay(std::time::Duration::from_millis(20)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let verifier = Arc::new(JwtVerifier::new(metadata_url(&server)).expect("verifier"));

    let mut joins = Vec::new();
    for _ in 0..100 {
        let v = Arc::clone(&verifier);
        joins.push(tokio::spawn(async move {
            let _ = v.verify(&fake_jwt("k1")).await;
        }));
    }
    for j in joins {
        j.await.expect("join");
    }
}

#[tokio::test]
async fn unknown_kid_forces_jwks_refetch() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body(&jwks_url(&server))))
        .expect(1)
        .mount(&server)
        .await;

    // First JWKS fetch only knows about k1.
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with(&["k1"])))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Second JWKS fetch knows about k1 and k2 (key rotation).
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with(&["k1", "k2"])))
        .expect(1)
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");

    // First call: cold cache, fetches metadata + JWKS, finds k1.
    let _ = verifier.verify(&fake_jwt("k1")).await;
    // Second call: warm cache for k1 — but we ask for k2, which isn't in
    // the cached JWKS, so the verifier must force-refetch.
    let _ = verifier.verify(&fake_jwt("k2")).await;
}

#[tokio::test]
async fn metadata_5xx_surfaces_as_metadata_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");
    let err = verifier
        .verify(&fake_jwt("k1"))
        .await
        .expect_err("expected error");

    match err {
        JwtError::Metadata(_) => {}
        other => panic!("expected JwtError::Metadata, got {other:?}"),
    }
}

#[tokio::test]
async fn jwks_5xx_surfaces_as_jwks_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body(&jwks_url(&server))))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");
    let err = verifier
        .verify(&fake_jwt("k1"))
        .await
        .expect_err("expected error");

    match err {
        JwtError::Jwks(_) => {}
        other => panic!("expected JwtError::Jwks, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_kid_after_refetch_returns_unknown_kid_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(METADATA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body(&jwks_url(&server))))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with(&["k1"])))
        .mount(&server)
        .await;

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");
    let err = verifier
        .verify(&fake_jwt("does-not-exist"))
        .await
        .expect_err("expected error");

    match err {
        JwtError::UnknownKid(kid) => assert_eq!(kid, "does-not-exist"),
        other => panic!("expected JwtError::UnknownKid, got {other:?}"),
    }
}

#[tokio::test]
async fn token_without_kid_returns_missing_kid_error() {
    let server = MockServer::start().await; // not actually used; verify fails before fetch

    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");

    // Build a token whose header has no kid.
    let header = json!({ "alg": "ES256", "typ": "JWT" });
    let payload = json!({
        "sub": "x",
        "iss": TEST_ISSUER,
        "exp": 9_999_999_999_i64,
        "iat": 0,
        "org_id": "22222222-2222-2222-2222-222222222222",
        "scope": "",
        "jti": "j",
    });
    let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let s = BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]);
    let token = format!("{h}.{p}.{s}");

    let err = verifier.verify(&token).await.expect_err("expected error");
    match err {
        JwtError::MissingKid => {}
        other => panic!("expected JwtError::MissingKid, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_token_returns_invalid_header_error() {
    let server = MockServer::start().await;
    let verifier = JwtVerifier::new(metadata_url(&server)).expect("verifier");

    let err = verifier
        .verify("not.a.jwt")
        .await
        .expect_err("expected error");
    match err {
        JwtError::InvalidHeader(_) => {}
        other => panic!("expected JwtError::InvalidHeader, got {other:?}"),
    }
}
