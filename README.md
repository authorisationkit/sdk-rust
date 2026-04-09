# authorisationkit

[![Crates.io](https://img.shields.io/crates/v/authorisationkit.svg)](https://crates.io/crates/authorisationkit)
[![Docs.rs](https://docs.rs/authorisationkit/badge.svg)](https://docs.rs/authorisationkit)

Rust SDK for the [Authorisationkit](https://api.authkit.tech) API.

Provides:

- A typed HTTP client for the Authorisationkit consumer API
  (register, login, fetch consumer, logout, resend confirmation), with
  default-on retries, idempotency-key generation on writes, request-id
  propagation in errors, and an injectable `reqwest::Client` for tests
  and middleware.
- A JWT verifier that bootstraps from an OAuth Authorization Server
  well-known URL, fetches and caches JWKS, single-flights concurrent
  refreshes, applies clock-skew leeway, and surfaces failures as typed
  errors.

## Installation

```toml
[dependencies]
authorisationkit = "0.1"
```

To use the platform-native TLS stack instead of `rustls`:

```toml
[dependencies]
authorisationkit = { version = "0.1", default-features = false, features = ["native-tls"] }
```

## Calling the API

```rust,no_run
use authorisationkit::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(std::env::var("AUTHKIT_KEY")?)?;

    let registration = client
        .register("https://my-app.example.com/auth/callback")
        .await?;

    println!("redirect user to: {}", registration.redirect);
    Ok(())
}
```

For non-default configuration (timeout, custom user agent, retry tuning,
injected `reqwest::Client`, alternate base URL):

```rust,no_run
use std::time::Duration;
use authorisationkit::Client;

fn build() -> Result<Client, authorisationkit::Error> {
    Client::builder()
        .api_key("my-api-key")
        .timeout(Duration::from_secs(10))
        .user_agent("myapp/1.2.3")
        .max_retries(5)
        .build()
}
```

## Verifying JWTs

```rust,no_run
use authorisationkit::JwtVerifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = JwtVerifier::new(
        "https://api.authkit.tech/.well-known/oauth-authorization-server/<org_id>",
    )?;

    let claims = verifier.verify("eyJhbGciOi...").await?;
    println!("verified subject: {}", claims.sub);
    Ok(())
}
```

The verifier:

- Caches AS metadata and JWKS for 10 minutes (configurable via
  `JwtVerifier::builder().jwks_ttl(...)`).
- Refetches JWKS eagerly on a cache miss for an unknown `kid`.
- Coalesces concurrent verifications during a refresh so a cold cache
  produces a single in-flight HTTP request, not a thundering herd.
- Applies a 60-second clock-skew leeway by default (configurable via
  `leeway_secs`).

## Retries and idempotency

By default the client retries idempotent requests up to 3 times on 5xx,
429, and transient transport errors using exponential backoff with jitter,
honoring `Retry-After`. Tune via `max_retries`, `min_retry_backoff`,
`max_retry_backoff`, or opt out entirely with `disable_retries()`.

`POST` requests automatically include a fresh `Idempotency-Key` UUID so
retries (whether by the SDK's middleware or by network-level retries
upstream) cannot cause the server to perform the same write twice.

## Error handling

All fallible operations return `authorisationkit::Error`. API failures
come through `Error::Api { status, request_id, message, body }` — quote
the `request_id` when reporting issues. JWT verification failures use
`authorisationkit::JwtError` with specific variants (`Expired`,
`InvalidSignature`, `UnknownKid`, …) so callers can react programmatically.

```rust,no_run
use authorisationkit::{Client, Error};

async fn fetch(client: &Client, id: uuid::Uuid) -> Result<(), Error> {
    match client.get_consumer(id).await {
        Ok(consumer) => println!("{consumer:?}"),
        Err(Error::Api { status, request_id, message, .. }) => {
            eprintln!("authkit returned {status} ({request_id:?}): {message}");
        }
        Err(other) => return Err(other),
    }
    Ok(())
}
```

## License

Licensed under either of MIT or Apache-2.0 at your option.
