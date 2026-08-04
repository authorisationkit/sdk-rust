# authorisationkit

Rust SDK for the [Authorisationkit](https://api.authkit.tech) API.

Two halves, drawn along the line of what an API description can express:

- **A generated HTTP client**, built from AuthKit's OpenAPI document at compile
  time. Every request method and every request and response type comes from
  `openapi.json`, so the SDK cannot fall behind the API or invent an endpoint it
  does not have. All nineteen documented operations are covered, including the
  OAuth 2.1 authorization server.
- **A hand-written JWT verifier**, because none of what it does is describable in
  OpenAPI: bootstrapping from an Authorization Server well-known URL, fetching
  and caching JWKS, single-flighting concurrent refreshes, applying clock-skew
  leeway, and reporting failures as typed errors.

Request behaviour that is likewise not in the document — the API key on every
request, an idempotency key on every write, retries on transient failures,
request-id capture on errors — is hand-written too, in `src/hooks.rs`, and
attaches to the generated client through progenitor's `ClientHooks`.

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
    let client = Client::with_api_key(std::env::var("AUTHKIT_KEY")?)?;

    let registration = client
        .get_registration_code("https://my-app.example.com/auth/callback")
        .await?
        .into_inner();

    println!("redirect user to: {}", registration.redirect);
    Ok(())
}
```

Generated methods return a `ResponseValue<T>`, which carries the status and
headers alongside the body; `.into_inner()` takes the body. Method names are the
operation ids from the OpenAPI document, so they match the other AuthKit SDKs —
`get_registration_code` here is `getRegistrationCode` in the JavaScript one.

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
- Coalesces concurrent verifications during a refresh so a cold cache produces a
  single in-flight HTTP request, not a thundering herd.
- Applies a 60-second clock-skew leeway by default (configurable via
  `leeway_secs`).

Access tokens are verified offline, so this needs no `Client` and no API key.

## Retries and idempotency

By default the client retries up to 3 times on 5xx, 429, and transient transport
errors, with backoff doubling from 1 second to a 30-second ceiling and
`Retry-After` honoured when the server sends one. A 4xx other than 429 is not
retried — it is the answer, not a hiccup. Tune via `max_retries`,
`min_retry_backoff`, `max_retry_backoff`, or opt out with `disable_retries()`.

Writes carry a fresh `Idempotency-Key`, minted once per call and replayed by
every retry of it, so a retried write is recognisable to the server as the write
it already saw.

## Error handling

Generated methods return `progenitor_client::Error`, which converts into
`authorisationkit::Error` — so `?` does the right thing in any function
returning the latter. API failures arrive as
`Error::Api { status, request_id, message, body }`; quote the `request_id` when
reporting issues.

```rust,no_run
use authorisationkit::{Client, Error};

async fn fetch(client: &Client, id: uuid::Uuid) -> Result<(), Error> {
    match client.get_consumer(&id).await {
        Ok(consumer) => println!("{:?}", consumer.into_inner()),
        Err(err) => match Error::from(err) {
            Error::Api { status, request_id, message, .. } => {
                eprintln!("authkit returned {status} ({request_id:?}): {message}");
            }
            other => return Err(other),
        },
    }
    Ok(())
}
```

Two edges are worth knowing, both consequences of generation:

- A response status the document does not list arrives as `Error::Api` with the
  status but no parsed message — progenitor hands back the raw response, and
  reading its body needs an `await` a `From` conversion cannot make.
- A body that does not match the documented error schema arrives as
  `Error::Decode`, because the status is discarded before the conversion sees
  it. A proxy's HTML error page lands here.

JWT verification failures use `authorisationkit::JwtError` with specific variants
(`Expired`, `InvalidSignature`, `UnknownKid`, …) so callers can react
programmatically.

## Regenerating the client

The OpenAPI document is vendored at `openapi.json` and read by `build.rs`. To
pick up API changes:

```sh
./scripts/update-spec.py                                      # production
./scripts/update-spec.py http://localhost:8099/openapi.json   # a local server
```

The script downloads the document, checks it before letting it replace the
working copy, reports which operations appeared or vanished, then regenerates
and runs the tests. The checks matter more than they look: this file is the sole
source of the crate's entire public API, so a truncated download or a server
that has not been redeployed would quietly rewrite every method signature. In
particular it refuses a document whose operation ids look derived from the
server's Rust module paths, which is what an un-deployed backend serves.

Nothing else is needed — `build.rs` declares `rerun-if-changed` on the spec, so
an ordinary `cargo build` regenerates the client whenever the document changes.

Generated code goes to `OUT_DIR` rather than into the repository, so it cannot
drift from the document beside it. Formatting uses `prettyplease`, so no nightly
toolchain is needed.

## License

Licensed under either of MIT or Apache-2.0 at your option.
