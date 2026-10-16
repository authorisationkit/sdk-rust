# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — the HTTP client is now generated

The transport layer is no longer hand-written. `build.rs` runs
[progenitor](https://github.com/oxidecomputer/progenitor) over the vendored
`openapi.json` at compile time, so every request method and every request and
response type comes from the OpenAPI document. What stays hand-written is
everything the document cannot express — the JWT verifier, and the cross-cutting
request behaviour in the new `hooks` module.

The reason is coverage as much as duplication: the hand-written client had 8 of
the API's 19 documented operations, and none of the OAuth 2.1 authorization
server. It now has all 19.

- **Breaking:** method names are the OpenAPI operation ids, so they match the
  other AuthKit SDKs. `register` → `get_registration_code`,
  `login_with_redirect` → `get_login_code`; `get_consumer`,
  `get_consumer_by_session`, `logout_consumer`, `resend_confirmation`,
  `list_consumer_grants` keep their names. `disconnect_consumer_grant` keeps
  its name but now takes `(client_id, consumer_id)` in the document's order.
- **Breaking:** `Client::new(api_key)` is now `Client::with_api_key(api_key)`.
  The generated client has its own `new(baseurl)`, which skips credential and
  retry setup; the rename keeps the two from being confused.
- **Breaking:** methods return `ResponseValue<T>` rather than `T`. Call
  `.into_inner()` for the body; the wrapper also carries status and headers.
- **Breaking:** methods return `progenitor_client::Error<ServerErrorValue>`
  rather than `Error`. `Error` implements `From` for it, so `?` still works in
  any function returning `Error`; an explicit `Error::from` is needed elsewhere.
- **Breaking:** parameters are borrowed and untyped-by-newtype —
  `get_consumer(&uuid)` rather than `get_consumer(impl Into<ConsumerId>)`.
- **Breaking:** `ConsumerId`, `SessionId` and `OAuthClientId` are gone from the
  `ids` module; the equivalents are generated into `types`. `OrgId` stays,
  because it appears only in JWT claims, which the document does not describe.
- **Breaking:** `models` and `client` modules removed. Response types live in
  `types`; `Client` and `ClientBuilder` are re-exported at the crate root.
- **Breaking:** `Error::Middleware` removed, `Error::InvalidRequest` added.
- **Breaking:** `ConsumerModel::created_at` is a `String` again rather than
  `chrono::DateTime<Utc>` — the document types it as a plain string, and the
  generated model follows it. Adding a `format: date-time` to the server's
  schema would restore the typed form.
- **Breaking:** MSRV is now 1.88 (was 1.85), required by progenitor.
- Retries moved from `reqwest-middleware`/`reqwest-retry` to progenitor's `exec`
  hook, because the generated client holds a plain `reqwest::Client` with
  nowhere to put a middleware stack. Behaviour is preserved except that backoff
  no longer jitters. A 4xx other than 429 is explicitly not retried.
- The idempotency key is now minted once per call and replayed by every retry of
  it, rather than regenerated per attempt — which is what makes sending one
  useful.
- `reqwest` 0.12 → 0.13; `reqwest-middleware` and `reqwest-retry` dropped.
- `progenitor-client` is MPL-2.0 and is a runtime dependency, so binaries
  linking this SDK now redistribute MPL-2.0 code. See `deny.toml` for why that
  is accepted.

Two error-mapping edges are new, both consequences of generation: a status the
document does not list arrives as `Error::Api` without a parsed message, and a
body that does not match the documented error schema arrives as `Error::Decode`
rather than `Error::Api`. Both are covered by tests.

### Added

- Strongly-typed identifier newtypes [`ConsumerId`], [`SessionId`], and
  [`OrgId`] in a new `ids` module. Each wraps a `uuid::Uuid` with
  `From`/`Into`, `FromStr`, `Display`, custom `Debug`, and
  `#[serde(transparent)]` so the JSON wire format is unchanged. Client
  methods now take `impl Into<ConsumerId>` / `impl Into<SessionId>`, so
  passing raw `uuid::Uuid` continues to work without changes.
- `Client::register` and `Client::login_with_redirect` now accept
  `impl reqwest::IntoUrl` for `redirect_url`, validating the URL form at
  the call boundary. A malformed URL surfaces as `Error::Transport`
  before any HTTP request is made.
- Default-on retry middleware (`reqwest-middleware` + `reqwest-retry`):
  3 retries on 5xx, 429, and transient transport errors with exponential
  backoff and jitter, honoring `Retry-After`. Configurable via
  `ClientBuilder::max_retries`, `min_retry_backoff`, `max_retry_backoff`,
  and `disable_retries`.
- Automatic `Idempotency-Key` UUID on all `POST`/`PUT`/`PATCH`/`DELETE`
  requests so retries cannot double-apply server-side side effects.
- `ClientBuilder` and `JwtVerifierBuilder` now expose `http_client(...)`
  for injecting a pre-configured `reqwest::Client` (useful for tests with
  `wiremock`, custom TLS, proxies, or middleware).
- `JwtVerifier::verify_with_claims::<C>()` for verifying tokens that carry
  application-specific fields beyond the standard `Claims` struct.
- `Error::Api { status, request_id, message, body }` variant exposing the
  `X-Request-Id` response header so support tickets can quote it.
- `Error::Middleware` variant for surfaces from custom middleware.
- `JwtError` enum with specific variants (`Expired`, `InvalidSignature`,
  `UnknownKid`, `Metadata`, `Jwks`, …) replacing the previous
  `Result<_, String>`.
- Crate-level lints: `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`,
  `#![warn(rust_2018_idioms)]`.
- Integration test suite (`tests/http_client.rs`, `tests/jwt_verifier.rs`)
  built on `wiremock`.
- GitHub Actions CI: fmt, clippy `-D warnings`, test (default and
  `--all-features`), `cargo doc -D warnings`, MSRV (1.85) build, and
  `cargo-deny check` (licenses, advisories, bans, sources).
- `deny.toml` enforcing: permissive licenses only (no GPL/LGPL/AGPL),
  RUSTSEC vulnerabilities and yanked crates denied, wildcard versions
  denied, and crates.io as the only allowed source.
- README is now included as crate-level rustdoc via `include_str!` so its
  examples are compile-checked on every build.
- `[package.metadata.docs.rs]` so docs.rs renders both TLS feature paths.
- `examples/register.rs` and `examples/verify_jwt.rs`.
- `CHANGELOG.md`.

### Changed

- **Breaking:** `Client::new` and `JwtVerifier::new` now return
  `Result<Self, Error>` instead of `Self`. They validate the API key
  (header characters), the base URL, and the well-known URL up front.
- **Breaking:** `Client::with_base_url` removed — use
  `Client::builder().base_url(...).build()`.
- **Breaking:** All client methods return `Result<_, Error>` instead of
  `Result<_, AuthkitError>`. `models::AuthkitError` is gone — use the
  top-level `authorisationkit::Error`.
- **Breaking:** `JwtVerifier::verify` returns `Result<_, JwtError>`
  instead of `Result<_, String>`.
- **Breaking:** `consumers/logout` now uses `POST` instead of `GET`,
  matching the server contract — logout is a state mutation and should
  not be retried implicitly by intermediaries.
- **Breaking:** `ConsumerModel::created_at` is now
  `chrono::DateTime<chrono::Utc>` instead of `chrono::NaiveDateTime`.
  The deserializer accepts both RFC 3339 (`...Z`) and naive ISO-8601
  forms (assuming UTC) so the wire format change is backward-compatible.
- **Breaking (source-level only):** `ConsumerModel::id` is now
  `ConsumerId` instead of `uuid::Uuid`. The wire format is unchanged
  thanks to `#[serde(transparent)]`. Code that destructured the field
  needs to call `.into_uuid()` (or accept `ConsumerId`).
- **Breaking (source-level only):** `jwt::Claims::org_id` is now
  `OrgId` instead of `String`. The wire format is unchanged — server-
  issued `org_id` values are always UUIDs, which the previous `String`
  typing failed to encode. Code reading `claims.org_id` as a string
  should call `claims.org_id.to_string()` or `claims.org_id.into_uuid()`.
- HTTP responses now check the status code before attempting to decode
  the body. Non-success responses become `Error::Api` with a parsed
  message instead of a confusing JSON-decode failure.
- The error body is parsed for both generic `{ "message": ... }` shapes
  and OAuth-style `{ "error": ..., "error_description": ... }` shapes.
- JWT verifier caches AS metadata and JWKS with a 10-minute TTL by
  default (configurable). Cache misses for an unknown `kid` force an
  immediate JWKS refetch to handle key rotation between TTL boundaries.
- JWT verifier coalesces concurrent verifications during a refresh
  through a single `tokio::sync::Mutex` so a cold cache produces a
  single in-flight HTTP request, not a thundering herd.
- JWT verifier applies a 60-second clock-skew leeway by default
  (configurable via `JwtVerifierBuilder::leeway_secs`).
- JWT verifier picks the verification algorithm from the JWK's `crv`
  field (P-256 → ES256, P-384 → ES384) and sanity-checks against the
  JWK's advertised `alg`, instead of hard-coding ES256.
- `Client` and `JwtVerifier` have manually-implemented `Debug` that
  redacts the API key (`api_key: "***"`) instead of derived `Debug`
  that printed it verbatim.
- `Cargo.toml`: explicit `rustls-tls` (default) / `native-tls` features;
  `tokio` slimmed to `["sync"]`; `chrono` to `default-features = false`;
  `urlencoding` dropped; version pins loosened to majors.

### Fixed

- **OAuth errors decode again.** AuthKit's token and client-registration
  endpoints now answer refusals in the shape RFC 6749 §5.2 and RFC 7591 §3.2.2
  prescribe — `{ "error": "invalid_grant", "error_description": "…" }` — instead
  of the rest of the API's `{ "error": { "code", "reason" } }`. Against the
  previous `openapi.json`, every refusal from `exchange_token` and
  `register_oauth_client` failed to decode and arrived as `Error::Decode`, with
  the status and reason lost. With the refreshed document they arrive as
  `Error::Api` carrying the status and the `error_description`; the OAuth code
  (`invalid_grant`, `invalid_redirect_uri`, …) is in `body`.
- **Breaking (narrow):** those two methods now return
  `progenitor_client::Error<OAuthErrorBody>` rather than
  `progenitor_client::Error<ServerErrorValue>`. Code that converts with `?` or
  `Error::from` is unaffected.
- `openapi.json` refreshed from production, which also brings in
  `resume_consumer_session`.
- Removed `eprintln!` debug logging in `login_with_redirect` that printed
  full request bodies (including credentials) to stderr. Errors now
  bubble up as typed `Error` values; verbose tracing is available via
  the `tracing` crate at `debug` level.
- Removed `expect("Invalid API key format")` panic in the per-request
  header construction. Invalid API keys now return `Error::Config` from
  `Client::builder().build()` instead of panicking later.
- Removed the synthetic `Url::parse("parse-error://...").unwrap_err()`
  hack in `login_with_redirect`.
- Query strings are now built via `RequestBuilder::query` instead of
  `format!` + manual encoding, fixing inconsistent URL-encoding across
  endpoints.
- `Client::Debug` no longer leaks the API key.
