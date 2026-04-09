//! Error types returned by the Authorisationkit SDK.

use reqwest::StatusCode;

/// Top-level error type for all SDK operations.
///
/// This enum is `#[non_exhaustive]`, so adding new variants is not a breaking
/// change. Always include a `_ => ...` arm when matching exhaustively.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// HTTP transport-level failure: connection refused, timeout, TLS, DNS,
    /// etc. The wrapped [`reqwest::Error`] retains the original cause.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The Authorisationkit API responded with a non-success HTTP status.
    ///
    /// The `request_id` field is populated from the `X-Request-Id` response
    /// header when present and should be quoted to support when reporting
    /// issues. The `body` is the raw response body (truncated by the server,
    /// not the SDK).
    #[error("authkit API error {status}: {message}")]
    Api {
        /// HTTP status code returned by the API.
        status: StatusCode,
        /// Value of the `X-Request-Id` response header, if any.
        request_id: Option<String>,
        /// Human-readable error message extracted from the response body, or
        /// the canonical reason phrase as a fallback.
        message: String,
        /// The raw response body, if it was readable.
        body: Option<String>,
    },

    /// The response body could not be deserialized into the expected type.
    ///
    /// This generally indicates an SDK/server schema mismatch and is worth
    /// reporting as a bug.
    #[error("failed to decode response body: {source}")]
    Decode {
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// A URL provided to the SDK (base URL, well-known URL, etc.) could not
    /// be parsed.
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    /// Invalid SDK configuration — for example, an API key with characters
    /// that are not valid in an HTTP header value.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// A retry/middleware layer wrapped around the HTTP client failed
    /// before the request reached the server. The boxed inner error is
    /// the original `reqwest_middleware` error; we hide its concrete type
    /// so callers don't need to depend on `reqwest_middleware` directly.
    #[error("middleware error: {0}")]
    Middleware(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// JWT verification failed. See [`JwtError`] for the specific failure.
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

impl From<reqwest_middleware::Error> for Error {
    fn from(err: reqwest_middleware::Error) -> Self {
        // Best-effort: unwrap the inner reqwest::Error so callers can match
        // on `Error::Transport`. Anything else (custom middleware error,
        // future variants) bubbles up as `Error::Middleware`.
        match err {
            reqwest_middleware::Error::Reqwest(inner) => Error::Transport(inner),
            other => Error::Middleware(Box::new(other)),
        }
    }
}

/// Errors produced by [`crate::JwtVerifier`].
///
/// These are kept separate from [`Error`] so callers verifying tokens can
/// match on the specific failure mode (expired vs. invalid signature vs.
/// network failure) without unwrapping a generic string.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// The token's `exp` claim is in the past (after applying clock leeway).
    #[error("JWT is expired")]
    Expired,

    /// The token's signature did not match any known signing key.
    #[error("JWT signature is invalid")]
    InvalidSignature,

    /// The JWT header is malformed (not valid base64, not valid JSON, etc.).
    #[error("JWT header is malformed: {0}")]
    InvalidHeader(String),

    /// The JWT header does not contain a `kid` field, so we cannot pick a
    /// signing key from the JWKS.
    #[error("JWT is missing 'kid' in header")]
    MissingKid,

    /// No signing key with the requested `kid` exists in the JWKS, even
    /// after a forced refresh.
    #[error("no signing key found for kid '{0}'")]
    UnknownKid(String),

    /// The signing key advertised in the JWKS is not a key type/curve this
    /// SDK supports.
    #[error("unsupported JWK: kty={kty}, crv={crv}")]
    UnsupportedKey {
        /// JWK `kty` field (e.g., `EC`, `RSA`).
        kty: String,
        /// JWK `crv` field (e.g., `P-256`).
        crv: String,
    },

    /// The OAuth Authorization Server metadata document could not be
    /// fetched.
    #[error("failed to fetch OAuth AS metadata: {0}")]
    Metadata(#[source] reqwest::Error),

    /// The JWKS document could not be fetched.
    #[error("failed to fetch JWKS: {0}")]
    Jwks(#[source] reqwest::Error),

    /// JWT validation failed for some other reason (issuer mismatch,
    /// `nbf` not yet reached, etc.). The string contains the underlying
    /// `jsonwebtoken` error.
    #[error("JWT validation failed: {0}")]
    Validation(String),

    /// The verifier was misconfigured.
    #[error("invalid JWT verifier configuration: {0}")]
    Config(String),
}

impl JwtError {
    pub(crate) fn from_jsonwebtoken(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidSignature => JwtError::InvalidSignature,
            _ => JwtError::Validation(err.to_string()),
        }
    }
}
