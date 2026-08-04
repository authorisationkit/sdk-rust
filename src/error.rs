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

    /// The request was rejected before it was sent — a path parameter that
    /// cannot be rendered into a URL, or a hook that refused it.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// JWT verification failed. See [`JwtError`] for the specific failure.
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

/// Flattens a generated client error into [`Error`].
///
/// The generated methods return `progenitor_client::Error<ServerErrorValue>`,
/// which distinguishes eight cases that callers of this SDK do not need to tell
/// apart — what they want to know is whether the API refused them, whether the
/// network failed, or whether the response did not match the schema.
///
/// The API's own `{ "error": { "code", "reason" } }` body is where the message
/// comes from; the `code` inside it is ignored in favour of the HTTP status,
/// which is the one the caller can act on.
impl<E: serde::Serialize> From<progenitor_client::Error<E>> for Error {
    fn from(err: progenitor_client::Error<E>) -> Self {
        use progenitor_client::Error as P;

        match err {
            P::InvalidRequest(message) | P::Custom(message) => Error::InvalidRequest(message),

            P::CommunicationError(source)
            | P::InvalidUpgrade(source)
            | P::ResponseBodyError(source) => Error::Transport(source),

            P::InvalidResponsePayload(_, source) => Error::Decode { source },

            P::ErrorResponse(response) => {
                let request_id = response
                    .headers()
                    .get(crate::hooks::REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let status = response.status();
                let body = serde_json::to_string(response.as_ref()).ok();
                let message = body
                    .as_deref()
                    .and_then(parse_api_error_message)
                    .unwrap_or_else(|| fallback_message(status));

                Error::Api {
                    status,
                    request_id,
                    message,
                    body,
                }
            }

            // Not described by the spec, so there is no typed body to read and
            // no request id worth trusting — report the status and move on.
            P::UnexpectedResponse(response) => Error::Api {
                status: response.status(),
                request_id: response
                    .headers()
                    .get(crate::hooks::REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                message: format!(
                    "undocumented response: {}",
                    fallback_message(response.status())
                ),
                body: None,
            },
        }
    }
}

fn fallback_message(status: StatusCode) -> String {
    status
        .canonical_reason()
        .unwrap_or("unknown error")
        .to_owned()
}

/// Best-effort extraction of a human-readable message from an API error body.
///
/// Recognises AuthKit's `{ "error": { "reason" } }` shape, the flatter
/// `{ "message" }`, and the OAuth `{ "error_description" }` form used by the
/// token endpoint — which is a different shape from the rest of the API
/// because RFC 6749 specifies it.
fn parse_api_error_message(body: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Nested {
        reason: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Body {
        #[serde(default)]
        error: Option<serde_json::Value>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        error_description: Option<String>,
    }

    let parsed: Body = serde_json::from_str(body).ok()?;

    let nested = parsed.error.as_ref().and_then(|value| {
        serde_json::from_value::<Nested>(value.clone())
            .ok()
            .and_then(|n| n.reason)
    });
    let flat = parsed
        .error
        .as_ref()
        .and_then(|value| value.as_str().map(str::to_owned));

    [nested, parsed.message, parsed.error_description, flat]
        .into_iter()
        .flatten()
        // A blank reason is not a message. Returning it would put an empty
        // string where the caller expects something to show a user, so fall
        // through to the status's canonical reason instead.
        .find(|candidate| !candidate.trim().is_empty())
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
