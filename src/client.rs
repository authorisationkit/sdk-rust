//! Typed HTTP client for the Authorisationkit consumer API.
//!
//! Construction goes through [`ClientBuilder`] (or the convenience
//! [`Client::new`]). The client is cheap to clone — it wraps an
//! `Arc<reqwest_middleware::ClientWithMiddleware>` internally — so prefer
//! storing one instance and cloning it rather than rebuilding per request.

use std::time::Duration;

use reqwest::header::{HeaderValue, USER_AGENT};
use reqwest::{IntoUrl, Method, Url};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::Error;
use crate::ids::{ConsumerId, SessionId};
use crate::models::{ConsumerModel, RegisterResponse, ResendConfirmationResponse};

const DEFAULT_BASE_URL: &str = "https://api.authkit.tech";
const DEFAULT_USER_AGENT: &str = concat!("authorisationkit-rust/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_MIN_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const DEFAULT_MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);
const API_KEY_HEADER: &str = "api_key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// HTTP client for the Authorisationkit consumer API.
///
/// Construct via [`Client::new`] for the common case, or
/// [`Client::builder`] when you need to customize the timeout, user agent,
/// base URL, retry policy, or inject a pre-configured `reqwest::Client`
/// (useful for tests, proxies, or custom middleware like tracing).
///
/// `Client` is `Clone` and cheap to clone. The underlying HTTP client
/// already pools connections internally.
///
/// # Retries
///
/// By default the client retries idempotent requests up to 3 times on 5xx,
/// 429, and transient transport errors using exponential backoff with
/// jitter. The `Retry-After` header is honored. Use
/// [`ClientBuilder::disable_retries`] to opt out, or
/// [`ClientBuilder::max_retries`] / [`ClientBuilder::min_retry_backoff`] to
/// tune.
///
/// # Idempotency
///
/// `POST` requests automatically include a fresh `Idempotency-Key` UUID so
/// that retries (whether by the SDK's middleware or by network-level
/// retries upstream) cannot cause the server to perform the same write
/// twice.
#[derive(Clone)]
pub struct Client {
    api_key_header: HeaderValue,
    base_url: Url,
    http: ClientWithMiddleware,
    user_agent: HeaderValue,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"***")
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Client {
    /// Create a client with default settings (production base URL, 30s
    /// timeout, default user agent, retries enabled).
    ///
    /// Returns [`Error::Config`] if the API key contains characters that
    /// are not valid in an HTTP header value.
    pub fn new(api_key: impl Into<String>) -> Result<Self, Error> {
        Self::builder().api_key(api_key).build()
    }

    /// Begin configuring a [`Client`] with non-default options.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Send a request and decode the JSON response, surfacing API errors as
    /// [`Error::Api`] rather than confusing JSON-decode failures.
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        let url = self.base_url.join(path)?;

        tracing::debug!(method = %method, url = %url, "authkit request");

        let mut builder = self
            .http
            .request(method.clone(), url)
            .header(API_KEY_HEADER, self.api_key_header.clone())
            .header(USER_AGENT, self.user_agent.clone())
            .query(query);

        // Auto-generate an Idempotency-Key for write methods so the
        // retry middleware (and any upstream retries) cannot double-apply
        // a side effect.
        if matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            builder = builder.header(IDEMPOTENCY_KEY_HEADER, uuid::Uuid::new_v4().to_string());
        }

        let response = builder.send().await?;

        let status = response.status();
        let request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if !status.is_success() {
            let body = response.text().await.ok();
            let message = body
                .as_deref()
                .and_then(parse_api_error_message)
                .unwrap_or_else(|| {
                    status
                        .canonical_reason()
                        .unwrap_or("unknown error")
                        .to_owned()
                });
            tracing::warn!(
                %status,
                request_id = ?request_id,
                "authkit API error"
            );
            return Err(Error::Api {
                status,
                request_id,
                message,
                body,
            });
        }

        let text = response.text().await?;
        serde_json::from_str::<T>(&text).map_err(|source| Error::Decode { source })
    }

    /// Begin a registration flow. The returned [`RegisterResponse`] contains
    /// the URL to redirect the end user to.
    ///
    /// `redirect_url` is validated as a URL at the call boundary; passing
    /// a malformed string returns [`Error::Transport`] before any HTTP
    /// request is made. Accepts anything that implements
    /// [`reqwest::IntoUrl`] — `&str`, `&String`, `String`, or `Url`.
    pub async fn register(&self, redirect_url: impl IntoUrl) -> Result<RegisterResponse, Error> {
        let url = redirect_url.into_url().map_err(Error::Transport)?;
        self.request(
            Method::GET,
            "provide/register",
            &[("redirect_url", url.as_str())],
        )
        .await
    }

    /// Begin a login flow. The returned [`RegisterResponse`] contains the
    /// URL to redirect the end user to.
    ///
    /// `redirect_url` is validated as a URL at the call boundary; passing
    /// a malformed string returns [`Error::Transport`] before any HTTP
    /// request is made. Accepts anything that implements
    /// [`reqwest::IntoUrl`] — `&str`, `&String`, `String`, or `Url`.
    pub async fn login_with_redirect(
        &self,
        redirect_url: impl IntoUrl,
    ) -> Result<RegisterResponse, Error> {
        let url = redirect_url.into_url().map_err(Error::Transport)?;
        self.request(
            Method::GET,
            "provide/login",
            &[("redirect_url", url.as_str())],
        )
        .await
    }

    /// Look up a consumer by their stable id.
    ///
    /// Accepts a [`ConsumerId`] or anything that converts into one (notably
    /// a raw [`uuid::Uuid`]).
    pub async fn get_consumer(&self, id: impl Into<ConsumerId>) -> Result<ConsumerModel, Error> {
        let id = id.into().to_string();
        self.request(Method::GET, "consumer", &[("id", id.as_str())])
            .await
    }

    /// Look up a consumer by an active session id.
    ///
    /// Accepts a [`SessionId`] or anything that converts into one (notably
    /// a raw [`uuid::Uuid`]).
    pub async fn get_consumer_by_session(
        &self,
        session_id: impl Into<SessionId>,
    ) -> Result<ConsumerModel, Error> {
        let sid = session_id.into().to_string();
        self.request(
            Method::GET,
            "consumer/session",
            &[("session_id", sid.as_str())],
        )
        .await
    }

    /// Log a consumer out by terminating their session.
    ///
    /// Accepts a [`SessionId`] or anything that converts into one (notably
    /// a raw [`uuid::Uuid`]).
    pub async fn logout_consumer(
        &self,
        session_id: impl Into<SessionId>,
    ) -> Result<ConsumerModel, Error> {
        let sid = session_id.into().to_string();
        self.request(
            Method::POST,
            "consumers/logout",
            &[("session_id", sid.as_str())],
        )
        .await
    }

    /// Resend the email confirmation for a pending consumer.
    ///
    /// Accepts a [`ConsumerId`] or anything that converts into one
    /// (notably a raw [`uuid::Uuid`]).
    pub async fn resend_confirmation(
        &self,
        consumer_id: impl Into<ConsumerId>,
    ) -> Result<ResendConfirmationResponse, Error> {
        let cid = consumer_id.into().to_string();
        self.request(
            Method::POST,
            "consumers/resend-confirmation",
            &[("consumer_id", cid.as_str())],
        )
        .await
    }
}

/// Builder for [`Client`].
///
/// ```no_run
/// use std::time::Duration;
/// use authorisationkit::Client;
///
/// # fn main() -> Result<(), authorisationkit::Error> {
/// let client = Client::builder()
///     .api_key("my-api-key")
///     .timeout(Duration::from_secs(10))
///     .user_agent("myapp/1.2.3")
///     .max_retries(5)
///     .build()?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
#[must_use = "ClientBuilder must be finalized with `.build()`"]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    user_agent: Option<String>,
    http_client: Option<reqwest::Client>,
    disable_retries: bool,
    max_retries: Option<u32>,
    min_retry_backoff: Option<Duration>,
    max_retry_backoff: Option<Duration>,
}

impl ClientBuilder {
    /// Set the API key sent in the `api_key` header.
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Override the base URL. Defaults to `https://api.authkit.tech`.
    ///
    /// A trailing slash is appended automatically if missing so the URL
    /// joins correctly with API paths.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the request timeout. Defaults to 30 seconds. Ignored if
    /// [`Self::http_client`] is also set — configure the timeout on the
    /// supplied client instead.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Override the `User-Agent` header. Defaults to
    /// `authorisationkit-rust/<crate-version>`.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Inject a pre-configured `reqwest::Client`. Useful for tests
    /// (`wiremock`), proxies, custom TLS settings, or telemetry.
    ///
    /// The supplied client is wrapped in the SDK's middleware stack
    /// (including retries, unless [`Self::disable_retries`] is set).
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http_client = Some(http);
        self
    }

    /// Disable automatic retries on transient failures (5xx, 429, transport
    /// errors).
    pub fn disable_retries(mut self) -> Self {
        self.disable_retries = true;
        self
    }

    /// Override the maximum number of retry attempts (default: 3). The
    /// initial request does not count as a retry, so `max_retries(3)`
    /// means up to 4 total attempts. Ignored if
    /// [`Self::disable_retries`] is set.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    /// Override the minimum delay between retry attempts (default: 1
    /// second). Backoff grows exponentially from this value with random
    /// jitter. Ignored if [`Self::disable_retries`] is set.
    pub fn min_retry_backoff(mut self, backoff: Duration) -> Self {
        self.min_retry_backoff = Some(backoff);
        self
    }

    /// Override the maximum delay between retry attempts (default: 30
    /// seconds). Ignored if [`Self::disable_retries`] is set.
    pub fn max_retry_backoff(mut self, backoff: Duration) -> Self {
        self.max_retry_backoff = Some(backoff);
        self
    }

    /// Finalize the builder.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the API key is missing or contains invalid
    ///   header characters, or if the user agent contains invalid header
    ///   characters.
    /// - [`Error::Url`] if the base URL is not a valid URL.
    /// - [`Error::Transport`] if constructing the default `reqwest::Client`
    ///   fails (e.g., TLS backend initialization).
    pub fn build(self) -> Result<Client, Error> {
        let api_key = self
            .api_key
            .ok_or_else(|| Error::Config("api_key is required".to_owned()))?;
        let api_key_header = HeaderValue::from_str(&api_key).map_err(|_| {
            Error::Config(
                "api_key contains characters that are not valid in an HTTP header".to_owned(),
            )
        })?;

        let base_url_input = self
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_BASE_URL)
            .to_owned();
        let base_url_input = if base_url_input.ends_with('/') {
            base_url_input
        } else {
            format!("{base_url_input}/")
        };
        let base_url = Url::parse(&base_url_input)?;

        let user_agent_str = self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
        let user_agent = HeaderValue::from_str(user_agent_str).map_err(|_| {
            Error::Config(
                "user_agent contains characters that are not valid in an HTTP header".to_owned(),
            )
        })?;

        let reqwest_client = if let Some(http) = self.http_client {
            http
        } else {
            reqwest::Client::builder()
                .timeout(self.timeout.unwrap_or(DEFAULT_TIMEOUT))
                .build()?
        };

        let mut middleware_builder = reqwest_middleware::ClientBuilder::new(reqwest_client);
        if !self.disable_retries {
            let policy = ExponentialBackoff::builder()
                .retry_bounds(
                    self.min_retry_backoff.unwrap_or(DEFAULT_MIN_RETRY_BACKOFF),
                    self.max_retry_backoff.unwrap_or(DEFAULT_MAX_RETRY_BACKOFF),
                )
                .build_with_max_retries(self.max_retries.unwrap_or(DEFAULT_MAX_RETRIES));
            middleware_builder =
                middleware_builder.with(RetryTransientMiddleware::new_with_policy(policy));
        }
        let http = middleware_builder.build();

        Ok(Client {
            api_key_header,
            base_url,
            http,
            user_agent,
        })
    }
}

/// Best-effort extraction of a human-readable error message from an API
/// response body. Recognizes both generic `{ "message": ... }` shapes and
/// OAuth-style `{ "error": ..., "error_description": ... }` shapes.
fn parse_api_error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Body {
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        error_description: Option<String>,
    }
    let parsed: Body = serde_json::from_str(body).ok()?;
    parsed.message.or(parsed.error_description).or(parsed.error)
}
