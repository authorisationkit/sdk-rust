#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod hooks;
pub mod ids;
pub mod jwt;

pub use error::{Error, JwtError};
pub use hooks::{Config, RetryPolicy};
pub use ids::OrgId;
pub use jwt::{Claims, JwtVerifier, JwtVerifierBuilder};

use std::time::Duration;

use reqwest::header::HeaderValue;

/// The client generated from AuthKit's OpenAPI document, at build time by
/// `build.rs`.
///
/// Every request method, and every request and response type, comes from
/// `openapi.json`, so the SDK and the API cannot disagree about what exists.
/// What the document cannot express is attached separately in [`crate::hooks`]:
/// the API key on every request, an idempotency key on every write, retries on
/// transient failures, and request-id capture on errors.
mod generated {
    #![allow(clippy::all)]
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

pub use generated::{Client, types};

const DEFAULT_BASE_URL: &str = "https://api.authkit.tech";
const DEFAULT_USER_AGENT: &str = concat!("authorisationkit-rust/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_MIN_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const DEFAULT_MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

impl Client {
    /// Create a client with default settings: production base URL, 30s
    /// timeout, retries enabled.
    ///
    /// Returns [`Error::Config`] if the API key contains characters that are
    /// not valid in an HTTP header value.
    ///
    /// Note this is `with_api_key` rather than `new`: the generated client
    /// already has a `new(baseurl)`, and that one skips the credential and
    /// retry setup [`ClientBuilder::build`] performs.
    pub fn with_api_key(api_key: impl Into<String>) -> Result<Self, Error> {
        ClientBuilder::default().api_key(api_key).build()
    }

    /// Begin configuring a client with non-default options.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
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
    /// A trailing slash is stripped: the generated client builds URLs by
    /// formatting `{baseurl}/consumer`, so leaving one on would double it.
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

    /// Override the maximum number of retry attempts (default: 3). The initial
    /// request does not count as a retry, so `max_retries(3)` means up to 4
    /// total attempts. Ignored if [`Self::disable_retries`] is set.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    /// Override the minimum delay between retry attempts (default: 1 second).
    /// Backoff doubles from this value, clamped to
    /// [`Self::max_retry_backoff`]. Ignored if [`Self::disable_retries`] is set.
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
    /// - [`Error::Config`] if the API key is missing or contains invalid header
    ///   characters, or if the user agent does.
    /// - [`Error::Transport`] if constructing the default `reqwest::Client`
    ///   fails (e.g. TLS backend initialization).
    pub fn build(self) -> Result<Client, Error> {
        let api_key = self
            .api_key
            .ok_or_else(|| Error::Config("api_key is required".to_owned()))?;
        let api_key = HeaderValue::from_str(&api_key).map_err(|_| {
            Error::Config(
                "api_key contains characters that are not valid in an HTTP header".to_owned(),
            )
        })?;

        let user_agent = self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
        let user_agent = HeaderValue::from_str(user_agent).map_err(|_| {
            Error::Config(
                "user_agent contains characters that are not valid in an HTTP header".to_owned(),
            )
        })?;

        let base_url = self.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
        let base_url = base_url.trim_end_matches('/');

        let http = match self.http_client {
            Some(http) => http,
            None => reqwest::Client::builder()
                .timeout(self.timeout.unwrap_or(DEFAULT_TIMEOUT))
                .build()?,
        };

        let retry = (!self.disable_retries).then(|| RetryPolicy {
            max_retries: self.max_retries.unwrap_or(DEFAULT_MAX_RETRIES),
            min_backoff: self.min_retry_backoff.unwrap_or(DEFAULT_MIN_RETRY_BACKOFF),
            max_backoff: self.max_retry_backoff.unwrap_or(DEFAULT_MAX_RETRY_BACKOFF),
        });

        Ok(Client::new_with_client(
            base_url,
            http,
            Config {
                api_key,
                user_agent,
                retry,
            },
        ))
    }
}
