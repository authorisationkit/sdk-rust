//! Request behaviour the OpenAPI document cannot express.
//!
//! Everything about *which* requests exist is generated. This module supplies
//! what a description of an API says nothing about: that the API key rides on
//! every request, that writes carry an idempotency key, that transient failures
//! are worth retrying, and that the server's request id belongs in the error a
//! caller sees.
//!
//! It attaches through progenitor's [`ClientHooks`], which the generated client
//! calls at three points — [`pre`](ClientHooks::pre) to amend the request,
//! [`exec`](ClientHooks::exec) to send it, and [`post`](ClientHooks::post) to
//! observe the result. Implementing them for `Client` rather than `&Client`
//! overrides the defaults, via the auto-ref specialization the trait documents.

use std::time::Duration;

use progenitor_client::{ClientHooks, ClientInfo, Error as ProgenitorError, OperationInfo};
use reqwest::header::{HeaderValue, USER_AGENT};

use crate::Client;

pub(crate) const API_KEY_HEADER: &str = "api_key";
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Per-client settings the hooks need, carried on the generated client as its
/// `inner` value.
///
/// This is what makes the generated methods usable as the public API: the
/// alternative is a wrapper struct holding the config, which would mean
/// re-declaring all nineteen methods by hand to forward through it — exactly
/// the hand-written transport this crate no longer has.
#[derive(Clone)]
pub struct Config {
    pub(crate) api_key: HeaderValue,
    pub(crate) user_agent: HeaderValue,
    pub(crate) retry: Option<RetryPolicy>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_key", &"***")
            .field("user_agent", &self.user_agent)
            .field("retry", &self.retry)
            .finish()
    }
}

/// Exponential backoff bounds for retrying transient failures.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub(crate) max_retries: u32,
    pub(crate) min_backoff: Duration,
    pub(crate) max_backoff: Duration,
}

impl RetryPolicy {
    /// Delay before attempt `attempt` (1-based), doubling from `min_backoff`
    /// and clamped to `max_backoff`.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.min_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

impl ClientHooks<Config> for Client {
    /// Add the credentials and headers every request carries.
    ///
    /// The idempotency key is per-attempt-set, not per-attempt: it is minted
    /// once here and the same value is replayed by every retry in
    /// [`Self::exec`], which is the entire point — a retried write must be
    /// recognisable to the server as the write it already saw.
    async fn pre<E>(
        &self,
        request: &mut reqwest::Request,
        _info: &OperationInfo,
    ) -> Result<(), ProgenitorError<E>> {
        let config = self.inner();
        let is_write = !matches!(
            *request.method(),
            reqwest::Method::GET | reqwest::Method::HEAD
        );

        let headers = request.headers_mut();
        headers.insert(API_KEY_HEADER, config.api_key.clone());
        headers.insert(USER_AGENT, config.user_agent.clone());

        if is_write && let Ok(key) = HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()) {
            headers.insert(IDEMPOTENCY_KEY_HEADER, key);
        }

        Ok(())
    }

    /// Send the request, retrying transient failures.
    ///
    /// Retrying belongs here rather than in `reqwest-middleware`, which the
    /// hand-written client used: progenitor's client holds a plain
    /// `reqwest::Client` and has nowhere to put a middleware stack. `exec` is
    /// the seam it offers instead.
    ///
    /// Only 5xx, 429 and transport errors are retried, and only requests whose
    /// body can be replayed — a streaming body cannot be sent twice, so those
    /// go out once. `Retry-After` is honoured when the server sends a plain
    /// number of seconds.
    async fn exec(
        &self,
        request: reqwest::Request,
        info: &OperationInfo,
    ) -> reqwest::Result<reqwest::Response> {
        let Some(policy) = self.inner().retry.clone() else {
            return self.client().execute(request).await;
        };

        let mut attempt = 0u32;
        loop {
            // A request can only be retried if it can be cloned; a streaming
            // body cannot, and silently sending it once is better than failing.
            let retryable = request.try_clone();
            let this_attempt = match retryable {
                Some(cloned) if attempt < policy.max_retries => cloned,
                _ => return self.client().execute(request).await,
            };

            let result = self.client().execute(this_attempt).await;
            attempt += 1;

            let delay = match &result {
                Ok(response) if is_transient(response.status()) => {
                    retry_after(response).unwrap_or_else(|| policy.backoff(attempt))
                }
                Err(error) if error.is_timeout() || error.is_connect() => policy.backoff(attempt),
                _ => return result,
            };

            tracing::debug!(
                operation_id = info.operation_id,
                attempt,
                delay_ms = delay.as_millis() as u64,
                "authkit retrying transient failure"
            );
            tokio::time::sleep(delay).await;
        }
    }

    /// Record the server's request id for the failing case.
    ///
    /// It is logged rather than returned because the hook cannot alter the
    /// response; [`crate::Error`] picks the header off the response itself when
    /// it converts a failure.
    async fn post<E>(
        &self,
        result: &reqwest::Result<reqwest::Response>,
        info: &OperationInfo,
    ) -> Result<(), ProgenitorError<E>> {
        if let Ok(response) = result
            && !response.status().is_success()
        {
            tracing::warn!(
                operation_id = info.operation_id,
                status = %response.status(),
                request_id = ?response
                    .headers()
                    .get(REQUEST_ID_HEADER)
                    .and_then(|v| v.to_str().ok()),
                "authkit API error"
            );
        }
        Ok(())
    }
}

/// Whether a status is worth a second attempt.
///
/// 429 and 5xx only. A 4xx other than 429 means the request itself is wrong,
/// and repeating it just spends the caller's latency budget to get the same
/// answer.
fn is_transient(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// `Retry-After` in delta-seconds form. The HTTP-date form is not parsed —
/// falling back to the computed backoff is safe, where mis-parsing a date is
/// not.
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_retries: 5,
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
        }
    }

    #[test]
    fn backoff_doubles_from_the_minimum() {
        let policy = policy();
        assert_eq!(policy.backoff(1), Duration::from_secs(1));
        assert_eq!(policy.backoff(2), Duration::from_secs(2));
        assert_eq!(policy.backoff(3), Duration::from_secs(4));
    }

    #[test]
    fn backoff_is_clamped_to_the_maximum() {
        assert_eq!(policy().backoff(20), Duration::from_secs(10));
    }

    /// `2^attempt` overflows a `u32` well before attempt 100, and a panicking
    /// multiply in a retry loop would turn a transient server error into a
    /// crash in the caller's process.
    #[test]
    fn backoff_does_not_overflow_on_absurd_attempt_counts() {
        assert_eq!(policy().backoff(u32::MAX), Duration::from_secs(10));
    }

    #[test]
    fn only_429_and_5xx_are_transient() {
        assert!(is_transient(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_transient(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_transient(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!is_transient(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_transient(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_transient(reqwest::StatusCode::OK));
    }
}
