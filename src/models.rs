//! Data models returned by the Authorisationkit API.

use serde::{Deserialize, Serialize};

use crate::ids::{ConsumerId, OAuthClientId};

/// Response returned by `/provide/register` and `/provide/login`.
///
/// `redirect` is the URL the SDK consumer should send the end user to in
/// order to begin the registration/login flow; `code` is the one-time code
/// the API has minted for that flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// One-time registration/login code minted by the API.
    pub code: String,
    /// URL to redirect the end user to.
    pub redirect: String,
}

/// How a consumer originally registered.
///
/// Marked `#[non_exhaustive]` so the API adding new registration types is
/// not a breaking change for SDK users.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UserRegistrationTypeValue {
    /// Registered via Google OAuth.
    Google,
    /// Registered via plain email/password flow.
    Plain,
}

/// An OAuth client a consumer has connected, and what they granted it.
///
/// One entry per client rather than per token: re-authorizing leaves several
/// live refresh tokens for the same client, which is an implementation detail
/// of rotation rather than something a consumer has any use for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthGrantModel {
    /// The client holding the grant.
    pub client_id: OAuthClientId,
    /// Display name the client gave at registration. Self-declared, so treat it
    /// as a label rather than as proof of which software is calling.
    pub client_name: String,
    /// Scopes the consumer granted.
    pub scopes: Vec<String>,
    /// When the consumer first authorized this client.
    #[serde(with = "naive_or_utc_datetime")]
    pub granted_at: chrono::DateTime<chrono::Utc>,
    /// When the grant was last exchanged for an access token.
    ///
    /// Clients refresh roughly once per access-token lifetime, so this trails
    /// real activity — it says "used within the last hour or so", not "used at
    /// this instant".
    #[serde(with = "naive_or_utc_datetime")]
    pub last_used_at: chrono::DateTime<chrono::Utc>,
}

/// A consumer (end user) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerModel {
    /// Stable identifier for the consumer.
    pub id: ConsumerId,
    /// Registration source.
    pub registration_type: UserRegistrationTypeValue,
    /// Email address.
    pub email: String,
    /// Server-side creation timestamp, normalized to UTC.
    ///
    /// The deserializer accepts both RFC 3339 strings (`...Z` /
    /// `...+00:00`) and naive ISO-8601 strings (no zone), assuming UTC for
    /// the latter — this matches the historical Authorisationkit wire
    /// format and is forward-compatible if the server starts emitting
    /// zoned timestamps.
    #[serde(with = "naive_or_utc_datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the consumer has confirmed their email.
    pub confirmed: bool,
}

/// Response returned by `/consumers/resend-confirmation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendConfirmationResponse {
    /// Whether a fresh confirmation email was dispatched.
    pub sent: bool,
}

/// Serde helper that deserializes either an RFC 3339 timestamp or a naive
/// ISO-8601 timestamp (assumed UTC) into a `DateTime<Utc>`. Serializes back
/// as RFC 3339 with a `Z` suffix.
mod naive_or_utc_datetime {
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // RFC 3339 with Z; e.g. 2024-01-02T03:04:05Z
        s.serialize_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;

        // Try the canonical RFC 3339 form first.
        if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
            return Ok(dt.with_timezone(&Utc));
        }

        // Fall back to the naive forms the Authorisationkit server has
        // historically emitted. Each is interpreted as UTC.
        const NAIVE_FORMATS: &[&str] = &[
            "%Y-%m-%dT%H:%M:%S%.f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S%.f",
            "%Y-%m-%d %H:%M:%S",
        ];
        for fmt in NAIVE_FORMATS {
            if let Ok(ndt) = NaiveDateTime::parse_from_str(&s, fmt) {
                return Ok(Utc.from_utc_datetime(&ndt));
            }
        }

        Err(serde::de::Error::custom(format!(
            "expected RFC 3339 or naive ISO-8601 datetime, got {s:?}"
        )))
    }
}
