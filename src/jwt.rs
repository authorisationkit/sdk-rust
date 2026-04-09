//! Verifies JWTs issued by Authorisationkit.
//!
//! [`JwtVerifier`] bootstraps from an OAuth Authorization Server well-known
//! URL:
//!
//! 1. Fetch `/.well-known/oauth-authorization-server/<org_id>` to obtain the
//!    `issuer` and `jwks_uri` claims.
//! 2. Fetch the JWKS document from `jwks_uri` to learn about signing keys.
//! 3. Verify the JWT's signature, expiry (with configurable clock leeway),
//!    and issuer.
//!
//! The verifier caches both documents with a configurable TTL (default 10
//! minutes), and refetches the JWKS eagerly on a cache miss for an unknown
//! `kid`. Concurrent verifications are coalesced through an internal mutex
//! so a cold cache produces a single in-flight HTTP request, not a thundering
//! herd.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;
use url::Url;

use crate::error::{Error, JwtError};
use crate::ids::OrgId;

/// Default lifetime for cached AS metadata and JWKS documents.
pub const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(600);

/// Default clock-skew leeway applied when checking `exp`/`nbf`.
pub const DEFAULT_LEEWAY_SECS: u64 = 60;

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Standard JWT claims issued by Authorisationkit.
///
/// You can use [`JwtVerifier::verify`] to deserialize into this type, or
/// [`JwtVerifier::verify_with_claims`] to use a custom claim type with
/// additional fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (`iss`).
    pub iss: String,
    /// Subject (`sub`).
    pub sub: String,
    /// Audience (`aud`), if present.
    #[serde(default)]
    pub aud: Option<String>,
    /// Authorisationkit organisation id. Always a UUID on the wire.
    pub org_id: OrgId,
    /// Space-delimited scope.
    pub scope: String,
    /// Expiry time, seconds since the Unix epoch.
    pub exp: i64,
    /// Issued-at time, seconds since the Unix epoch.
    pub iat: i64,
    /// Unique JWT id.
    pub jti: String,
}

#[derive(Debug, Deserialize)]
struct AsMetadata {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Clone)]
struct JwkKey {
    kid: String,
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

/// JWT verifier with cached JWKS.
///
/// Cheap to clone — internally an `Arc` around the cache state.
#[derive(Clone)]
pub struct JwtVerifier {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("well_known_url", &self.inner.well_known_url.as_str())
            .field("jwks_ttl", &self.inner.jwks_ttl)
            .field("leeway_secs", &self.inner.leeway_secs)
            .finish()
    }
}

struct Inner {
    well_known_url: Url,
    http: reqwest::Client,
    jwks_ttl: Duration,
    leeway_secs: u64,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    metadata: Option<CachedMetadata>,
    jwks: Option<CachedJwks>,
}

#[derive(Clone)]
struct CachedMetadata {
    issuer: String,
    jwks_uri: String,
    fetched_at: Instant,
}

struct CachedJwks {
    keys: Vec<JwkKey>,
    fetched_at: Instant,
}

impl JwtVerifier {
    /// Create a verifier with default settings.
    ///
    /// The argument is the full OAuth AS well-known URL, e.g.
    /// `https://api.authkit.tech/.well-known/oauth-authorization-server/<org_id>`.
    pub fn new(well_known_url: impl Into<String>) -> Result<Self, Error> {
        Self::builder().well_known_url(well_known_url).build()
    }

    /// Begin configuring a [`JwtVerifier`].
    pub fn builder() -> JwtVerifierBuilder {
        JwtVerifierBuilder::default()
    }

    /// Verify a JWT and return its standard [`Claims`].
    pub async fn verify(&self, token: &str) -> Result<Claims, JwtError> {
        self.verify_with_claims::<Claims>(token).await
    }

    /// Verify a JWT and deserialize the payload into a custom claim type.
    ///
    /// Useful when the token carries application-specific fields beyond the
    /// ones in [`Claims`].
    pub async fn verify_with_claims<C: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<C, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::InvalidHeader(e.to_string()))?;
        let kid = header.kid.clone().ok_or(JwtError::MissingKid)?;

        let (issuer, decoding_key, algorithm) = self.resolve(&kid).await?;

        let mut validation = Validation::new(algorithm);
        validation.validate_aud = false;
        validation.leeway = self.inner.leeway_secs;
        validation.set_issuer(&[&issuer]);

        let token_data =
            decode::<C>(token, &decoding_key, &validation).map_err(JwtError::from_jsonwebtoken)?;
        Ok(token_data.claims)
    }

    /// Look up the issuer and decoding key for the given `kid`, refreshing
    /// the metadata and JWKS caches as needed. The lock is held across
    /// network IO so concurrent callers see a single in-flight refresh
    /// rather than a thundering herd.
    async fn resolve(&self, kid: &str) -> Result<(String, DecodingKey, Algorithm), JwtError> {
        let mut state = self.inner.state.lock().await;

        let metadata = match state.metadata.as_ref() {
            Some(m) if m.fetched_at.elapsed() < self.inner.jwks_ttl => m.clone(),
            _ => {
                let fetched =
                    fetch_metadata(&self.inner.http, self.inner.well_known_url.as_str()).await?;
                let cached = CachedMetadata {
                    issuer: fetched.issuer,
                    jwks_uri: fetched.jwks_uri,
                    fetched_at: Instant::now(),
                };
                state.metadata = Some(cached.clone());
                cached
            }
        };

        let needs_jwks_fetch = match state.jwks.as_ref() {
            None => true,
            Some(cached) => {
                cached.fetched_at.elapsed() >= self.inner.jwks_ttl
                    || !cached.keys.iter().any(|k| k.kid == kid)
            }
        };

        if needs_jwks_fetch {
            let keys = fetch_jwks(&self.inner.http, &metadata.jwks_uri).await?;
            state.jwks = Some(CachedJwks {
                keys,
                fetched_at: Instant::now(),
            });
        }

        let jwks = state
            .jwks
            .as_ref()
            .expect("jwks populated above this point");
        let key = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| JwtError::UnknownKid(kid.to_owned()))?;

        let (decoding_key, algorithm) = decoding_key_from_jwk(key)?;
        Ok((metadata.issuer, decoding_key, algorithm))
    }
}

/// Builder for [`JwtVerifier`].
#[derive(Debug, Default)]
#[must_use = "JwtVerifierBuilder must be finalized with `.build()`"]
pub struct JwtVerifierBuilder {
    well_known_url: Option<String>,
    http_client: Option<reqwest::Client>,
    jwks_ttl: Option<Duration>,
    leeway_secs: Option<u64>,
}

impl JwtVerifierBuilder {
    /// Set the OAuth AS well-known URL. Required.
    pub fn well_known_url(mut self, url: impl Into<String>) -> Self {
        self.well_known_url = Some(url.into());
        self
    }

    /// Inject a pre-configured `reqwest::Client`. Useful for tests, custom
    /// TLS, or telemetry.
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http_client = Some(http);
        self
    }

    /// Override the JWKS / metadata cache TTL. Defaults to
    /// [`DEFAULT_JWKS_TTL`] (10 minutes). A shorter TTL responds faster to
    /// key rotation; a longer TTL reduces JWKS endpoint load.
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_ttl = Some(ttl);
        self
    }

    /// Override the clock-skew leeway applied when validating `exp`/`nbf`.
    /// Defaults to [`DEFAULT_LEEWAY_SECS`] (60 seconds).
    pub fn leeway_secs(mut self, leeway: u64) -> Self {
        self.leeway_secs = Some(leeway);
        self
    }

    /// Finalize the builder.
    ///
    /// # Errors
    ///
    /// - [`Error::Jwt`] wrapping [`JwtError::Config`] if `well_known_url`
    ///   was not provided.
    /// - [`Error::Url`] if the well-known URL is not a valid URL.
    /// - [`Error::Transport`] if constructing the default `reqwest::Client`
    ///   fails.
    pub fn build(self) -> Result<JwtVerifier, Error> {
        let well_known_url = self
            .well_known_url
            .ok_or_else(|| Error::Jwt(JwtError::Config("well_known_url is required".to_owned())))?;
        let well_known_url = Url::parse(&well_known_url)?;

        let http = if let Some(http) = self.http_client {
            http
        } else {
            reqwest::Client::builder()
                .timeout(DEFAULT_HTTP_TIMEOUT)
                .build()?
        };

        Ok(JwtVerifier {
            inner: Arc::new(Inner {
                well_known_url,
                http,
                jwks_ttl: self.jwks_ttl.unwrap_or(DEFAULT_JWKS_TTL),
                leeway_secs: self.leeway_secs.unwrap_or(DEFAULT_LEEWAY_SECS),
                state: Mutex::new(State::default()),
            }),
        })
    }
}

async fn fetch_metadata(http: &reqwest::Client, url: &str) -> Result<AsMetadata, JwtError> {
    tracing::debug!(url, "fetching authkit AS metadata");
    let response = http.get(url).send().await.map_err(JwtError::Metadata)?;
    let response = response.error_for_status().map_err(JwtError::Metadata)?;
    response.json().await.map_err(JwtError::Metadata)
}

async fn fetch_jwks(http: &reqwest::Client, url: &str) -> Result<Vec<JwkKey>, JwtError> {
    tracing::debug!(url, "fetching authkit JWKS");
    let response = http.get(url).send().await.map_err(JwtError::Jwks)?;
    let response = response.error_for_status().map_err(JwtError::Jwks)?;
    let parsed: JwksResponse = response.json().await.map_err(JwtError::Jwks)?;
    Ok(parsed.keys)
}

fn decoding_key_from_jwk(key: &JwkKey) -> Result<(DecodingKey, Algorithm), JwtError> {
    match key.kty.as_str() {
        "EC" => {
            let crv = key.crv.as_deref().ok_or_else(|| JwtError::UnsupportedKey {
                kty: key.kty.clone(),
                crv: "<missing>".to_owned(),
            })?;
            let x = key
                .x
                .as_deref()
                .ok_or_else(|| JwtError::Validation("EC JWK missing 'x'".to_owned()))?;
            let y = key
                .y
                .as_deref()
                .ok_or_else(|| JwtError::Validation("EC JWK missing 'y'".to_owned()))?;
            let algorithm = match crv {
                "P-256" => Algorithm::ES256,
                "P-384" => Algorithm::ES384,
                _ => {
                    return Err(JwtError::UnsupportedKey {
                        kty: key.kty.clone(),
                        crv: crv.to_owned(),
                    });
                }
            };
            // If the JWK advertises a specific alg, sanity-check it.
            if let Some(advertised) = key.alg.as_deref() {
                let expected = match algorithm {
                    Algorithm::ES256 => "ES256",
                    Algorithm::ES384 => "ES384",
                    _ => "",
                };
                if !expected.is_empty() && advertised != expected {
                    return Err(JwtError::Validation(format!(
                        "JWK alg '{advertised}' does not match curve '{crv}'"
                    )));
                }
            }
            let decoding = DecodingKey::from_ec_components(x, y).map_err(|e| {
                JwtError::Validation(format!("failed to construct EC decoding key: {e}"))
            })?;
            Ok((decoding, algorithm))
        }
        _ => Err(JwtError::UnsupportedKey {
            kty: key.kty.clone(),
            crv: key.crv.clone().unwrap_or_default(),
        }),
    }
}
