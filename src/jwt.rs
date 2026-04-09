use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// JWT claims matching what authkit signs.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Option<String>,
    pub org_id: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
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
    crv: String,
    x: String,
    y: String,
}

/// Verifies JWTs issued by authkit.
///
/// Bootstraps from an OAuth AS well-known URL:
/// 1. Fetches `/.well-known/oauth-authorization-server/<org_id>` to get `issuer` and `jwks_uri`
/// 2. Fetches JWKS from `jwks_uri` to get signing keys
/// 3. Validates JWT signature, expiry, and issuer
#[derive(Clone)]
pub struct JwtVerifier {
    well_known_url: String,
    http: reqwest::Client,
    state: Arc<RwLock<VerifierState>>,
}

#[derive(Default)]
struct VerifierState {
    issuer: Option<String>,
    jwks_url: Option<String>,
    keys: Vec<JwkKey>,
}

impl JwtVerifier {
    /// Create a verifier from an AS well-known URL.
    /// Example: `https://api.authkit.tech/.well-known/oauth-authorization-server/117f88dd-...`
    pub fn new(well_known_url: &str) -> Self {
        Self {
            well_known_url: well_known_url.to_string(),
            http: reqwest::Client::new(),
            state: Arc::new(RwLock::new(VerifierState::default())),
        }
    }

    /// Fetch AS metadata and extract issuer + jwks_uri.
    async fn fetch_metadata(&self) -> Result<(String, String), String> {
        let meta: AsMetadata = self
            .http
            .get(&self.well_known_url)
            .send()
            .await
            .map_err(|e| format!("AS metadata fetch failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("AS metadata parse failed: {}", e))?;

        let mut state = self.state.write().await;
        state.issuer = Some(meta.issuer.clone());
        state.jwks_url = Some(meta.jwks_uri.clone());

        Ok((meta.issuer, meta.jwks_uri))
    }

    /// Fetch JWKS and cache the keys.
    async fn fetch_jwks(&self, jwks_url: &str) -> Result<Vec<JwkKey>, String> {
        let resp: JwksResponse = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {}", e))?;

        let mut state = self.state.write().await;
        state.keys = resp.keys.clone();
        Ok(resp.keys)
    }

    /// Ensure metadata is loaded, returning (issuer, jwks_url).
    async fn ensure_metadata(&self) -> Result<(String, String), String> {
        {
            let state = self.state.read().await;
            if let (Some(issuer), Some(jwks_url)) = (&state.issuer, &state.jwks_url) {
                return Ok((issuer.clone(), jwks_url.clone()));
            }
        }
        self.fetch_metadata().await
    }

    /// Get a decoding key for the given kid, fetching JWKS if needed.
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, String> {
        let (_, jwks_url) = self.ensure_metadata().await?;

        // Try cache first
        {
            let state = self.state.read().await;
            if let Some(key) = state.keys.iter().find(|k| k.kid == kid) {
                return decoding_key_from_jwk(key);
            }
        }

        // Fetch fresh JWKS
        let keys = self.fetch_jwks(&jwks_url).await?;
        let key = keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| format!("No key found for kid '{}'", kid))?;

        decoding_key_from_jwk(key)
    }

    /// Verify a JWT and return its claims.
    /// Checks signature, expiry, and issuer (from AS metadata).
    pub async fn verify(&self, token: &str) -> Result<Claims, String> {
        let (issuer, _) = self.ensure_metadata().await?;

        let header =
            decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;

        let kid = header
            .kid
            .ok_or_else(|| "JWT missing kid in header".to_string())?;

        let decoding_key = self.get_decoding_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        validation.set_issuer(&[&issuer]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT verification failed: {}", e))?;

        Ok(token_data.claims)
    }
}

fn decoding_key_from_jwk(key: &JwkKey) -> Result<DecodingKey, String> {
    if key.kty != "EC" || key.crv != "P-256" {
        return Err(format!("Unsupported key type: {} / {}", key.kty, key.crv));
    }

    DecodingKey::from_ec_components(&key.x, &key.y)
        .map_err(|e| format!("Failed to construct decoding key: {}", e))
}
