use reqwest::{
    Url,
    header::{HeaderMap, HeaderValue},
};

use crate::models::{AuthkitError, ConsumerModel, RegisterResponse, ResendConfirmationResponse};

#[derive(Debug, Clone)]
pub struct Client {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl Client {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.authkit.tech".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "api_key",
            HeaderValue::from_str(&self.api_key).expect("Invalid API key format"),
        );
        headers
    }

    pub async fn register(&self, redirect_url: &str) -> Result<RegisterResponse, AuthkitError> {
        let url = Url::parse(&format!(
            "{}/provide/register?redirect_url={}",
            self.base_url,
            urlencoding::encode(redirect_url)
        ))
        .map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        response
            .json::<RegisterResponse>()
            .await
            .map_err(AuthkitError::Request)
    }

    pub async fn login_with_redirect(
        &self,
        redirect_url: &str,
    ) -> Result<RegisterResponse, AuthkitError> {
        let url = Url::parse(&format!(
            "{}/provide/login?redirect_url={}",
            self.base_url,
            urlencoding::encode(redirect_url)
        ))
        .map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        let status = response.status();
        let body = response.text().await.map_err(AuthkitError::Request)?;
        eprintln!("authkit /provide/login status={status} body={body}");

        match serde_json::from_str::<RegisterResponse>(&body) {
            Ok(r) => Ok(r),
            Err(e) => {
                eprintln!("authkit response parse error: {e}");
                // Re-parse as URL error to fit the error type
                Err(AuthkitError::Parse(url::Url::parse(&format!("parse-error://{e}")).unwrap_err()))
            }
        }
    }

    pub async fn get_consumer(&self, id: uuid::Uuid) -> Result<ConsumerModel, AuthkitError> {
        let url_str = format!("{}/consumer?id={}", self.base_url, id);
        let url = Url::parse(&url_str).map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        response
            .json::<ConsumerModel>()
            .await
            .map_err(AuthkitError::Request)
    }

    pub async fn get_consumer_by_session(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<ConsumerModel, AuthkitError> {
        let url_str = format!(
            "{}/consumer/session?session_id={}",
            self.base_url, session_id
        );
        let url = Url::parse(&url_str).map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        response
            .json::<ConsumerModel>()
            .await
            .map_err(AuthkitError::Request)
    }

    pub async fn logout_consumer(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<ConsumerModel, AuthkitError> {
        let url_str = format!(
            "{}/consumers/logout?session_id={}",
            self.base_url, session_id
        );
        let url = Url::parse(&url_str).map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        response
            .json::<ConsumerModel>()
            .await
            .map_err(AuthkitError::Request)
    }

    pub async fn resend_confirmation(
        &self,
        consumer_id: uuid::Uuid,
    ) -> Result<ResendConfirmationResponse, AuthkitError> {
        let url_str = format!(
            "{}/consumers/resend-confirmation?consumer_id={}",
            self.base_url, consumer_id
        );
        let url = Url::parse(&url_str).map_err(AuthkitError::Parse)?;
        let response = self
            .client
            .post(url.as_str())
            .headers(self.build_headers())
            .send()
            .await
            .map_err(AuthkitError::Request)?;

        response
            .json::<ResendConfirmationResponse>()
            .await
            .map_err(AuthkitError::Request)
    }
}
