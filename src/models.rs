use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub code: String,
    pub redirect: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum UserRegistrationTypeValue {
    Google,
    Plain,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsumerModel {
    pub id: Uuid,
    pub registration_type: UserRegistrationTypeValue,
    pub email: String,
    pub created_at: chrono::NaiveDateTime,
    pub confirmed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResendConfirmationResponse {
    pub sent: bool,
}

#[derive(Debug)]
pub enum AuthkitError {
    Parse(url::ParseError),
    Request(reqwest::Error),
}

impl fmt::Display for AuthkitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthkitError::Parse(err) => write!(f, "Authkit failed to parse an URL: {}", err),
            AuthkitError::Request(err) => write!(f, "Authkit request failed: {}", err),
        }
    }
}

impl std::error::Error for AuthkitError {}
