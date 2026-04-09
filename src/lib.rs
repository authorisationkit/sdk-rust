#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod client;
pub mod error;
pub mod ids;
pub mod jwt;
pub mod models;

pub use client::{Client, ClientBuilder};
pub use error::{Error, JwtError};
pub use ids::{ConsumerId, OrgId, SessionId};
pub use jwt::{Claims, JwtVerifier, JwtVerifierBuilder};
