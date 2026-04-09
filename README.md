# authorisationkit

[![Crates.io](https://img.shields.io/crates/v/authorisationkit.svg)](https://crates.io/crates/authorisationkit)
[![Docs.rs](https://docs.rs/authorisationkit/badge.svg)](https://docs.rs/authorisationkit)

Rust SDK for the [Authorisationkit](https://api.authkit.tech) API.

Provides:

- **`Client`** — typed HTTP client for the Authorisationkit consumer API
  (register, login, fetch consumer, logout, resend confirmation).
- **`JwtVerifier`** — verifies JWTs issued by Authorisationkit by bootstrapping
  from an OAuth Authorization Server well-known URL: fetches AS metadata,
  fetches JWKS, validates signature/expiry/issuer.

## Installation

```toml
[dependencies]
authorisationkit = "0.1"
```

## Usage

### Calling the API

```rust
use authorisationkit::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(std::env::var("AUTHKIT_KEY")?);

    let registration = client
        .register("https://my-app.example.com/auth/callback")
        .await?;

    println!("redirect user to: {}", registration.redirect);
    Ok(())
}
```

### Verifying JWTs

```rust
use authorisationkit::JwtVerifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = JwtVerifier::new(
        "https://api.authkit.tech/.well-known/oauth-authorization-server/<org_id>",
    );

    let claims = verifier.verify("eyJhbGciOi...").await?;
    println!("verified subject: {}", claims.sub);
    Ok(())
}
```

The verifier caches AS metadata and JWKS internally and refetches keys on
unknown `kid`.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
