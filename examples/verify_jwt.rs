//! Verify a JWT issued by Authorisationkit.
//!
//! ```sh
//! cargo run --example verify_jwt -- \
//!     'https://api.authkit.tech/.well-known/oauth-authorization-server/<org_id>' \
//!     eyJhbGciOi...
//! ```

use authorisationkit::JwtVerifier;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let well_known_url = args
        .next()
        .ok_or("usage: verify_jwt <well_known_url> <token>")?;
    let token = args
        .next()
        .ok_or("usage: verify_jwt <well_known_url> <token>")?;

    let verifier = JwtVerifier::new(well_known_url)?;
    let claims = verifier.verify(&token).await?;

    println!("subject:  {}", claims.sub);
    println!("issuer:   {}", claims.iss);
    println!("org_id:   {}", claims.org_id);
    println!("scope:    {}", claims.scope);
    println!("expires:  {}", claims.exp);
    Ok(())
}
