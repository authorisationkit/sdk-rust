//! Begin a registration flow.
//!
//! ```sh
//! AUTHKIT_KEY=... cargo run --example register -- https://my-app.example.com/auth/callback
//! ```

use authorisationkit::Client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("AUTHKIT_KEY").map_err(|_| "set AUTHKIT_KEY in the environment")?;
    let redirect_url = std::env::args()
        .nth(1)
        .ok_or("usage: register <redirect_url>")?;

    let client = Client::new(api_key)?;
    let registration = client.register(&redirect_url).await?;

    println!("code:     {}", registration.code);
    println!("redirect: {}", registration.redirect);
    Ok(())
}
