//! Generates the HTTP client from `openapi.json` at build time.
//!
//! The transport layer is not hand-written: every request method, request and
//! response type in this crate comes from the AuthKit OpenAPI document. What is
//! hand-written is everything the document cannot express — the JWT verifier in
//! `src/jwt.rs`, and the cross-cutting request behaviour in `src/hooks.rs`
//! (API key, idempotency keys, retries, request-id capture), which attaches to
//! the generated client through progenitor's `ClientHooks`.
//!
//! To pick up API changes, refresh the document and rebuild:
//!
//! ```text
//! curl -s https://api.authkit.tech/openapi.json -o openapi.json
//! cargo build
//! ```
//!
//! The generated code is written to `OUT_DIR` rather than committed, so it
//! cannot drift from the document beside it. Formatting goes through
//! `prettyplease` rather than rustfmt, so no nightly toolchain is required.

use std::{env, fs, path::Path};

fn main() {
    println!("cargo::rerun-if-changed=openapi.json");
    println!("cargo::rerun-if-changed=build.rs");

    let spec = fs::read_to_string("openapi.json").expect("openapi.json is readable");
    let spec: openapiv3::OpenAPI = serde_json::from_str(&spec).expect("openapi.json parses");

    let mut settings = progenitor::GenerationSettings::default();
    settings
        // Carries the API key and retry policy onto the generated client, so
        // the hooks in `src/hooks.rs` can reach them without a wrapper type
        // that would mean re-declaring every method by hand.
        .with_inner_type(quote::quote!(crate::hooks::Config))
        .with_interface(progenitor::InterfaceStyle::Positional)
        .with_tag(progenitor::TagStyle::Merged)
        .with_derive("PartialEq");

    let mut generator = progenitor::Generator::new(&settings);
    let tokens = generator.generate_tokens(&spec).expect("spec generates");
    let ast = syn::parse2(tokens).expect("generated tokens parse");
    let content = prettyplease::unparse(&ast);

    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR is set")).join("codegen.rs");
    fs::write(out, content).expect("generated client is written");
}
