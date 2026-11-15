// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SHA-256 of "abc" through `POST /v2/hash`.
//!
//! ```sh
//! CRYPTO_SERVICE_URL=http://127.0.0.1:3000 CRYPTO_SERVICE_API_KEY=... cargo run --example hash
//! ```

use crypto_service_sdk::{Client, Error, HashAlgorithm, HashRequest};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let result = client
        .hash(&HashRequest {
            algorithm: HashAlgorithm::Sha256,
            data: "abc".into(),
        })
        .await?;
    println!(
        "{} {} ({} bytes)",
        result.algorithm, result.digest, result.length
    );
    assert_eq!(
        result.digest.to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
