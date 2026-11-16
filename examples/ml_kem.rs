// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ML-KEM-768 with a server-held key: generate it, encapsulate to its
//! public key, decapsulate with its keyId, and compare the secrets.

use crypto_service_sdk::{Client, Error, MlKemDecapsulateRequest, MlKemEncapsulateRequest};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let key = client.ml_kem_generate_key_pair().await?;
    println!(
        "{} key {}, public key {} bytes",
        key.algorithm,
        key.key_id,
        key.public_key.len()
    );
    let sent = client
        .ml_kem_encapsulate(&MlKemEncapsulateRequest {
            public_key: key.public_key,
        })
        .await?;
    let received = client
        .ml_kem_decapsulate(&MlKemDecapsulateRequest {
            key_id: key.key_id,
            ciphertext: sent.ciphertext,
        })
        .await?;
    assert_eq!(
        sent.shared_secret.expose_secret(),
        received.shared_secret.expose_secret(),
        "both sides hold the same secret"
    );
    println!(
        "shared secrets match ({} bytes)",
        received.shared_secret.expose_secret().len()
    );
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
