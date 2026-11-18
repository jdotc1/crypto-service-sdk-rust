// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The blocking client (`--features blocking`): the same calls, no
//! `async`. Runs a KMS round trip on the server's local provider.

use crypto_service_sdk::{
    blocking, Client, Error, KmsCreateKeyRequest, KmsDecryptRequest, KmsEncryptRequest,
};

fn main() -> Result<(), Error> {
    let async_client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let client = blocking::Client::from_async(async_client)?;
    let health = client.health()?;
    println!("server {} (up {:.0} s)", health.status, health.uptime);
    let key = client.kms_create_key(&KmsCreateKeyRequest::default())?;
    let sealed = client.kms_encrypt(&KmsEncryptRequest::bytes(&key.key_id, &[0x00, 0xff]))?;
    let opened = client.kms_decrypt(&KmsDecryptRequest {
        key_id: key.key_id,
        ciphertext: sealed.ciphertext,
        ..KmsDecryptRequest::default()
    })?;
    assert_eq!(opened.hex.expose_secret(), [0x00, 0xff]);
    println!(
        "KMS round trip on {}: {} bytes",
        opened.provider,
        opened.hex.expose_secret().len()
    );
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
