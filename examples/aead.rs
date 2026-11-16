// SPDX-License-Identifier: Apache-2.0 OR MIT
//! XChaCha20-Poly1305 round trip: `POST /v2/encrypt`, then `/v2/decrypt`.
//! The key is a synthetic test value; use a key from your own key
//! management in real code.

use crypto_service_sdk::{Client, DecryptRequest, EncryptRequest, Error, SecretBytes};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let key = SecretBytes::new((0u8..32).collect::<Vec<u8>>());
    let sealed = client
        .encrypt(&EncryptRequest {
            key: key.clone(),
            plaintext: "round trip".into(),
        })
        .await?;
    println!(
        "{}: {} bytes of ciphertext",
        sealed.algorithm,
        sealed.ciphertext.len()
    );
    let opened = client
        .decrypt(&DecryptRequest {
            key,
            ciphertext: sealed.ciphertext,
        })
        .await?;
    assert_eq!(opened.plaintext.expose_secret(), "round trip");
    println!("decrypted: {:?}", opened.plaintext);
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
