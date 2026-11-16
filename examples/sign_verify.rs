// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ed25519 with a server-held key: generate it, sign with its keyId,
//! verify against its public key, then delete it.

use crypto_service_sdk::{
    Client, Error, GenerateKeyPairRequest, KeyAlgorithm, KeyIdRequest, SignRequest, VerifyRequest,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let key = client
        .generate_key_pair(&GenerateKeyPairRequest {
            algorithm: Some(KeyAlgorithm::Ed25519),
            metadata: None,
        })
        .await?;
    println!("generated {} key {}", key.algorithm, key.key_id);
    let signed = client
        .sign(&SignRequest {
            key_id: key.key_id.clone(),
            message: "pay 10 EUR to Alice".into(),
        })
        .await?;
    let verified = client
        .verify(&VerifyRequest {
            message: "pay 10 EUR to Alice".into(),
            public_key: key.public_key.clone(),
            signature: signed.signature.clone(),
        })
        .await?;
    assert!(verified.valid, "the signature verifies");
    let tampered = client
        .verify(&VerifyRequest {
            message: "pay 99 EUR to Alice".into(),
            public_key: key.public_key,
            signature: signed.signature,
        })
        .await?;
    assert!(!tampered.valid, "a changed message does not verify");
    client.keys_delete(&KeyIdRequest::new(key.key_id)).await?;
    println!(
        "signature valid: {}, tampered valid: {}",
        verified.valid, tampered.valid
    );
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
