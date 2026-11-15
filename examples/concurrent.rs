// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One client shared by many tasks: its clones share one connection
//! pool, and the calls run concurrently.

use crypto_service_sdk::{Client, Error, HashAlgorithm, HashRequest};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let client = client.clone();
            tokio::spawn(async move {
                let request = HashRequest {
                    algorithm: HashAlgorithm::Blake3,
                    data: format!("message {i}").into(),
                };
                client.hash(&request).await
            })
        })
        .collect();
    let mut digests = Vec::new();
    for task in tasks {
        let result = task.await.expect("task ran")?;
        digests.push(result.digest.to_string());
    }
    digests.sort();
    digests.dedup();
    assert_eq!(digests.len(), 8, "eight distinct digests");
    println!("{} concurrent hashes, all distinct", digests.len());
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
