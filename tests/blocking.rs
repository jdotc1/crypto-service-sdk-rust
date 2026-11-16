// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The blocking client against a live server (`CRYPTO_SERVICE_URL` and
//! `CRYPTO_SERVICE_API_KEY`), shared by several threads at once. Skipped
//! without them, unless `CRYPTO_SERVICE_REQUIRE_LIVE` is set.

use std::thread;

use crypto_service_sdk::{blocking, Client, HashAlgorithm, HashRequest};

fn assert_shareable<T: Send + Sync + Clone + 'static>() {}

#[test]
fn both_clients_are_send_sync_and_clone() {
    assert_shareable::<Client>();
    assert_shareable::<blocking::Client>();
}

#[test]
fn threads_share_one_blocking_client() {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(url), Some(key)) = (var("CRYPTO_SERVICE_URL"), var("CRYPTO_SERVICE_API_KEY")) else {
        assert!(
            var("CRYPTO_SERVICE_REQUIRE_LIVE").is_none(),
            "set CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY"
        );
        eprintln!("blocking: skipped (CRYPTO_SERVICE_URL not set)");
        return;
    };
    let client = Client::builder(url).api_key(key).build().expect("client");
    let client = blocking::Client::from_async(client).expect("blocking client");
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let client = client.clone();
            thread::spawn(move || {
                let request = HashRequest {
                    algorithm: HashAlgorithm::Sha256,
                    data: format!("thread {i}").into(),
                };
                client.hash(&request).expect("hash").digest.len()
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().expect("thread"), 32);
    }
    assert_eq!(client.health().expect("health").status, "ok");
}
