// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A loopback round trip, `round_trip_hash`, against the server at
//! `CRYPTO_SERVICE_URL` (with `CRYPTO_SERVICE_API_KEY`). Reports itself
//! skipped without it. Mind the server's tenant quota (60 requests a
//! minute per principal): a full measured run needs a server whose
//! principal is not shared with anything else, or a token per run.

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_service_sdk::{Client, HashAlgorithm, HashRequest};

fn round_trip_hash(c: &mut Criterion) {
    let Ok(url) = std::env::var("CRYPTO_SERVICE_URL") else {
        eprintln!("round_trip_hash: skipped (CRYPTO_SERVICE_URL not set)");
        return;
    };
    let key = std::env::var("CRYPTO_SERVICE_API_KEY").unwrap_or_default();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let client = Client::builder(url).api_key(key).build().expect("client");
    let request = HashRequest {
        algorithm: HashAlgorithm::Sha256,
        data: "abc".into(),
    };
    c.bench_function("round_trip_hash", |b| {
        b.to_async(&runtime)
            .iter(|| async { client.hash(&request).await.expect("hash") });
    });
}

criterion_group!(benches, round_trip_hash);
criterion_main!(benches);
