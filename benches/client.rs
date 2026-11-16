// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Client-side cost with no network: encoding a request body, decoding a
//! success answer and decoding a problem. Needs the `internals` feature
//! (`make bench`). Scenario names are shared by every Crypto Service SDK.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_service_sdk::fuzzing::{decode_data, encode, problem};
use crypto_service_sdk::{HashAlgorithm, HashRequest, HashResult, KeyPair, SecretString};

const HASH: &[u8] = include_bytes!("responses/hash.json");
const KEYGEN: &[u8] = include_bytes!("responses/ml-kem-keygen.json");
const PROBLEM: &[u8] = include_bytes!("responses/problem.json");

fn encode_request(c: &mut Criterion) {
    let request = HashRequest {
        algorithm: HashAlgorithm::Sha256,
        data: SecretString::new("a".repeat(1024)),
    };
    c.bench_function("encode_request", |b| {
        b.iter(|| encode(black_box(&request)).expect("encodes"));
    });
}

fn decode_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_response");
    group.bench_function("hash", |b| {
        b.iter(|| decode_data::<HashResult>(200, black_box(HASH)).expect("decodes"));
    });
    group.bench_function("ml_kem_keygen", |b| {
        b.iter(|| decode_data::<KeyPair>(200, black_box(KEYGEN)).expect("decodes"));
    });
    group.finish();
}

fn decode_problem(c: &mut Criterion) {
    c.bench_function("decode_problem", |b| {
        b.iter(|| problem(404, black_box(PROBLEM)));
    });
}

criterion_group!(benches, encode_request, decode_response, decode_problem);
criterion_main!(benches);
