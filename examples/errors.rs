// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! How failures arrive: an RFC 9457 problem for a key that does not
//! exist, a validation problem with its per-field errors, and a transport
//! error for a server that is not there.

use std::time::Duration;

use crypto_service_sdk::http::Method;
use crypto_service_sdk::{Client, Error, RawRequest, SignRequest};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Client::builder(env("CRYPTO_SERVICE_URL"))
        .api_key(env("CRYPTO_SERVICE_API_KEY"))
        .build()?;

    let unknown = SignRequest {
        key_id: "k_AAAAAAAAAAAAAAAAAAAAAA".into(),
        message: "m".into(),
    };
    match client.sign(&unknown).await {
        Err(Error::Api(api)) => {
            println!(
                "{} {} {:?}: {}",
                api.status,
                api.problem.kind,
                api.code(),
                api.problem.detail
            );
            assert_eq!(api.status, 404);
        }
        other => panic!("expected a 404 problem, got {other:?}"),
    }

    // A body the typed request cannot express, sent raw: missing `data`.
    let raw = RawRequest::json(Method::POST, "/v2/hash", &json!({"algorithm": "sha256"}))?;
    let response = client.send_raw(raw).await?;
    let problem = crypto_service_sdk::Problem::from_body(response.status, &response.body);
    println!("{} {}: {:?}", problem.status, problem.kind, problem.errors);
    assert_eq!(problem.kind, "urn:crypto-service:problem:validation-failed");
    assert_ne!(problem.errors.len(), 0);

    let nowhere = Client::builder("http://127.0.0.1:9")
        .timeout(Duration::from_secs(2))
        .build()?;
    match nowhere.health().await {
        Err(Error::Transport(transport)) => {
            println!("transport error, timed out: {}", transport.timed_out);
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
    Ok(())
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}
