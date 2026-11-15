// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The checks the fuzz targets run. Each states a promise the crate's
//! documentation makes about what a server's answer turns into, and
//! panics (a libFuzzer crash) when the client breaks it.

use std::fmt::Debug;

use crypto_service_sdk::fuzzing::{decode, decode_data, problem};
use crypto_service_sdk::*;
use serde::de::DeserializeOwned;

/// Splits an input into a status line and a body; `None` unless the first
/// line is a status code from 100 to 999.
pub fn split_status(data: &[u8]) -> Option<(u16, &[u8])> {
    let end = data.iter().position(|&b| b == b'\n')?;
    let status: u16 = std::str::from_utf8(&data[..end])
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (100..=999)
        .contains(&status)
        .then_some((status, &data[end + 1..]))
}

/// A non-2xx answer is an `Error::Api` whose problem is the body's, or
/// the `about:blank` stand-in.
pub fn check_problem(status: u16, body: &[u8]) {
    if (200..300).contains(&status) {
        return;
    }
    let parsed = problem(status, body);
    assert!(parsed.status != 0, "a problem always has a status");
    assert!(!parsed.title.is_empty(), "a problem always has a title");
    let has_detail = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("detail").map(serde_json::Value::is_string))
        .unwrap_or(false);
    if !has_detail {
        assert_eq!(parsed, Problem::blank(status), "no detail: about:blank");
    }
    match decode::<Health>(status, body) {
        Err(Error::Api(api)) => {
            assert_eq!(api.status, status);
            assert_eq!(api.problem, parsed);
        }
        other => panic!("a {status} answer must be Error::Api, got {other:?}"),
    }
}

/// A 2xx body decodes as each answer type, or fails with a decode error
/// whose message carries a position and nothing from the body.
pub fn check_success(body: &[u8]) {
    check::<HashResult>(body);
    check::<Signature>(body);
    check::<KeyPair>(body);
    check::<GeneratedKeyPair>(body);
    check::<ExportedKey>(body);
    check_secrets(body);
}

/// The answers that carry secrets.
fn check_secrets(body: &[u8]) {
    check::<HpkeOpened>(body);
    check::<KmsPlaintext>(body);
    check::<MultiRecipientCiphertext>(body);
    check::<SecretString>(body);
    check::<SecretBytes>(body);
    check_meta(body);
}

/// The answers of the meta and probe routes.
fn check_meta(body: &[u8]) {
    check::<Algorithms>(body);
    check::<DoraCompliance>(body);
    check_bare::<Cbom>(body);
    check_bare::<Health>(body);
    check_bare::<Readiness>(body);
}

fn check<T: DeserializeOwned + Debug>(body: &[u8]) {
    outcome(decode_data::<T>(200, body));
}

fn check_bare<T: DeserializeOwned + Debug>(body: &[u8]) {
    outcome(decode::<T>(200, body));
}

fn outcome<T: Debug>(result: Result<T, Error>) {
    match result {
        Ok(value) => drop(format!("{value:?}")),
        Err(Error::Decode(error)) => {
            let message = error.to_string();
            let expected = format!(
                "response body could not be decoded ({} error at line {}, column {})",
                message
                    .trim_start_matches("response body could not be decoded (")
                    .split(' ')
                    .next()
                    .unwrap_or_default(),
                error.line(),
                error.column()
            );
            assert_eq!(message, expected, "a decode error names a position only");
        }
        Err(other) => panic!("a 2xx body must decode or be Error::Decode, got {other:?}"),
    }
}
