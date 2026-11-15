// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The conformance kit (`conformance/`, vendored from crypto-service)
//! against a live server, through the SDK's public methods.
//!
//! Each file runs in order as its own principal, `conformance-<group>`,
//! with HS256 tokens signed with the server's `JWT_SECRET`, as the kit's
//! README describes. A vector whose body a request type can express goes
//! through that method; the rest (bodies the kit sends to provoke an
//! error, v1, `/metrics`) through `Client::send_raw`. Either way the
//! answer's status, media type, headers and body are checked against the
//! vector, and a typed answer must re-encode to exactly the body the
//! server sent.
//!
//! Needs `CRYPTO_SERVICE_URL`, `CRYPTO_SERVICE_API_KEY` and
//! `CRYPTO_SERVICE_JWT_SECRET` (plus `CRYPTO_SERVICE_JWT_ISSUER` and
//! `CRYPTO_SERVICE_JWT_AUDIENCE` when the server checks them). Without
//! them the live test reports itself skipped, unless
//! `CRYPTO_SERVICE_REQUIRE_LIVE` is set (`make conformance` sets it), when
//! it fails.

mod auth;
mod dispatch;
mod template;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crypto_service_sdk::http::{HeaderMap, HeaderValue, Method};
use crypto_service_sdk::{
    BoxFuture, Client, Error, HttpRequest, HttpResponse, Problem, RawRequest, ReqwestTransport,
    Transport, TransportError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::auth::Minter;
use crate::template::{mismatches, pointer, same, substitute, Captured};

fn kit() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance")
}

#[test]
fn the_kit_matches_its_checksums() {
    let sums = fs::read_to_string(kit().join("SHA256SUMS")).expect("SHA256SUMS");
    let mut listed = Vec::new();
    for line in sums.lines() {
        let (digest, file) = line.split_once("  ").expect("sha256sum format");
        let bytes = fs::read(kit().join(file)).expect(file);
        assert_eq!(hex(&Sha256::digest(&bytes)), digest, "{file}");
        listed.push(file.to_owned());
    }
    let mut files: Vec<String> = fs::read_dir(kit())
        .expect("kit")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name != "SHA256SUMS")
        .collect();
    files.sort();
    listed.sort();
    assert_eq!(listed, files);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A transport that keeps the last answer, so the runner sees the status,
/// headers and raw body behind a typed call.
#[derive(Debug)]
struct Recorder {
    inner: ReqwestTransport,
    last: Mutex<Option<HttpResponse>>,
}

impl Transport for Recorder {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let response = self.inner.send(request).await?;
            *self.last.lock().expect("lock") = Some(response.clone());
            Ok(response)
        })
    }
}

struct Live {
    url: String,
    minter: Minter,
    recorder: Arc<Recorder>,
}

impl Live {
    fn from_env() -> Option<Live> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let url = var("CRYPTO_SERVICE_URL");
        let key = var("CRYPTO_SERVICE_API_KEY");
        let secret = var("CRYPTO_SERVICE_JWT_SECRET");
        let (Some(url), Some(_), Some(secret)) = (url, key, secret) else {
            assert!(
                var("CRYPTO_SERVICE_REQUIRE_LIVE").is_none(),
                "set CRYPTO_SERVICE_URL, CRYPTO_SERVICE_API_KEY and CRYPTO_SERVICE_JWT_SECRET"
            );
            eprintln!("conformance: skipped (CRYPTO_SERVICE_URL and credentials not set)");
            return None;
        };
        let minter = Minter {
            secret,
            issuer: var("CRYPTO_SERVICE_JWT_ISSUER"),
            audience: var("CRYPTO_SERVICE_JWT_AUDIENCE"),
        };
        let recorder = Arc::new(Recorder {
            inner: ReqwestTransport::new().expect("transport"),
            last: Mutex::new(None),
        });
        Some(Live {
            url,
            minter,
            recorder,
        })
    }

    /// A client for the vector's `auth` as principal `sub`.
    fn client(&self, auth: Option<&Value>, sub: &str) -> Client {
        let builder = Client::builder(&self.url).transport(self.recorder.clone());
        let builder = match auth {
            Some(Value::String(none)) if none == "none" => builder,
            Some(Value::Object(scoped)) => {
                let granted: Vec<String> = scoped["scopes"]
                    .as_array()
                    .expect("scopes")
                    .iter()
                    .map(|s| s.as_str().expect("scope").to_owned())
                    .collect();
                builder.token(self.minter.token(sub, &granted))
            }
            _ => builder.token(self.minter.token(sub, &["crypto:admin".to_owned()])),
        };
        builder.build().expect("client")
    }

    fn take(&self) -> Option<HttpResponse> {
        self.recorder.last.lock().expect("lock").take()
    }
}

#[derive(Default)]
struct Tally {
    passed: usize,
    typed: usize,
    raw: Vec<String>,
    failures: Vec<String>,
}

#[tokio::test]
async fn every_vector_passes_against_the_live_server() {
    let Some(live) = Live::from_env() else {
        return;
    };
    let mut files: Vec<PathBuf> = fs::read_dir(kit())
        .expect("kit")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    let mut tally = Tally::default();
    for file in files {
        run_file(&live, &file, &mut tally).await;
    }
    let total = tally.passed + tally.failures.len();
    println!(
        "conformance: {}/{total} vectors passed; {} through typed methods, {} raw",
        tally.passed,
        tally.typed,
        tally.raw.len()
    );
    println!("conformance: raw vectors: {}", tally.raw.join(", "));
    assert!(
        tally.failures.is_empty(),
        "failures:\n{}",
        tally.failures.join("\n")
    );
}

async fn run_file(live: &Live, file: &Path, tally: &mut Tally) {
    let doc: Value = serde_json::from_slice(&fs::read(file).expect("vector file")).expect("JSON");
    let sub = format!("conformance-{}", doc["group"].as_str().expect("group"));
    let mut captured = Captured::new();
    let mut clients: HashMap<String, Client> = HashMap::new();
    for vector in doc["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().expect("id").to_owned();
        let auth = vector.get("auth");
        let key = auth.map_or_else(|| "admin".to_owned(), Value::to_string);
        let client = clients
            .entry(key)
            .or_insert_with(|| live.client(auth, &sub))
            .clone();
        let problems = run_vector(live, &client, vector, &mut captured, tally).await;
        if problems.is_empty() {
            tally.passed += 1;
        } else {
            tally
                .failures
                .push(format!("{id}: {}", problems.join("; ")));
        }
    }
}

async fn run_vector(
    live: &Live,
    client: &Client,
    vector: &Value,
    captured: &mut Captured,
    tally: &mut Tally,
) -> Vec<String> {
    let request = substitute(&vector["request"], captured);
    let expect = substitute(&vector["expect"], captured);
    let method = request["method"].as_str().expect("method");
    let path = request["path"].as_str().expect("path");
    let body = request.get("body").cloned().unwrap_or(Value::Null);
    let raw_body = request.get("rawBody").is_some();
    let typed = if raw_body {
        None
    } else {
        dispatch::call(client, method, path, &body).await
    };
    let mut problems = Vec::new();
    let response = if let Some(outcome) = typed {
        tally.typed += 1;
        let Some(response) = live.take() else {
            return vec![format!("no answer: {outcome:?}")];
        };
        check_typed(&outcome, &response, &mut problems);
        response
    } else {
        tally
            .raw
            .push(vector["id"].as_str().unwrap_or("?").to_owned());
        match client.send_raw(raw(&request)).await {
            Ok(response) => response,
            Err(error) => return vec![format!("no answer: {error}")],
        }
    };
    check_answer(&expect, &response, &mut problems);
    if let Some(capture) = vector.get("capture").and_then(Value::as_object) {
        let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        for (name, at) in capture {
            match pointer(&body, at.as_str().expect("pointer")) {
                Some(value) => drop(captured.insert(name.clone(), value)),
                None => problems.push(format!("capture {name}: nothing at {at}")),
            }
        }
    }
    problems
}

/// The raw request a vector describes.
fn raw(request: &Value) -> RawRequest {
    let method =
        Method::from_bytes(request["method"].as_str().expect("method").as_bytes()).expect("method");
    let mut raw = RawRequest::new(method, request["path"].as_str().expect("path"));
    if let Some(text) = request.get("rawBody").and_then(Value::as_str) {
        raw.body = Some(text.as_bytes().to_vec());
    } else if let Some(body) = request.get("body").filter(|b| !b.is_null()) {
        raw.body = Some(serde_json::to_vec(body).expect("body"));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in request
        .get("headers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let name: crypto_service_sdk::http::HeaderName = name.parse().expect("header name");
        let value = HeaderValue::from_str(value.as_str().expect("header")).expect("value");
        headers.insert(name, value);
    }
    raw.headers = headers;
    raw
}

/// A typed outcome agrees with the raw answer behind it.
fn check_typed(
    outcome: &Result<Value, Error>,
    response: &HttpResponse,
    problems: &mut Vec<String>,
) {
    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    match outcome {
        Ok(value) => {
            let wrapped = body
                .get("data")
                .filter(|_| body.as_object().is_some_and(|o| o.len() == 1));
            let expected = wrapped.unwrap_or(&body);
            if !same(value, expected) {
                problems.push(format!(
                    "typed answer re-encodes as {value}, server sent {expected}"
                ));
            }
        }
        Err(Error::Api(api)) => {
            if api.status != response.status {
                problems.push(format!(
                    "typed error status {} != {}",
                    api.status, response.status
                ));
            }
            if api.problem != Problem::from_body(response.status, &response.body) {
                problems.push("typed problem differs from the body".to_owned());
            }
        }
        Err(other) => problems.push(format!("typed call failed: {other}")),
    }
}

/// Status, media type, headers and body against `expect`.
fn check_answer(expect: &Value, response: &HttpResponse, problems: &mut Vec<String>) {
    let status = expect["status"].as_u64().expect("status");
    if u64::from(response.status) != status {
        problems.push(format!("status {} != {status}", response.status));
    }
    let media = expect["mediaType"].as_str().expect("mediaType");
    if response.media_type() != media {
        problems.push(format!("media type {} != {media}", response.media_type()));
    }
    for (name, value) in expect
        .get("headers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if response.header(name) != value.as_str() {
            problems.push(format!(
                "header {name}: {:?} != {value}",
                response.header(name)
            ));
        }
    }
    let (template, actual) = match expect.get("body") {
        Some(template) => (
            template,
            serde_json::from_slice(&response.body).unwrap_or(Value::Null),
        ),
        None => (
            &expect["text"],
            Value::String(String::from_utf8_lossy(&response.body).into_owned()),
        ),
    };
    mismatches(template, &actual, "", problems);
}
