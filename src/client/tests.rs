// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Client unit tests against the loopback stub; no crypto-server needed.

use std::collections::BTreeMap;

use super::*;
use crate::stub::{refused, response, response_with, serve, serve_raw, serve_sequence, silent};
use crate::transport::{self, ReqwestTransport};
use crate::{HashAlgorithm, HashRequest, KeyIdRequest};

const HEALTH: &str = r#"{"statusCode":200,"status":"ok","uptime":1.5}"#;

fn hash_request() -> HashRequest {
    HashRequest {
        algorithm: HashAlgorithm::Sha256,
        data: "abc".into(),
    }
}

#[tokio::test]
async fn health_sends_the_default_headers_and_no_body() {
    let (url, seen) = serve(200, HEALTH);
    let client = Client::new(format!("{url}/")).expect("client");
    assert_eq!(client.base_url(), url);
    let health = client.health().await.expect("health");
    assert_eq!(health.status, "ok");
    let seen = seen.recv().expect("request");
    assert_eq!(seen.request_line, "GET /health HTTP/1.1");
    assert_eq!(seen.header("user-agent"), Some(USER_AGENT));
    assert_eq!(
        seen.header("accept"),
        Some("application/json, application/problem+json")
    );
    assert_eq!(seen.header("content-type"), None);
    assert_eq!(seen.header("x-api-key"), None);
    assert_eq!(seen.header("authorization"), None);
    assert_eq!(seen.header("traceparent"), None);
    assert!(seen.body.is_empty());
    assert_eq!(USER_AGENT, format!("crypto-service-sdk-rust/{VERSION}"));
}

#[tokio::test]
async fn credentials_and_a_fixed_traceparent_travel_and_never_show() {
    let (url, seen) = serve(
        200,
        r#"{"data":{"digest":"ab","algorithm":"sha256","length":1}}"#,
    );
    let trace = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let client = Client::builder(url)
        .api_key("synthetic-key")
        .token("synthetic-token")
        .traceparent(Traceparent::Fixed(format!(" {trace} ")))
        .build()
        .expect("client");
    let digest = client.hash(&hash_request()).await.expect("hash");
    assert_eq!(digest.digest.as_bytes(), [0xab]);
    let seen = seen.recv().expect("request");
    assert_eq!(seen.request_line, "POST /v2/hash HTTP/1.1");
    assert_eq!(seen.header("x-api-key"), Some("synthetic-key"));
    assert_eq!(seen.header("authorization"), Some("Bearer synthetic-token"));
    assert_eq!(seen.header("traceparent"), Some(trace));
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.body, r#"{"algorithm":"sha256","data":"abc"}"#);
    let debug = format!("{client:?}");
    assert!(
        !debug.contains("synthetic") && debug.contains("<redacted>"),
        "{debug}"
    );
}

#[tokio::test]
async fn an_auto_traceparent_is_fresh_and_well_formed() {
    let (url, seen) = serve_sequence(vec![response(200, HEALTH), response(200, HEALTH)]);
    let client = Client::builder(url)
        .traceparent(Traceparent::Auto)
        .build()
        .expect("client");
    client.health().await.expect("first");
    client.health().await.expect("second");
    let first = seen.recv().expect("first");
    let second = seen.recv().expect("second");
    let first = first.header("traceparent").expect("traceparent");
    assert_ne!(Some(first), second.header("traceparent"));
    let parts: Vec<&str> = first.split('-').collect();
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1].len(), 32);
    assert_eq!(parts[2].len(), 16);
    assert_eq!(parts[3], "01");
    assert!(parts[1] != "0".repeat(32) && parts[2] != "0".repeat(16));
}

fn config_error(builder: ClientBuilder) -> &'static str {
    match builder.build() {
        Err(Error::Config(message)) => message,
        other => panic!("expected a config error, got {other:?}"),
    }
}

#[test]
fn the_builder_refuses_bad_urls() {
    assert!(config_error(Client::builder("not a url")).contains("absolute"));
    assert!(config_error(Client::builder("ftp://example.com")).contains("http"));
    let with_password = Client::builder("https://user:pw@example.com");
    assert!(config_error(with_password).contains("credentials"));
    let password_only = Client::builder("https://:pw@example.com");
    assert!(config_error(password_only).contains("credentials"));
    let with_user = Client::builder("https://user@example.com");
    assert!(config_error(with_user).contains("credentials"));
    assert!(config_error(Client::builder("https://example.com/?a=1")).contains("query"));
    assert!(config_error(Client::builder("https://example.com/#x")).contains("query"));
}

#[test]
fn the_builder_refuses_bad_headers_and_redacts_credentials() {
    let base = || Client::builder("https://example.com");
    assert!(config_error(base().api_key("bad\nkey")).contains("credential"));
    assert!(config_error(base().token("bad\ntoken")).contains("credential"));
    let bad_trace = base().traceparent(Traceparent::Fixed("bad\ntrace".into()));
    assert!(config_error(bad_trace).contains("traceparent"));
    let builder = base().api_key("synthetic").token("synthetic");
    let debug = format!("{builder:?}");
    assert!(
        !debug.contains("synthetic") && debug.contains("<redacted>"),
        "{debug}"
    );
    let empty = base().traceparent(Traceparent::Fixed("  ".into()));
    assert!(!empty
        .headers()
        .expect("headers")
        .contains_key("traceparent"));
    assert_eq!(Traceparent::default(), Traceparent::Off);
    let invalid = reqwest::Client::new().get("::").build().unwrap_err();
    assert!(matches!(transport::build_failed(invalid), Error::Config(_)));
}

#[tokio::test]
async fn a_problem_answer_is_an_api_error() {
    let problem = r#"{"type":"urn:crypto-service:problem:key-not-found","title":"Not Found","status":404,"detail":"Key not found","instance":"/v2/sign","code":"KEY_NOT_FOUND"}"#;
    let (url, _seen) = serve(404, problem);
    let client = Client::new(url).expect("client");
    let request = crate::SignRequest {
        key_id: "k_AAAAAAAAAAAAAAAAAAAAAA".into(),
        message: "m".into(),
    };
    let error = client.sign(&request).await.expect_err("404");
    assert_eq!(error.status(), Some(404));
    let Error::Api(api) = &error else {
        panic!("{error:?}")
    };
    assert_eq!(api.code(), Some("KEY_NOT_FOUND"));
    assert_eq!(api.problem().instance.as_deref(), Some("/v2/sign"));
    assert_eq!(
        error.to_string(),
        "crypto-service API error: HTTP 404 Not Found (urn:crypto-service:problem:key-not-found)"
    );
}

#[tokio::test]
async fn a_body_that_is_not_a_problem_becomes_about_blank() {
    let (url, _seen) = serve_raw(response_with(502, &[], "<html>proxy</html>"));
    let client = Client::new(url).expect("client");
    let error = client.health().await.expect_err("502");
    let problem = error.problem().expect("problem");
    assert_eq!(problem.kind, "about:blank");
    assert_eq!(problem.title, "Bad Gateway");
    assert_eq!(problem.status, 502);
    assert_eq!(
        problem.detail,
        "The server answered 502 without a problem body"
    );
}

#[tokio::test]
async fn a_2xx_body_of_the_wrong_shape_is_a_decode_error_without_the_value() {
    let (url, _seen) = serve(200, r#"{"data":{"digest":"secret-value","length":"x"}}"#);
    let client = Client::new(url).expect("client");
    let error = client.hash(&hash_request()).await.expect_err("decode");
    assert!(matches!(error, Error::Decode(_)), "{error:?}");
    assert!(!error.to_string().contains("secret-value"), "{error}");
    assert_eq!(error.status(), None);
    assert!(error.problem().is_none());
}

#[tokio::test]
async fn send_raw_returns_any_status_with_extra_headers() {
    let (url, seen) = serve(415, r#"{"detail":"x"}"#);
    let mut request = RawRequest::new(Method::POST, "/v2/hash");
    request.body = Some(b"<a/>".to_vec());
    request
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    let client = Client::new(url).expect("client");
    let response = client.send_raw(request).await.expect("raw");
    assert_eq!(response.status, 415);
    assert_eq!(response.media_type(), "application/json");
    assert_eq!(response.header("content-length"), Some("14"));
    let seen = seen.recv().expect("request");
    assert_eq!(seen.header("content-type"), Some("application/xml"));
    assert_eq!(seen.body, "<a/>");
    let debug = format!("{response:?}");
    assert!(
        debug.contains("415") && !debug.contains("detail"),
        "{debug}"
    );
}

#[test]
fn raw_json_requests_encode_or_fail_cleanly() {
    let request = RawRequest::json(Method::POST, "/v2/hash", &hash_request()).expect("json");
    assert_eq!(
        request.body.as_deref(),
        Some(&br#"{"algorithm":"sha256","data":"abc"}"#[..])
    );
    let mut bad = BTreeMap::new();
    bad.insert(vec![1u8], 1u8);
    let error = RawRequest::json(Method::POST, "/", &bad).expect_err("map keys");
    assert!(matches!(error, Error::Decode(_)));
}

#[tokio::test]
async fn a_silent_server_times_out_each_attempt() {
    let client = Client::builder(silent())
        .timeout(Duration::from_millis(100))
        .build()
        .expect("client");
    let error = client.health().await.expect_err("timeout");
    assert!(error.is_timeout(), "{error:?}");
    assert_eq!(error.to_string(), "request timed out");
}

#[tokio::test]
async fn the_deadline_bounds_the_whole_call() {
    let client = Client::builder(silent())
        .timeout(Duration::ZERO)
        .deadline(Duration::from_millis(100))
        .build()
        .expect("client");
    let error = client.health().await.expect_err("deadline");
    assert!(error.is_timeout());
    assert_eq!(error.to_string(), "deadline exceeded");
}

#[tokio::test]
async fn a_refused_connection_is_a_transport_error() {
    let (url, _socket) = refused();
    let client = Client::new(url).expect("client");
    let error = client.health().await.expect_err("refused");
    let Error::Transport(transport) = &error else {
        panic!("{error:?}")
    };
    assert!(!transport.timed_out);
    assert_eq!(error.to_string(), "network error");
    assert!(std::error::Error::source(transport).is_some());
    assert!(!error.is_timeout());
}

fn retrying(url: String) -> Client {
    let policy = RetryPolicy::new()
        .max_retries(2)
        .initial_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5));
    Client::builder(url).retry(policy).build().expect("client")
}

#[tokio::test]
async fn transient_answers_are_retried_then_succeed() {
    let (url, seen) = serve_sequence(vec![
        response(503, "{}"),
        response_with(429, &[("Retry-After", "0")], "{}"),
        response(200, HEALTH),
    ]);
    retrying(url).health().await.expect("third attempt");
    assert_eq!(seen.iter().take(3).count(), 3);
}

#[tokio::test]
async fn retries_stop_at_the_budget_or_a_long_retry_after() {
    let (url, _seen) = serve_sequence(vec![response(504, "{}"); 3]);
    let error = retrying(url).health().await.expect_err("504 thrice");
    assert_eq!(error.status(), Some(504));
    let (url, seen) = serve_raw(response_with(503, &[("Retry-After", "60")], "{}"));
    let error = retrying(url).health().await.expect_err("too long to wait");
    assert_eq!(error.status(), Some(503));
    assert_eq!(seen.iter().count(), 1);
}

#[tokio::test]
async fn a_stateful_call_is_not_retried_after_a_504_or_a_lost_connection() {
    let (url, seen) = serve_sequence(vec![response(504, "{}"), response(200, "{}")]);
    let request = KeyIdRequest::new("k_AAAAAAAAAAAAAAAAAAAAAA");
    let error = retrying(url).keys_delete(&request).await.expect_err("504");
    assert_eq!(error.status(), Some(504));
    let first = seen.recv().expect("one request");
    assert_eq!(first.request_line, "POST /v2/keys/delete HTTP/1.1");
    let (url, _socket) = refused();
    let error = retrying(url)
        .keys_delete(&request)
        .await
        .expect_err("refused");
    assert!(matches!(error, Error::Transport(_)));
}

#[tokio::test]
async fn a_stateful_call_is_retried_after_429_and_503() {
    let (url, seen) = serve_sequence(vec![
        response(429, "{}"),
        response(503, "{}"),
        response(200, r#"{"data":{"deleted":true,"keyId":"k"}}"#),
    ]);
    let request = KeyIdRequest::new("k_AAAAAAAAAAAAAAAAAAAAAA");
    let deleted = retrying(url).keys_delete(&request).await.expect("retried");
    assert!(deleted.deleted);
    assert_eq!(seen.iter().take(3).count(), 3);
}

#[tokio::test]
async fn an_idempotent_call_is_retried_after_a_lost_connection() {
    let (url, _socket) = refused();
    let error = retrying(url).health().await.expect_err("refused");
    assert!(matches!(error, Error::Transport(_)));
}

#[tokio::test]
async fn the_body_limit_and_a_cut_body_are_transport_errors() {
    let (url, _seen) = serve(200, HEALTH);
    let transport = Arc::new(ReqwestTransport::with_limit(4).expect("transport"));
    let client = Client::builder(url)
        .transport(transport)
        .build()
        .expect("client");
    let error = client.health().await.expect_err("over the limit");
    assert!(matches!(error, Error::Transport(_)), "{error:?}");
    let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}".to_vec();
    let (url, _seen) = serve_raw(cut);
    let client = Client::new(url).expect("client");
    let error = client.health().await.expect_err("cut");
    assert!(matches!(error, Error::Transport(_)), "{error:?}");
}

#[test]
fn requests_show_no_header_values_or_body_in_debug() {
    let mut headers = HeaderMap::new();
    headers.insert(API_KEY, HeaderValue::from_static("synthetic-secret"));
    let request = HttpRequest {
        method: Method::POST,
        url: "http://127.0.0.1/v2/encrypt".into(),
        headers,
        body: Some(b"plaintext-secret".to_vec()),
    };
    let debug = format!("{request:?}");
    assert!(
        debug.contains("x-api-key") && !debug.contains("secret"),
        "{debug}"
    );
    let response = HttpResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Vec::new(),
    };
    assert_eq!(response.media_type(), "");
    assert_eq!(response.header("x"), None);
}

#[tokio::test]
async fn a_body_that_cannot_be_encoded_is_never_sent() {
    let client = Client::new(refused().0).expect("client");
    let mut bad = BTreeMap::new();
    bad.insert(vec![1u8], 1u8);
    let outcome = client
        .call::<_, serde_json::Value>(Method::POST, "/v2/hash", Some(&bad))
        .await;
    assert!(matches!(outcome, Err(Error::Decode(_))));
}
