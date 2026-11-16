// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{self, Read};

use super::*;

#[test]
fn a_problem_body_is_kept_and_completed() {
    let full = br#"{"type":"urn:crypto-service:problem:validation-failed","title":"Bad Request","status":400,"detail":"body/data is required","instance":"/v2/hash","errors":[{"field":"/data","message":"is required"}],"traceId":"t"}"#;
    let problem = Problem::from_body(400, full);
    assert_eq!(problem.kind, "urn:crypto-service:problem:validation-failed");
    assert_eq!(problem.errors[0].field, "/data");
    assert_eq!(problem.extensions["traceId"], "t");
    let sparse = Problem::from_body(
        429,
        br#"{"detail":"slow down","limit":60,"resetSeconds":9}"#,
    );
    assert_eq!(sparse.kind, "about:blank");
    assert_eq!(sparse.title, "Too Many Requests");
    assert_eq!(sparse.status, 429);
    assert_eq!((sparse.limit, sparse.reset_seconds), (Some(60), Some(9)));
}

#[test]
fn anything_else_is_about_blank() {
    for body in [&b""[..], b"null", b"[]", br#"{"detail":1}"#, b"<html/>"] {
        let problem = Problem::from_body(503, body);
        assert_eq!(problem, Problem::blank(503));
    }
    assert_eq!(Problem::blank(599).title, "HTTP error");
    assert_eq!(Problem::blank(1000).title, "HTTP error");
    let encoded = serde_json::to_value(Problem::blank(500)).expect("encodes");
    assert_eq!(encoded["type"], "about:blank");
    assert!(encoded.get("errors").is_none());
}

#[test]
fn error_accessors_cover_every_kind() {
    let api = Error::from(ApiError {
        status: 404,
        problem: Problem::blank(404),
    });
    assert_eq!(api.status(), Some(404));
    assert!(api.problem().is_some());
    assert!(!api.is_timeout());
    let Error::Api(inner) = &api else {
        panic!("api")
    };
    assert_eq!(inner.code(), None);
    let timeout = Error::from(TransportError::attempt_timeout());
    assert!(timeout.is_timeout());
    assert_eq!(timeout.status(), None);
    assert!(std::error::Error::source(&TransportError::deadline()).is_none());
    let custom = TransportError::new("stub", true);
    assert_eq!(custom.to_string(), "request timed out");
    assert!(custom.timed_out);
    let config = Error::Config("x");
    assert_eq!(config.to_string(), "invalid client configuration: x");
    assert!(config.problem().is_none());
}

struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}

#[test]
fn decode_errors_name_the_position_and_kind_only() {
    let data = serde_json::from_str::<u8>(r#""a secret""#).unwrap_err();
    let error = DecodeError::from(data);
    assert_eq!(
        error.to_string(),
        "response body could not be decoded (data error at line 1, column 10)"
    );
    assert_eq!((error.line(), error.column()), (1, 10));
    let syntax = DecodeError::from(serde_json::from_str::<u8>("x").unwrap_err());
    assert!(syntax.to_string().contains("syntax"));
    let eof = DecodeError::from(serde_json::from_str::<u8>("").unwrap_err());
    assert!(eof.to_string().contains("eof"));
    let io = DecodeError::from(serde_json::from_reader::<_, u8>(Broken).unwrap_err());
    assert!(io.to_string().contains("io"));
    assert!(Error::from(io).to_string().contains("io error"));
}
