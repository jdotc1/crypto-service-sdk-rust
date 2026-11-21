// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The error every call returns: an RFC 9457 problem from the server, a
//! request that got no answer, or an answer that did not decode.
//!
//! No message here carries a credential, a key, a plaintext or a body:
//! an [`ApiError`] shows the problem's status, type and title (which the
//! server writes for the client), a [`TransportError`] a fixed text, and a
//! [`DecodeError`] the position of the fault, never the value found there.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// What went wrong with a call. Every variant wraps a type of its own, so
/// a caller can match the kind and keep the details.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server answered with a status other than 2xx.
    #[error(transparent)]
    Api(Box<ApiError>),
    /// No answer arrived: the connection failed, an attempt timed out, or
    /// the overall deadline passed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A 2xx answer did not have the documented shape.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The client could not be built, or a request could not be formed
    /// from its options (for example a base URL that is not a URL).
    #[error("invalid client configuration: {0}")]
    Config(&'static str),
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        Error::Api(Box::new(error))
    }
}

impl Error {
    /// The HTTP status of an [`Error::Api`]; `None` for the other kinds.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api(api) => Some(api.status),
            _ => None,
        }
    }

    /// The problem of an [`Error::Api`]; `None` for the other kinds.
    #[must_use]
    pub fn problem(&self) -> Option<&Problem> {
        match self {
            Error::Api(api) => Some(&api.problem),
            _ => None,
        }
    }

    /// Whether this is a [`TransportError`] caused by a timeout or the
    /// deadline.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Transport(t) if t.timed_out)
    }
}

/// A non-2xx answer, with its RFC 9457 problem.
///
/// A body that is not a problem (an HTML page from a proxy, an empty
/// body) becomes an `about:blank` problem for the status, so
/// [`ApiError::problem`] always has the problem shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    /// The HTTP status code.
    pub status: u16,
    /// The problem the server sent, or the `about:blank` stand-in.
    pub problem: Problem,
}

impl ApiError {
    /// The problem, as the server sent it.
    #[must_use]
    pub fn problem(&self) -> &Problem {
        &self.problem
    }

    /// The problem's `code` (for example `KEY_NOT_FOUND`), when it has one.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.problem.code.as_deref()
    }
}

// Escape only controls in server-controlled text before it reaches a log.
fn escape_control_chars(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            escaped.extend(ch.escape_default());
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "crypto-service API error: HTTP {} {} ({})",
            self.status,
            escape_control_chars(&self.problem.title),
            escape_control_chars(&self.problem.kind)
        )
    }
}

impl std::error::Error for ApiError {}

/// RFC 9457 problem details (`application/problem+json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// Problem type: `urn:crypto-service:problem:<slug>`, or `about:blank`.
    #[serde(rename = "type", default = "about_blank")]
    pub kind: String,
    /// Summary of the problem type.
    #[serde(default)]
    pub title: String,
    /// HTTP status code.
    #[serde(default)]
    pub status: u16,
    /// Explanation of this occurrence, written by the server for the
    /// client.
    pub detail: String,
    /// Request path, without the query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Error code from crypto-lib, the key store or a KMS provider (for
    /// example `INVALID_HEX`, `KEY_NOT_FOUND`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Each field that failed validation (`validation-failed`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ValidationError>,
    /// Requests a tenant may make per minute (tenant quota).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Seconds until the tenant quota resets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_seconds: Option<u64>,
    /// Any other extension member.
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

/// One field that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    /// The field, as a JSON pointer or a body field name.
    pub field: String,
    /// Why it failed.
    pub message: String,
}

fn about_blank() -> String {
    String::from("about:blank")
}

impl Problem {
    /// The problem a non-2xx `body` carries: the body itself when it is a
    /// JSON object with a string `detail`, with any missing `type`, `title`
    /// or `status` filled in; otherwise an `about:blank` problem for
    /// `status`.
    #[must_use]
    pub fn from_body(status: u16, body: &[u8]) -> Self {
        match serde_json::from_slice::<Problem>(body) {
            Ok(mut problem) => {
                if problem.title.is_empty() {
                    problem.title = reason(status);
                }
                if problem.status == 0 {
                    problem.status = status;
                }
                problem
            }
            Err(_) => Self::blank(status),
        }
    }

    /// The `about:blank` problem for a status without a problem body.
    #[must_use]
    pub fn blank(status: u16) -> Self {
        Problem {
            kind: about_blank(),
            title: reason(status),
            status,
            detail: format!("The server answered {status} without a problem body"),
            instance: None,
            code: None,
            errors: Vec::new(),
            limit: None,
            reset_seconds: None,
            extensions: Map::new(),
        }
    }
}

/// The canonical reason phrase of `status`, or `HTTP error`.
fn reason(status: u16) -> String {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("HTTP error")
        .to_owned()
}

/// No answer arrived.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    /// Whether the attempt's timeout or the call's deadline ended it.
    pub timed_out: bool,
    message: &'static str,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl TransportError {
    /// A failure with `source` as its cause; `timed_out` says whether a
    /// timeout ended it. For custom [`Transport`](crate::Transport)s.
    pub fn new<E>(source: E, timed_out: bool) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        TransportError {
            timed_out,
            message: if timed_out {
                "request timed out"
            } else {
                "network error"
            },
            source: Some(source.into()),
        }
    }

    /// An attempt that ran past the per-attempt timeout.
    pub(crate) fn attempt_timeout() -> Self {
        TransportError {
            timed_out: true,
            message: "request timed out",
            source: None,
        }
    }

    /// A call that ran past its deadline.
    pub(crate) fn deadline() -> Self {
        TransportError {
            timed_out: true,
            message: "deadline exceeded",
            source: None,
        }
    }
}

/// A 2xx body that did not decode. It names where the fault is, never the
/// value found there, which could be a key or a plaintext.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("response body could not be decoded ({category} error at line {line}, column {column})")]
pub struct DecodeError {
    category: &'static str,
    line: usize,
    column: usize,
}

impl DecodeError {
    /// The 1-based line of the fault, or 0 when it is not at a position.
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }

    /// The 1-based column of the fault, or 0 when it is not at a position.
    #[must_use]
    pub fn column(&self) -> usize {
        self.column
    }
}

impl From<serde_json::Error> for DecodeError {
    fn from(error: serde_json::Error) -> Self {
        use serde_json::error::Category;
        DecodeError {
            category: match error.classify() {
                Category::Io => "io",
                Category::Syntax => "syntax",
                Category::Data => "data",
                Category::Eof => "eof",
            },
            line: error.line(),
            column: error.column(),
        }
    }
}

#[cfg(test)]
mod tests;
