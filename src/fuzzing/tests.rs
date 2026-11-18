// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;
use crate::{HashRequest, HashResult};

#[test]
fn the_helpers_reach_the_client_paths() {
    let body = br#"{"data":{"digest":"00","algorithm":"sha256","length":1}}"#;
    let hash: HashResult = decode_data(200, body).expect("decodes");
    assert_eq!(hash.length, 1);
    assert_eq!(problem(500, b"").status, 500);
    let bytes = encode(&HashRequest::default()).expect("encodes");
    assert_eq!(bytes, br#"{"algorithm":"sha256","data":""}"#);
}
