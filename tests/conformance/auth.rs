// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HS256 tokens for the kit's principals (`conformance-<group>`), signed
//! with the server's `JWT_SECRET`. Test code: the SDK itself never signs
//! anything.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

/// What the runner needs to mint tokens.
pub struct Minter {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl Minter {
    /// A token for `sub` with exactly `scopes`, valid for five minutes.
    pub fn token(&self, sub: &str, scopes: &[String]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        let mut claims = json!({ "sub": sub, "scopes": scopes, "iat": now, "exp": now + 300 });
        if let Some(issuer) = &self.issuer {
            claims["iss"] = Value::from(issuer.as_str());
        }
        if let Some(audience) = &self.audience {
            claims["aud"] = Value::from(audience.as_str());
        }
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let input = format!("{header}.{payload}");
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).expect("any key length");
        mac.update(input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{input}.{signature}")
    }
}
