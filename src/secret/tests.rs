// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;

#[test]
fn debug_never_shows_the_secret() {
    let bytes = SecretBytes::from([0xde_u8, 0xad]);
    let text = SecretString::from("hunter2");
    assert_eq!(format!("{bytes:?}"), "SecretBytes(<redacted>)");
    assert_eq!(format!("{text:?}"), "SecretString(<redacted>)");
    assert_eq!(bytes.expose_secret(), [0xde, 0xad]);
    assert_eq!(text.expose_secret(), "hunter2");
}

#[test]
fn serde_uses_hex_for_bytes_and_text_for_strings() {
    let bytes = SecretBytes::from(vec![0xde_u8, 0xad]);
    assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"dead\"");
    let back: SecretBytes = serde_json::from_str("\"DEAD\"").unwrap();
    assert_eq!(back.expose_secret(), [0xde, 0xad]);
    assert!(serde_json::from_str::<SecretBytes>("\"xyz\"").is_err());
    let text = SecretString::from(String::from("pw"));
    assert_eq!(serde_json::to_string(&text).unwrap(), "\"pw\"");
    let back: SecretString = serde_json::from_str("\"pw\"").unwrap();
    assert_eq!(back.expose_secret(), "pw");
}

#[test]
fn constructors_wrap_the_value() {
    assert_eq!(SecretBytes::from(&[1u8][..]).expose_secret(), [1]);
    assert_eq!(SecretBytes::from_hex("0a").unwrap().expose_secret(), [10]);
    assert_eq!(SecretBytes::default().expose_secret().len(), 0);
    assert_eq!(SecretString::default().expose_secret().len(), 0);
}
