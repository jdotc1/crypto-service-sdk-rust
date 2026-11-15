// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;

#[test]
fn hex_round_trips_and_reads_either_case() {
    let hex = Hex::parse("00aBff").expect("hex");
    assert_eq!(hex.as_bytes(), [0x00, 0xab, 0xff]);
    assert_eq!(hex.to_string(), "00abff");
    assert_eq!(format!("{hex:?}"), "Hex(00abff)");
    assert_eq!(serde_json::to_string(&hex).unwrap(), "\"00abff\"");
    let back: Hex = serde_json::from_str("\"00ABFF\"").unwrap();
    assert_eq!(back, hex);
    assert_eq!(&*back, &[0, 0xab, 0xff]);
    assert_eq!(back.as_ref(), &[0, 0xab, 0xff]);
    assert_eq!(back.into_vec(), vec![0, 0xab, 0xff]);
}

#[test]
fn hex_refuses_odd_lengths_and_other_characters() {
    assert_eq!(Hex::parse("abc"), Err(EncodingError("hex")));
    assert_eq!(Hex::parse("zz"), Err(EncodingError("hex")));
    assert_eq!(Hex::parse("0g"), Err(EncodingError("hex")));
    assert_eq!(EncodingError("hex").to_string(), "not valid hex");
    let err = serde_json::from_str::<Hex>("\"xy\"").unwrap_err();
    assert!(err.to_string().contains("not valid hex"));
    let err = serde_json::from_str::<Hex>("12").unwrap_err();
    assert!(err.to_string().contains("an encoded byte string"));
    assert_eq!(Hex::parse("").unwrap().len(), 0);
}

#[test]
fn base64_is_standard_and_padded() {
    let b = Base64::from(b"any carnal pleasure.".as_slice());
    assert_eq!(b.to_string(), "YW55IGNhcm5hbCBwbGVhc3VyZS4=");
    assert_eq!(format!("{b:?}"), "Base64(<20 bytes>)");
    let back: Base64 = serde_json::from_str("\"YW55IGNhcm5hbCBwbGVhc3VyZS4=\"").unwrap();
    assert_eq!(back, b);
    assert!(Base64::parse("YW55IGNhcm5hbCBwbGVhc3VyZS4").is_err());
    assert!(Base64::parse("-_").is_err());
}

#[test]
fn constructors_wrap_the_bytes() {
    assert_eq!(Hex::new(vec![1u8]).as_bytes(), [1]);
    assert_eq!(Hex::from([1u8, 2]).as_bytes(), [1, 2]);
    assert_eq!(Base64::from(vec![3u8]).into_vec(), vec![3]);
    assert_eq!(Base64::new([4u8]).as_ref(), &[4]);
    assert_eq!(Base64::from([5u8; 1]).len(), 1);
    assert_eq!(encode_hex(&[0x0f, 0xf0]), "0ff0");
    assert_eq!(decode_hex("0FF0").unwrap(), vec![0x0f, 0xf0]);
}
