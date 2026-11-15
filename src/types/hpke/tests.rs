// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;
use crate::encoding::encode_hex;

#[test]
fn text_that_reads_as_hex_is_sent_as_its_bytes() {
    let as_json = |data: HpkeData| serde_json::to_string(&data).unwrap();
    assert_eq!(as_json("hello".into()), "\"hello\"");
    assert_eq!(as_json("abcd".into()), "\"61626364\"");
    assert_eq!(as_json("abc".into()), "\"abc\"");
    assert_eq!(as_json(vec![0xab_u8].into()), "\"ab\"");
    assert_eq!(as_json(HpkeData::default()), "\"\"");
    let back: HpkeData = serde_json::from_str("\"abcd\"").unwrap();
    assert!(matches!(back, HpkeData::Text(t) if t.expose_secret() == "abcd"));
    assert_eq!(format!("{:?}", HpkeData::from("x")), "HpkeData(<redacted>)");
    assert_eq!(encode_hex(b"ab"), "6162");
}
