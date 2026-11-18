// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde_json::json;

use super::*;
use crate::{Hex, SecretBytes};

#[test]
fn request_enums_use_the_server_names() {
    let names = |v: &dyn erased::Named| v.name();
    assert_eq!(names(&HashAlgorithm::Sha3_256), "\"sha3-256\"");
    assert_eq!(names(&MacAlgorithm::Sha3_512), "\"sha3-512\"");
    assert_eq!(names(&KdfAlgorithm::Pbkdf2Sha256), "\"pbkdf2-sha256\"");
    assert_eq!(names(&KeyAlgorithm::MlKem768), "\"ml-kem-768\"");
    assert_eq!(names(&KeyAlgorithm::P384), "\"p384\"");
    assert_eq!(names(&KeyWrapAlgorithm::AesKwp), "\"aes-kwp\"");
}

#[test]
fn more_request_enums_use_the_server_names() {
    let names = |v: &dyn erased::Named| v.name();
    assert_eq!(names(&HpkeKem::X25519MlKem768), "\"x25519-ml-kem-768\"");
    assert_eq!(names(&HpkeKem::XWing), "\"x-wing\"");
    assert_eq!(names(&HpkeAead::Aes128Gcm), "\"aes-128-gcm\"");
    assert_eq!(names(&SlhDsaVariant::Shake256s), "\"shake-256s\"");
    assert_eq!(
        names(&OpaqueSuite::Ristretto255Sha512),
        "\"ristretto255-SHA512\""
    );
    assert_eq!(names(&KmsEncoding::Hex), "\"hex\"");
    assert_eq!(names(&KmsKeyUsage::Wrap), "\"wrap\"");
    assert_eq!(names(&RecipientType::Pq), "\"pq\"");
    assert_eq!(names(&KeyUse::Enc), "\"enc\"");
}

mod erased {
    pub trait Named {
        fn name(&self) -> String;
    }

    impl<T: serde::Serialize> Named for T {
        fn name(&self) -> String {
            serde_json::to_string(self).expect("encodes")
        }
    }
}

#[test]
fn ml_dsa_levels_are_numbers() {
    assert_eq!(serde_json::to_string(&MlDsaLevel::L65).unwrap(), "65");
    assert_eq!(serde_json::to_string(&MlDsaLevel::L87).unwrap(), "87");
    let level: MlDsaLevel = serde_json::from_str("44").unwrap();
    assert_eq!(level, MlDsaLevel::L44);
    assert_eq!(MlDsaLevel::try_from(65), Ok(MlDsaLevel::L65));
    assert_eq!(MlDsaLevel::try_from(87), Ok(MlDsaLevel::L87));
    assert!(serde_json::from_str::<MlDsaLevel>("45").is_err());
    let request = MlDsaKeygenRequest {
        level: MlDsaLevel::L65,
    };
    assert_eq!(serde_json::to_value(request).unwrap(), json!({"level": 65}));
}

#[test]
fn kms_encrypt_never_leaves_the_encoding_to_guesswork() {
    let text = KmsEncryptRequest::text("local-1", "00ff");
    assert_eq!(
        serde_json::to_value(&text).unwrap(),
        json!({"keyId": "local-1", "plaintext": "00ff"})
    );
    let bytes = KmsEncryptRequest::bytes("local-1", &[0x00, 0xff]);
    assert_eq!(
        serde_json::to_value(&bytes).unwrap(),
        json!({"keyId": "local-1", "plaintext": "00ff", "encoding": "hex"})
    );
}

#[test]
fn optional_members_are_left_out_and_renamed_ones_kept() {
    assert_eq!(serde_json::to_value(Empty {}).unwrap(), json!({}));
    assert_eq!(
        serde_json::to_value(KeyIdRequest::new("k")).unwrap(),
        json!({"keyId": "k"})
    );
    let generate = GenerateKeyPairRequest {
        algorithm: Some(KeyAlgorithm::Ed25519),
        metadata: Some(KeyMetadata {
            kid: Some("kid".into()),
            key_use: Some(KeyUse::Sig),
            exp: None,
        }),
    };
    assert_eq!(
        serde_json::to_value(generate).unwrap(),
        json!({"algorithm": "ed25519", "metadata": {"kid": "kid", "use": "sig"}})
    );
    let kdf = KdfRequest {
        params: Some(KdfParams {
            n: Some(131_072),
            ..KdfParams::default()
        }),
        ..KdfRequest::default()
    };
    assert_eq!(
        serde_json::to_value(kdf).unwrap()["params"],
        json!({"N": 131_072})
    );
    let recipient = Recipient {
        kind: RecipientType::Classical,
        public_key: Hex::from([1u8]),
        ml_kem_public_key: None,
    };
    assert_eq!(
        serde_json::to_value(recipient).unwrap(),
        json!({"type": "classical", "publicKey": "01"})
    );
}

#[test]
fn answers_decode_with_secrets_wrapped() {
    let opened: HpkeOpened =
        serde_json::from_value(json!({"plaintext": "hi", "hex": "6869"})).unwrap();
    assert_eq!(opened.plaintext.expose_secret(), "hi");
    assert_eq!(opened.hex.expose_secret(), b"hi");
    let debug = format!("{opened:?}");
    assert!(
        !debug.contains("hi\"") && !debug.contains("6869"),
        "Debug output is not redacted as required"
    );
    let exported: ExportedKey = serde_json::from_value(json!({
        "keyId": "k", "algorithm": "ed25519", "publicKey": "01", "privateKey": "02",
        "futureSecret": "03"
    }))
    .unwrap();
    assert_eq!(
        exported
            .private_key
            .as_ref()
            .map(SecretBytes::expose_secret),
        Some(&[2u8][..])
    );
    assert!(!format!("{exported:?}").contains("03"));
    let ready: Readiness = serde_json::from_value(json!({
        "status": "ready", "checks": {"accepting": true, "keyStore": true, "kms": false}
    }))
    .unwrap();
    assert_eq!(ready.checks.other.get("kms"), Some(&false));
}
