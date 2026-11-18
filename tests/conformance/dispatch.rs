// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sends a vector through the SDK method for its route, when the vector's
//! body is exactly what that method's request type sends.

use std::future::Future;

use crypto_service_sdk::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::template::same;

/// A typed call's outcome: the answer re-encoded as JSON, or the error.
pub type Typed = Result<Value, Error>;

/// `request` as the typed `R`, when it encodes back to exactly `body`;
/// `None` when the vector sends something the type cannot (an unknown
/// member, an invalid encoding, a missing field).
pub fn typed_request<R: DeserializeOwned + Serialize>(body: &Value) -> Option<R> {
    let request: R = serde_json::from_value(body.clone()).ok()?;
    let encoded = serde_json::to_value(&request).ok()?;
    same(&encoded, body).then_some(request)
}

fn json<T: Serialize>(result: Result<T, Error>) -> Typed {
    result.map(|value| serde_json::to_value(value).expect("answers encode"))
}

/// Decodes `body` as `R` and, when that is exact, makes the call.
async fn post<R, T, F, Fut>(body: &Value, call: F) -> Option<Typed>
where
    R: DeserializeOwned + Serialize,
    T: Serialize,
    F: FnOnce(R) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let request = typed_request::<R>(body)?;
    Some(json(call(request).await))
}

/// The typed call for `method path` with `body`, or `None` when there is
/// no method for the route or the body is not expressible.
pub async fn call(client: &Client, method: &str, path: &str, body: &Value) -> Option<Typed> {
    if method == "GET" {
        return get(client, path).await;
    }
    let empty = body.as_object().is_some_and(serde_json::Map::is_empty);
    match without_body(client, path, empty).await {
        Some(result) => Some(result),
        None => post_route(client, path, body).await,
    }
}

async fn get(client: &Client, path: &str) -> Option<Typed> {
    Some(match path {
        "/" => json(client.root().await),
        "/health" => json(client.health().await),
        "/live" => json(client.live().await),
        "/ready" => json(client.ready().await),
        "/v2/algorithms" => json(client.algorithms().await),
        "/v2/compliance/dora" => json(client.get_dora_compliance().await),
        "/v2/compliance/cbom" => json(client.get_cbom().await),
        _ => return None,
    })
}

/// The two `POST`s whose body is always `{}`.
async fn without_body(client: &Client, path: &str, empty: bool) -> Option<Typed> {
    Some(match (path, empty) {
        ("/v2/pq/keygen", true) => json(client.ml_kem_generate_key_pair().await),
        ("/v2/pq/hybrid/keygen", true) => json(client.pq_generate_key_pair().await),
        _ => return None,
    })
}

/// The route table: path, SDK method, request type.
macro_rules! routes {
    ($($path:literal => $method:ident($request:ty),)*) => {
        async fn post_route(client: &Client, path: &str, body: &Value) -> Option<Typed> {
            match path {
                $($path => post(body, |r: $request| async move { client.$method(&r).await }).await,)*
                _ => None,
            }
        }
    };
}

routes! {
    "/v2/pq/encapsulate" => ml_kem_encapsulate(MlKemEncapsulateRequest),
    "/v2/pq/decapsulate" => ml_kem_decapsulate(MlKemDecapsulateRequest),
    "/v2/pq/hybrid/encapsulate" => pq_encapsulate(HybridEncapsulateRequest),
    "/v2/pq/hybrid/decapsulate" => pq_decapsulate(HybridDecapsulateRequest),
    "/v2/pq/dsa/keygen" => pq_sign_keygen(MlDsaKeygenRequest),
    "/v2/pq/dsa/sign" => pq_sign(SignRequest),
    "/v2/pq/dsa/verify" => pq_verify(MlDsaVerifyRequest),
    "/v2/pq/slh-dsa/keygen" => pq_hash_sign_keygen(SlhDsaKeygenRequest),
    "/v2/pq/slh-dsa/sign" => pq_hash_sign(SignRequest),
    "/v2/pq/slh-dsa/verify" => pq_hash_verify(SlhDsaVerifyRequest),
    "/v2/kms/create-key" => kms_create_key(KmsCreateKeyRequest),
    "/v2/kms/encrypt" => kms_encrypt(KmsEncryptRequest),
    "/v2/kms/decrypt" => kms_decrypt(KmsDecryptRequest),
    "/v2/kms/generate-data-key" => kms_generate_data_key(KmsGenerateDataKeyRequest),
    "/v2/kms/wrap" => kms_wrap(KmsWrapRequest),
    "/v2/kms/unwrap" => kms_unwrap(KmsUnwrapRequest),
    "/v2/stream/sign" => stream_sign(StreamSignRequest),
    "/v2/stream/verify" => stream_verify(StreamVerifyRequest),
    "/v2/stream/iso20022" => stream_iso20022(Iso20022VerifyRequest),
    "/v2/stream/pq-encrypt" => stream_pq_encrypt(StreamPqEncryptRequest),
    "/v2/stream/pq-decrypt" => stream_pq_decrypt(StreamPqDecryptRequest),
    "/v2/stream/multi-pq-encrypt" => stream_multi_pq_encrypt(StreamMultiPqEncryptRequest),
    "/v2/stream/multi-pq-decrypt" => stream_multi_pq_decrypt(StreamMultiPqDecryptRequest),
    "/v2/opaque/register/init" => opaque_register_init(OpaqueRegisterInitRequest),
    "/v2/opaque/register/finish" => opaque_register_finish(OpaqueRegisterFinishRequest),
    "/v2/opaque/login/init" => opaque_login_init(OpaqueLoginInitRequest),
    "/v2/opaque/login/finish" => opaque_login_finish(OpaqueLoginFinishRequest),
    "/v2/keys/generate" => generate_key_pair(GenerateKeyPairRequest),
    "/v2/keys/export" => export_key(KeyIdRequest),
    "/v2/keys/delete" => keys_delete(KeyIdRequest),
    "/v2/keys/wrap" => key_wrap(KeyWrapRequest),
    "/v2/keys/unwrap" => key_unwrap(KeyUnwrapRequest),
    "/v2/encrypt" => encrypt(EncryptRequest),
    "/v2/decrypt" => decrypt(DecryptRequest),
    "/v2/secretbox/seal" => secretbox_seal(SecretboxSealRequest),
    "/v2/secretbox/open" => secretbox_open(SecretboxOpenRequest),
    "/v2/password/encrypt" => password_encrypt(PasswordEncryptRequest),
    "/v2/password/decrypt" => password_decrypt(PasswordDecryptRequest),
    "/v2/hash" => hash(HashRequest),
    "/v2/hmac" => mac(MacRequest),
    "/v2/hmac/verify" => mac_verify(MacVerifyRequest),
    "/v2/kdf" => kdf(KdfRequest),
    "/v2/password/hash" => password_hash(PasswordHashRequest),
    "/v2/password/verify" => password_verify(PasswordVerifyRequest),
    "/v2/sign" => sign(SignRequest),
    "/v2/verify" => verify(VerifyRequest),
    "/v2/sealedbox/seal" => sealedbox_seal(SealedboxSealRequest),
    "/v2/sealedbox/open" => sealedbox_open(SealedboxOpenRequest),
    "/v2/sealedbox/seal-pq" => sealedbox_seal_pq(SealedboxSealPqRequest),
    "/v2/sealedbox/open-pq" => sealedbox_open_pq(SealedboxOpenRequest),
    "/v2/multi-recipient/encrypt" => multi_recipient_encrypt(MultiRecipientEncryptRequest),
    "/v2/hpke/keygen" => hpke_generate_key_pair(HpkeKeygenRequest),
    "/v2/hpke/seal" => hpke_seal(HpkeSealRequest),
    "/v2/hpke/open" => hpke_open(HpkeOpenRequest),
}
