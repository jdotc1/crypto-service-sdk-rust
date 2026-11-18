// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One method per operation, generated for the async [`Client`] and, with
//! the `blocking` feature, for `blocking::Client`. Names follow the
//! TypeScript SDK where it has the operation, and the `operationId`
//! otherwise.

use http::Method;

use crate::client::Client;
use crate::error::Error;
// Every type of the module is some operation's request or answer.
#[allow(clippy::wildcard_imports)]
use crate::types::*;
use crate::{SecretBytes, SecretString};

/// Defines each operation as an async method on [`Client`] and a blocking
/// method on `blocking::Client`. `POST` operations take a request; `GET`
/// ones, and `POST`s whose body is always `{}`, take none. `data` marks an
/// answer wrapped in `{ "data": ... }`, `bare` one that is not.
macro_rules! operations {
    ($(
        $(#[doc = $doc:literal])*
        fn $name:ident($($req:ty)?) -> $res:ty = $method:ident $path:literal $wrap:ident;
    )*) => {
        impl Client {
            $(
                $(#[doc = $doc])*
                #[doc = concat!("\n\n`", stringify!($method), " ", $path, "`.")]
                #[doc = "\n\n# Errors\n\n[`Error::Api`] for a non-2xx answer, [`Error::Transport`] when none arrived, [`Error::Decode`] for a 2xx body of the wrong shape."]
                pub async fn $name(&self $(, request: &$req)?) -> Result<$res, Error> {
                    let body = operations!(@body $method $(, { let request: &$req = request; request })?);
                    operations!(@call $wrap, self, Method::$method, $path, body)
                }
            )*
        }

        #[cfg(feature = "blocking")]
        impl crate::blocking::Client {
            $(
                $(#[doc = $doc])*
                #[doc = concat!("\n\n`", stringify!($method), " ", $path, "`, blocking the calling thread.")]
                #[doc = "\n\n# Errors\n\nAs the async method of the same name."]
                pub fn $name(&self $(, request: &$req)?) -> Result<$res, Error> {
                    self.block_on(self.inner().$name($({ let request: &$req = request; request })?))
                }
            )*
        }

        /// Every operation's method and path, for the tests.
        #[cfg(test)]
        pub(crate) const ROUTES: &[(&str, &str, &str)] = &[
            $((stringify!($name), stringify!($method), $path)),*
        ];
    };
    (@body GET) => { None::<&Empty> };
    (@body POST) => { Some(&Empty {}) };
    (@body POST, $request:expr) => { Some($request) };
    (@call data, $client:expr, $($args:expr),*) => { $client.call_data($($args),*).await };
    (@call bare, $client:expr, $($args:expr),*) => { $client.call($($args),*).await };
}

operations! {
    /// What the service is: name, version, licence.
    fn root() -> ServiceInfo = GET "/" bare;
    /// Liveness and uptime.
    fn health() -> Health = GET "/health" bare;
    /// Whether the process is alive.
    fn live() -> Liveness = GET "/live" bare;
    /// Whether the server accepts requests; `503` (an [`Error::Api`]) when
    /// it does not.
    fn ready() -> Readiness = GET "/ready" bare;
    /// The algorithm catalogue, by category.
    fn algorithms() -> Algorithms = GET "/v2/algorithms" data;
    /// The self-reported DORA inventory; not a compliance assessment.
    fn get_dora_compliance() -> DoraCompliance = GET "/v2/compliance/dora" data;
    /// The CycloneDX 1.6 cryptographic bill of materials.
    fn get_cbom() -> Cbom = GET "/v2/compliance/cbom" bare;

    /// XChaCha20-Poly1305 under a caller-held key.
    fn encrypt(EncryptRequest) -> Ciphertext = POST "/v2/encrypt" data;
    /// Opens what [`Client::encrypt`] produced.
    fn decrypt(DecryptRequest) -> Plaintext = POST "/v2/decrypt" data;
    /// A digest of the UTF-8 bytes of the data.
    fn hash(HashRequest) -> HashResult = POST "/v2/hash" data;
    /// An HMAC of the UTF-8 bytes of the data.
    fn mac(MacRequest) -> MacResult = POST "/v2/hmac" data;
    /// Whether an HMAC tag holds.
    fn mac_verify(MacVerifyRequest) -> Verification = POST "/v2/hmac/verify" data;
    /// scrypt, HKDF-SHA256 or PBKDF2-SHA256.
    fn kdf(KdfRequest) -> KdfResult = POST "/v2/kdf" data;
    /// An Argon2id password hash.
    fn password_hash(PasswordHashRequest) -> PasswordHashResult = POST "/v2/password/hash" data;
    /// Whether a password matches an Argon2id hash.
    fn password_verify(PasswordVerifyRequest) -> PasswordVerifyResult = POST "/v2/password/verify" data;
    /// Argon2id and XChaCha20-Poly1305 under a password.
    fn password_encrypt(PasswordEncryptRequest) -> PasswordEncryptResult = POST "/v2/password/encrypt" data;
    /// Opens a password envelope; the answer is the plaintext.
    fn password_decrypt(PasswordDecryptRequest) -> SecretString = POST "/v2/password/decrypt" data;
    /// XChaCha20-Poly1305 with associated data.
    fn secretbox_seal(SecretboxSealRequest) -> Sealed = POST "/v2/secretbox/seal" data;
    /// Opens a secretbox; the answer is the plaintext.
    fn secretbox_open(SecretboxOpenRequest) -> SecretString = POST "/v2/secretbox/open" data;
    /// AES-KW or AES-KWP key wrap.
    fn key_wrap(KeyWrapRequest) -> KeyWrapResult = POST "/v2/keys/wrap" data;
    /// AES-KW or AES-KWP key unwrap; the answer is the key.
    fn key_unwrap(KeyUnwrapRequest) -> SecretBytes = POST "/v2/keys/unwrap" data;

    /// A key pair whose private key stays on the server. Retried only
    /// after `429` or `503`.
    fn generate_key_pair(GenerateKeyPairRequest) -> GeneratedKeyPair = POST "/v2/keys/generate" data;
    /// The private parts of a key pair this principal generated; needs
    /// the `crypto:keys:export` scope, which `crypto:admin` lacks.
    fn export_key(KeyIdRequest) -> ExportedKey = POST "/v2/keys/export" data;
    /// Deletes a key pair this principal generated. Retried only after
    /// `429` or `503`.
    fn keys_delete(KeyIdRequest) -> DeletedKey = POST "/v2/keys/delete" data;
    /// An Ed25519 signature with a server-held key.
    fn sign(SignRequest) -> Signature = POST "/v2/sign" data;
    /// Whether an Ed25519 signature holds.
    fn verify(VerifyRequest) -> Verification = POST "/v2/verify" data;
    /// Ed25519 signatures over many messages.
    fn stream_sign(StreamSignRequest) -> StreamSignResult = POST "/v2/stream/sign" data;
    /// Checks many Ed25519 signatures.
    fn stream_verify(StreamVerifyRequest) -> StreamVerifyResult = POST "/v2/stream/verify" data;

    /// An ML-KEM-768 key pair held by the server. Retried only after
    /// `429` or `503`.
    fn ml_kem_generate_key_pair() -> KeyPair = POST "/v2/pq/keygen" data;
    /// A shared secret and ciphertext for an ML-KEM-768 public key.
    fn ml_kem_encapsulate(MlKemEncapsulateRequest) -> MlKemEncapsulation = POST "/v2/pq/encapsulate" data;
    /// The shared secret, with a server-held ML-KEM-768 key.
    fn ml_kem_decapsulate(MlKemDecapsulateRequest) -> SharedSecret = POST "/v2/pq/decapsulate" data;
    /// An X25519 and ML-KEM-768 hybrid key pair held by the server.
    /// Retried only after `429` or `503`.
    fn pq_generate_key_pair() -> HybridKeyPair = POST "/v2/pq/hybrid/keygen" data;
    /// A combined shared secret for a hybrid public key.
    fn pq_encapsulate(HybridEncapsulateRequest) -> HybridEncapsulation = POST "/v2/pq/hybrid/encapsulate" data;
    /// The combined shared secret, with a server-held hybrid key.
    fn pq_decapsulate(HybridDecapsulateRequest) -> SharedSecret = POST "/v2/pq/hybrid/decapsulate" data;
    /// An ML-DSA key pair held by the server. Retried only after `429` or
    /// `503`.
    fn pq_sign_keygen(MlDsaKeygenRequest) -> KeyPair = POST "/v2/pq/dsa/keygen" data;
    /// An ML-DSA signature with a server-held key.
    fn pq_sign(SignRequest) -> Signature = POST "/v2/pq/dsa/sign" data;
    /// Whether an ML-DSA signature holds.
    fn pq_verify(MlDsaVerifyRequest) -> Verification = POST "/v2/pq/dsa/verify" data;
    /// An SLH-DSA key pair held by the server. Retried only after `429` or
    /// `503`.
    fn pq_hash_sign_keygen(SlhDsaKeygenRequest) -> KeyPair = POST "/v2/pq/slh-dsa/keygen" data;
    /// An SLH-DSA signature with a server-held key.
    fn pq_hash_sign(SignRequest) -> Signature = POST "/v2/pq/slh-dsa/sign" data;
    /// Whether an SLH-DSA signature holds.
    fn pq_hash_verify(SlhDsaVerifyRequest) -> Verification = POST "/v2/pq/slh-dsa/verify" data;
    /// Checks an ISO 20022 envelope's digest and dual signatures.
    fn stream_iso20022(Iso20022VerifyRequest) -> Iso20022Verification = POST "/v2/stream/iso20022" data;

    /// An anonymous X25519 sealed box.
    fn sealedbox_seal(SealedboxSealRequest) -> Sealed = POST "/v2/sealedbox/seal" data;
    /// Opens a sealed box with a server-held X25519 key; the answer is the
    /// plaintext.
    fn sealedbox_open(SealedboxOpenRequest) -> SecretString = POST "/v2/sealedbox/open" data;
    /// A hybrid X25519 and ML-KEM-768 sealed box.
    fn sealedbox_seal_pq(SealedboxSealPqRequest) -> Sealed = POST "/v2/sealedbox/seal-pq" data;
    /// Opens a hybrid sealed box with a server-held hybrid key; the answer
    /// is the plaintext.
    fn sealedbox_open_pq(SealedboxOpenRequest) -> SecretString = POST "/v2/sealedbox/open-pq" data;
    /// One ciphertext with a wrapped key per recipient.
    fn multi_recipient_encrypt(MultiRecipientEncryptRequest) -> MultiRecipientCiphertext = POST "/v2/multi-recipient/encrypt" data;
    /// Chunked hybrid post-quantum encryption.
    fn stream_pq_encrypt(StreamPqEncryptRequest) -> Ciphertext = POST "/v2/stream/pq-encrypt" data;
    /// Opens a hybrid post-quantum stream with a server-held key.
    fn stream_pq_decrypt(StreamPqDecryptRequest) -> Plaintext = POST "/v2/stream/pq-decrypt" data;
    /// A hybrid post-quantum stream for several recipients.
    fn stream_multi_pq_encrypt(StreamMultiPqEncryptRequest) -> MultiPqCiphertext = POST "/v2/stream/multi-pq-encrypt" data;
    /// Opens a multi-recipient stream with a server-held key.
    fn stream_multi_pq_decrypt(StreamMultiPqDecryptRequest) -> MultiPqPlaintext = POST "/v2/stream/multi-pq-decrypt" data;

    /// An HPKE key pair held by the server. Retried only after `429` or
    /// `503`.
    fn hpke_generate_key_pair(HpkeKeygenRequest) -> KeyPair = POST "/v2/hpke/keygen" data;
    /// HPKE seal to a public key.
    fn hpke_seal(HpkeSealRequest) -> HpkeSealed = POST "/v2/hpke/seal" data;
    /// HPKE open with a server-held key.
    fn hpke_open(HpkeOpenRequest) -> HpkeOpened = POST "/v2/hpke/open" data;

    /// A KMS key. Retried only after `429` or `503`.
    fn kms_create_key(KmsCreateKeyRequest) -> KmsKey = POST "/v2/kms/create-key" data;
    /// KMS encryption.
    fn kms_encrypt(KmsEncryptRequest) -> KmsCiphertext = POST "/v2/kms/encrypt" data;
    /// KMS decryption, as text and bytes.
    fn kms_decrypt(KmsDecryptRequest) -> KmsPlaintext = POST "/v2/kms/decrypt" data;
    /// A data key, in the clear and wrapped.
    fn kms_generate_data_key(KmsGenerateDataKeyRequest) -> KmsDataKey = POST "/v2/kms/generate-data-key" data;
    /// Wraps key bytes under a KMS key.
    fn kms_wrap(KmsWrapRequest) -> KmsWrapped = POST "/v2/kms/wrap" data;
    /// Unwraps a key wrapped under a KMS key.
    fn kms_unwrap(KmsUnwrapRequest) -> KmsUnwrapped = POST "/v2/kms/unwrap" data;

    /// OPAQUE registration, step 1. Retried only after `429` or `503`.
    fn opaque_register_init(OpaqueRegisterInitRequest) -> OpaqueRegisterInitResult = POST "/v2/opaque/register/init" data;
    /// OPAQUE registration, step 2. Retried only after `429` or `503`.
    fn opaque_register_finish(OpaqueRegisterFinishRequest) -> OpaqueRegistered = POST "/v2/opaque/register/finish" data;
    /// OPAQUE login, step 1.
    fn opaque_login_init(OpaqueLoginInitRequest) -> OpaqueLoginInitResult = POST "/v2/opaque/login/init" data;
    /// OPAQUE login, step 2: the session key.
    fn opaque_login_finish(OpaqueLoginFinishRequest) -> OpaqueSession = POST "/v2/opaque/login/finish" data;
}

#[cfg(test)]
mod tests;
