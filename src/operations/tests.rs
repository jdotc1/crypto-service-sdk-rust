// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Every operation reaches its documented method and path.

use std::sync::{Arc, Mutex};

use super::*;
use crate::error::TransportError;
use crate::transport::{BoxFuture, HttpRequest, HttpResponse, Transport};

/// Answers every request with a 500 problem and keeps each request line.
#[derive(Debug, Default)]
struct Routes {
    seen: Mutex<Vec<String>>,
}

impl Transport for Routes {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        let path = request.url.trim_start_matches("http://stub");
        let line = format!(
            "{} {}",
            request.method,
            if path.is_empty() { "/" } else { path }
        );
        self.seen.lock().expect("lock").push(line);
        Box::pin(async {
            Ok(HttpResponse {
                status: 500,
                headers: http::HeaderMap::new(),
                body: Vec::new(),
            })
        })
    }
}

/// Calls every method with a default request.
macro_rules! call_all {
    ($client:expr, $wait:ident; get: [$($get:ident),*]; post: [$($post:ident),*]) => {{
        vec![
            $( $wait!($client.$get()).map(|_| ()), )*
            $( $wait!($client.$post(&Default::default())).map(|_| ()), )*
        ]
    }};
}

macro_rules! every_method {
    ($client:expr, $wait:ident) => {
        call_all!($client, $wait;
            get: [root, health, live, ready, algorithms, get_dora_compliance, get_cbom];
            post: [encrypt, decrypt, hash, mac, mac_verify, kdf, password_hash, password_verify,
                password_encrypt, password_decrypt, secretbox_seal, secretbox_open, key_wrap,
                key_unwrap, generate_key_pair, export_key, keys_delete, sign, verify, stream_sign,
                stream_verify, ml_kem_encapsulate, ml_kem_decapsulate, pq_encapsulate,
                pq_decapsulate, pq_sign_keygen, pq_sign, pq_verify, pq_hash_sign_keygen,
                pq_hash_sign, pq_hash_verify, stream_iso20022, sealedbox_seal, sealedbox_open,
                sealedbox_seal_pq, sealedbox_open_pq, multi_recipient_encrypt, stream_pq_encrypt,
                stream_pq_decrypt, stream_multi_pq_encrypt, stream_multi_pq_decrypt,
                hpke_generate_key_pair, hpke_seal, hpke_open, kms_create_key, kms_encrypt,
                kms_decrypt, kms_generate_data_key, kms_wrap, kms_unwrap, opaque_register_init,
                opaque_register_finish, opaque_login_init, opaque_login_finish]
        )
    };
}

macro_rules! later {
    ($e:expr) => {
        $e.await
    };
}

fn expected() -> Vec<String> {
    let order = |name: &str| ROUTES.iter().position(|(n, _, _)| *n == name);
    let mut routes: Vec<_> = ROUTES.to_vec();
    // The two body-less POSTs are called last, apart from the list.
    routes.sort_by_key(|(name, _, _)| {
        matches!(*name, "ml_kem_generate_key_pair" | "pq_generate_key_pair")
            .then_some(usize::MAX)
            .or(order(name))
    });
    routes.iter().map(|(_, m, p)| format!("{m} {p}")).collect()
}

fn stub() -> (Client, Arc<Routes>) {
    let routes = Arc::new(Routes::default());
    let client = Client::builder("http://stub")
        .transport(routes.clone())
        .build()
        .expect("client");
    (client, routes)
}

#[tokio::test]
async fn every_async_method_reaches_its_route() {
    let (client, routes) = stub();
    let mut outcomes = every_method!(client, later);
    outcomes.push(client.ml_kem_generate_key_pair().await.map(|_| ()));
    outcomes.push(client.pq_generate_key_pair().await.map(|_| ()));
    assert_eq!(outcomes.len(), 63);
    assert!(outcomes
        .iter()
        .all(|o| matches!(o, Err(Error::Api(a)) if a.status == 500)));
    assert_eq!(*routes.seen.lock().unwrap(), expected());
}

#[cfg(feature = "blocking")]
#[test]
fn every_blocking_method_reaches_its_route() {
    macro_rules! now {
        ($e:expr) => {
            $e
        };
    }
    let (client, routes) = stub();
    let client = crate::blocking::Client::from_async(client).expect("blocking");
    let mut outcomes = every_method!(client, now);
    outcomes.push(client.ml_kem_generate_key_pair().map(|_| ()));
    outcomes.push(client.pq_generate_key_pair().map(|_| ()));
    let raw = client.send_raw(crate::RawRequest::new(Method::GET, "/metrics"));
    assert_eq!(raw.expect("raw").status, 500);
    assert_eq!(outcomes.len(), 63);
    assert!(outcomes.iter().all(|o| matches!(o, Err(Error::Api(_)))));
    let mut expected = expected();
    expected.push("GET /metrics".into());
    assert_eq!(*routes.seen.lock().unwrap(), expected);
}

#[test]
fn the_route_table_has_59_v2_operations() {
    let v2 = ROUTES
        .iter()
        .filter(|(_, _, p)| p.starts_with("/v2/"))
        .count();
    assert_eq!(v2, 59);
    assert_eq!(ROUTES.len(), 63);
}
