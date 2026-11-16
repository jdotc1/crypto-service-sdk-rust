// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;

#[test]
fn runtime_failure_is_a_config_error() {
    let error = runtime_failed(std::io::Error::other("no threads"));
    assert_eq!(
        error.to_string(),
        "invalid client configuration: the blocking client's runtime could not start"
    );
}

#[test]
fn wraps_the_async_client() {
    let client = Client::new("http://127.0.0.1:9/").expect("client");
    assert_eq!(client.base_url(), "http://127.0.0.1:9");
    assert_eq!(client.inner().base_url(), "http://127.0.0.1:9");
    assert!(Client::new("not a url").is_err());
    assert!(format!("{client:?}").contains("Client"));
}
