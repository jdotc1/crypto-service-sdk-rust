// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A 2xx body, decoded as every typed call's answer. It must decode or
//! fail with `Error::Decode` naming only a position, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    crypto_service_sdk_fuzz::check_success(data);
});
