// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! An error answer: the first line is the status code, the rest is the
//! body. It must become an `Error::Api` with an RFC 9457 problem, never a
//! panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((status, body)) = crypto_service_sdk_fuzz::split_status(data) {
        crypto_service_sdk_fuzz::check_problem(status, body);
    }
});
