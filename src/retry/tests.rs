// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;

fn policy() -> RetryPolicy {
    RetryPolicy::new()
        .max_retries(3)
        .initial_delay(Duration::from_millis(100))
        .max_delay(Duration::from_millis(1000))
}

#[test]
fn defaults_match_the_typescript_sdk() {
    let p = RetryPolicy::default();
    assert_eq!(p.get_max_retries(), 0);
    assert_eq!(p.get_initial_delay(), Duration::from_millis(200));
    assert_eq!(p.get_max_delay(), Duration::from_secs(2));
}

#[test]
fn backoff_is_full_jitter_under_a_doubling_cap() {
    let p = policy();
    assert_eq!(p.backoff(1, 0), Duration::ZERO);
    assert_eq!(p.backoff(1, u64::MAX), Duration::from_millis(100));
    assert_eq!(p.backoff(2, u64::MAX), Duration::from_millis(200));
    assert_eq!(p.backoff(3, u64::MAX), Duration::from_millis(400));
    assert_eq!(p.backoff(9, u64::MAX), Duration::from_millis(1000));
    assert_eq!(p.backoff(99, u64::MAX), Duration::from_millis(1000));
    let half = p.backoff(1, u64::MAX / 2);
    assert!(half > Duration::from_millis(49) && half < Duration::from_millis(51));
    let huge = RetryPolicy::new()
        .initial_delay(Duration::MAX)
        .max_delay(Duration::MAX);
    assert_eq!(huge.backoff(1, u64::MAX), Duration::from_nanos(u64::MAX));
}

#[test]
fn statuses_follow_the_safety_table() {
    let p = policy();
    for status in [429, 503, 504] {
        assert!(p.after_status(1, status, None, true).is_some(), "{status}");
    }
    assert!(p.after_status(1, 500, None, true).is_none());
    assert!(p.after_status(1, 200, None, true).is_none());
    assert!(p.after_status(4, 503, None, true).is_none());
    assert!(p.after_status(1, 504, None, false).is_none());
    assert!(p.after_status(1, 429, None, false).is_some());
    assert!(p.after_status(1, 503, None, false).is_some());
}

#[test]
fn retry_after_is_honoured_up_to_the_maximum_delay() {
    let p = policy();
    assert_eq!(
        p.after_status(1, 429, Some("1"), true),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        p.after_status(1, 429, Some("0"), true),
        Some(Duration::ZERO)
    );
    assert_eq!(p.after_status(1, 429, Some("2"), true), None);
    let backoff = p.after_status(1, 429, Some("soon"), true).expect("backoff");
    assert!(backoff <= Duration::from_millis(100));
}

#[test]
fn failures_retry_only_idempotent_calls() {
    let p = policy();
    assert!(p.after_failure(1, true).is_some());
    assert!(p.after_failure(3, true).is_some());
    assert!(p.after_failure(4, true).is_none());
    assert!(p.after_failure(1, false).is_none());
}

#[test]
fn the_stateful_table_matches_request_ts() {
    let post = http::Method::POST;
    for path in [
        "/v2/keys/generate",
        "/v2/keys/delete",
        "/v2/pq/keygen",
        "/v2/pq/hybrid/keygen",
        "/v2/pq/dsa/keygen",
        "/v2/pq/slh-dsa/keygen",
        "/v2/hpke/keygen",
        "/v2/kms/create-key",
        "/v2/opaque/register/init",
        "/v2/opaque/register/finish",
    ] {
        assert!(!is_idempotent(&post, path), "{path}");
    }
    for path in [
        "/v2/hash",
        "/v2/keys/export",
        "/v2/opaque/login/init",
        "/v2/sign",
    ] {
        assert!(is_idempotent(&post, path), "{path}");
    }
    assert!(is_idempotent(&http::Method::GET, "/v2/keys/generate"));
}

#[test]
fn retry_after_reads_seconds_and_imf_dates() {
    let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
    assert_eq!(parse_retry_after(" 7 ", now), Some(Duration::from_secs(7)));
    assert_eq!(
        parse_retry_after("99999999999999999999999", now),
        Some(Duration::from_secs(u64::MAX))
    );
    let date = "Sun, 06 Nov 1994 08:49:47 GMT";
    assert_eq!(parse_retry_after(date, now), Some(Duration::from_secs(10)));
    let past = "Sun, 06 Nov 1994 08:49:27 GMT";
    assert_eq!(parse_retry_after(past, now), Some(Duration::ZERO));
}

#[test]
fn retry_after_refuses_anything_else() {
    let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
    assert_eq!(parse_retry_after("", now), None);
    assert_eq!(parse_retry_after("-1", now), None);
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:37 UTC", now),
        None
    );
    assert_eq!(
        parse_retry_after("Sun, 06 Foo 1994 08:49:37 GMT", now),
        None
    );
    assert_eq!(
        parse_retry_after("Sun, xx Nov 1994 08:49:37 GMT", now),
        None
    );
    assert_eq!(
        parse_retry_after("Sun, 06 Nov year 08:49:37 GMT", now),
        None
    );
    assert_eq!(parse_retry_after("Sun, 06 Nov 1994 08:49 GMT", now), None);
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:xx:37 GMT", now),
        None
    );
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 xx:49:37 GMT", now),
        None
    );
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:xx GMT", now),
        None
    );
    assert_eq!(
        parse_retry_after("Thu, 01 Jan 1960 00:00:00 GMT", now),
        None
    );
}

#[test]
fn days_from_civil_handles_leap_years_and_month_starts() {
    assert_eq!(days_from_civil(1970, 0, 1), 0);
    assert_eq!(days_from_civil(2000, 1, 29), 11_016);
    assert_eq!(days_from_civil(2000, 2, 1), 11_017);
    assert_eq!(days_from_civil(1969, 11, 31), -1);
    assert!(random() != random() || random() != random());
}
