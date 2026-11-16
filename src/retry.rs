// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retries of transient failures, with the TypeScript SDK's safety table.

use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When a [`Client`](crate::Client) tries a call again.
///
/// The default retries nothing (`max_retries` 0). With retries on, a call
/// is tried again after a `429`, `503` or `504` answer or a lost
/// connection or attempt timeout, up to `max_retries` more times, except
/// that a call that creates or deletes server state (`keys/generate`,
/// `keys/delete`, every `*/keygen`, `kms/create-key`,
/// `opaque/register/*`) is retried only after a `429` or `503`, when the
/// server certainly did not act on it: after a `504` or a lost connection
/// it may already have.
///
/// The wait before retry `n` (from 1) is full jitter: a random point in
/// `[0, min(max_delay, initial_delay * 2^(n-1))]`. A `Retry-After` header,
/// in seconds or as an HTTP date, is waited exactly instead; one asking
/// for longer than `max_delay` ends the retries and returns that answer.
///
/// ```
/// use crypto_service_sdk::RetryPolicy;
/// use std::time::Duration;
///
/// let policy = RetryPolicy::new()
///     .max_retries(2)
///     .initial_delay(Duration::from_millis(100));
/// assert_eq!(policy.get_max_delay(), Duration::from_secs(2));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_retries: u32,
    initial_delay: Duration,
    max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_retries: 0,
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    /// No retries; 200 ms initial delay and 2 s maximum delay once
    /// [`max_retries`](Self::max_retries) turns them on.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how many times a call may be retried after the first attempt.
    #[must_use]
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the backoff ceiling before the first retry.
    #[must_use]
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the longest wait before any retry, which is also the longest
    /// `Retry-After` honoured.
    #[must_use]
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Retries allowed after the first attempt.
    #[must_use]
    pub fn get_max_retries(&self) -> u32 {
        self.max_retries
    }

    /// The backoff ceiling before the first retry.
    #[must_use]
    pub fn get_initial_delay(&self) -> Duration {
        self.initial_delay
    }

    /// The longest wait before any retry.
    #[must_use]
    pub fn get_max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Full-jitter backoff before retry `retry` (from 1), `random` picking
    /// the point.
    pub(crate) fn backoff(&self, retry: u32, random: u64) -> Duration {
        let shift = retry.saturating_sub(1).min(31);
        let cap = self
            .initial_delay
            .saturating_mul(1 << shift)
            .min(self.max_delay);
        let nanos = u64::try_from(cap.as_nanos()).unwrap_or(u64::MAX);
        let picked = u128::from(random) * u128::from(nanos) / u128::from(u64::MAX);
        Duration::from_nanos(u64::try_from(picked).unwrap_or(nanos))
    }

    /// The wait before retry `retry` after an answer with `status` and
    /// `retry_after`, or `None` when that answer is the result.
    pub(crate) fn after_status(
        &self,
        retry: u32,
        status: u16,
        retry_after: Option<&str>,
        idempotent: bool,
    ) -> Option<Duration> {
        if retry > self.max_retries || !matches!(status, 429 | 503 | 504) {
            return None;
        }
        // A 504 may have been processed upstream; a 429 or 503 was not.
        if !idempotent && status == 504 {
            return None;
        }
        match retry_after.and_then(|v| parse_retry_after(v, SystemTime::now())) {
            Some(wait) if wait > self.max_delay => None,
            Some(wait) => Some(wait),
            None => Some(self.backoff(retry, random())),
        }
    }

    /// The wait before retry `retry` after no answer arrived, or `None`.
    pub(crate) fn after_failure(&self, retry: u32, idempotent: bool) -> Option<Duration> {
        (idempotent && retry <= self.max_retries).then(|| self.backoff(retry, random()))
    }
}

/// Whether repeating `method path` cannot create or delete anything twice:
/// every `GET`, and every route outside the stateful table.
#[must_use]
pub(crate) fn is_idempotent(method: &http::Method, path: &str) -> bool {
    method == http::Method::GET || !is_stateful(path)
}

/// The routes that create or delete server state (`request.ts`'s
/// `STATEFUL_ROUTE`).
fn is_stateful(path: &str) -> bool {
    path.contains("/keygen")
        || path.contains("/keys/generate")
        || path.contains("/keys/delete")
        || path.contains("/kms/create-key")
        || path.contains("/opaque/register/")
}

/// A random `u64` for jitter, from the standard library's per-process
/// random hash keys; no dependency, and enough to spread retries.
pub(crate) fn random() -> u64 {
    RandomState::new().hash_one(SystemTime::now())
}

/// A `Retry-After` value as a wait from `now`: delta-seconds, or an
/// IMF-fixdate (RFC 9110, section 10.2.3). A date in the past is no wait.
pub(crate) fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = http_date(value)?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// An IMF-fixdate, `Sun, 06 Nov 1994 08:49:37 GMT`, as a time. The
/// obsolete RFC 850 and asctime forms are not read.
fn http_date(value: &str) -> Option<SystemTime> {
    let fields: Vec<&str> = value.split(' ').collect();
    let [_weekday, day, month, year, time, "GMT"] = fields.as_slice() else {
        return None;
    };
    let month = MONTHS.iter().position(|m| m == month)?;
    // Four-digit years and two-digit days: u16 and u8 bound the arithmetic.
    let year = i64::from(year.parse::<u16>().ok()?);
    let day = i64::from(day.parse::<u8>().ok()?);
    let seconds = days_from_civil(year, month, day) * 86_400 + seconds_of_day(time)?;
    u64::try_from(seconds)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

/// `HH:MM:SS` as seconds since midnight.
fn seconds_of_day(time: &str) -> Option<i64> {
    let fields: Vec<&str> = time.split(':').collect();
    let [hours, minutes, seconds] = fields.as_slice() else {
        return None;
    };
    let [hours, minutes, seconds] =
        [hours, minutes, seconds].map(|f| f.parse::<u8>().ok().map(i64::from));
    Some(hours? * 3600 + minutes? * 60 + seconds?)
}

/// Days from 1970-01-01 to `year`-`month0 + 1`-`day` in the proleptic
/// Gregorian calendar (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month0: usize, day: i64) -> i64 {
    // Months counted from March, so the leap day ends the year.
    let march = i64::try_from((month0 + 10) % 12).unwrap_or(0);
    let year = if march >= 10 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests;
