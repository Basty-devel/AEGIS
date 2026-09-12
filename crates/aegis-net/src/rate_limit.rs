//! Per-account rate limiting, keyed by a validated
//! [`crate::capability::CapabilityToken`]'s identity. See
//! `AEGIS.Plan.V0.2.md` Section 6.3: "Mailbox nodes validate the token
//! to enforce per-account rate limits — this is the *only* bookkeeping
//! a node performs."
//!
//! # Fixed window, not sliding window — a documented tradeoff
//!
//! [`RateLimiter`] implements the simplest correct scheme: a fixed
//! window per identity, `window_seconds` wide, holding up to
//! `max_requests`. This has the well-known fixed-window "boundary
//! burst" property — an identity can send up to `max_requests` right
//! before a window boundary and another `max_requests` right after,
//! for up to `2 * max_requests` in a span much shorter than
//! `window_seconds`. This is a known, named limitation of fixed-window
//! limiting (a sliding-window log or a token bucket would close it),
//! not an oversight; §6.3 does not specify which scheme to use, and
//! fixed-window is the correct starting point for the *first* pass —
//! tightening it is a scoped, independent future change to this
//! module's internals that would not need to touch its public API
//! shape.
//!
//! # Determinism
//!
//! [`RateLimiter::check_and_record`] takes `now: u64` as an explicit
//! parameter and never reads the system clock — the same discipline
//! [`crate::capability`] follows, for the same reason: deterministic,
//! reproducible tests, with the real wall-clock time supplied by
//! whatever caller (eventually `aegis-net`'s mailbox-facing runtime)
//! actually has one.

use crate::error::NetError;
use std::collections::HashMap;

/// One identity's current fixed-window state.
#[derive(Debug)]
struct WindowState {
    /// The `now` value that opened the current window.
    window_start: u64,
    /// Requests recorded in the current window so far.
    count: u32,
}

/// The outcome of [`RateLimiter::check_and_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// The request is within the identity's current window budget (and
    /// has been recorded as consuming one unit of it).
    Allowed,
    /// The identity's current window budget is exhausted.
    Denied {
        /// Seconds until the current window ends and a fresh one
        /// begins, computed as `window_start + window_seconds - now`.
        retry_after_seconds: u64,
    },
}

/// A fixed-window, per-identity request rate limiter (see the module
/// doc comment for the fixed-vs-sliding-window tradeoff this makes).
#[derive(Debug)]
pub struct RateLimiter {
    window_seconds: u64,
    max_requests: u32,
    windows: HashMap<[u8; 32], WindowState>,
}

impl RateLimiter {
    /// Build a limiter allowing up to `max_requests` requests per
    /// identity in any `window_seconds`-second window.
    ///
    /// `max_requests == 0` is accepted (a limiter that denies every
    /// request for every identity — a legitimate, if degenerate,
    /// configuration, e.g. for an account under active abuse
    /// investigation).
    ///
    /// # Errors
    ///
    /// [`NetError::InvalidRateLimitConfig`] if `window_seconds == 0`: a
    /// zero-length window can never elapse (`now >= window_start +
    /// 0` is true immediately, which would make every single request
    /// open a "fresh" window and reset the count to 1 before the very
    /// next request — see [`Self::check_and_record`]'s window-reset
    /// condition — meaning the limiter would never actually deny
    /// anything past the very first request in flight, which cannot be
    /// what a caller configuring rate limiting wants).
    pub fn new(window_seconds: u64, max_requests: u32) -> Result<Self, NetError> {
        if window_seconds == 0 {
            return Err(NetError::InvalidRateLimitConfig {
                reason: "window_seconds must be at least 1",
            });
        }
        Ok(Self {
            window_seconds,
            max_requests,
            windows: HashMap::new(),
        })
    }

    /// Check whether `identity` may make one more request at time
    /// `now`, and record it if so.
    ///
    /// `identity` is a plain 32-byte key (in practice, a validated
    /// [`crate::capability::CapabilityToken::ed25519_identity`]) rather
    /// than a whole `CapabilityToken` — this module has no dependency
    /// on token validity itself; callers are expected to call this only
    /// after `CapabilityToken::verify` has already succeeded, keeping
    /// the two concerns (is this identity genuine — `capability`; is
    /// this identity within budget — this module) independently
    /// testable, matching how this crate's whole Section 6.3 slice is
    /// scoped.
    pub fn check_and_record(&mut self, identity: &[u8; 32], now: u64) -> RateLimitDecision {
        let state = self.windows.entry(*identity).or_insert(WindowState {
            window_start: now,
            count: 0,
        });

        // A `now` older than the recorded window_start (out-of-order
        // calls, e.g. clock skew between concurrent callers) is treated
        // as still within that window rather than opening a new one:
        // the window is defined by its start plus its fixed width, and
        // "before the window started" is unambiguously still "before
        // the window ended."
        if now >= state.window_start.saturating_add(self.window_seconds) {
            state.window_start = now;
            state.count = 0;
        }

        if state.count < self.max_requests {
            state.count += 1;
            RateLimitDecision::Allowed
        } else {
            let window_end = state.window_start.saturating_add(self.window_seconds);
            RateLimitDecision::Denied {
                retry_after_seconds: window_end.saturating_sub(now),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitDecision, RateLimiter};
    use crate::error::NetError;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];

    #[test]
    fn first_request_in_a_window_is_allowed() {
        let mut limiter = RateLimiter::new(60, 3).unwrap();
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_000),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn the_nth_request_is_allowed_and_the_n_plus_first_is_denied() {
        let mut limiter = RateLimiter::new(60, 3).unwrap();
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_000),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_010),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_020),
            RateLimitDecision::Allowed
        );
        match limiter.check_and_record(&ALICE, 1_030) {
            RateLimitDecision::Denied {
                retry_after_seconds,
            } => {
                // window opened at 1_000, spans 60s -> resets at 1_060
                assert_eq!(retry_after_seconds, 30);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn request_after_the_window_expires_resets_the_count() {
        let mut limiter = RateLimiter::new(60, 1).unwrap();
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_000),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            limiter.check_and_record(&ALICE, 1_030),
            RateLimitDecision::Denied { .. }
        ));
        // Exactly at the boundary: window_start(1000) + window(60) = 1060.
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_060),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn two_identities_have_independent_buckets() {
        let mut limiter = RateLimiter::new(60, 1).unwrap();
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_000),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            limiter.check_and_record(&ALICE, 1_010),
            RateLimitDecision::Denied { .. }
        ));
        // Bob's own first request in the same window must still be
        // allowed — Alice's usage must not bleed into Bob's bucket.
        assert_eq!(
            limiter.check_and_record(&BOB, 1_010),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn zero_max_requests_denies_every_request() {
        let mut limiter = RateLimiter::new(60, 0).unwrap();
        assert!(matches!(
            limiter.check_and_record(&ALICE, 1_000),
            RateLimitDecision::Denied { .. }
        ));
    }

    #[test]
    fn zero_window_seconds_is_rejected_at_construction() {
        let err = RateLimiter::new(0, 10).unwrap_err();
        assert!(matches!(err, NetError::InvalidRateLimitConfig { .. }));
    }

    #[test]
    fn decisions_depend_only_on_the_supplied_now_not_wall_clock() {
        // Two independently constructed limiters, fed the identical
        // (identity, now) sequence, must reach identical decisions —
        // proof that nothing here reads the real clock.
        let mut limiter_a = RateLimiter::new(10, 2).unwrap();
        let mut limiter_b = RateLimiter::new(10, 2).unwrap();
        let schedule = [1_000u64, 1_002, 1_004, 1_015, 1_020];
        let decisions_a: Vec<_> = schedule
            .iter()
            .map(|&now| limiter_a.check_and_record(&ALICE, now))
            .collect();
        let decisions_b: Vec<_> = schedule
            .iter()
            .map(|&now| limiter_b.check_and_record(&ALICE, now))
            .collect();
        assert_eq!(decisions_a, decisions_b);
    }

    #[test]
    fn requests_out_of_order_within_the_same_window_still_count_correctly() {
        // A caller presenting `now` values that aren't monotonically
        // increasing (clock skew between concurrent callers, e.g.) must
        // not panic or corrupt the bucket; it degrades gracefully to
        // treating the window as still open as long as the given `now`
        // is within `window_start..window_start + window_seconds`.
        let mut limiter = RateLimiter::new(60, 2).unwrap();
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_010),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_and_record(&ALICE, 1_005),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            limiter.check_and_record(&ALICE, 1_008),
            RateLimitDecision::Denied { .. }
        ));
    }
}
