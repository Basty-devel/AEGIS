# aegis-net

Capability-token issuance/verification and per-account rate limiting
for [AegisPQC](https://github.com/Basty-devel/AEGIS), a post-quantum
secure messenger. Phase 1 of `AEGIS.Plan.V0.2.md` Section 6, scoped to
**Section 6.3 only** — see
[`docs/superpowers/specs/2026-09-12-aegis-net-phase1-design.md`](../../docs/superpowers/specs/2026-09-12-aegis-net-phase1-design.md)
for why Section 6.1 (Tor transport) and Section 6.2 (federated mailbox
gossip) are out of scope for this phase. Depends on `aegis-crypto`
only.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

A pure, transport-agnostic engine — no networking, no I/O, no
knowledge of Tor/arti or the mailbox gossip protocol. You hand it a
`DualKeyPair` and it hands back a signed, self-certifying token; a
mailbox node hands it a decoded token and a `now`, and it tells the
node whether to trust the token and whether the identity behind it is
still within its request budget.

1. **Capability tokens** ([`capability`](src/capability.rs)) — a
   signed, time-bounded, self-certifying token proving control of an
   Ed25519 + ML-DSA-87 identity keypair, per spec Section 6.3: "Each
   account holds a signed, rate-limited capability token from its
   identity key." [`capability::CapabilityToken::issue`] /
   [`capability::CapabilityToken::verify`] are the whole runtime
   surface; [`capability::CapabilityToken::to_bytes`] /
   [`capability::CapabilityToken::from_bytes`] handle the wire
   encoding.
2. **Rate limiting** ([`rate_limit`](src/rate_limit.rs)) — a
   deterministic, fixed-window, per-identity request limiter. Per
   spec Section 6.3: "Mailbox nodes validate the token to enforce
   per-account rate limits — this is the *only* bookkeeping a node
   performs." [`rate_limit::RateLimiter::check_and_record`] is the
   whole runtime surface.

| Module | Contents |
|---|---|
| [`capability`](src/capability.rs) | `CapabilityToken`, `MAX_TOKEN_VALIDITY_SECONDS` |
| [`rate_limit`](src/rate_limit.rs) | `RateLimiter`, `RateLimitDecision` |
| [`error`](src/error.rs) | `NetError` |

## Wire format (capability token)

```text
offset  size  field
0       4     magic: b"CAP1"
4       32    ed25519_pub
36      2     ml_dsa87_pub_len, u16 big-endian
38      N     ml_dsa87_pub (N = ml_dsa87_pub_len)
38+N    8     issued_at, u64 big-endian, unix seconds
46+N    8     expires_at, u64 big-endian, unix seconds
54+N    16    nonce
70+N    64    ed25519 signature
134+N   2     ml_dsa87_sig_len, u16 big-endian
136+N   M     ml_dsa87 signature (M = ml_dsa87_sig_len)
```

A token is self-certifying, in the same spirit as spec Section 6.2's
"a user's identity is simply their public key": it carries its own
claimed public keys, and `verify` proves only that whoever produced
the token holds the matching private keys — a mailbox node does not
need to already know the account to validate a token presented to it.

## Why every timestamp is caller-supplied

Neither `CapabilityToken::issue`/`verify` nor `RateLimiter::check_and_record`
ever calls `SystemTime::now()`. Every timestamp (`issued_at`,
`expires_at`, `now`) is a plain `u64` parameter, supplied by the
caller (eventually `aegis-net`'s mailbox-facing runtime). This keeps
both modules pure functions of their inputs — deterministic,
reproducible tests, with no dependency on wall-clock time or system
clock skew during verification.

## Verify before you trust: check ordering in `CapabilityToken::verify`

`verify` checks the dual signature *first*, and only trusts
`issued_at`/`expires_at` for the structural (`issued_at <= expires_at`)
and temporal (`now < expires_at`) checks that follow *after* the
signature has already proven authenticity. An earlier draft of this
method checked the structural invariant before the signature — every
field on a freshly-decoded token is attacker-controlled until
signature verification passes, so branching on it first is the wrong
general habit even in cases (like this one) where the outcome is
still a rejection either way. See the `verify` doc comment for the
full rationale, and
[`capability::tests::genuinely_signed_token_with_inverted_window_is_rejected_by_structural_check`]
for a test that proves the structural check still does independent
work, by hand-constructing a genuinely-signed token that
`CapabilityToken::issue` itself could never produce.

## Rate limiting: fixed window, not sliding window

[`rate_limit::RateLimiter`] implements a fixed window per identity —
the simplest correct scheme, with the well-known "boundary burst"
property (up to `2 * max_requests` in a span much shorter than
`window_seconds`, if a client times its requests around a window
boundary). This is a documented, known tradeoff, not an oversight; see
the `rate_limit` module doc comment. Tightening it to a sliding-window
log or token bucket is a scoped, independent future change that would
not need to touch the public API shape.

## Error handling

Nothing in this crate panics on data an attacker controls — a
malformed wire-encoded token, a tampered/truncated/trailing-garbage
token, or an expired/not-yet-issued window all return
[`error::NetError`] (`#[non_exhaustive]`).

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use;
commercial use requires a separate license.
