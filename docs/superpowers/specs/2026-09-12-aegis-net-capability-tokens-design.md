# aegis-net: Capability Tokens & Per-Account Rate Limiting (Section 6.3) — Design

Implements `AEGIS.Plan.V0.2.md` Section 6, narrowed to **Section 6.3
only**. Depends only on `aegis-crypto` (path dependency, currently
0.1.4), matching Section 10's mandatory build order (`aegis-net` is
the fifth crate, after `aegis-crypto` → `aegis-ratchet` → `aegis-vault`
→ `aegis-file` → `aegis-net`; nothing later in the order depends on it
yet).

**Naming note:** this doc originally called itself "Phase 1." Section
6.1 (Tor transport) is being designed and built as an independent,
concurrent track rather than a later phase of this one — see
`2026-09-12-aegis-net-transport-phase1-design.md`. The two do not
depend on each other (this doc's Section 0 already establishes 6.3 has
no transport dependency), so both are titled by section number instead
of a shared phase sequence that would wrongly imply one blocks the
other.

## 0. Phase Scope

Section 6 covers three genuinely separable concerns, unlike Section
5's (`aegis-file`) single self-contained streaming+integrity pair:

1. **Section 6.1 — Tor/arti transport.** Onion-routed connectivity
   between clients and mailbox nodes.
2. **Section 6.2 — Federated mailbox gossip.** Node-to-node message
   relay/gossip, with "a user's identity is simply their public key."
3. **Section 6.3 — Capability tokens & rate limiting.** "Each account
   holds a signed, rate-limited capability token from its identity
   key. Mailbox nodes validate the token to enforce per-account rate
   limits — this is the *only* bookkeeping a node performs."

Phase 1 builds **6.3 only**: token issuance/verification
([`capability`](../../crates/aegis-net/src/capability.rs)) and the
per-identity rate-limit bookkeeping the tokens gate
([`rate_limit`](../../crates/aegis-net/src/rate_limit.rs)). This is
the narrowest slice of Section 6 that is simultaneously: (a) fully
self-contained — no dependency on a Tor client, no assumption of a
running mailbox node, no network I/O of any kind, so it is provable by
pure unit tests exactly like `aegis-crypto`/`aegis-file` were; and (b)
a genuine prerequisite for both of the other two — 6.1's transport and
6.2's gossip both need *something* to authenticate and rate-limit
against a peer, and 6.3 is that something, defined independently of
which transport eventually carries it.

**Explicitly out of scope for this doc:**

- **6.1 (Tor/arti transport)** — pulls in an external onion-routing
  dependency and async networking, a different engineering surface
  entirely from the pure/synchronous style every crate in this
  workspace has used so far. Mixing it into this doc would combine
  "provable by unit test" work with "needs an integration-test harness
  and a real or simulated Tor circuit" work, diluting both — it is
  being designed and built as its own independent track instead (see
  the naming note above), not deferred behind this one.
- **6.2 (federated mailbox gossip)** — a stateful, multi-node protocol
  (message propagation, node discovery, the actual mailbox storage/TTL
  behaviour). It is a natural *consumer* of 6.3's tokens (a node
  gossiping on a user's behalf still needs to prove and rate-limit
  that user), so building 6.3 first, with a stable public API, lets
  6.2's future design treat capability tokens as a settled dependency
  rather than co-evolving both at once.

This mirrors `aegis-file`'s own phase-1 scoping note (Section 5's
72-hour relay TTL deferred to `aegis-net`): each crate's contract ends
at its own well-defined boundary, and what's out of scope this phase
is recorded rather than silently absent.

## 1. Capability Tokens: Self-Certifying, Not Registry-Backed

Per spec Section 6.2's "a user's identity is simply their public key,"
a `CapabilityToken` is **self-certifying**: it carries its own claimed
Ed25519 + ML-DSA-87 public keys, and `verify` proves only that
whoever produced the token holds the matching private keys. A mailbox
node validating a token does not need to already know the account —
there is no registry lookup, no identity-provisioning step this crate
is responsible for. This is a deliberate consequence of adopting
6.2's identity model one section early: 6.3's token design only makes
sense given 6.2's "identity = public key" premise, even though the
gossip protocol built on top of it is deferred.

## 2. Wire Format

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

Every variable-length field is `u16`-big-endian length-framed, even
though only `ml_dsa87_pub`/`ml_dsa87_sig` vary in practice — the same
anti-ambiguity discipline `aegis_crypto::kdf::derive_key`'s doc comment
explains: an unframed variable-length field lets two logically
different inputs serialise to identical bytes, which would let two
different tokens collide onto the same signed payload. The signed
payload itself (`capability::signing_payload`) additionally prefixes a
crate-local domain-separation label (`AEGIS-NET-v1-capability-token`)
and a protocol version byte, distinct from every other domain label
used elsewhere in this workspace
(`aegis_crypto::sas::SAS_CONTEXT`, `aegis-file`'s chunk AAD label), so
a signature produced for one purpose can never be replayed as valid
for another.

**Dual signature, both components required.** `verify_dual` (from
`aegis_crypto::signature`) requires both the Ed25519 and ML-DSA-87
signature to verify — a token is rejected if either component alone
fails, matching every other dual-signed construction in this
workspace. This is what makes the token secure against both a
classical and a post-quantum adversary independently; breaking either
signature scheme alone does not forge a token.

## 3. Why Every Timestamp Is Caller-Supplied

`CapabilityToken::issue` takes `issued_at: u64`;
`CapabilityToken::verify` takes `now: u64`; `RateLimiter::check_and_record`
takes `now: u64`. None of the three ever calls `SystemTime::now()`
internally — the same discipline `aegis-crypto`/`aegis-file` already
follow wherever freshness or ordering matters. This keeps all three a
pure function of their inputs: every boundary case in the test suite
(exact-expiry, exact-window-reset) is deterministic and reproducible
rather than racing the real clock, and
`rate_limit::tests::decisions_depend_only_on_the_supplied_now_not_wall_clock`
exists specifically to pin this — two independently constructed
limiters fed an identical `(identity, now)` sequence must reach
identical decisions.

## 4. Check Ordering in `verify`: Authenticate Before You Trust

This is the one place Phase 1 development surfaced and fixed a real
design bug, not just implemented to a pre-written spec.

The first working implementation of `CapabilityToken::verify` checked
the structural invariant `issued_at <= expires_at` **before**
verifying the dual signature — a natural "cheap check first" ordering.
Every field on a freshly-`from_bytes`-decoded token is
attacker-controlled until the signature check passes, though, so this
meant control flow could branch on unauthenticated wire bytes: a
`tampering_issued_at_after_encoding_fails_verification` test (flip one
byte of the encoded `issued_at`) exposed this directly — the tampered
byte happened to push `issued_at` above `expires_at`, so `verify`
returned `NetError::InvalidValidityWindow` instead of the
`NetError::SignatureInvalid` the test expected. The token was still
correctly *rejected* either way — this was never an authentication
bypass — but the ordering was the wrong general habit: a node should
never make a trust decision using a field it has not yet authenticated,
even when today's specific consequence is harmless.

**Fix:** `verify` now checks the dual signature first, and only
consults `issued_at`/`expires_at` for the structural and temporal
checks afterward, once authenticity is established. See the `verify`
doc comment in [`capability.rs`](../../crates/aegis-net/src/capability.rs)
for the in-code rationale.

**Assertion-strength gap this fix exposed, and how it was closed.**
Reordering the checks meant every *existing* "inverted window" test
(all of which tamper an already-signed, already-encoded token) now
gets caught by the signature check before ever reaching the structural
check — because tampering `issued_at` post-encoding necessarily also
invalidates the signature, since `issued_at` is part of the signed
payload. That left the structural check provably untested: nothing in
the suite proved it does independent work rather than being dead code
permanently shadowed by the signature check. `CapabilityToken::issue`
itself can never produce a token with `issued_at > expires_at` (it
rejects such a window before signing), so the gap was closed with
`genuinely_signed_token_with_inverted_window_is_rejected_by_structural_check`
— a test that bypasses `issue` entirely, hand-builds the signed
payload via the crate-internal `signing_payload` function, signs it
with a real keypair, and constructs a `CapabilityToken` via its
(private-field, same-module-accessible) struct literal. This is the
only test in the suite that reaches inside `issue`'s normal
construction path, and it exists specifically because the mutation
(deleting the structural check) would otherwise survive every other
test unnoticed.

## 5. Rate Limiting: Fixed Window, a Documented Tradeoff

`RateLimiter` implements the simplest correct scheme — a fixed window
per identity, `window_seconds` wide, holding up to `max_requests`.
This has the well-known fixed-window "boundary burst" property: an
identity can send up to `max_requests` right before a window boundary
and another `max_requests` right after, for up to `2 * max_requests`
in a span much shorter than `window_seconds`. Section 6.3 does not
specify which limiting scheme to use, and fixed-window is the correct
starting point for a first pass — it is the scheme every other
production messaging system's rate limiter starts with, it is exactly
as easy to reason about and test as its boundary behaviour suggests,
and tightening it later (a sliding-window log, a token bucket) is a
scoped, internal-only change that would not need to touch
`RateLimiter`'s public API (`new`, `check_and_record`,
`RateLimitDecision`).

Identity in `check_and_record` is a plain `[u8; 32]` — in practice, a
`CapabilityToken::ed25519_identity()` the caller has already run
through `verify` — not a whole `CapabilityToken`. This deliberately
keeps the two 6.3 concerns independently testable: "is this identity
genuine" (`capability`) and "is this identity within budget"
(`rate_limit`) have zero code-level coupling, only a documented
calling convention (verify, then rate-limit).

`RateLimiter::new` rejects `window_seconds == 0` at construction — a
zero-length window can never elapse (`now >= window_start + 0` is true
immediately), which would make every single request open a "fresh"
window and reset the count before the very next request arrives,
silently defeating rate limiting rather than erroring loudly.
`max_requests == 0` is accepted, deliberately: a limiter that denies
every request for a given identity is a legitimate (if degenerate)
configuration — e.g. for an account already flagged for abuse.

## 6. Error Handling

`NetError`, `#[non_exhaustive]`, `From<aegis_crypto::CryptoError>` for
the underlying primitive-level failure layer. Every variant carries
only length/timestamp/shape information a peer already controls or
could derive from the token it presented — never secret-dependent
detail — so rendering or logging a `NetError` cannot leak key material.
`Truncated` vs. `MalformedLength` are kept as distinct variants (both
panic-free, distinguished only by which check a given malformed input
trips first) so a caller can tell "the buffer was simply short" from
"the declared length was itself implausible" — the same
`Truncated`/length-prefix discipline `aegis-file`'s wire-header parsing
already established, applied here to `capability::take`/`take_framed`.

Nothing in this crate panics on attacker-controlled data — a
malformed wire-encoded token (bad magic, truncated at every possible
prefix length, an implausible length prefix, trailing garbage after a
complete token) always returns `NetError` rather than unwinding. The
one documented exception —
`getrandom::fill`'s fail-closed panic on OS RNG failure inside
`CapabilityToken::issue` — is not attacker-controlled (no wire data
reaches that call) and matches every other fresh-randomness site in
this workspace (`aegis_crypto::aead::ChunkNonceSequence::random`,
`DualKeyPair::generate`).

## 7. Testing Strategy

28 tests, all synchronous and pure — no `#[ignore]` tier, no mock vs.
real-backend split (nothing in this phase touches an OS service the
way `aegis-vault`'s hardware-key-storage tests needed to).

- **`capability` (16 tests)** — issuance succeeds/fails at the
  validity-window boundaries (zero, exactly-max, over-max);
  verification succeeds up to but not including expiry (half-open
  interval, tested at the exact boundary second); round-trip
  encode/decode preserves and re-verifies; tampering `issued_at`,
  tampering the nonce, and substituting a different signer's public
  keys onto another signer's signed fields all fail signature
  verification specifically (not just "fail somehow"); every possible
  truncation prefix length is rejected without panicking (a loop over
  every `cut in 0..bytes.len()`, not a handful of hand-picked cuts);
  trailing garbage, bad magic, and an implausible length prefix are
  each rejected; two issuances of the same identity/window use
  different nonces (issuance is not deterministic); the hand-crafted
  inverted-window test (Section 4 above) proving the structural check
  is not dead code.
- **`rate_limit` (8 tests)** — first request allowed; the Nth request
  allowed and N+1th denied with the correct `retry_after_seconds`;
  a request exactly at the window-reset boundary (`window_start +
  window_seconds`) is allowed (the reset, not the still-open window);
  two identities have fully independent buckets; `max_requests == 0`
  denies immediately; `window_seconds == 0` is rejected at
  construction; determinism (identical `(identity, now)` sequences on
  two independently constructed limiters reach identical decisions);
  out-of-order `now` values within a window (clock skew between
  concurrent callers) do not panic or corrupt the bucket.
- **`error`/`lib` (4 tests)** — `Display` renders offending values,
  `NetError: std::error::Error`, `CryptoError` converts via `From`,
  the `SECURITY_DISCLAIMER` states "NOT independently audited."

All 28 pass (`cargo test -p aegis-net`); `cargo clippy -p aegis-net
--all-targets -- -D warnings` (the workspace's CI lint level) is
clean; `cargo fmt` applied.

**Assertion-strength check.** Beyond the structural-check gap in
Section 4 (found and closed), the following core branches were
manually inverted and confirmed to be caught by an existing test: the
`RateLimiter` window-reset condition (`now >= window_start +
window_seconds`) — inverting to strict `>` is caught by
`request_after_the_window_expires_resets_the_count`'s exact-boundary
assertion; the `state.count < self.max_requests` allow/deny threshold
— inverting to `<=` is caught by
`the_nth_request_is_allowed_and_the_n_plus_first_is_denied`; the
half-open expiry check `now >= self.expires_at` — inverting to `>` is
caught by `token_verifies_up_to_but_not_including_expiry`'s exact
`4_600` boundary. No mutation-testing tool (`cargo mutants`) was
installed for this phase — the manual inversion above is what the TDD
process's assertion-strength step actually ran; a `cargo mutants`
pass remains a reasonable follow-up for higher confidence, but was not
performed here.

## 8. What Is Deliberately Not Here

- **Tor/arti transport (Section 6.1).** No networking of any kind in
  this crate yet — see Section 0.
- **Federated mailbox gossip (Section 6.2), node discovery, message
  relay, and mailbox storage/TTL.** `capability`/`rate_limit` are
  designed to be consumed by that future protocol, not to implement
  it.
- **Sealed Sender 2.0.** Named in this crate's `lib.rs` module doc
  comment as part of `aegis-net`'s eventual scope per spec Section 6,
  but not part of the 6.3 slice this phase builds; deferred alongside
  6.1/6.2.
- **Token revocation / a denylist.** A token is valid until its own
  `expires_at`, full stop — there is no mechanism here to invalidate a
  token early (e.g. on account compromise) before its own declared
  expiry. `MAX_TOKEN_VALIDITY_SECONDS` (24 hours) bounds how long a
  compromised token stays useful without such a mechanism; a shorter
  bound or an explicit revocation list is a future design question for
  whichever phase builds the mailbox-facing runtime that actually
  issues and tracks tokens in production.
