# Design rationale: AEGIS.Plan.V0.2

Companion notes for [`AEGIS.Plan.V0.2.md`](../../../AEGIS.Plan.V0.2.md),
the improved AegisPQC system prompt. Captures what changed from
`AEGIS.Plan.V0.1` and why, so the reasoning isn't lost if the spec is
revised again later.

## Purpose of the document (unchanged in kind)

This is an AI code-generation system prompt, not human-facing engineering
documentation — improvements were optimized for precision and buildability
by an AI agent, not for narrative readability.

## Key gaps found in v0.1 and how v0.2 resolves them

1. **No adversary/threat model.** v0.1 listed mechanisms (mixnets, sealed
   sender, PQ crypto) without stating what attack each one stops. v0.2 adds
   an explicit threat model (§1) with six named adversaries (A1–A6) that
   every later section's mechanisms map back to.

2. **Undefined decentralized relay/storage economics — the biggest gap.**
   v0.1 required a libp2p mesh over Tor/I2P/Sphinx mixnets *and* a separate
   ephemeral blob-storage layer, with no operator model, incentive story,
   or Sybil resistance — an open research problem even for funded projects.
   v0.2 resolves this concretely: Tor (via `arti`) as the sole v1 transport
   (reusing Tor's already-solved relay incentive/reputation system), plus a
   federated mailbox model for store-and-forward (accountable, named
   operators gossiping a signed directory — not permissionless P2P, not a
   token/staking economy). I2P, a custom mixnet, and full permissionless
   federation are named as explicit post-v1 directions rather than silently
   dropped.

3. **Vague "ZK-Nym" pseudonym system.** Replaced with: identity = public key
   only, plus signed capability tokens for per-account rate limiting. No
   new zero-knowledge proof system needs to be designed/built for v1.

4. **Underspecified crypto details.** The KDF combiner (`HKDF-SHA512(SS_ecc
   || SS_kem)`) had no domain separation or transcript binding — a
   cross-protocol confusion risk even though ML-KEM-1024 is IND-CCA2 secure
   on its own. The chunk nonce ("derived from K_file") wasn't a concrete
   construction. Both are now fully specified (§2).

5. **No guardrail against inventing novel cryptography.** Added §9.1:
   every construction must cite a published reference, tests must use
   official NIST/RFC KAT vectors (not just "deterministic vectors"), and an
   "not independently audited" disclaimer is mandatory until a real audit
   happens. This matters because this spec asks an AI agent to author
   original hybrid-PQC protocol code — a place where clean style and
   passing tests are not the same thing as a sound protocol.

6. **No group messaging or multi-device support**, despite the plan's goal
   of exceeding Signal. Added: sender-keys groups reusing the existing
   pairwise ratchet (§3.1), and a linked-device model with per-device keys
   signed into an account device list (§3.2) — both explicitly deferring
   heavier alternatives (MLS, raw key export) to future revisions.

7. **`#![deny(unsafe_code)] outside cryptographic hardware wrappers`** was
   unrealistic — FFI/JNI/keystore bindings need `unsafe` in more places
   than just crypto wrappers. Scoped realistically in §10: deny at the
   workspace root, narrow documented exceptions in identified
   binding modules only.

## Decisions made explicitly with the user (not just inferred)

- Scope handling: keep **one system prompt**, internally sequenced by
  dependency order (not split into separate phased prompts).
- Zero-fallback hardware-key-isolation policy: **kept strict** (hard
  refuse-to-run) rather than softened to graceful degradation — an
  explicit tradeoff accepted for the project's maximum-security stance.
- Add both group messaging and multi-device support to v1 scope.
- Narrow the transport requirement to Tor-only for v1, with I2P/mixnet as
  named future pluggable transports rather than building all three now.

## Non-decisions / open items for a future pass

- The federated mailbox node model is a concrete v1 answer, not a final
  one — full permissionless federation with crypto-economic Sybil
  resistance is explicitly named as future work, not designed here.
- No third-party cryptographic audit has occurred; the disclaimer
  requirement in §9.1 stands until one does.
- This document is the deliverable itself (an improved prompt), not an
  implementation plan — turning it into an actual phased implementation
  plan (writing-plans) is a separate future task if/when implementation
  of AegisPQC begins.
