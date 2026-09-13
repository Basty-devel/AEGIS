# aegis-file Phase 1: Chunked AEAD File Streaming & BLAKE3 Merkle Integrity — Design

Implements `AEGIS.Plan.V0.2.md` Section 5. Depends only on `aegis-crypto`
(published, currently 0.1.4) — no dependency on `aegis-ratchet` or
`aegis-vault`, matching Section 10's mandatory build order (`aegis-file`
depends only on `aegis-crypto`; `aegis-net`, not yet started, is what
will depend on `aegis-file`).

## 0. Phase Scope

Section 5 is a single, self-contained concern — a streaming
encrypt/decrypt engine plus an integrity primitive — with no natural
sub-phases the way `aegis-vault`'s hardware-backend breadth had. Phase 1
builds the whole of Section 5:

1. **Chunked AEAD streaming** — 4 MiB fixed chunks, AES-256-GCM or
   ChaCha20-Poly1305 (caller's choice, both already implemented in
   `aegis_crypto::aead`), the nonce construction `aegis-crypto` already
   specifies (random per-file salt ‖ monotonic per-chunk counter, via
   `aegis_crypto::aead::ChunkNonceSequence` — no new nonce scheme
   invented here).
2. **BLAKE3 Merkle tree** — root computation and inclusion proofs over
   ciphertext-chunk hashes.
3. **Bounded 4 MiB transient buffer** — enforced by construction: the
   streaming loop allocates exactly one chunk-sized buffer once, reuses
   it every iteration, and never reads more of the input than one
   chunk at a time.

One narrowing, matching this workspace's established pattern of noting
where a crate's scope stops at its own boundary: `aegis-file` does not
itself talk to `aegis-net`'s mailbox protocol, ephemeral relay storage,
or the 72-hour TTL described in spec Section 5's last bullet — those are
`aegis-net`'s responsibility once it exists (Section 10 build order: it
depends on `aegis-file`, not the reverse). This crate's contract ends at
"here is ciphertext to transport, and here is how to verify what comes
back."

## 1. Streaming Design: Why `plaintext_len` Is a Required Parameter

A generic `Read` does not know its own total length, but the encrypted
container's wire header needs `plaintext_len`/`chunk_count` written
*before* the first chunk for genuine single-pass streaming (writing the
header only after buffering the whole file to learn its length would
violate the "never load a full payload into memory" requirement, just
relocated from the read side to a hypothetical write-side buffer).

`encrypt_stream` therefore takes `plaintext_len: u64` as a caller-supplied
parameter (in practice, `std::fs::metadata(path)?.len()`), and:

- Validates it against the 1 GiB cap **before touching the reader at
  all** — an oversized declared length is rejected with zero I/O
  performed (see
  `stream::tests::declared_length_over_the_cap_is_rejected_without_touching_the_reader`,
  which uses a reader that panics on any `read()` call to prove this).
- Uses it to compute `chunk_count` deterministically
  (`chunk_count_for`), enabling the header to be written immediately.
- Is cross-checked against what the reader actually produces: fewer
  bytes than declared is `FileError::UnexpectedEndOfInput`; more is
  `FileError::TrailingData`. A caller passing a wrong length is a bug in
  the caller, and this crate surfaces it as a typed error rather than
  silently truncating or padding.

This is treated as the correct design, not a workaround: an unbounded or
unknown-length input is itself a resource-exhaustion vector, so requiring
the length be declared and enforced up front is consistent with spec
Section 5's "strict memory bounding" requirement, generalized from
payload buffering to total-size enforcement.

## 2. Wire Container Format

```text
offset  size  field
0       4     magic: b"AGF1"
4       1     algorithm: 0 = AES-256-GCM, 1 = ChaCha20-Poly1305
5       4     nonce salt
9       8     plaintext_len, u64 big-endian
17      4     chunk_count, u32 big-endian
21      ..    chunk_count ciphertext chunks, back to back
```

No per-chunk length prefix. `plaintext_len` and `chunk_count` alone
determine every chunk's exact plaintext size (`CHUNK_SIZE` for all but
the last, which holds the remainder), so every ciphertext chunk's length
— plaintext size plus the fixed 16-byte AEAD tag — is implied rather
than transmitted. Removing that field removes an attacker's ability to
desynchronise a claimed length from the true chunk boundary.

**The BLAKE3 Merkle root is deliberately not part of this container.**
Spec Section 5: "Only `K_file`, metadata, and the BLAKE3 root tree hash
travel through the primary PQ-Double-Ratchet envelope." The ciphertext
stream itself crosses adversary A2's territory (a malicious or
compromised relay); embedding the root inside that same untrusted stream
would let the same adversary who could tamper with the chunks also
"correct" the root to match, defeating its purpose as an
independently-authenticated value. `decrypt_stream` therefore takes the
expected root — and every other header field — as an explicit
[`FileManifest`] parameter the caller obtained out of band (via the
ratchet envelope, in the full system; via direct construction in this
crate's own tests, which stand in for "however the caller actually
received it").

## 3. AAD Binding: Authenticating the Unencrypted Header

`algorithm`, `plaintext_len`, and `chunk_count` travel in the clear, but
every chunk's AEAD associated data includes all three plus that chunk's
own index (`stream::chunk_aad`). The concrete attack this closes: a relay
drops trailing chunks and patches `chunk_count`/`plaintext_len` in the
header to describe a shorter file consistent with what it kept. Without
AAD binding, every surviving chunk's ciphertext bytes are completely
untouched and would still individually authenticate — decryption would
"succeed" on a silently truncated file. With the header fields bound into
every chunk's AAD, the attacker cannot patch the header without
invalidating every already-encrypted chunk, since patching requires
re-encrypting under the new AAD, which requires the key.

Two tests exercise this from different angles:

- `truncating_chunks_and_patching_the_header_is_detected` — the
  straightforward case: patch the header, keep the caller's `expected`
  manifest as the true original. Caught by the manifest-vs-header
  comparison alone (`FileError::ManifestMismatch`), before AAD even
  enters into it.
- `aad_binding_alone_rejects_a_header_edited_to_match_a_truncated_chunk_set`
  — the harder case, isolating the AAD mechanism specifically: construct
  an `expected` manifest that *does* match the patched header field-for-
  field (simulating an attacker who also controls what the caller treats
  as "expected"), and confirm the surviving chunk still fails
  `ChunkAuthenticationFailed` because its AAD was computed under the
  *original* file's `plaintext_len`/`chunk_count`, not the patched ones.

The per-chunk index is additionally bound into AAD for defence in depth,
on top of the nonce counter already being index-derived —
`reordering_two_chunks_fails_to_decrypt` demonstrates chunk-swap
detection, which the nonce-derivation alone already provides; the AAD
binding is redundant with it by design (belt and suspenders), not the
sole mechanism.

## 4. BLAKE3 Merkle Tree — RFC 6962, BLAKE3 Substituted for SHA-256

Per spec Section 9.1 ("never invent a novel construction... cite a
published reference"), the tree shape, leaf/node domain-separation
prefixes, and audit-path construction are
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) §2.1 (`MTH`) and
§2.1.1 (`PATH`), with BLAKE3 substituted for SHA-256 — the same
primitive-substitution-while-keeping-construction pattern this workspace
already uses (e.g. brainpool512r1 in place of a NIST curve in the hybrid
KEM combiner, which still cites NIST SP 800-56C for the combiner
construction itself).

**Why RFC 6962's split rule, not naive pairwise reduction with odd-node
duplication:** RFC 6962 splits at "the largest power of two smaller than
`n`" (a lopsided split when `n` isn't a power of two) rather than the
more common scheme of pairing adjacent leaves and duplicating an unpaired
last leaf to force an even count. Leaf duplication is a known weakness —
several early Merkle-tree implementations (including an early Bitcoin
one) used it, and it lets an attacker who controls leaf contents craft a
second, different leaf sequence with the same root, because the
duplicated node collides with itself under concatenation. RFC 6962's
split-based `MTH` has no unpaired node at any level to duplicate.
`merkle::tests::naive_last_node_duplication_gives_a_different_root_than_rfc6962`
pins that this implementation does not fall back to the weaker scheme.

The `0x00`/`0x01` leaf/internal-node prefixes are RFC 6962's second,
independent defence: they prevent a leaf hash from ever being confused
with (or substituted for) an internal node hash.

**Empty-tree and single-leaf conventions**, both taken directly from RFC
6962 §2.1: `MTH({})` is the hash of the empty string (not a zero value or
a special sentinel), and `MTH({d(0)})` for a single leaf is the leaf hash
itself, not a further wrapping. Both are exercised
(`empty_tree_root_is_the_hash_of_the_empty_string`,
`single_leaf_root_is_the_leaf_hash_itself`) since a 0-byte file (0
chunks) and a ≤4 MiB file (1 chunk) are both realistic cases, not edge
cases to special-case away.

**Inclusion proofs** (`MerkleTree::generate_proof` /
`merkle::verify_inclusion`) implement RFC 6962 §2.1.1's `PATH`, extended
to record each sibling's left/right position explicitly (RFC 6962's own
`PATH` returns only sibling hashes and relies on the verifier
re-deriving position by replaying the same `(m, n)` recursive split;
recording position directly in the proof is a simpler, equally sound
verification contract that does not require the verifier to know the
tree's total leaf count separately). Not used by `decrypt_stream` itself
— it already holds every leaf, since it must read every chunk to decrypt
the file, and so verifies the whole root directly rather than a
per-chunk proof. This exists as the public primitive Section 9's module
breakdown calls for ("BLAKE3 Merkle tree engine") for a future
partial/resumable-download path in `aegis-net`, where a peer might want
to verify one chunk against an already-known root before the rest of the
file has arrived.

## 5. Integrity: Two Independent Layers

1. **Per-chunk AEAD authentication**, checked before that chunk's
   plaintext is written to the output. Matches spec Section 5's "verify
   each chunk's hash incrementally during download, before writing to
   disk" directly: `decrypt_stream`'s loop authenticates a chunk, and
   only on success writes its plaintext, before moving to the next
   chunk.
2. **Whole-file BLAKE3 Merkle root**, checked once every chunk has
   individually authenticated, against `expected.root_hash`. Independent
   of layer 1 by design: it adds nothing against an adversary who already
   holds the file key (they could recompute a matching root too), but it
   catches a relay serving an internally-consistent-looking short or
   reordered *set* of otherwise-genuine chunks that per-chunk
   authentication alone would not reveal as incomplete. See
   `merkle_root_mismatch_is_detected_even_when_every_chunk_authenticates`,
   which corrupts only the expected root — leaving header and every
   chunk exactly as genuinely encrypted — to prove the two checks are
   independent, not one masking the other.

## 6. Error Handling

`FileError`, `#[non_exhaustive]`, `From<std::io::Error>` and
`From<aegis_crypto::CryptoError>` for the underlying I/O and
primitive-level failure layers. Every variant carries only
length/index/shape information a peer already controls or could derive
from the ciphertext it sent — never secret-dependent detail — so
rendering or logging an error cannot leak key material or plaintext.

Nothing in this crate panics on attacker-controlled data: a malformed
header, a tampered/truncated/reordered/header-patched ciphertext stream,
and a wrong key all return `FileError` rather than unwinding. The one
documented exception —
`aegis_crypto::aead::ChunkNonceSequence::random`'s fail-closed panic on
OS RNG failure — is not attacker-controlled and is `aegis-crypto`'s own
documented behaviour, not something this crate could recover from
differently.

## 7. Testing Strategy

Unlike `aegis-vault` (which needed a mock-vs-real-backend split because
its correctness depends on an external OS service), `aegis-file` is pure
and synchronous — every test in both `stream` and `merkle` runs
unconditionally, no `#[ignore]` tier. 50 tests total across the crate:

- **`chunk_count_for`/`chunk_plaintext_len` boundary arithmetic** — zero
  bytes, one byte under/over a chunk boundary, the exact 1 GiB/256-chunk
  cap — verified as pure arithmetic, not by allocating gigabyte buffers.
- **Round-trip correctness** across both AEAD algorithms, empty
  plaintext, single-chunk, exact chunk boundary, multi-chunk with a short
  final chunk.
- **Adversarial-input rejection**: oversized declared length (checked
  before any read), short/long readers relative to declared length,
  tampered ciphertext byte, wrong key, reordered chunks, truncated
  stream, trailing garbage, bad magic, unknown algorithm byte,
  internally-inconsistent header, header exceeding the size cap,
  header/manifest mismatch, AAD-binding-specific truncate-and-patch
  attack (two angles, per Section 3 above), Merkle root mismatch
  isolated from per-chunk authentication.
- **Merkle tree**: empty/single-leaf conventions, hand-computed 2-leaf
  and 3-leaf roots (the latter pinning the lopsided split direction),
  the anti-leaf-duplication regression test, order- and
  content-sensitivity, proof generation/verification round-tripping
  every index for tree sizes 1–32 plus the exact 256-leaf boundary,
  tampered-leaf and tampered-proof-step rejection, cross-tree proof
  rejection, determinism.

All 50 tests pass; `cargo clippy -p aegis-file --all-targets -- -D
warnings` (the workspace's CI lint level) is clean; `cargo fmt` applied.

## 8. What Is Deliberately Not Here

- **Resumable/partial downloads.** `MerkleProof`/`verify_inclusion` are
  the primitive; the actual resume protocol (which chunks to re-request,
  how a peer signals partial receipt) is `aegis-net`'s concern once it
  exists.
- **The 72-hour relay TTL / ephemeral storage described in spec Section
  5's last bullet.** That is federated mailbox node behaviour
  (`aegis-net`), not something a streaming codec crate enforces.
- **Compression.** Not mentioned in spec Section 5, and compressing
  before encryption on attacker-influenced plaintext reopens exactly the
  class of length-oracle side channels (CRIME/BREACH-style) that
  encrypted messengers specifically avoid; not adding it is the
  deliberate choice, not an oversight.
