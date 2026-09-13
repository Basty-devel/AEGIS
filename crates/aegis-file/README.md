# aegis-file

Chunked AEAD file streaming engine (up to 1 GiB) with BLAKE3 Merkle
tree integrity verification for [AegisPQC](https://github.com/Basty-devel/AEGIS),
a post-quantum secure messenger. Phase 1 of `AEGIS.Plan.V0.2.md`
Section 5. Depends on `aegis-crypto` only.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

A pure, synchronous streaming engine — no I/O beyond generic
`std::io::Read`/`Write`, no networking, no storage, no knowledge of
`aegis-net`'s mailbox protocol. You hand it a reader, a writer, a key,
and (on encrypt) a declared plaintext length; it hands back (on
encrypt) or checks against (on decrypt) a [`FileManifest`](src/stream.rs).
Callers own key lifecycle and transport — in particular, *where the
manifest's root hash travels*: per spec Section 5, that is the
authenticated PQ-Double-Ratchet envelope, never the ciphertext stream
itself.

1. **Chunked AEAD streaming** ([`stream`](src/stream.rs)) — splits
   plaintext into fixed 4 MiB chunks, encrypts each with
   `aegis_crypto::aead` (AES-256-GCM or ChaCha20-Poly1305) under the
   nonce construction from `aegis-crypto`'s spec (a random per-file
   salt plus a monotonic per-chunk counter), and never buffers more
   than one chunk's plaintext or ciphertext in memory regardless of
   total file size. [`stream::encrypt_stream`] / [`stream::decrypt_stream`]
   are the whole runtime surface.
2. **BLAKE3 Merkle tree** ([`merkle`](src/merkle.rs)) — an
   [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) §2.1 Merkle Tree
   Hash over ciphertext-chunk hashes, BLAKE3 substituted for SHA-256.
   `stream` uses this internally for whole-file root computation and
   verification; [`merkle::MerkleTree::generate_proof`] /
   [`merkle::verify_inclusion`] are exposed directly as a building
   block for a future partial/resumable-download path in `aegis-net`.

| Module | Contents |
|---|---|
| [`stream`](src/stream.rs) | `encrypt_stream`, `decrypt_stream`, `FileManifest`, `CHUNK_SIZE`, `MAX_FILE_SIZE`, `MAX_CHUNKS`, `chunk_count_for` |
| [`merkle`](src/merkle.rs) | `MerkleTree`, `MerkleProof`, `ProofStep`, `leaf_hash`, `verify_inclusion` |
| [`error`](src/error.rs) | `FileError` |

## Wire container format

```text
offset  size  field
0       4     magic: b"AGF1"
4       1     algorithm: 0 = AES-256-GCM, 1 = ChaCha20-Poly1305
5       4     nonce salt
9       8     plaintext_len, u64 big-endian
17      4     chunk_count, u32 big-endian
21      ..    chunk_count ciphertext chunks, back to back
```

No per-chunk length prefix: `plaintext_len` and `chunk_count` alone
determine every chunk's exact size, removing a field an attacker could
otherwise desynchronise from the true chunk boundary. The BLAKE3
Merkle root is deliberately **not** part of this container — see the
[`stream`](src/stream.rs) module doc comment for why, and for the
AAD-binding mechanism that keeps a relay from truncating chunks and
patching the header to match.

## Why the declared plaintext length is a required parameter

`encrypt_stream` takes `plaintext_len` from the caller (typically
filesystem metadata) rather than discovering it by reading the input
to completion. This is what lets the 1 GiB cap be enforced — and
rejected, with zero bytes read — before any I/O happens, and what lets
the wire header be written before the first chunk: this crate performs
true single-pass streaming, never holding more than one 4 MiB chunk at
a time no matter how large the declared length is (up to the cap).

## Integrity: two independent layers

1. **Per-chunk AEAD authentication**, checked before that chunk's
   plaintext is ever written to the output — "verify each chunk's hash
   incrementally during download, before writing to disk," per spec
   Section 5.
2. **Whole-file BLAKE3 Merkle root**, checked once every chunk has
   authenticated, against the root the caller received through the
   authenticated ratchet envelope. This is independent of layer 1: it
   catches a relay that serves an internally self-consistent but
   incomplete or reordered *set* of otherwise-genuine chunks, which
   per-chunk authentication alone would not reveal — see
   [`stream::tests::merkle_root_mismatch_is_detected_even_when_every_chunk_authenticates`].

## Memory zeroization

Chunk plaintext/ciphertext working buffers are `zeroize::Zeroizing`,
consistent with [`aegis-crypto`](https://crates.io/crates/aegis-crypto)'s
own discipline. The Merkle leaf list (32 bytes per chunk, 8 KiB at the
256-chunk/1 GiB cap) is not secret material and is not zeroized.

## Error handling

Nothing in this crate panics on data an attacker controls — a
malformed wire header, a tampered, truncated, reordered, or
header-patched ciphertext stream, and a wrong key all return
[`error::FileError`] (`#[non_exhaustive]`).

## Quick start

```toml
# Cargo.toml
[dependencies]
aegis-file = "0.1.0"
aegis-crypto = "0.1.4"
```

```rust
use aegis_crypto::aead::AeadAlgorithm;
use aegis_file::{encrypt_stream, decrypt_stream};
use std::io::Cursor;

let key = [0x2au8; 32];
let plaintext = b"hello world";

let mut ciphertext = Vec::new();
let manifest = encrypt_stream(
    AeadAlgorithm::Aes256Gcm,
    &key,
    &plaintext.len().to_string(),
    Cursor::new(&plaintext[..]),
    &mut ciphertext,
)
.unwrap();

// The root hash travels through the authenticated ratchet envelope,
// not the ciphertext stream itself.
let manifest_trusted = manifest;

let mut recovered = Vec::new();
decrypt_stream(
    &key,
    Cursor::new(&ciphertext[..]),
    &manifest_trusted,
    &mut recovered,
)
.unwrap();
assert_eq!(plaintext.as_slice(), &recovered);
```

## Limitations

- **No transport or storage** — this crate is a pure streaming engine;
  callers own the mailbox protocol (`aegis-net`) and vault storage
  (`aegis-vault-pqc`).
- **Whole-file Merkle computed in one pass** — streaming *encryption*
  incrementally builds the Merkle root; *decryption* re-derives it. A
  resumable single-chunk proof path is out of scope until `aegis-net`
  consumes `merkle::MerkleTree` directly.

## Cipher choice

Both `AES-256-GCM` and `ChaCha20-Poly1305` are supported (wire byte
`0`/`1`, see [`stream`](src/stream.rs)). The **sender picks**; the
receiver dispatches. Prefer **AES-256-GCM** where hardware acceleration
(AES-NI / ARMv8 Crypto) is present; fall back to **ChaCha20-Poly1305**
on software-only targets. Why:

| Cipher | Hardware | Software | Side-channel | Good when |
|---|---:|---:|---:|---|
| **AES-256-GCM** | AES-NI/ARMv8 Crypto → fast & constant-time | AES rounds can leak via cache timing | Constant-time only with HW | x86_64 / modern ARM with AES-NI |
| **ChaCha20-Poly1305** | No HW needed | Constant-time by construction, fast in pure software | Naturally cache-timing resistant | Mobile, wasm, non-x86 |

Non-reuse invariant is the same for both: never reuse `(key, nonce)`.
Aegis's per-file random salt + per-chunk counter guarantees this within one
file/key. **Frontend:** expose a selector (default AES, ChaCha fallback
or explicit user override) — negotiation at the file/net layer, not
inside the AEAD dispatcher.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use;
commercial use requires a separate license.
