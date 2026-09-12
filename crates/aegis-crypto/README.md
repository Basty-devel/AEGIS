# aegis-crypto

Hybrid post-quantum cryptographic primitives for [AegisPQC](https://github.com/Basty-devel/AEGIS),
a post-quantum secure messenger. Every construction here follows a cited
published reference — see `AEGIS.Plan.V0.2.md` Sections 2 and 9.1 in the
main repository for the full cryptographic ground rules this crate is
built against.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed. This is also exposed at runtime as
> `aegis_crypto::SECURITY_DISCLAIMER`.

## What's inside

| Module | Primitive | Reference |
|---|---|---|
| [`kem`](src/kem.rs) | ML-KEM-1024 | NIST FIPS 203 |
| [`ecdh`](src/ecdh.rs) | brainpoolP512r1 ECDH | RFC 5639 §3.7 |
| [`hybrid`](src/hybrid.rs) | ML-KEM-1024 + brainpoolP512r1 combiner | NIST SP 800-56C |
| [`signature`](src/signature.rs) | Ed25519 + ML-DSA-87 dual signatures | NIST FIPS 204 |
| [`aead`](src/aead.rs) | AES-256-GCM / ChaCha20-Poly1305 | — |
| [`kdf`](src/kdf.rs) | Domain-separated HKDF-SHA512 | RFC 5869, NIST SP 800-56C |
| [`passphrase`](src/passphrase.rs) | Argon2id | RFC 9106 |
| [`sas`](src/sas.rs) | BLAKE3-keyed Short Authentication Strings | — |
| [`version`](src/version.rs) | Protocol version / algorithm-suite negotiation | — |

The dual signature scheme in particular means a signature is only
considered valid if **both** the Ed25519 and ML-DSA-87 components verify —
that's what "ML-DSA-87 paired with Ed25519" means throughout the spec.

## Memory zeroization

Spec Section 2 requires ephemeral private keys and shared secrets to be
wiped after use:

- Every function that returns a shared secret returns it inside
  [`zeroize::Zeroizing`], so it's wiped when the caller drops it.
- Intermediate secrets (ECDH rejection-sampling candidates, KEM seeds and
  encapsulation randomness, signing-key seeds, the combiner's concatenated
  IKM) are wiped before the function returns.
- Long-lived key types wipe themselves on drop — this required explicitly
  enabling the non-default `zeroize` feature on both `ml-kem` and `ml-dsa`
  (see this crate's `Cargo.toml`).

What this does **not** guarantee, and no pure-Rust crate can: that the
operating system never copied a secret elsewhere first. Values moved on
the stack, spilled to registers, paged to swap, or captured in a core dump
are outside `zeroize`'s reach. Zeroization narrows the window; it does not
close it.

## Error handling

Nothing in this crate panics on data an attacker controls. Malformed peer
public keys, encapsulation keys, ciphertexts, signatures, and
signature-verification keys all return [`error::CryptoError`] or `false`.
The only panics are fail-closed reactions to operating-system RNG failure,
documented at each call site.

## A note on brainpoolP512r1

No brainpoolP512r1 implementation exists in the mainline RustCrypto
ecosystem as of this writing, so `ecdh` is built on
[`bp512-nestler`](https://github.com/Basty-devel/bp512-nestler) — the
first published pure-Rust implementation of this curve, with domain
parameters cross-verified against RFC 5639 and OpenSSL. See that crate's
own README for its dependency chain and provenance.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial
use; commercial use requires a separate license.
