# aegis-vault

SQLCipher-encrypted local storage with hardware-backed key isolation
for [AegisPQC](https://github.com/Basty-devel/AEGIS), a post-quantum
secure messenger. Phase 1 of `AEGIS.Plan.V0.2.md` Section 4: a
generic, namespaced encrypted key/value store, not concrete
message/contact schemas — see this crate's design spec for why.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

- **Hardware-backed key isolation, zero-fallback** ([`keystore`](src/keystore.rs)) — a
  random Vault Master Key (VMK) lives only in the OS credential store
  (Windows Credential Manager / Linux Secret Service, via the
  `keyring` crate's `v1` API) and is never written to disk by this
  crate. If the OS store can't be reached, `Vault::open` fails outright
  — there is no lower-security fallback path anywhere in this crate.
- **Per-record envelope encryption** ([`vault`](src/vault.rs)) — every record gets
  its own random Data Encryption Key (DEK), encrypted with
  `aegis_crypto::aead` (AES-256-GCM) and wrapped under a VMK-derived
  key. SQLCipher's own page cipher (AES-256-CBC + HMAC-SHA512 — not
  GCM, despite what the plan document's storage bullet says) encrypts
  the database file underneath this as a second, whole-file layer.
- **GDPR Art. 17 erasure** — `Vault::erase` destroys one record's
  wrapped DEK, making that record's ciphertext permanently
  unrecoverable even though its bytes may still exist in the database
  file until VACUUM. `Vault::destroy_vault` destroys VMK itself,
  instantly invalidating every record — and the SQLCipher key, which
  is VMK-derived — at once.
- **GDPR Art. 20 export** ([`export`](src/export.rs)) — every readable record, as
  JSON, signed with the caller's dual (Ed25519 + ML-DSA-87) identity
  key, encrypted under an Argon2id key derived from a
  caller-supplied passphrase.

## Memory zeroization

VMK, every derived key, every DEK, and every returned plaintext are
`zeroize::Zeroizing`, consistent with
[`aegis-crypto`](https://crates.io/crates/aegis-crypto)'s own
discipline.

## Error handling

Nothing in this crate panics on data an attacker or a corrupted disk
controls. Malformed stored records, unreachable hardware key stores,
and SQLCipher failures all return [`error::VaultError`](src/error.rs)
(`#[non_exhaustive]`).

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use;
commercial use requires a separate license.
