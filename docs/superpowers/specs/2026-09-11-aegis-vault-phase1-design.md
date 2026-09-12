# aegis-vault Phase 1: Encrypted Storage & Hardware Key Isolation — Design

Implements `AEGIS.Plan.V0.2.md` Section 4. Depends only on `aegis-crypto`
(published, currently 0.1.4) — no dependency on `aegis-ratchet`.

## 0. Phase Scope

Section 4 bundles three concerns that don't all need to land at once:

1. **Storage engine** — SQLCipher-encrypted local database.
2. **Hardware key isolation** — across four platform backends (Windows
   Credential Manager, Linux Secret Service/Keyutils, Android
   Keystore/StrongBox, Apple Secure Enclave/Keychain) plus a strict
   zero-fallback policy.
3. **GDPR engines** — Art. 20 export, Art. 17 erasure.

Phase 1 builds all three, but **narrows item 2 to desktop**: a
`HardwareKeyStore` trait ships with one implementation (`KeyringBackend`,
covering Windows Credential Manager and Linux Secret Service/Keyutils via
the `keyring` crate — both testable in this environment). Android
Keystore/StrongBox and Apple Secure Enclave get their own future plan once
a mobile toolchain exists to actually validate them; the trait boundary is
designed now so those backends slot in later without touching `Vault`'s
own logic.

Phase 1 also narrows the **storage schema**: the plan's storage bullet
mentions messages, contacts, and key metadata, but no crate in this
workspace produces a "message" or "contact" concept yet — `aegis-ratchet`
only emits opaque session bytes. `aegis-vault` Phase 1 is a generic,
schema-agnostic encrypted namespace→key→bytes store. Concrete tables
(messages, contacts) are for whichever future crate actually produces
that data to define, on top of this substrate.

**A correction to the plan text:** Section 4's storage bullet says
"SQLCipher-encrypted local database (AES-256-GCM)." SQLCipher's actual
page cipher is AES-256-CBC with HMAC-SHA512 per page — it has no GCM
mode. Rather than build something that doesn't match its own claim,
Section 1 below places the GCM guarantee at the layer where it's actually
true (per-record encryption via `aegis_crypto::aead`), with SQLCipher's
real CBC+HMAC cipher as a second, whole-file layer underneath it. The
plan document should be corrected to reflect this; see the "Rulings"
entry this design produces when reviewed.

## 1. Key Hierarchy & Envelope Encryption

Three key tiers:

- **Vault Master Key (VMK)** — a random 256-bit key, generated once when
  a vault is created. Stored *directly* as the secret in the OS-native
  credential store (Windows Credential Manager / Linux Secret Service)
  via `keyring::Entry`. This crate never writes VMK to disk itself — the
  OS credential store is the hardware-backed isolation boundary.
- **Data Encryption Key (DEK)** — a fresh random 256-bit key generated
  per record, at write time. Encrypts that record's plaintext via
  `aegis_crypto::aead` (AES-256-GCM). The DEK is then itself encrypted
  ("wrapped") under VMK, also via `aegis_crypto::aead`, under a
  domain-separation label distinct from record-content encryption's own
  label (spec discipline: two different things encrypted by the same key
  must use disjoint labels/contexts).
- **SQLCipher page cipher** — encrypts the database file as a whole
  (AES-256-CBC + HMAC-SHA512, SQLCipher's actual default). Defense in
  depth underneath the per-record envelope encryption above; not the
  layer where this design's "AES-256-GCM" guarantee lives.

**Why per-record DEKs, not keys derived deterministically from VMK:** a
key derived from VMK (e.g. via HKDF over a record identifier) is always
re-derivable as long as VMK exists — destroying "it" destroys nothing,
since it was never stored, only computed on demand. A genuinely random,
independently-generated-and-then-stored DEK can be destroyed for real:
deleting its wrapped form makes that record's ciphertext permanently
unrecoverable even though VMK survives and even though the ciphertext
bytes may still physically linger in the SQLCipher file until VACUUM.
This is what makes Art. 17 erasure (Section 4 below) a cryptographic
guarantee rather than a database `DELETE` statement, and it's why the
design uses per-record DEKs even though it costs one extra AEAD operation
and 12-16 bytes of wrapped-key storage per record.

**SQLCipher's own key** (the `PRAGMA key` SQLCipher uses for its page
cipher) is derived directly from VMK via HKDF-SHA512
(`aegis_crypto::kdf::derive_key`) under its own domain-separation label,
distinct from the DEK-wrap label above — it is never independently
generated or stored. This is a deliberate bootstrapping fix: the
SQLCipher key must be available *before* any table in the database can
be read (SQLCipher decrypts pages as they're read), so it cannot itself
live inside a database row — see Section 3 for the resulting `open()`
sequence. A side effect worth noting: because this key is VMK-derived
rather than independently stored, destroying VMK (Section 4's
`destroy_vault`) makes the entire SQLCipher file unreadable, not only
the individual records inside it — one more layer of the same
"destroying VMK destroys everything" guarantee.

## 2. Hardware Key Isolation & Zero-Fallback

```rust
pub(crate) trait HardwareKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError>;
    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    fn destroy_vmk(&self) -> Result<(), VaultError>;
}
```

`KeyringBackend` is the only implementation this phase ships, wrapping
`keyring::Entry`. The `keyring` crate itself selects Windows Credential
Manager vs. Linux Secret Service/Keyutils at runtime based on the host
OS, so one implementation covers both platforms named in Phase 1's scope.

**Zero-fallback is structural, not a runtime check that can be bypassed
by configuration.** There is no second code path anywhere in this crate
capable of obtaining or storing a VMK other than through
`HardwareKeyStore`. `Vault::open` calls into `KeyringBackend`; if the OS
backend can't be reached — no Secret Service daemon running on a headless
Linux host, for example — that error propagates directly out of `open()`
as `VaultError::HardwareKeyStoreUnavailable`, and nothing else in the
crate can create or open a vault. This is also what "Security-by-Default
/ Max-Only" means concretely here: there is no lower-security path to
fall back to, because none was ever written. No feature flag, config
option, or environment variable can enable one.

## 3. Storage Schema & Public API

Two tables in the SQLCipher database:

- `vault_meta` — schema version, and a VMK **canary**: a small fixed
  known-plaintext value AEAD-encrypted directly under VMK. On `open()`,
  decrypting the canary is a defense-in-depth correctness check for the
  loaded VMK, on top of the implicit check SQLCipher already performs
  (a wrong page-cipher key produces "file is not a database" on the
  first read) — if the canary doesn't decrypt, `open()` returns
  `VaultError::VmkCanaryMismatch` rather than proceeding with a key that
  might be subtly wrong or a store that's corrupted.
- `vault_records` — primary key `(namespace, key)`, columns
  `wrapped_dek`, `dek_nonce`, `ciphertext`, `nonce`, `created_at`,
  `updated_at`. `namespace` gives future crates (`aegis-net`, a later UI
  layer) separate keyspaces without collisions, without this crate
  needing to know anything about what they store.

**`open()`'s actual sequence**, since it must resolve the bootstrapping
order from Section 1 correctly:

1. Load VMK from `HardwareKeyStore` (no database access — zero-fallback
   gate is here).
2. Derive the SQLCipher key from VMK via HKDF (still no database
   access).
3. Open the SQLite connection and set `PRAGMA key` to the derived value.
4. Read and decrypt the `vault_meta` canary; mismatch is
   `VaultError::VmkCanaryMismatch`.

Only after step 4 succeeds is the `Vault` considered open and its other
methods usable.

Public API (signatures indicative, finalized during planning):

```rust
pub struct Vault { /* opaque: open SQLCipher connection + in-memory VMK (Zeroizing) */ }

pub struct VaultConfig {
    pub db_path: PathBuf,
    pub keyring_service_name: String,
}

impl Vault {
    pub fn open(config: VaultConfig) -> Result<Self, VaultError>;
    pub fn put(&mut self, namespace: &str, key: &str, plaintext: &[u8]) -> Result<(), VaultError>;
    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;
    pub fn list_keys(&self, namespace: &str) -> Result<Vec<String>, VaultError>;
    pub fn erase(&mut self, namespace: &str, key: &str) -> Result<(), VaultError>;
    pub fn destroy_vault(self) -> Result<(), VaultError>;
    pub fn export(
        &self,
        signing_key: &aegis_crypto::signature::DualKeyPair,
        passphrase: &str,
    ) -> Result<Vec<u8>, VaultError>;
}
```

`open()` creates a new vault (generating VMK, the SQLCipher key, and the
canary) if `db_path` doesn't exist, or opens and verifies an existing one
if it does. Both paths go through the same zero-fallback-gated
`HardwareKeyStore` call.

## 4. GDPR Compliance Engines

**Art. 17 erasure, two granularities:**

- `erase(namespace, key)` — per-record cryptographic shredding.
  Zeroizes and deletes that record's `wrapped_dek`/`dek_nonce` row.
  Without the DEK, the corresponding `ciphertext` is permanently
  unrecoverable (256-bit AES key, no feasible brute force), satisfying
  the plan's "not just a database row delete" requirement even though
  the ciphertext bytes themselves may persist in the SQLCipher file
  until a future VACUUM. This is the operation a "disappearing message"
  feature (built by a future crate on top of this one) would call.
- `destroy_vault(self)` — whole-vault purge ("local purge" in the plan
  text). Destroys VMK via `HardwareKeyStore::destroy_vmk` and zeroizes
  the in-memory copy; every record's wrapped DEK becomes simultaneously
  unrecoverable, instantly, regardless of database size. Deletes the
  database file itself as a final step (best-effort; VMK destruction
  alone already makes the file's contents cryptographically inert).

**Art. 20 export**, `export(signing_key, passphrase)`:

1. Iterate every `(namespace, key)` record, unwrap each DEK under VMK,
   decrypt to plaintext.
2. Assemble into a structured JSON document (`serde_json` — a real,
   non-dev dependency for this crate specifically, unlike the manual
   byte-encoding `aegis-ratchet` uses for its wire protocol: that format
   faces an adversarial peer over a network, this export file faces only
   the vault's own owner after the fact, so there's no security reason to
   hand-roll it, and JSON keeps the export human-inspectable, which helps
   a user actually verify their own GDPR export).
3. Sign the JSON bytes with `signing_key`
   (`aegis_crypto::signature::DualKeyPair`, Ed25519 + ML-DSA-87 — both
   components must verify, consistent with this project's dual-signature
   discipline everywhere else; the plan's "ML-DSA-87 identity key"
   phrasing is read as shorthand for "the identity key," which is
   inherently dual throughout this codebase).
4. Derive an AES-256-GCM key from `passphrase` via
   `aegis_crypto::passphrase` (Argon2id), encrypt the signed bytes via
   `aegis_crypto::aead`.

`export` takes the signing key as a caller-supplied parameter rather than
generating or owning identity keys itself — the caller (whoever holds the
actual identity key, most likely retrieved from this same vault via
`get()` beforehand) passes it in. This keeps `aegis-vault` a generic
storage engine and avoids adding `aegis-ratchet` as a dependency, which
the build order doesn't call for here.

## 5. Error Handling

`VaultError`, `#[non_exhaustive]`, `From<aegis_crypto::CryptoError>` for
primitive-level failures. Key variants:

- `HardwareKeyStoreUnavailable` — the OS backend couldn't be reached at
  `open()` time (zero-fallback trigger).
- `VmkCanaryMismatch` — the loaded VMK failed to decrypt the stored
  canary (wrong key, or store corruption).
- `StorageCorrupted` — malformed row data that can't be a bug-free
  product of this crate's own writes.
- Wrapped `rusqlite::Error` and `std::io::Error` variants for the
  underlying database/filesystem layer.

`get()` on a missing `(namespace, key)` returns `Ok(None)`, not an error.
`erase()` of a missing key is an idempotent no-op (`Ok(())`) — a caller
retrying an erasure after a partial prior failure shouldn't get a
different error class than "it's already gone."

Nothing in this crate panics on data an attacker or a corrupted disk
controls — malformed stored records, keyring failures, and SQLCipher
errors all return `VaultError`.

## 6. Testing Strategy

Two tiers:

1. **Default, CI-safe tests** run against `keyring-core`'s built-in
   `mock` module (an in-memory `CredentialStore` implementation the
   `keyring` crate ships specifically for client testing — no feature
   flag needed, unlike the separate `sample` module) — no real OS
   credential store touched. These cover this
   crate's own logic, which is the overwhelming majority of what needs
   verifying: envelope-encryption round-trip (`put` then `get` returns
   the original plaintext), canary verification on `open()`, per-record
   `erase()` genuinely making that record's plaintext unrecoverable
   (not merely absent from a subsequent `get()` — assert the raw stored
   ciphertext bytes are unchanged while `wrapped_dek` is gone),
   `destroy_vault()` invalidating every record at once, GDPR export
   round-trip (independently re-verify the dual signature and decrypt
   with the export passphrase), and zero-fallback triggering when the
   mock backend is configured to simulate an unavailable store.
2. **Real-backend integration tests**, `#[ignore]` by default, run
   manually (`cargo test -- --ignored`) — a small set exercising the
   actual Windows Credential Manager / Linux Secret Service, confirming
   genuine OS integration rather than only this crate's abstraction over
   it. Marked `#[ignore]` because a fresh CI container commonly has no
   Secret Service daemon running at all, so these can't run unattended
   in every environment; the mock-backend tests above already cover this
   crate's real logic; only the OS boundary itself is stood in for there.
