# aegis-core

Unified runtime facade for [AegisPQC](https://github.com/Basty-devel/AEGIS) — a post-quantum secure messenger. Composes the leaf crates (`aegis-crypto`, `aegis-ratchet`, `aegis-vault-pqc`, `aegis-file`, `aegis-net`) into a single typed entry point. Implements `AEGIS.Plan.V0.2.md` §8/§9 item 1.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

A thin, ergonomic aggregation layer — no new cryptography or protocols.
All algorithms are delegated to the published leaf crates:

- **aegis-crypto** — hybrid ML-KEM-1024 + brainpoolP512r1 KEM, dual ML-DSA-87 + Ed25519 signatures, AEAD, Argon2id, HKDF-SHA512, BLAKE3 SAS
- **aegis-ratchet** — PQ-X3DH key agreement, Double Ratchet, group sender keys, multi-device linking
- **aegis-vault-pqc** — SQLCipher encrypted storage, hardware key isolation (Windows Credential Manager / Linux Secret Service), GDPR Art. 17/20 erasure + export
- **aegis-file** — chunked AEAD streaming (4 MiB chunks, up to 1 GiB), BLAKE3 Merkle tree integrity, bounded 4 MiB buffering
- **aegis-net** — Tor transport (`arti`), capability tokens, rate limiting, Sealed Sender 2.0

`aegis-core` provides:

1. **`AegisError`** — unified error type wrapping every leaf error (`From` impls per variant)
2. **`AegisRuntime`** — owns a `Vault` (opened first, fail-closed on hardware trust) + `RatchetState` (future) behind a single handle
3. **Cipher choice** — sender picks AES-256-GCM (AES-NI/ARMv8 HW) or ChaCha20-Poly1305 (software constant-time, mobile/wasm); wire byte `0/1` in `aegis-file` header; frontend should negotiate (AES preferred with HW, ChaCha20 fallback)

## Quick start

```toml
# Cargo.toml
[dependencies]
aegis-core = "0.1.0"
```

```rust
use aegis_core::{AegisRuntime, RuntimeConfig};
use std::path::Path;

let config = RuntimeConfig {
    db_path: Path::new("vault.db").to_path_buf(),
    keyring_service_name: "com.example.myapp".into(),
};

let runtime = AegisRuntime::new(config).expect("credential store unavailable");

// Access the vault
runtime.vault().put("messages", "alice@example.com", b"hello")?;

// Runtime also exposes ratchet state (when initialised)
// runtime.ratchet()
```

## Architecture

```
AegisRuntime
├── Vault (aegis-vault-pqc)        ← opened FIRST (fail-closed hardware trust)
├── RatchetState (aegis-ratchet)   ← identity material from vault
└── Transport (aegis-net)          ← Tor / mailbox (future, behind AegisRuntime)
```

The constructor `AegisRuntime::new` is **fail-closed**: it opens the vault first. If the OS credential store (Windows Credential Manager / Linux Secret Service) cannot be reached, it returns `AegisError::Vault` without creating any other state — no fallback, no half-initialised handle.

## Error handling

All fallible operations return `AegisError`, which unifies:

| Variant | Source crate |
|---------|--------------|
| `Crypto` | `aegis_crypto::CryptoError` |
| `Ratchet` | `aegis_ratchet::RatchetError` |
| `Vault` | `aegis_vault_pqc::VaultError` |
| `File` | `aegis_file::FileError` |
| `Net` | `aegis_net::NetError` |
| `Io` | `std::io::Error` |

All variants implement `From`, so the `?` operator chains cleanly:

```rust
fn example() -> Result<(), AegisError> {
    let vault = runtime.vault();
    vault.put("ns", "key", b"data")?; // FileError → AegisError::File
    Ok(())
}
```

## Cipher choice

Both `AES-256-GCM` and `ChaCha20-Poly1305` are supported via `aegis_crypto::aead::AeadAlgorithm`. The sender chooses; the receiver dispatches on the wire byte (`0` = AES, `1` = ChaCha20-Poly1305 in `aegis-file` header). Recommended policy: **AES preferred where HW acceleration exists; ChaCha20 fallback otherwise**. Frontend should expose a selector (default AES, ChaCha20 fallback or explicit user override).

See `aegis_crypto::aead::AeadAlgorithm` for the suitability matrix and negotiation note.

## Memory zeroization

Secret material lives inside the leaf crates' `zeroize::Zeroizing` wrappers. `AegisRuntime` adds no second zeroization layer; stack copies outside `zeroize`'s reach are documented as out-of-scope (same limitation the leaves document).

## Panics

No panic is reachable from attacker-controlled, relay-controlled, or vault-unavailable data. Only OS-level RNG failure (`getrandom`) or unrecoverable vault/SQL hard errors may panic — neither is attacker-controlled.

## Security disclaimer

**This crate is NOT independently audited.** Do not rely on this code for life-critical communications until a third-party cryptographic audit has been completed. See `AEGIS.Plan.V0.2.md`, document header, and §9.1.

```rust
pub const SECURITY_DISCLAIMER: &str = aegis_crypto::SECURITY_DISCLAIMER;
```

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use; commercial use requires a separate license.