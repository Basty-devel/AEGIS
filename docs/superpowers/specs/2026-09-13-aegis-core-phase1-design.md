# aegis-core Phase 1: Runtime Facade — Design

Implements `AEGIS.Plan.V0.2.md` §9 item 1. Depends on all published leaf crates (currently: `aegis-crypto@0.1.5`, `aegis-ratchet@0.1.1`, `aegis-file@0.1.1`, `aegis-vault-pqc@0.1.0`, `aegis-net@0.1.0`) — built last per §10 build order before `aegis-ffi`.

All Phase 1 work stays `forbid(unsafe_code)` (inherits the workspace `[workspace.lints.rust] unsafe_code = "deny"`; the only `unsafe` exception is `aegis-ffi` per §10, matched to its own doc comment). No crate here may carry a scoped `#[allow(unsafe_code)]`.

## 0. Phase Scope

§8 calls `aegis-core` the "Shared Core Library — ... all cryptography, state machines, networking, and ratchet engines reside exclusively in `aegis-core`." Read narrowly that is misleading: the concrete cryptography already lives in `aegis-crypto`, the ratchet in `aegis-ratchet`, the vault in `aegis-vault-pqc`, the file engine in `aegis-file`, the Tor/mailbox plumbing in `aegis-net`. Re-implementing any of that under `aegis-core` would double the audit surface.

Phase 1 therefore scopes `aegis-core` to the thing none of the leaves owns — a single typed, fail-closed composition layer that a future `aegis-ffi` (C-ABI/UniFFI, the only crate that may use `unsafe`) and any platform UI can hold in one hand. Typical duties:

- unified `AegisError` that can wrap each leaf `*Error` via `From` impls, so callers don't have to spell four unrelated error types;
- a small owned `AegisRuntime` / `Client`-like handle that owns a `Vault` + a `RatchetState` (and holds the file-manifest plumbing), with a single constructor that enforces fail-closed init ordering: vault opens first and hardware trust is verified before anything else proceeds, delegating per-leaf zero-fallback behaviour rather than re-implementing it;
- re-exports of the handful of leaf types that make the import surface ergonomic, so platform code can `use aegis_core::*` without depending on four crate names.

Deferred to Phase 2+: group/mutex gossip, I2P/mixnet future transports, Tokio event-loop wiring, identity-provisioning UX, and the Tauri desktop host — none has a design spec yet, and none belongs in a first `0.1.0`.

## 1. Public API (additive, semver-friendly)

```rust
pub enum AegisError {   // #[non_exhaustive]
    Crypto(aegis_crypto::CryptoError),
    Ratchet(aegis_ratchet::RatchetError),
    Vault(aegis_vault_pqc::VaultError),
    File(aegis_file::FileError),
    Net(aegis_net::NetError),
    Io(std::io::Error),
}
impl From<…> for AegisError { … } // one per wrapping variant above
impl std::error::Error for AegisError {}
```

```rust
pub struct RuntimeConfig {
    pub db_path: PathBuf,
    pub keyring_service_name: String,
}

pub struct AegisRuntime { // owns the per-leaf state, not trait-object erased
    // e.g. vault: aegis_vault_pqc::Vault
    //      ratchet: Option<aegis_ratchet::RatchetState>
    // transport handle: placeholder (the tor/mailbox stack is its own crate)
}

impl AegisRuntime {
    /// Fail-closed: opens the vault first; on HardwareKeyStoreUnavailable
    /// returns AegisError::Vault without creating or mutating anything.
    pub fn new(config: RuntimeConfig) -> Result<Self, AegisError> { … }

    pub fn vault(&self) -> &aegis_vault_pqc::Vault { … }
    pub fn vault_mut(&mut self) -> &mut aegis_vault_pqc::Vault { … }
    // ratchet accessor added once identity wire format stabilizes in aegis-ratchet
}
```

Shape chosen to keep `aegis-ffi`'s future bindgen trivial: owned types, no generics to monomorphize, no trait-object error type. Adding transport ownership later is a new field on `AegisRuntime`/`RuntimeConfig`, not a breaking API change.

`SECURITY_DISCLAIMER` is re-exported (`pub const`) just as the leaf crates do — same wording, same disclaimer test.

## 2. Error handling

All fallible `AegisRuntime` operations return `Result<_, AegisError>` — no panics on attacker-controlled / relay-controlled / vault-unavailable data. The crate's fallible surface delegates directly to the leaves:

- `VaultError::HardwareKeyStoreUnavailable`, `VmkMissing`, etc. map through `From<VaultError>` into `AegisError::Vault`;
- file/stream header/tamper failures map into `AegisError::File`;
- ratchet/X3DH failures map into `AegisError::Ratchet`.

New failure modes are additive: `AegisError` is `#[non_exhaustive]` with one variant per leaf error + `Io`, so future leaves add typed variants without semver breakage. `From` impls let callers chain `?` cleanly.

## 3. Cipher choice (no new cryptography)

`aegis-core` does not invent or re-explain ciphers. The wire mapping and policy live in the leaves and are cited:

- `aegis_crypto::aead::AeadAlgorithm` — suitability matrix (AES-256-GCM: HW-accelerated, faster on x86/ARM; ChaCha20-Poly1305: software constant-time, faster on mobile/wasm) and negotiation note.
- `aegis-file` header wire byte `0/1` mapping and the rule "sender picks, receiver dispatches."

`aegis-core` doc comments cross-link `AeadAlgorithm` and the `aegis-file` header and repeat the frontend policy in one paragraph (AES preferred where HW exists, ChaCha20 fallback, wire byte + enum argument), mirroring `aead.rs` + `aegis-file/src/stream.rs`. No new construction; cites leaf crates.

## 4. Zeroization and panics

The leaf crates already wrap secrets in `zeroize::Zeroizing`. `AegisRuntime` holds owned `Vault` / `RatchetState` values whose `Drop` behaviour is determined entirely by the leaves — it does not add a second zeroization layer. Doc comments state the same limitation the leaves do (stack/register/swap copies outside `zeroize`'s reach).

No panic on attacker-controlled data; the only panics `AegisRuntime` could reach are the leaves' documented fail-closed reactions to OS-RNG failure (`getrandom`/`ChunkNonceSequence::random`, `try_into` on nonce lengths) or vault/SQLCipher hard failures — neither is attacker-controlled. Doc comments say so explicitly.

## 5. Testing strategy (TDD)

- Unit, same-file (`#[cfg(test)]`): `AegisError` `Display`/`From`/`std::error::Error` round-trips per variant; `RuntimeConfig` construction; `AegisRuntime::new` with a mocked vault path (isolated temp dir) to exercise fail-closed vault-unavailable → `AegisError::Vault` path and the happy path.
- Integration (`crates/aegis-core/tests/` or crate-level tests): a small smoke that opens/mocks a vault, performs one `aegis-ratchet` X3DH round-trip through the `AegisRuntime` handle, and streams a small file via `aegis-file` through its `FileManifest` plumbing — explicitly exercising both AES and ChaCha choices through the vault→ratchet→file wire.

Fixture strategy: reuse `aegis-net`'s `testing` feature where needed for transport mocks; `tempfile` for isolated vault DB paths; parameterization as the leaf crates already do. Every test passes before each commit.

## 6. Publish checklist

Same repeat that the last four crate publishes used:

- `crates/aegis-core/Cargo.toml`: `version = "0.1.0"`, `rust-version = "1.75"`, `[package.metadata.docs.rs]` `all-features + cfg(docsrs)`, description ending "NOT independently audited", `license = "PolyForm-Noncommercial-1.0.0"`, `readme = "README.md"`, `repository.workspace = true`, `[lints] workspace = true`, deps on each leaf pinned to its published version, `SECURITY_DISCLAIMER` re-export, `#[deny(unsafe_code)]` inherited (no `#[allow]`), disclaimer test.
- New `crates/aegis-core/README.md` — Quick start / What this is / Security disclaimer / cipher-choice note by cross-link.
- `Cargo.lock` replay if needed.
- Before publish, pending 9 doctest regressions in `aegis-vault-pqc` (`aegis_vault::` → `aegis_vault_pqc::` after rename) must already be fixed in-tree; `aegis-core` depends on `aegis-vault-pqc`.

## 7. Out-of-scope explicitly

- Group/mutex gossip, pending-forward-secret ratchet refinements (follow `aegis-ratchet` spec).
- I2P or mixnet future transports (follow `aegis-net` spec).
- Tokio event-loop / background-task orchestration beyond `aegis-net`'s existing `background.rs`.
- Platform TUIs or `aegis-ffi`'s C-ABI/UniFFI bindgen — `aegis-core` stays safe Rust; `aegis-ffi` is the only consumer that adds `unsafe`.

## 8. Next step

Invoke `superpowers:writing-plans` → TDD cycle (tests first, then implementation), modeled on the vault/file/net publish cadence. No code lands before the implementation plan is approved.
