# aegis-ffi Phase 1: C-ABI / UniFFI Export Layer — Design

Implements `AEGIS.Plan.V0.2.md` §8/§9 item 7 — the mandatory build-order position that the plan makes explicit: "do not start platform UIs before `aegis-ffi` is stable" (§10). Depends on all leaf crates plus `aegis-core` being stable. Allowed the one `#[allow(unsafe_code)]` exception per `Cargo.toml` `[workspace.lints.rust]` comment / §10: "narrowly scoped `#[allow(unsafe_code)]` at the point of use."

This doc is consumed by `superpowers:writing-plans`.

## 0. Phase Scope

`aegis-ffi` is the last of the seven workspace members (build order §10 item 7 before platform UIs). Its Phase 1 is deliberately thin: a deterministic, audit-constrainable export surface for the already-tested Rust runtime that lives in `aegis-core` plus the leaf crates. Two responsibilities, neither invents new protocol or crypto:

- **C-ABI layer:** wrap `AegisRuntime` / `AegisError` / leaf read-only surfaces (`Vault` reads, file streaming is already pure) into functions whose signatures are representable across a native shared-library boundary (plain integers, counted byte slices, UTF-8 string handles) and whose allocation discipline (`alloc` on the Rust side, explicit `free` per handle/buffer via an exported `aegis_free`) avoids aliasing the host runtime's heap without coordination.
- **UniFFI layer:** once C-ABI is stable, expose that same surface via `uniffi-rs` proc macros so generated Kotlin (JNI) and Swift (SPM, Keychain/Secure Enclave hosts) bindings can consume `AegisRuntime` through owned handles without hand-written JNI or SwiftShims.

Everything invented for Phase 1 is **generatable at publish time from a stable crate version** — no ad-hoc UI logic, no async event loop (Tokio work already lives in `aegis-net`'s `background.rs`). Async/aggregation stays in Rust (Tokio), not in the wire boundary.

### What it is

- **Shim, not a second runtime.** The native side does not run a separate vault/ratchet/file/net state machine; every call delegates to `aegis-core`'s `AegisRuntime` or directly to the leaf crate that owns the behaviour. That keeps the audit surface inside the leaves and lets `aegis-core` already carry unified `AegisError`.
- **Phase 1 only sells the read-only half of the vault.** Mutating the vault (cross-namespace `put`, `erase`, `destroy_vault`, GDPR Art. 20 export) is leaf-correct through `aegis-core` already but wants a FFI error-mapping review and a platform credential-store path before it becomes the documented first published surface — deferring that does not block publishing the read-only half as `0.1.0` behind the same disclaimer.
- **Per Section 10, narrowly scoped `#[allow(unsafe_code)]` only at the point of use.** Every `unsafe` block carries a doc comment justifying soundness (why the pointed-to handles, slices, and UTF-8 contract stay valid for the call's duration). No bare `unsafe {}` without a block-level rationale.

## 1. Export surface (minimal Phase 1 handle)

```rust
// The only Phase 1 handle exposed across the wall.
pub struct AegisHandle { /* Box<AegisRuntime> behind the boundary */ }

// Construction / teardown (explicit "who frees it" rule):
//   - `aegis_runtime_create(path, service_name) -> *mut AegisHandle`
//   - `aegis_runtime_destroy(handle: *mut AegisHandle)`
//   - `aegis_str_free(ptr: *mut u8, len: usize)`
//   - `aegis_bytes_free(ptr: *mut u8, len: usize)`
// Ownership: caller passes counted slices (`ptr+len`), Rust copies; on the
// return path Rust allocates counted buffers caller frees via the `*_free`
// pair per allocation kind. Strings are in fact UTF-8; invalid UTF-8 fails
// closed (null/error, not a lossy fallback).

// Reads that already delegate to the leaves without inventing semantics:
//   - vault `get` (namespaced, envelope-decrypted bytes)
//   - `list_keys` for a given namespace
//   - crate's `SECURITY_DISCLAIMER` as a counted string
// Later phases wire identity provisioning, ratchet X3DH init, file
// streaming (the leaves already stream — FFI only needs the call-site map),
// and transport (depends on the mailbox protocol maturing).
```

All return paths carry a counted error string (`aegis_error` / mapped `AegisError::Vault|Sas|Net|Io`) rather than an untyped integer — callers can match on the header without depending on integer codes staying stable. No `CString` marshalling outside `unsafe` blocks; slices are borrowed for the call's duration only.

## 2. Allocation and lifetime contract

- Inputs: `*const u8 + len` pairs, valid only for the call. FFI copies before doing any fallible work.
- Outputs: Rust allocates on its heap and returns a counted buffer/string; caller must free via the matching `aegis_str_free` / `aegis_bytes_free` (explicit, two-function rule — no conditional `match` on the Rust side). No caller-allocated out-buffers where Rust would write — that pattern invites over/under-run.
- `AegisHandle` is owned by the caller after `aegis_runtime_create`; exactly one `aegis_runtime_destroy` must follow. Double-free is defined as caller UB (documented), not trapped — trapping would need atomics that the shim does not own.

## 3. UniFFI (after C-ABI hardens)

Add `uniffi::export`, `uniffi::setup_scaffolding!`, and a `uniffi.toml` conditioned on `#[cfg(feature = "uniffi")]` so `cargo test` (which never enables `uniffi`) stays a clean proof that the C-ABI shim alone works. Generated Kotlin/Swift bindings are not checked into `feature/aegis-crypto` at this phase — only the `.udl`/scaffolding source needed to regenerate them, plus a `cargo package --list` sanity test. CocoaPods / SPM plugin wiring is an `aegis-ffi` Phase 2 concern.

## 4. Error and disclaimer mapping

The crate exports `SECURITY_DISCLAIMER` exactly as the leaves do. Fallible FFI surfaces return `Result<T, E>` on the Rust side and surface `AegisError::Vault|Crypto|Ratchet|File|Net|Io` across the wall as counted strings; non-fallible handle-creation failures (allocation failure) return a null handle and set a last-error string that `aegis_last_error()` exposes — single place to standardise such "C can't spell Result."

## 5. Testing strategy (TDD)

- Crate-level, same-file (`#[cfg(test)]`) and `#[cfg(test)]` FFI tests that call into the C-ABI surface through the documented `unsafe` blocks and prove the exact unsafety condition (`ptr+len` valid for `len`, `handle != null`, string valid UTF-8).
- Round-trip: create-time → `put` → `get` through the FFI boundary vs. through `aegis-core` directly, proving the shim does not invent semantics.
- Cross-cut: `cargo test -p aegis-ffi` (with and without `--features uniffi`), `cargo fmt`, `cargo clippy -- -D warnings`, `cargo doc --no-deps`.

## 6. Publish checklist

`Cargo.toml` inherits `rust-version = "1.75"`, `[package.metadata.docs.rs]` `all-features + cfg(docsrs)`, `[lints] workspace`, description ending "NOT independently audited", `license = "PolyForm-Noncommercial-1.0.0"`, `readme = "README.md"`, `repository.workspace = true`, `version = "0.1.0"` (or `-pqc` if the name collides). Deps pinned to published versions (`aegis-core-pqc@0.1.0`, etc.).

## 7. Out-of-scope explicitly

- Tauri/Kotlin/Swift platform UIs — they consume `aegis-ffi`'s published crate, not this phase.
- Async event-loop / background-task orchestration beyond what `aegis-net::background` already owns.
- I2P / mixnet future transports (see aegis-net future directions).

## 8. Next step

Invoke `superpowers:writing-plans` → TDD cycle. No crate lands before its implementation plan is approved.
