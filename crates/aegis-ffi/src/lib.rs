//! UniFFI / C-ABI export layer producing native bindings for desktop,
//! Android (Kotlin/JNI), and iOS/macOS (Swift) platform targets.
//!
//! See `AEGIS.Plan.V0.2.md` Sections 8 and 9. Depends on all other
//! `aegis-*` crates being stable. This crate is scaffolding only — no
//! behavior has been implemented yet. Per Section 10, `unsafe` blocks
//! required for FFI binding code must each carry a doc comment
//! justifying soundness and will need a scoped `#[allow(unsafe_code)]`
//! at the point of use, overriding the workspace-level deny.
