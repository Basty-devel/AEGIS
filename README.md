# AegisPQC (AEGIS)

> **Federated, Zero-Trust, Post-Quantum Hyper-Secure Messenger**

> ⚠️ **DISCLAIMER: NOT INDEPENDENTLY AUDITED**
>
> AegisPQC implements novel protocol engineering (a hybrid post-quantum ratchet, a federated relay/mailbox network). Every cryptographic construction in this repository follows published references, but composition of published primitives into a new protocol is itself a source of risk — novel composition is exactly what audits exist to catch. **Until a third-party cryptographic audit has been completed, every release, binary, and page of documentation MUST carry a visible "not independently audited" disclaimer, and the software MUST NOT be represented as audited, certified, or production-hardened.**

---

## Table of Contents

1. [Overview](#overview)
2. [Key Advantages over Signal](#key-advantages-over-signal)
3. [Hardware & OS Recommendation](#hardware--os-recommendation-grapheneos--google-pixel-9-pro-series)
4. [System Architecture & Workspace Breakdown](#system-architecture--workspace-breakdown)
5. [Threat Model](#threat-model)
6. [Cryptographic Agility & Versioning](#cryptographic-agility--versioning)
7. [Compliance Mapping](#compliance-mapping)
8. [Build & Development](#build--development)
9. [Security Disclosure Policy](#security-disclosure-policy)
10. [Non-Goals](#non-goals)
11. [Roadmap](#roadmap)
12. [License](#license)

---

## Overview

**AegisPQC** is a federated, zero-trust, post-quantum-safe messaging platform engineered to defend against advanced global passive network observers, post-quantum decryption threats ("Harvest Now, Decrypt Later"), device seizure, and legal compulsion of infrastructure operators. It provides high-throughput payload streaming, strict metadata elimination at the protocol layer, and hardware-bound vault security.

AEGIS is a **specification and reference implementation**, not a finished, audited product. Anyone deploying it for real-world sensitive communication should read the [Threat Model](#threat-model) and [Non-Goals](#non-goals) sections in full before relying on it.

---

## Key Advantages over Signal

While the Signal Protocol remains the benchmark for classic mobile end-to-end encryption, AEGIS raises the cryptographic and architectural security ceiling to address the adversary classes defined in the [Threat Model](#threat-model) (A1–A6):

| Feature / Metric | Signal | AegisPQC (AEGIS) | Advantage of AEGIS |
| :--- | :--- | :--- | :--- |
| **Post-Quantum Security** | NIST Level 1–3 (PQXDH with ML-KEM-768) | **NIST Security Level 5** (ML-KEM-1024 + brainpool512r1 KEM, ML-DSA-87 + Ed25519) | Maximum defense against "Harvest Now, Decrypt Later" quantum attacks (A5). |
| **Network Anonymity** | Centralized TLS / AWS infrastructure (IP addresses exposed to server) | **Tor-Native Transport** (`arti` Rust stack), cover traffic & 4 KB fixed-size packet padding | Protection against global passive network observers (A1) and traffic/timing analysis (A2). |
| **Identity & Metadata** | Phone number registration required; central contact graph lookup | **Zero PII collection**; blind capability tokens; public key is identity | No central contact graph, no PII at registration, reduced metadata surface (see [residual metadata risk](#residual-metadata-risk)). |
| **File Payloads** | ~100 MB limit | **Up to 1 GB** out-of-band chunked AEAD streaming (4 MB chunks, BLAKE3 Merkle tree) | Bounded 4 MB RAM footprint with support for large binary assets and data files. |
| **Server Architecture** | Centralized service | **Federated mailbox network** with Sealed Sender 2.0 | No single point of legal compulsion, compromise, or failure (mitigates A4, does not eliminate it — see [Threat Model](#threat-model)). |
| **Local Device Hardening** | Software-fallback allowed | **Strict zero-fallback policy** (mandatory hardware TEE / StrongBox / Secure Enclave) | App refuses to launch without verified hardware key isolation, reducing the blast radius of device seizure (A6). |

---

## Hardware & OS Recommendation: GrapheneOS + Google Pixel 9+ Pro Series

To achieve the maximum security posture envisioned by the AEGIS specification (OWASP MASVS-L3 & BSI TR-03183), **AEGIS is strongly recommended to be deployed on GrapheneOS running on Google Pixel 9 Pro or 9 Pro XL (or newer) hardware.**

### Why GrapheneOS?

1. **Minimized Operating System Telemetry:** Reduces OS-level background data flows, complementing AEGIS's zero-PII, protocol-level metadata-minimization architecture. This is an OS-level property outside AEGIS's own trust boundary — see [Threat Model → Out of Scope](#out-of-scope).
2. **Hardened Runtime Environment:** Hardened memory allocation (`hardened_malloc`), Control Flow Integrity (CFI), and strict application sandboxing to raise the cost of zero-day memory-corruption exploits.
3. **Google-Free Stack:** AEGIS operates natively over Tor (`arti`) using federated push mechanics, requiring no Google Play Services or Firebase Cloud Messaging (FCM), removing a metadata channel present in most mobile messengers.

### Why the Google Pixel 9+ Pro Series?

* **Titan M2 Hardware Security Module:** Enforces the strict **zero-fallback policy** via hardware-backed key isolation in Android Keystore (StrongBox/TEE).
* **16 GB RAM Capacity:** Post-Quantum Level 5 cryptography (ML-KEM-1024, ML-DSA-87), double-ratchet execution, streaming file buffers, and background Tor circuits are memory-intensive; 16 GB avoids aggressive background process termination.
* **ARMv9 Memory Tagging Extension (MTE):** Hardware-enforced mitigation against buffer overflows and use-after-free bugs, supporting OWASP MASVS-L3 requirements.
* **Modern High-Efficiency Modem:** Offsets battery drain from continuous Tor circuit maintenance (`arti`) and constant-rate cover traffic.

> **Note on Compatibility:** Devices lacking a hardware enclave (TEE/StrongBox) or running an OS AEGIS cannot attest as trustworthy will fail the AEGIS hardware initialization check by design (fail-closed, not fail-open).

---

## System Architecture & Workspace Breakdown

AEGIS is built as a modular Rust workspace (`#![forbid(unsafe_code)]` in every crate except a narrowly scoped, individually audited `unsafe` shim in `aegis-vault` for enclave FFI), exporting C-ABI / UniFFI bindings for cross-platform integration:

```text
aegis/
├── aegis-crypto/    # Hybrid PQC (ML-KEM-1024/brainpool512r1, ML-DSA-87/Ed25519, Argon2id, KAT tests)
├── aegis-ratchet/   # Post-Quantum Double Ratchet (PQ-DR), Group Sender-Keys & Multi-Device
├── aegis-vault/     # SQLCipher storage, StrongBox/Enclave hardware isolation, GDPR Art. 17/20 engines
├── aegis-file/      # 1 GB streaming engine, 4 MB chunking, BLAKE3 Merkle tree verification
├── aegis-net/       # Tor transport via `arti`, federated mailbox relay, Sealed Sender 2.0, capability tokens
├── aegis-ffi/       # UniFFI / C-ABI export layer for Kotlin (Android), Swift (iOS/macOS), and Desktop
└── platforms/       # UI wrappers (Android Kotlin, iOS Swift, Desktop Tauri v2)
```

Each crate owns one trust-relevant responsibility and is designed to be independently reviewable and independently fuzzed; crate boundaries in the table below double as the trust boundaries used in the threat model.

| Crate | Primary Assets Owned | Untrusted Inputs It Parses |
| :--- | :--- | :--- |
| `aegis-crypto` | Long-term identity keys, ephemeral KEM secrets, session keys | Peer public keys/ciphertexts, KAT vectors at build time |
| `aegis-ratchet` | Ratchet state (root/chain keys), message keys | Inbound ratchet headers, out-of-order ciphertext |
| `aegis-vault` | Encrypted local database, vault master key | SQLCipher file on disk, enclave attestation responses |
| `aegis-file` | File encryption keys, chunk integrity state | Inbound file chunks, Merkle proofs from untrusted relays |
| `aegis-net` | Capability tokens, relay session state, Tor circuit state | All wire-format frames from federated relays and peers |
| `aegis-ffi` | Nothing directly; marshals ownership across the FFI boundary | Data crossing the Rust/host-language boundary |
| `platforms/` | UI state, clipboard, notification payloads | User input, OS IPC (share sheets, notifications, deep links) |

---

## Threat Model

This section defines the adversaries AEGIS is designed to resist, the assets it protects, the trust boundaries between components, and — as importantly — what it does **not** protect against. A threat model that only lists strengths is marketing; the [Out of Scope](#out-of-scope) and [Residual Risk](#residual-metadata-risk) subsections are load-bearing parts of this document, not caveats.

### Assets

| Asset | Description | Confidentiality | Integrity | Availability |
| :--- | :--- | :--- | :--- | :--- |
| Message plaintext | Content of 1:1 and group messages | Critical | Critical | High |
| File payloads | Up to 1 GB attachments | Critical | Critical | Medium |
| Long-term identity key pair (ML-DSA-87/Ed25519) | Proves "you are you" across sessions | Critical | Critical | High |
| Ratchet state (root/chain/message keys) | Enables forward secrecy & post-compromise security | Critical | Critical | High |
| Social graph (who talks to whom, when) | Derivable from metadata even with encrypted content | Critical | N/A | N/A |
| Capability tokens | Anonymous authorization to a mailbox, without identity | High | Critical | Medium |
| Vault master key | Protects all local state at rest | Critical | Critical | High |
| Device attestation state | Proves hardware TEE/StrongBox is genuine and unmodified | High | Critical | Medium |

### Adversary Classes (A1–A6)

| ID | Adversary | Capabilities Assumed | Capabilities Explicitly Excluded |
| :--- | :--- | :--- | :--- |
| **A1** | Global Passive Network Observer (GPA) | Observes/logs all traffic on backbone links and IXPs; correlates timing across the whole network; does not control endpoints | Cannot break Tor's onion encryption directly; not assumed to control >~ the fraction of the Tor network needed for practical end-to-end correlation |
| **A2** | Local Network / Traffic Analyst | Sits on the user's LAN, ISP, or a malicious Wi-Fi AP; performs timing/size correlation, packet counting | Cannot see Tor-internal hops; defeated by fixed-size padding and cover traffic to the extent volume/timing alone would otherwise leak information |
| **A3** | Malicious or Compelled Federated Relay Operator | Controls one or more mailbox relay nodes; can log metadata it legitimately receives, drop/delay/duplicate/reorder messages, collude with other relays it operates | Cannot forge messages (authenticated), cannot decrypt payloads (E2EE), cannot deanonymize sender without also controlling the entry/guard relay or breaking Sealed Sender |
| **A4** | State Actor / Legal Compulsion | Can issue legal process against any single jurisdiction's relay operator, ISP, or platform; can conduct targeted (not global) surveillance; assumed capable of coercing one relay operator, not the majority of independent federation members simultaneously | Not assumed to compel every independent relay operator in the federation at once, nor to have a working large-scale quantum computer today |
| **A5** | "Harvest Now, Decrypt Later" (HNDL) Adversary | Records all ciphertext today; assumed to possess a cryptographically relevant quantum computer at some future date | Not assumed to break the classical (ECDH/Ed25519) component even with a quantum computer within the protocol's design horizon — hybrid construction requires **both** components broken |
| **A6** | Device-Present Adversary (Seizure / Border Search / Theft) | Has physical possession of a locked or powered-off device; can attempt cold-boot, chip-off, JTAG, or coerce the passphrase from the user (rubber-hose) | Cannot extract keys from a genuine, unmodified TEE/StrongBox without physical key material or the user's passphrase; **cannot** protect the user against being compelled, under threat, to unlock a device they are physically present and cooperating with — this is a legal/physical-safety problem, not a cryptographic one |

Two adversaries are deliberately **not** primary design targets and are covered under [Out of Scope](#out-of-scope): a fully malicious *sender or recipient endpoint* (e.g., a compromised counterparty who screenshots your messages), and a *nation-state that has already gained arbitrary code execution on your device* (full endpoint compromise defeats essentially any messenger).

### Trust Boundaries

```text
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   Device A (fully trusted)   │        │   Device B (fully trusted)    │
│  ┌────────────────────────┐  │        │  ┌────────────────────────┐  │
│  │ aegis-vault (TEE-bound) │  │        │  │ aegis-vault (TEE-bound) │  │
│  │ aegis-ratchet           │  │        │  │ aegis-ratchet           │  │
│  │ aegis-crypto            │  │        │  │ aegis-crypto            │  │
│  └───────────┬────────────┘  │        │  └───────────┬────────────┘  │
│              │ aegis-net      │        │              │ aegis-net      │
└──────────────┼───────────────┘        └──────────────┼───────────────┘
               │  Tor (arti) — E2E ciphertext only         │
     ══════════▼════════════ TRUST BOUNDARY ═══════════════▼══════════
               │                                             │
      ┌────────▼────────┐   federation protocol    ┌─────────▼────────┐
      │ Relay Node R1    │◄─────────────────────────►│ Relay Node R2    │
      │ (untrusted;      │                            │ (untrusted;      │
      │  A3/A4 adversary)│                            │  A3/A4 adversary)│
      └──────────────────┘                            └──────────────────┘
```

Everything left of the trust-boundary line is assumed honest (subject to [device compromise](#out-of-scope) caveats); everything right of it — every relay, every network hop, every federation partner — is assumed **actively malicious** for design purposes, per zero-trust principle of least privilege. No relay is trusted for confidentiality, integrity of routing, or availability; a relay is only trusted to relay *some* fraction of traffic *eventually*, and even that assumption is not load-bearing for message secrecy.

### STRIDE Analysis by Component

| Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `aegis-crypto` | Mitigated: mutual authentication via hybrid ML-DSA-87 + Ed25519 signatures; classical break alone is insufficient | Mitigated: AEAD (ChaCha20-Poly1305/AES-256-GCM) on all ciphertext; KAT tests catch implementation drift | Non-repudiation is a **non-goal** by design (deniable messaging, like Signal) | Primary risk surface: side-channel leakage of ephemeral secrets — mitigated via constant-time arithmetic and RAM zeroization (`Zeroize`, `explicit_bzero` equivalents) on drop | N/A (no network exposure) | Mitigated: no code execution surface; pure computation |
| `aegis-ratchet` | Mitigated: ratchet advances only on authenticated KEM/DSA material | Mitigated: skipped-message-key store bounded and MAC-verified before decrypt | Same as above | Header encryption limits metadata leakage of message counters to passive observers of ciphertext at rest | Skipped-key store has a **hard cap** (bounded queue) to prevent memory-exhaustion DoS from an adversary sending many out-of-order messages | N/A |
| `aegis-vault` | Mitigated: vault unlock requires TEE-attested key release, not password alone | Mitigated: SQLCipher page-level AEAD; tamper triggers hard failure, not silent corruption | GDPR Art. 17 (erasure) engine must produce cryptographic evidence of deletion (key destruction), addressed under [Compliance Mapping](#compliance-mapping) | **A6 residual risk:** cold-boot/chip-off against a device with the vault *unlocked and the master key resident in RAM* is not fully mitigated by any software control — see [Residual Risk](#residual-metadata-risk) | Zero-fallback policy is itself an availability trade-off: a device without a working TEE is bricked for AEGIS use by design | Mitigated: enclave boundary enforced by hardware, not by AEGIS code |
| `aegis-file` | Mitigated: chunks authenticated via BLAKE3 Merkle root signed in the message envelope | Mitigated: per-chunk AEAD + Merkle proof rejects any tampered or substituted chunk before it reaches the assembly buffer | N/A | 4 MB bounded chunk buffer prevents a malicious relay from inferring file structure beyond size (padded) and forces constant per-chunk memory disclosure ceiling | Chunk reassembly is bounded (4 MB working set); a relay withholding chunks causes a stall, not a crash, and is retryable from any relay holding the ciphertext | N/A |
| `aegis-net` | Sealed Sender 2.0 hides sender identity from relays; **relays can still spoof relay-to-relay identity within the federation protocol** unless federation-level mutual TLS/pinning is enforced — tracked as an open hardening item | Federation messages are signed; a relay altering routing metadata it does *not* have signing authority over is detectable by the recipient relay | Relays legitimately see connection metadata (timing, size buckets, capability token use) they route — this is an accepted, minimized, but nonzero disclosure | **Primary residual metadata surface** — see [Residual Risk](#residual-metadata-risk) | Federated architecture provides relay-level redundancy; a single relay outage degrades, not halts, delivery for clients configured with fallback relays | Capability tokens are scoped and time-bound; a compromised relay cannot mint tokens for a mailbox it does not host |
| `aegis-ffi` | N/A (no independent identity) | Mitigated: UniFFI-generated bindings are type-checked; no raw pointer arithmetic crosses the boundary | N/A | Care required: host-language garbage collectors (Kotlin/Swift) may retain copies of key material passed across FFI longer than Rust's `Zeroize` can reach — tracked as an open hardening item, see [Non-Goals](#non-goals) | N/A | Mitigated: `#![forbid(unsafe_code)]` on the Rust side of the boundary |
| `platforms/` | Mitigated: platform UI cannot forge protocol messages, only display them | OS clipboard, notification previews, and screenshots are **outside AEGIS's control** and are a well-known leak path — mitigated via notification content redaction and clipboard auto-clear timers, not eliminated | User can always deny having sent a message (deniability is intentional) | **Highest-likelihood leak point in practice**: shoulder-surfing, notification previews on lock screen, OS-level screenshot/backup services | Platform-level app freezing/killing is an OS decision AEGIS cannot prevent | Mitigated by OS app sandboxing (GrapheneOS hardened sandbox recommended) |

## Cryptographic Agility & Versioning

* All wire-format messages carry an explicit algorithm-suite identifier; suite negotiation is authenticated as part of session establishment so a network adversary cannot force a downgrade to a weaker suite (no silent fallback).
* NIST PQC parameter sets are pinned per protocol version (currently ML-KEM-1024 / ML-DSA-87); a cryptanalytic advance against either requires a coordinated protocol version bump, not a silent algorithm swap.
* Every hybrid construction combines exactly one post-quantum and one classical primitive such that **breaking either alone is insufficient** to compromise confidentiality or authenticity (defense in depth against both "PQC turns out to be broken" and "quantum computers arrive sooner than expected").
* Known-Answer-Test (KAT) vectors from the NIST reference implementations are run in CI on every commit touching `aegis-crypto`.

## Compliance Mapping

| Requirement | Mechanism | Status |
| :--- | :--- | :--- |
| OWASP MASVS-L3 (resilience) | Hardware-backed key storage, zero-fallback policy, MTE | Design target; not independently verified |
| BSI TR-03183 (component security) | SBOM generation, reproducible builds (tracked, see [Non-Goals](#non-goals)) | In progress |
| GDPR Art. 17 (right to erasure) | Vault key destruction renders all local ciphertext unrecoverable; no server-side plaintext ever exists to erase | Implemented in `aegis-vault`; not independently audited |
| GDPR Art. 20 (data portability) | Local vault export in a documented, versioned schema | Implemented in `aegis-vault`; not independently audited |
| NIST SP 800-207 (Zero Trust Architecture) | No implicit trust in relay/transport infrastructure; per-session authentication; least-privilege capability tokens | Architectural principle throughout `aegis-net` |

None of the above constitutes a certification. Treat this table as a map of intent and mechanism, not a compliance attestation.

## Build & Development

```bash
# Toolchain
rustup toolchain install stable
rustup component add clippy rustfmt

# Build the full workspace
cargo build --workspace --locked

# Run unit + KAT tests
cargo test --workspace --locked

# Lint (deny warnings in CI)
cargo clippy --workspace --all-targets -- -D warnings

# Fuzz a specific crate (requires cargo-fuzz)
cargo fuzz run aegis_ratchet_fuzz -- -max_total_time=300
```

Platform shells build independently against the `aegis-ffi` UniFFI bindings:

```bash
# Android (Kotlin) bindings
./aegis-ffi/scripts/gen-kotlin.sh

# iOS/macOS (Swift) bindings
./aegis-ffi/scripts/gen-swift.sh
```

Minimum supported Rust version (MSRV) and exact dependency versions are pinned in `Cargo.lock`; CI builds with `--locked` to prevent unreviewed dependency drift from entering a release.

## Security Disclosure Policy

Do not open a public issue for a suspected vulnerability. Given the current pre-audit status of this project, treat any finding as high-impact until triaged.

* Report privately to the maintainers' published security contact (PGP key fingerprint to be listed in `SECURITY.md`).
* Include: affected crate/version, reproduction steps or PoC, and impacted asset(s) from the [Assets](#assets) table above.
* Expect acknowledgment within 5 business days and a coordinated disclosure timeline agreed before any public write-up.
* Findings affecting the ratchet, KEM/signature composition, or vault key derivation are treated as critical by default given their position in the [STRIDE table](#stride-analysis-by-component).

## Non-Goals

Explicitly deferred or rejected design goals, so scope creep and audit expectations stay bounded:

* **Reproducible/deterministic builds and SBOM publication** — planned, not yet implemented; tracked against [BSI TR-03183](#compliance-mapping).
* **FFI-boundary key zeroization guarantees on garbage-collected host languages** (Kotlin/Swift) — Rust-side zeroization is enforced; host-language retention of copied key material cannot currently be bounded and is an open hardening item, not a resolved one.
* **Protection against a fully compromised endpoint** — out of scope by definition; see [Out of Scope](#out-of-scope).
* **Anonymity guarantees stronger than the underlying Tor network provides** — AEGIS does not attempt to re-implement or improve on Tor's anonymity properties, only to carry traffic over them correctly.
* **Independent third-party cryptographic audit** — not yet completed. This is the single most important open item; see the disclaimer at the top of this document.

## Roadmap

1. Complete `aegis-ffi` cross-boundary zeroization hardening.
2. Reproducible build pipeline + SBOM (BSI TR-03183 alignment).
3. Federation-level relay-to-relay mutual authentication hardening (closes the open item in the `aegis-net` STRIDE row).
4. Engage an independent cryptographic auditor; publish findings and remediation status regardless of outcome.
5. Formal verification (e.g., ProVerif/Tamarin model) of the PQ-Ratchet state machine.

## License

License to be finalized before first tagged release. Until a `LICENSE` file is present in this repository, no rights are granted to use, copy, modify, or distribute this code beyond viewing the source.
