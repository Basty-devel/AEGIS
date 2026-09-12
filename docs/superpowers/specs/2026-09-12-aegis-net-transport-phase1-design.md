# aegis-net: Tor Transport Layer (Section 6.1), Phase 1 — Design

Implements the transport slice of `AEGIS.Plan.V0.2.md` Section 6.1.
Depends on no other AEGIS crate — `aegis-net`'s eventual dependency on
`aegis-ratchet` and `aegis-file` (Section 10's build order) is exercised
by the future mailbox-protocol phase, not this one. This phase's only
new external dependency is `arti-client` (and its
`onion-service-client`/`onion-service-service` features).

**Naming note:** "Phase 1" here scopes *this track* (Section 6.1) only.
Section 6.3 (capability tokens & rate limiting) already exists as a
separately completed, independent track — see
`2026-09-12-aegis-net-capability-tokens-design.md` — built concurrently
rather than as a prior phase this one follows; the two have no
dependency on each other, so their existing code (`capability.rs`,
`rate_limit.rs`) is unaffected by this doc.

## 0. Phase Scope

Section 6 bundles three fairly independent subsystems: transport (6.1),
the federated mailbox protocol (6.2), and abuse resistance (6.3). 6.2
depends on 6.1 for actual byte transport and on 6.3 for the capability
tokens it authenticates peers with; 6.3 itself has no dependency on 6.1.
`aegis-net` is therefore being built as independent tracks per section
rather than one Section-6-sized design, matching this workspace's
established pattern of phased/narrowed crate delivery (`aegis-ratchet`'s
groups/multi-device deferral, `aegis-vault`'s hardware-backend
narrowing) — generalized here from sequential phases to independent
tracks, since 6.1 and 6.3 genuinely don't block each other the way, say,
`aegis-vault`'s backends did.

**This track's Phase 1 builds only:**

1. A `Transport` trait — the seam every later phase and every future
   pluggable transport (I2P, a custom mixnet — both named
   explicitly-deferred in spec Section 6.1) implements against.
2. `TorTransport`, an `arti-client`-backed implementation: outbound
   dialing to a peer's v3 onion address, and hosting a local v3 onion
   service (both directions, not outbound-only — a node operator needs
   to be reachable, not just able to reach others).
3. `FakeTransport`, an in-memory implementation used solely to test
   `aegis-net`'s own logic deterministically, without a live Tor
   connection.

**Deliberately not in this track:** the federated mailbox protocol
itself (node identity/directory gossip, mailbox storage, message framing
— Section 6.2) and the network-facing half of Section 6.3 (Sealed Sender
2.0 onion envelopes, cover traffic, 4 KB padding). Capability-token
issuance/verification and per-identity rate limiting — also Section 6.3
— are **already built**, as an independent track with no dependency on
this one (see the naming note above); this doc does not duplicate or
depend on that work. The mailbox protocol gets its own design doc once
both this track's `Transport` trait and the capability-tokens track
exist to build against. This track's contract ends at "here is a
byte-stream connection to a given onion address, and here is how to
accept one" — nothing about what travels over it.

## 1. Sync Facade Over an Async-Only Dependency

`arti-client` is async-only (built on `tokio`), but every other crate in
this workspace (`aegis-crypto`, `aegis-ratchet`, `aegis-file`) exposes a
plain synchronous API with no async runtime anywhere in the dependency
tree. Introducing `async fn`/`Future`-based methods on `aegis-net`'s
public API would force every future consumer — eventually `aegis-ffi`
and, through it, every platform binding (Kotlin, Swift, desktop) — to
adopt an async runtime purely because of this one crate's underlying
dependency, not because the workspace's own design calls for it.

`TorTransport` therefore owns one persistent multi-threaded
`tokio::runtime::Runtime` for its entire lifetime and exposes only
blocking methods. Each blocking call bridges to the async side via
`runtime_handle.block_on(...)`:

- **Bootstrap:** `TorTransport::bootstrap(config: TorTransportConfig)`
  does `runtime.block_on(TorClient::create_bootstrapped(arti_config))`.
- **Connect:** `connect(addr)` does
  `handle.block_on(tor_client.connect(addr.as_tor_addr()))`, wrapping the
  resulting `arti_client::DataStream` in a `TorStream(DataStream,
  Handle)` newtype whose `Read`/`Write` impls each do one `block_on` per
  call (`handle.block_on(async_stream.read(buf))` /
  `...write(buf)`).
- **Host:** see Section 3 — a background task, not a per-call bridge,
  since accepting is push-driven (arti delivers requests when they
  arrive, not on caller demand the way a single `read()` call is).

This is a proven pattern (the same shape `reqwest::blocking` uses to
wrap an async HTTP client) rather than a novel one. The accepted cost:
each read/write pays a small scheduling round-trip into the runtime.
`aegis-net` v1 is message-oriented (mailbox store-and-forward; bulk
chunking already happens one layer up in `aegis-file`), not a
high-frequency small-packet pipe, so this overhead is not a driving
constraint — a per-stream dedicated-thread bridge (lower overhead, real
added lifecycle/backpressure complexity) was considered and rejected as
premature for this throughput profile.

## 2. The `Transport` Trait

```text
crates/aegis-net/src/
  lib.rs          // re-exports, SECURITY_DISCLAIMER (matching other crates)
  error.rs        // TransportError, #[non_exhaustive]
  transport.rs    // Transport / TransportListener traits, TransportAddr — the seam
  tor.rs          // TorTransport, TorStream, TorListener: arti-backed impl
  fake.rs         // FakeTransport, FakeListener: in-memory impl, gated
                  // `#[cfg(any(test, feature = "testing"))]` — usable by this
                  // crate's own unit tests and, via the `testing` feature, by
                  // downstream crates' tests; never compiled into a release
                  // build that doesn't explicitly opt in
```

```rust
pub trait Transport {
    type Stream: Read + Write + Send;
    type Listener: TransportListener<Stream = Self::Stream>;

    fn connect(&self, addr: &TransportAddr) -> Result<Self::Stream, TransportError>;
    fn host(&self, config: OnionServiceConfig) -> Result<Self::Listener, TransportError>;
}

pub trait TransportListener {
    type Stream: Read + Write + Send;
    fn accept(&self) -> Result<Self::Stream, TransportError>;
    fn local_addr(&self) -> TransportAddr;
}
```

- `TransportAddr` is a newtype validating a v3 onion address at
  construction (`TransportAddr::parse(&str)`), not a raw `String` —
  malformed addresses are rejected at the API boundary, not deep inside
  `connect`/`host`. V2 onion addresses are rejected outright: v2 is
  deprecated network-wide, and Section 9.1's "never invent a novel
  construction, cite a published reference" ground rule argues equally
  for not supporting a construction the reference implementation itself
  has retired.
- `Self::Stream: Read + Write` (not async) is what lets a later phase
  hand a `TransportStream` straight to `aegis-ratchet`'s envelope
  serialization or `aegis-file`'s `encrypt_stream`/`decrypt_stream`
  without an adapter layer — both already speak `std::io::Read`/`Write`.
- Two implementations satisfy this trait: `TorTransport` (real) and
  `FakeTransport` (test-only, gated behind a `testing` Cargo feature so
  it never ships in a release build of a downstream consumer).

## 3. Onion Service Hosting: The Two-Level Accept Model

`arti_client::TorClient::launch_onion_service` returns
`(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)`. Per
`arti-client`'s own documented model, a `RendRequest` does not itself
carry a usable connection — accepting it yields a *second* stream of
`StreamRequest`s, each of which must itself be accepted to obtain a
`DataStream`. `TorListener` therefore runs two nested background tasks
for the hosting session's lifetime:

1. **Outer task:** drains the `RendRequest` stream; for each request,
   calls `.accept()` to obtain its `StreamRequest` stream, and spawns an
   **inner task** to drain that.
2. **Inner task:** for each `StreamRequest`, calls `.accept()` to obtain
   a `DataStream`, wraps it as `TorStream`, and pushes it onto a
   `std::sync::mpsc::SyncSender<TorStream>` shared with the listener.

`TransportListener::accept()` is `receiver.recv()` — a plain blocking
call, matching the sync facade. `TorListener` holds the
`Arc<RunningOnionService>` (keeps the service alive; backs
`local_addr()`) alongside both tasks' `JoinHandle`s for shutdown.

This two-level shape is `arti`'s own accept model, not something to
collapse into one task: flattening it into "accept everything
unconditionally" would remove the only place a future phase (Section
6.3's capability-token rate limiting) could reject an abusive or
unauthenticated request before a `DataStream` is even established.
Phase 1 accepts every request unconditionally (there is no rate limiting
yet), but the two-task structure is where that logic attaches later —
not a redesign.

## 4. Configuration

```rust
pub struct TorTransportConfig {
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub bootstrap_timeout: Duration,
}
```

`arti-client` requires persistent state/cache directories (consensus
data, guard selection, onion-service keys); `aegis-net` takes no
position on where those live and does not default to a hardcoded path —
that decision belongs to whatever calls this crate (eventually
application-level config, not `aegis-vault`; this crate does not depend
on `aegis-vault`, matching Section 10's build order). `OnionServiceConfig`
(passed to `host`) is `arti-client`'s own config type, re-exported rather
than wrapped, since Phase 1 adds no policy on top of it.

Real Tor bootstrap (consensus fetch, initial circuit building) takes
real wall-clock time and can hang indefinitely against a degraded or
censored network path. `bootstrap_timeout` is mandatory, not optional
with a built-in default, so a caller cannot silently inherit a hang —
`TorTransport::bootstrap` returns `TransportError::BootstrapTimeout`
rather than blocking forever, per the "fail early and explicitly" rule.

## 5. Error Handling

```rust
#[non_exhaustive]
pub enum TransportError {
    Bootstrap(String),
    BootstrapTimeout,
    InvalidAddress(String),
    Connect(String),
    HostingFailed(String),
    Io(std::io::Error),
    ListenerClosed,
}
```

Variants are split by retryability, not just by which `arti` call
failed: `BootstrapTimeout` (retry with backoff — the network may
recover) is distinct from `Bootstrap` (a harder failure — e.g.
consensus signature rejection — retrying identically is unlikely to
help) and from `InvalidAddress` (a caller bug, not retryable at all,
since the address string itself is malformed). `ListenerClosed` is
distinct from `Io` so a caller can tell "the listener was shut down
[deliberately]" apart from "a specific accepted stream had an I/O
error" — the former means stop calling `accept()`, the latter does not.

No variant carries `arti`'s internal error types directly (wrapped as
`String` instead) — `arti_client::Error` is not `Send + Sync +
'static`-stable across its own semver range in a way this crate's public
API should commit to; the message text is preserved for diagnostics
without exposing that surface.

## 6. Resource Cleanup

`TorTransport::drop` and `TorListener::drop` call `JoinHandle::abort()`
on every background task they own *before* the owning `Runtime` itself
drops — no task is left executing against a `TorClient`/
`RunningOnionService` that may already be gone. `Runtime::drop` then
blocks briefly until tokio's own shutdown completes; this is the only
place a drop path blocks, and it is bounded (tokio's shutdown, not a
network wait). `TorListener` dropping does not drop the
`Arc<RunningOnionService>` out from under an in-flight `TorTransport` —
each holds its own `Arc` clone, so a listener can be torn down and
recreated (a new `host()` call) without rebuilding the underlying
`TorTransport`/bootstrap.

## 7. Testing Strategy

Per this workspace's determinism requirement, and the fact that a real
Tor bootstrap needs live network egress this sandboxed environment does
not reliably have:

- **`FakeTransport`/`FakeListener`** (in-memory, `std::sync::mpsc`-backed
  dial/accept pairs): exercises the `Transport`/`TransportListener`
  contract itself, `TransportAddr` parsing/validation (valid v3, rejected
  v2, malformed strings, wrong length), and `TransportError` variant
  selection — fully deterministic, runs unconditionally in `cargo test`.
- **`TorTransport`/`TorStream`/`TorListener`**: unit tests limited to
  construction and config validation that does not require a live
  bootstrap — e.g. `TorTransportConfig` with a zero `bootstrap_timeout`,
  an unwritable `state_dir` — asserting the correct `TransportError`
  variant. No test in this tier touches the network.
- **`tests/live_tor.rs`**, `#[ignore]`d: a real bootstrap, self-host an
  onion service, dial it from a second `TorTransport`, round-trip bytes.
  Documented as manual-only — this is a known, explicit gap (this
  environment cannot run it), recorded the same way `SECURITY_DISCLAIMER`
  documents the pending-audit gap elsewhere in the workspace, not silently
  omitted.

## 8. What Is Deliberately Not Here

- **The federated mailbox protocol** (node identity, gossip-replicated
  directory, mailbox pinning/storage) — Section 6.2, its own future
  design. Node identity in particular is a separate concern from an
  onion service's `HsId` key: this phase's hosting uses whatever key
  `arti`'s own keystore manages for the onion service, with no attempt
  yet to unify it with a node's application-level Ed25519 identity —
  that decision belongs to the mailbox protocol's design once the
  directory/gossip model is being built.
- **Sealed Sender 2.0, cover traffic, and 4 KB padding** — the
  network-facing half of Section 6.3, still a future design once the
  mailbox protocol's message shape exists to wrap. (Capability-token
  issuance/verification and rate limiting — the other half of 6.3 — are
  already built as an independent track; see the naming note at the top
  of this doc.) The two-level accept model (Section 3) is deliberately
  structured so that future design has a place to attach request-level
  rejection; this phase does not implement any rejection policy itself.
- **I2P and custom-mixnet transports.** Named explicitly as pluggable,
  post-v1 in spec Section 6.1. The `Transport` trait is the seam a future
  implementation would satisfy; none is built now.
- **Resumable/partial connections, connection pooling, or multiplexing
  multiple logical streams over one Tor circuit.** Not called for by
  spec Section 6.1; each `connect()`/accepted stream is one independent
  `DataStream`.
