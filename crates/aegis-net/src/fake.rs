//! [`FakeTransport`]: an in-memory [`crate::transport::Transport`]
//! implementation used to test `aegis-net`'s own logic (and, via the
//! `testing` feature, downstream crates' logic) without a live Tor
//! connection. Gated behind `#[cfg(any(test, feature = "testing"))]`
//! so it never compiles into a release build that doesn't explicitly
//! opt in.

use crate::error::TransportError;
use crate::transport::{Transport, TransportAddr, TransportListener};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

type Registry = Arc<Mutex<HashMap<TransportAddr, SyncSender<FakeStream>>>>;

/// Deterministically derives a valid-shaped (56-character, `a`-`z`/`2`-`7`)
/// fake v3 onion address from `nickname`. Not cryptographic — this is a
/// test double, not a real onion service — just stable per nickname and
/// distinct across different nicknames.
fn fake_addr_for_nickname(nickname: &str) -> TransportAddr {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes = nickname.as_bytes();
    let mut label = String::with_capacity(56);
    for i in 0..56 {
        let source_byte = if bytes.is_empty() {
            b'a'
        } else {
            bytes[i % bytes.len()]
        };
        label.push(ALPHABET[(source_byte as usize) % 32] as char);
    }
    TransportAddr::parse(&format!("{label}.onion:1")).expect("generated label is always well-formed")
}

fn duplex_pair() -> (FakeStream, FakeStream) {
    let (a_tx, b_rx) = sync_channel::<Vec<u8>>(64);
    let (b_tx, a_rx) = sync_channel::<Vec<u8>>(64);
    (FakeStream::new(a_tx, a_rx), FakeStream::new(b_tx, b_rx))
}

/// An in-memory [`Transport`]. Cheaply [`Clone`] — every clone shares
/// the same registry (a plain `HashMap` behind a `Mutex`, not real
/// networking of any kind), so two `FakeTransport` clones can dial each
/// other by address, mirroring how two real `TorTransport` instances
/// dial each other over the network.
#[derive(Debug, Clone, Default)]
pub struct FakeTransport {
    registry: Registry,
}

impl FakeTransport {
    /// Creates a `FakeTransport` backed by a fresh, empty registry.
    pub fn new() -> Self {
        FakeTransport::default()
    }
}

impl Transport for FakeTransport {
    type Stream = FakeStream;
    type Listener = FakeListener;

    fn connect(&self, addr: &TransportAddr) -> Result<Self::Stream, TransportError> {
        let sender = {
            let registry = self
                .registry
                .lock()
                .expect("fake transport registry poisoned");
            registry.get(addr).cloned()
        };
        let sender = sender.ok_or_else(|| {
            TransportError::Connect(format!("no FakeListener hosted at `{addr}`"))
        })?;
        let (caller_side, listener_side) = duplex_pair();
        sender
            .send(listener_side)
            .map_err(|_| TransportError::Connect(format!("listener at `{addr}` is closed")))?;
        Ok(caller_side)
    }

    fn host(&self, nickname: &str) -> Result<Self::Listener, TransportError> {
        let local_addr = fake_addr_for_nickname(nickname);
        let (accept_tx, accept_rx) = sync_channel::<FakeStream>(16);
        self.registry
            .lock()
            .expect("fake transport registry poisoned")
            .insert(local_addr.clone(), accept_tx);
        Ok(FakeListener {
            local_addr,
            accept_rx,
            registry: Arc::clone(&self.registry),
        })
    }
}

/// An in-memory listener produced by [`FakeTransport::host`]. Removes
/// its own registry entry on drop, so a subsequent `connect` to the
/// same address fails with [`TransportError::Connect`] rather than
/// silently succeeding against a listener nobody is accepting from.
#[derive(Debug)]
pub struct FakeListener {
    local_addr: TransportAddr,
    accept_rx: Receiver<FakeStream>,
    registry: Registry,
}

impl TransportListener for FakeListener {
    type Stream = FakeStream;

    fn accept(&self) -> Result<Self::Stream, TransportError> {
        self.accept_rx
            .recv()
            .map_err(|_| TransportError::ListenerClosed)
    }

    fn local_addr(&self) -> TransportAddr {
        self.local_addr.clone()
    }
}

impl Drop for FakeListener {
    fn drop(&mut self) {
        self.registry
            .lock()
            .expect("fake transport registry poisoned")
            .remove(&self.local_addr);
    }
}

/// An in-memory duplex byte stream. Each `write` call's bytes arrive
/// as one `read`-sized unit on the other end, which is stricter than a
/// real TCP-like stream, not laxer — code that works against
/// `FakeStream` cannot be accidentally relying on partial reads/writes
/// never happening, since a real `Read`/`Write` caller must already
/// handle a `read` returning fewer bytes than the buffer size.
#[derive(Debug)]
pub struct FakeStream {
    tx: SyncSender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

impl FakeStream {
    fn new(tx: SyncSender<Vec<u8>>, rx: Receiver<Vec<u8>>) -> Self {
        FakeStream {
            tx,
            rx,
            pending: Vec::new(),
        }
    }
}

impl Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.pending = chunk,
                Err(_) => return Ok(0), // peer dropped: EOF
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_then_connect_round_trips_bytes() {
        let transport = FakeTransport::new();
        let listener = transport.host("test-node").expect("host");
        let addr = listener.local_addr();

        let server = std::thread::spawn(move || {
            let mut stream = listener.accept().expect("accept");
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).expect("read");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").expect("write");
        });

        let mut client = transport.connect(&addr).expect("connect");
        client.write_all(b"hello").expect("write");
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"world");

        server.join().expect("server thread panicked");
    }

    #[test]
    fn connecting_to_unhosted_address_fails() {
        let transport = FakeTransport::new();
        let addr = fake_addr_for_nickname("nobody-home");
        let err = transport.connect(&addr).unwrap_err();
        assert!(matches!(err, TransportError::Connect(_)));
    }

    #[test]
    fn dropping_listener_removes_it_from_registry() {
        let transport = FakeTransport::new();
        let listener = transport.host("temp-node").expect("host");
        let addr = listener.local_addr();
        drop(listener);
        let err = transport.connect(&addr).unwrap_err();
        assert!(matches!(err, TransportError::Connect(_)));
    }

    #[test]
    fn fake_addr_for_nickname_is_deterministic_and_distinct() {
        let a1 = fake_addr_for_nickname("alice");
        let a2 = fake_addr_for_nickname("alice");
        let b = fake_addr_for_nickname("bob");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }

    #[test]
    fn accept_after_sender_dropped_returns_listener_closed() {
        // White-box test reaching into a private field to exercise a
        // path the public API can't otherwise trigger deterministically
        // — same convention `capability.rs`'s own tests already use for
        // otherwise-unreachable branches.
        let (tx, rx) = sync_channel::<FakeStream>(1);
        drop(tx);
        let listener = FakeListener {
            local_addr: fake_addr_for_nickname("closed-test"),
            accept_rx: rx,
            registry: Arc::new(Mutex::new(HashMap::new())),
        };
        let err = listener.accept().unwrap_err();
        assert!(matches!(err, TransportError::ListenerClosed));
    }
}
