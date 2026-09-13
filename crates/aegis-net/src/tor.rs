//! [`TorTransport`]: a `crate::transport::Transport` implementation
//! backed by `arti-client`, Tor-in-Rust. Exposes a plain synchronous
//! API — see the design doc's "Sync Facade" section for why: `arti`
//! is async-only, but this crate (and every consumer downstream of it)
//! stays synchronous, with one persistent `tokio` runtime hidden
//! behind [`TorTransport`].

use crate::error::TransportError;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Configuration for [`TorTransport::bootstrap`].
#[derive(Debug, Clone)]
pub struct TorTransportConfig {
    /// Directory `arti` persists long-lived state in (guard selection,
    /// onion-service keys, ...).
    pub state_dir: PathBuf,
    /// Directory `arti` caches consensus/directory data in.
    pub cache_dir: PathBuf,
    /// How long to wait for bootstrap (consensus fetch, initial circuit
    /// building) before giving up with
    /// [`TransportError::BootstrapTimeout`]. Real bootstrap can hang
    /// indefinitely against a degraded or censored network path, so
    /// this is mandatory and validated eagerly — see
    /// [`TorTransportConfig::new`].
    pub bootstrap_timeout: Duration,
}

impl TorTransportConfig {
    /// Validates and constructs a `TorTransportConfig`. Rejects
    /// `bootstrap_timeout == Duration::ZERO` at construction — a
    /// zero-length timeout can never let bootstrap succeed, so this
    /// fails loudly here (`TransportError::InvalidConfig`) rather than
    /// deferring to a confusing `BootstrapTimeout` from every
    /// subsequent `bootstrap()` call. Also eagerly creates `state_dir`
    /// and `cache_dir` (via `create_dir_all`) if they do not already
    /// exist, surfacing a creation failure as
    /// `TransportError::InvalidConfig` immediately rather than only at
    /// bootstrap time.
    pub fn new(
        state_dir: PathBuf,
        cache_dir: PathBuf,
        bootstrap_timeout: Duration,
    ) -> Result<Self, TransportError> {
        if bootstrap_timeout == Duration::ZERO {
            return Err(TransportError::InvalidConfig(
                "bootstrap_timeout must not be zero".to_string(),
            ));
        }
        std::fs::create_dir_all(&state_dir).map_err(|err| {
            TransportError::InvalidConfig(format!(
                "could not create state_dir `{}`: {err}",
                state_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&cache_dir).map_err(|err| {
            TransportError::InvalidConfig(format!(
                "could not create cache_dir `{}`: {err}",
                cache_dir.display()
            ))
        })?;
        Ok(TorTransportConfig {
            state_dir,
            cache_dir,
            bootstrap_timeout,
        })
    }
}

#[allow(dead_code)] // client/runtime are consumed by dial/host in later tasks
struct TorTransportInner {
    client: Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    runtime: Runtime,
}

/// A `crate::transport::Transport` backed by a live Tor connection.
/// Cheaply [`Clone`] (an `Arc` around the underlying client and its
/// owning `tokio` runtime) — cloning shares the same bootstrapped
/// client and runtime, it does not bootstrap a second one. A
/// `TorListener` produced by [`Transport::host`] holds a clone, which
/// is what keeps the runtime alive for as long as any listener spawned
/// from this transport is still accepting connections, even if the
/// original `TorTransport` handle is dropped.
#[derive(Clone)]
#[allow(dead_code)] // inner is read by dial/host in later tasks
pub struct TorTransport {
    inner: Arc<TorTransportInner>,
}

impl TorTransport {
    /// Builds an `arti` client and bootstraps it against the live Tor
    /// network, blocking until bootstrap completes,
    /// `config.bootstrap_timeout` elapses
    /// ([`TransportError::BootstrapTimeout`]), or bootstrap itself
    /// fails ([`TransportError::Bootstrap`]).
    pub fn bootstrap(config: TorTransportConfig) -> Result<Self, TransportError> {
        let runtime = Runtime::new().map_err(|err| {
            TransportError::Bootstrap(format!(
                "failed to start the internal tokio runtime: {err}"
            ))
        })?;

        let arti_config = arti_client::config::TorClientConfigBuilder::from_directories(
            &config.state_dir,
            &config.cache_dir,
        )
        .build()
        .map_err(|err| {
            TransportError::Bootstrap(format!("invalid Tor client configuration: {err}"))
        })?;

        let bootstrap_result = runtime.block_on(async {
            tokio::time::timeout(
                config.bootstrap_timeout,
                arti_client::TorClient::create_bootstrapped(arti_config),
            )
            .await
        });

        let client = match bootstrap_result {
            Ok(Ok(client)) => client,
            Ok(Err(err)) => return Err(TransportError::Bootstrap(err.to_string())),
            Err(_elapsed) => return Err(TransportError::BootstrapTimeout),
        };

        Ok(TorTransport {
            inner: Arc::new(TorTransportInner { client, runtime }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-net-test-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn zero_bootstrap_timeout_is_rejected_at_construction() {
        let state_dir = unique_temp_dir("zero-timeout-state");
        let cache_dir = unique_temp_dir("zero-timeout-cache");
        let err = TorTransportConfig::new(state_dir, cache_dir, Duration::ZERO).unwrap_err();
        assert!(matches!(err, TransportError::InvalidConfig(_)));
    }

    #[test]
    fn valid_config_creates_directories_and_succeeds() {
        let state_dir = unique_temp_dir("valid-state");
        let cache_dir = unique_temp_dir("valid-cache");
        let config = TorTransportConfig::new(
            state_dir.clone(),
            cache_dir.clone(),
            Duration::from_secs(30),
        )
        .expect("valid config should be accepted");
        assert!(state_dir.is_dir());
        assert!(cache_dir.is_dir());
        assert_eq!(config.bootstrap_timeout, Duration::from_secs(30));
        std::fs::remove_dir_all(&state_dir).ok();
        std::fs::remove_dir_all(&cache_dir).ok();
    }

    #[test]
    fn state_dir_blocked_by_a_file_is_rejected() {
        // Cross-platform-deterministic way to force create_dir_all to
        // fail: put a plain file where a path *component* needs to be
        // a directory. Works identically on Windows and Unix, unlike
        // relying on permission bits.
        let base = unique_temp_dir("blocked-base");
        std::fs::create_dir_all(&base).expect("create base temp dir");
        let blocker_file = base.join("blocker");
        std::fs::write(&blocker_file, b"not a directory").expect("create blocker file");
        let state_dir = blocker_file.join("nested"); // blocker_file is a file, not a dir
        let cache_dir = unique_temp_dir("blocked-cache");

        let err = TorTransportConfig::new(state_dir, cache_dir, Duration::from_secs(30))
            .unwrap_err();
        assert!(matches!(err, TransportError::InvalidConfig(_)));

        std::fs::remove_dir_all(&base).ok();
    }
}
