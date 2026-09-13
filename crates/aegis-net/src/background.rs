//! [`BackgroundTasks`]: a small guard that owns a set of
//! `tokio::task::JoinHandle`s and aborts every one of them on drop.
//! Used by `crate::tor::TorTransport`/`TorListener` so no task is left
//! running against a `TorClient`/`RunningOnionService` that may already
//! be gone — see the design doc's "Resource Cleanup" section.
//!
//! Only registers handles for abort; it does not wait for the abort to
//! take effect (`JoinHandle::abort` merely *requests* cancellation —
//! the task's own `Arc` clones of any shared state keep that state
//! alive for as long as the task itself takes to actually stop, which
//! is safe by construction, just not necessarily instant).

use std::sync::Mutex;
use tokio::task::JoinHandle;

/// Owns zero or more spawned tasks; aborts all of them when dropped.
#[derive(Debug, Default)]
#[allow(dead_code)] // Used by TorTransport/TorListener in later tasks
pub struct BackgroundTasks {
    handles: Mutex<Vec<JoinHandle<()>>>,
}

#[allow(dead_code)] // Used by TorTransport/TorListener in later tasks
impl BackgroundTasks {
    /// An empty guard, owning no tasks yet.
    pub fn new() -> Self {
        BackgroundTasks::default()
    }

    /// Adopts `handle`; it will be aborted when this guard drops.
    pub fn push(&self, handle: JoinHandle<()>) {
        self.handles
            .lock()
            .expect("BackgroundTasks mutex poisoned")
            .push(handle);
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        let handles = self
            .handles
            .get_mut()
            .expect("BackgroundTasks mutex poisoned");
        for handle in handles.iter() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BackgroundTasks;

    #[tokio::test]
    async fn dropping_aborts_every_owned_task() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let mut started_tx = Some(started_tx);
        let mut tx = Some(tx);

        struct SendOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for SendOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let handle = tokio::spawn(async move {
            let _guard = SendOnDrop(tx.take());
            if let Some(started_tx) = started_tx.take() {
                let _ = started_tx.send(());
            }
            std::future::pending::<()>().await;
        });

        // Wait for the task to actually start running (and construct
        // `_guard`) before we abort it — otherwise abort() can cancel
        // a never-polled future, which drops the raw captured Sender
        // without ever running SendOnDrop's logic.
        started_rx
            .await
            .expect("spawned task should have started running");

        let tasks = BackgroundTasks::new();
        tasks.push(handle);
        drop(tasks);

        // Deterministic: this resolves exactly when the aborted task's
        // future is actually dropped (running `SendOnDrop::drop`), not
        // after an arbitrary sleep.
        rx.await
            .expect("aborted task's future should have been dropped");
    }
}
