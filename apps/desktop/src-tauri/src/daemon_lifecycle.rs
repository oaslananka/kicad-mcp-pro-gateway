//! Production sidecar lifecycle for the desktop shell.
//!
//! The desktop owns availability, not policy. It may launch only Tauri's
//! configured bundled sidecar, then every IPC operation is gated by the
//! identity/readiness handshake in `ipc_client`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use companion_protocol::{DaemonIdentityView, IpcResponse};
use tauri::AppHandle;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use tokio::sync::{watch, Mutex};

use crate::ipc_client::{
    probe_daemon, send_shutdown_request, wait_for_ready, wait_for_stopped, ProbeError,
};

const SIDECAR_NAME: &str = "kicad-mcp-gateway-daemon";
const START_ATTEMPTS: usize = 3;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const WATCHDOG_MIN_DELAY: Duration = Duration::from_secs(2);
const WATCHDOG_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonLifecycleState {
    Starting,
    Ready,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DaemonLifecycleView {
    pub state: DaemonLifecycleState,
    pub message: Option<String>,
    pub identity: Option<DaemonIdentityView>,
}

#[derive(Clone)]
pub struct DaemonLauncher {
    app: AppHandle,
    start_lock: Arc<Mutex<()>>,
    adopt_stop_marker_on_first_start: Arc<AtomicBool>,
    state_tx: watch::Sender<DaemonLifecycleView>,
}

impl DaemonLauncher {
    pub fn new(app: AppHandle) -> Self {
        let initial = DaemonLifecycleView {
            state: DaemonLifecycleState::Starting,
            message: Some("Starting the packaged Gateway daemon".to_string()),
            identity: None,
        };
        let (state_tx, _) = watch::channel(initial);
        Self {
            app,
            start_lock: Arc::new(Mutex::new(())),
            adopt_stop_marker_on_first_start: Arc::new(AtomicBool::new(true)),
            state_tx,
        }
    }

    pub fn lifecycle_view(&self) -> DaemonLifecycleView {
        self.state_tx.borrow().clone()
    }

    fn set_state(&self, view: DaemonLifecycleView) {
        self.state_tx.send_replace(view);
    }

    fn set_starting(&self) {
        self.set_state(DaemonLifecycleView {
            state: DaemonLifecycleState::Starting,
            message: Some("Starting the packaged Gateway daemon".to_string()),
            identity: None,
        });
    }

    fn set_ready(&self, identity: DaemonIdentityView) {
        self.set_state(DaemonLifecycleView {
            state: DaemonLifecycleState::Ready,
            message: None,
            identity: Some(identity),
        });
    }

    fn set_stopped(&self, message: String) {
        self.set_state(DaemonLifecycleView {
            state: DaemonLifecycleState::Stopped,
            message: Some(message),
            identity: None,
        });
    }

    fn set_failed(&self, message: String) {
        self.set_state(DaemonLifecycleView {
            state: DaemonLifecycleState::Failed,
            message: Some(message),
            identity: None,
        });
    }

    async fn stop_verified_daemon(&self, data_dir: &std::path::Path) -> Result<(), String> {
        let response = send_shutdown_request(data_dir).await.map_err(|error| {
            let message = format!(
                "Stale Gateway daemon could not be stopped safely: {error}. No replacement daemon was launched."
            );
            self.set_failed(message.clone());
            message
        })?;
        match response {
            IpcResponse::Ack => {}
            IpcResponse::Error(_) => {
                let message =
                    "Stale Gateway daemon refused shutdown. No replacement daemon was launched."
                        .to_string();
                self.set_failed(message.clone());
                return Err(message);
            }
            _ => {
                let message =
                    "Stale Gateway daemon returned an unexpected shutdown response variant. No replacement daemon was launched."
                        .to_string();
                self.set_failed(message.clone());
                return Err(message);
            }
        }
        wait_for_stopped(data_dir, STOP_TIMEOUT).await.map_err(|error| {
            let message = format!(
                "Stale Gateway daemon did not release its local endpoint: {error}. No replacement daemon was launched."
            );
            self.set_failed(message.clone());
            message
        })
    }

    /// Ensures a compatible daemon is serving the IPC endpoint derived from
    /// the configured Gateway data directory. The mutex collapses concurrent
    /// UI polls into one launch attempt.
    pub async fn ensure_ready(&self) -> Result<PathBuf, String> {
        let _guard = self.start_lock.lock().await;
        self.ensure_ready_locked().await
    }

    async fn ensure_ready_locked(&self) -> Result<PathBuf, String> {
        let config = companion_core::config::load(companion_core::config::CliOverrides::default())
            .map_err(|error| format!("Gateway configuration is invalid: {error}"))?;
        let data_dir = config.data_dir.clone();
        let stop_marker = data_dir.join(companion_core::config::DAEMON_STOP_MARKER_FILE);

        if self
            .adopt_stop_marker_on_first_start
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            match std::fs::remove_file(&stop_marker) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    let message = format!(
                        "Could not clear the previous explicit daemon-stop state: {error}. No daemon was launched."
                    );
                    self.set_failed(message.clone());
                    return Err(message);
                }
            }
        } else if stop_marker.exists() {
            let message =
                "Gateway daemon was stopped explicitly from the CLI. Run `kicad-mcp-gateway daemon start` or reopen Gateway Desktop."
                    .to_string();
            self.set_stopped(message.clone());
            return Err(message);
        }

        match probe_daemon(&data_dir).await {
            Ok(identity) => {
                self.set_ready(identity);
                return Ok(data_dir);
            }
            Err(ProbeError::Incompatible(message)) => {
                let message = format!(
                    "Refusing local endpoint: {message}. No alternate endpoint or process will be used."
                );
                self.set_failed(message.clone());
                return Err(message);
            }
            Err(ProbeError::VersionMismatch { expected, actual }) => {
                self.set_starting();
                self.stop_verified_daemon(&data_dir).await?;
                eprintln!("replaced stale Gateway daemon {actual} with packaged {expected}");
            }
            Err(ProbeError::Unavailable(_)) => {
                if stop_marker.exists() {
                    let message =
                        "Gateway daemon was stopped explicitly from the CLI. Run `kicad-mcp-gateway daemon start` or reopen Gateway Desktop."
                            .to_string();
                    self.set_stopped(message.clone());
                    return Err(message);
                }
            }
        }

        self.set_starting();
        let mut last_error = "packaged daemon did not become ready".to_string();
        for attempt in 0..START_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
            }
            self.spawn_packaged_daemon(&data_dir)?;
            match wait_for_ready(&data_dir, READY_TIMEOUT).await {
                Ok(identity) => {
                    if stop_marker.exists() {
                        let _ = self.stop_verified_daemon(&data_dir).await;
                        let message =
                            "Gateway daemon was stopped explicitly from the CLI; the desktop supervisor did not restart it."
                                .to_string();
                        self.set_stopped(message.clone());
                        return Err(message);
                    }
                    self.set_ready(identity);
                    return Ok(data_dir);
                }
                Err(ProbeError::Incompatible(message)) => {
                    let message = format!(
                        "Refusing local endpoint: {message}. No alternate endpoint or process will be used."
                    );
                    self.set_failed(message.clone());
                    return Err(message);
                }
                Err(ProbeError::VersionMismatch { expected, actual }) => {
                    let message = format!(
                        "A stale Gateway daemon {actual} appeared during startup; expected {expected}. It will not receive privileged requests."
                    );
                    self.set_failed(message.clone());
                    return Err(message);
                }
                Err(ProbeError::Unavailable(message)) => last_error = message,
            }
        }

        let message = format!(
            "Packaged Gateway daemon did not become ready: {last_error}. Reinstall Gateway; no alternate daemon will be launched."
        );
        self.set_failed(message.clone());
        Err(message)
    }

    fn spawn_packaged_daemon(&self, data_dir: &std::path::Path) -> Result<(), String> {
        let command = self
            .app
            .shell()
            .sidecar(SIDECAR_NAME)
            .map_err(|error| {
                let message = format!(
                    "Packaged Gateway daemon is missing or invalid: {error}. Reinstall Gateway; no alternate daemon will be launched."
                );
                self.set_failed(message.clone());
                message
            })?
            .env("GATEWAY_DATA_DIR", data_dir)
            // A desktop launch must never inherit a development/mock relay
            // mode from its own process environment.
            .env("GATEWAY_TRANSPORT_MODE", "disabled");
        let (mut events, child) = command.spawn().map_err(|error| {
            let message = format!(
                "Packaged Gateway daemon could not start: {error}. No alternate daemon will be launched."
            );
            self.set_failed(message.clone());
            message
        })?;

        // Keep the sidecar's pipes drained and retain its process handle. Drop
        // only detaches the handle; the daemon remains available to the CLI
        // after the desktop window closes.
        tauri::async_runtime::spawn(async move {
            let _child = child;
            while let Some(event) = events.recv().await {
                match event {
                    CommandEvent::Terminated(payload) => {
                        eprintln!(
                            "packaged Gateway daemon exited with code {:?}",
                            payload.code
                        );
                    }
                    CommandEvent::Error(error) => {
                        eprintln!("packaged Gateway daemon process error: {error}");
                    }
                    CommandEvent::Stdout(_) | CommandEvent::Stderr(_) => {
                        // Daemon output is deliberately not copied into the
                        // desktop process or UI; sanitized reproduction is
                        // available through the packaged CLI/daemon.
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }
}

pub fn spawn_watchdog(launcher: DaemonLauncher) {
    tauri::async_runtime::spawn(async move {
        let mut delay = WATCHDOG_MIN_DELAY;
        loop {
            tokio::time::sleep(delay).await;
            if launcher.ensure_ready().await.is_ok() {
                delay = WATCHDOG_MIN_DELAY;
            } else {
                delay = next_watchdog_delay(delay);
            }
        }
    });
}

fn next_watchdog_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(WATCHDOG_MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_backoff_is_bounded() {
        let mut delay = WATCHDOG_MIN_DELAY;
        for _ in 0..10 {
            delay = next_watchdog_delay(delay);
        }
        assert_eq!(delay, WATCHDOG_MAX_DELAY);
    }
}
