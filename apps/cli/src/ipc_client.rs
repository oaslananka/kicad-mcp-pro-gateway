//! The CLI's only path to the daemon. Every privileged request first performs
//! the zero-side-effect identity/readiness handshake and fails closed if the
//! local endpoint is not the intended Gateway daemon.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use companion_protocol::{
    read_message, write_message, DaemonIdentityView, IpcRequest, IpcResponse,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};

pub const EXPECTED_DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// No listener is currently reachable at the endpoint derived from the
    /// selected data directory, or it did not complete the bounded handshake.
    Unavailable(String),
    /// Something is listening, but it did not prove that it is a compatible
    /// Gateway daemon. This must never fall back to another endpoint/process.
    Incompatible(String),
    /// The endpoint proved that it is Gateway with a compatible local IPC
    /// contract, but it is not the daemon packaged with this CLI release.
    VersionMismatch { expected: String, actual: String },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Incompatible(message) => f.write_str(message),
            Self::VersionMismatch { expected, actual } => write!(
                f,
                "incompatible Gateway daemon version: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for ProbeError {}

async fn connect(data_dir: &Path) -> anyhow::Result<interprocess::local_socket::tokio::Stream> {
    let name = companion_protocol::socket_name(data_dir)
        .to_ns_name::<GenericNamespaced>()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn send_raw(data_dir: &Path, request: IpcRequest) -> anyhow::Result<IpcResponse> {
    let mut stream = connect(data_dir).await?;
    write_message(&mut stream, &request).await?;
    let response: IpcResponse = read_message(&mut stream).await?;
    Ok(response)
}

async fn read_identity(
    stream: &mut interprocess::local_socket::tokio::Stream,
) -> Result<DaemonIdentityView, ProbeError> {
    let response: IpcResponse = read_message(stream)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    let identity = match response {
        IpcResponse::Identity(identity) => identity,
        IpcResponse::Error(_) => {
            return Err(ProbeError::Incompatible(
                "local endpoint returned an error instead of the Gateway identity response"
                    .to_string(),
            ));
        }
        _ => {
            return Err(ProbeError::Incompatible(
                "local endpoint returned an unexpected identity response variant".to_string(),
            ));
        }
    };
    identity
        .validate_for_client()
        .map_err(|error| ProbeError::Incompatible(error.to_string()))?;
    Ok(identity)
}

async fn probe_daemon_inner(data_dir: &Path) -> Result<DaemonIdentityView, ProbeError> {
    let mut stream = connect(data_dir)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    write_message(&mut stream, &IpcRequest::Identity)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    let identity = read_identity(&mut stream).await?;
    identity
        .validate_daemon_version(EXPECTED_DAEMON_VERSION)
        .map_err(|error| match error {
            companion_protocol::DaemonIdentityError::DaemonVersionMismatch { expected, actual } => {
                ProbeError::VersionMismatch { expected, actual }
            }
            other => ProbeError::Incompatible(other.to_string()),
        })?;
    Ok(identity)
}

/// Performs the bounded local readiness handshake and validates product,
/// protocol, instance, and packaged daemon version before returning identity.
pub async fn probe_daemon(data_dir: &Path) -> Result<DaemonIdentityView, ProbeError> {
    tokio::time::timeout(PROBE_TIMEOUT, probe_daemon_inner(data_dir))
        .await
        .map_err(|_| {
            ProbeError::Unavailable(
                "local daemon identity handshake exceeded its deadline".to_string(),
            )
        })?
}

/// Polls only the deterministic endpoint derived from `data_dir` until the
/// intended daemon is ready or the bounded timeout expires.
pub async fn wait_for_ready(
    data_dir: &Path,
    timeout: Duration,
) -> Result<DaemonIdentityView, ProbeError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error;
    loop {
        match probe_daemon(data_dir).await {
            Ok(identity) => return Ok(identity),
            Err(ProbeError::Incompatible(message)) => {
                return Err(ProbeError::Incompatible(message));
            }
            Err(ProbeError::VersionMismatch { expected, actual }) => {
                return Err(ProbeError::VersionMismatch { expected, actual });
            }
            Err(ProbeError::Unavailable(message)) => last_error = message,
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ProbeError::Unavailable(last_error));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn wait_for_stopped(data_dir: &Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if connect(data_dir).await.is_err() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("local daemon did not stop before the deadline");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn send_request_inner(
    data_dir: &Path,
    request: IpcRequest,
) -> Result<IpcResponse, ProbeError> {
    let mut stream = connect(data_dir)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    write_message(&mut stream, &IpcRequest::Identity)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    let identity = read_identity(&mut stream).await?;
    identity
        .validate_daemon_version(EXPECTED_DAEMON_VERSION)
        .map_err(|error| match error {
            companion_protocol::DaemonIdentityError::DaemonVersionMismatch { expected, actual } => {
                ProbeError::VersionMismatch { expected, actual }
            }
            other => ProbeError::Incompatible(other.to_string()),
        })?;

    write_message(&mut stream, &request)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    read_message(&mut stream)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))
}

/// Sends a privileged request on the same connection that proved the intended
/// daemon identity, avoiding a probe/request endpoint-swap window.
pub async fn send_request(data_dir: &Path, request: IpcRequest) -> anyhow::Result<IpcResponse> {
    tokio::time::timeout(REQUEST_TIMEOUT, send_request_inner(data_dir, request))
        .await
        .map_err(|_| anyhow::anyhow!("local daemon request exceeded its deadline"))?
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Sends only the explicit daemon lifecycle control request. Callers must
/// first prove Gateway product/protocol identity; this is never used for a
/// privileged operation.
pub async fn send_shutdown_request(data_dir: &Path) -> anyhow::Result<IpcResponse> {
    tokio::time::timeout(
        PROBE_TIMEOUT,
        send_raw(data_dir, IpcRequest::DaemonShutdown),
    )
    .await
    .map_err(|_| anyhow::anyhow!("local daemon shutdown request exceeded its deadline"))?
}

/// Turns an `IpcResponse::Error` into an `Err` so the CLI exits non-zero
/// and prints a clear message, instead of every call site re-checking for
/// the error variant.
pub fn ok_or_bail(response: IpcResponse) -> anyhow::Result<IpcResponse> {
    if let IpcResponse::Error(error) = &response {
        anyhow::bail!("{} ({})", error.message, error.code);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use companion_protocol::{DAEMON_PRODUCT_ID, LOCAL_IPC_PROTOCOL_VERSION};

    use super::*;

    #[test]
    fn incompatible_identity_is_not_classified_as_unavailable() {
        let error = DaemonIdentityView {
            product_id: "other-product".to_string(),
            protocol_version: LOCAL_IPC_PROTOCOL_VERSION,
            daemon_version: EXPECTED_DAEMON_VERSION.to_string(),
            instance_id: "instance".to_string(),
        }
        .validate_for_client()
        .expect_err("a different local product must be rejected");
        assert!(error.to_string().contains("unexpected daemon product"));
        assert!(!DAEMON_PRODUCT_ID.is_empty());
    }

    #[test]
    fn packaged_cli_and_daemon_versions_are_not_empty() {
        assert!(!EXPECTED_DAEMON_VERSION.is_empty());
    }
}
