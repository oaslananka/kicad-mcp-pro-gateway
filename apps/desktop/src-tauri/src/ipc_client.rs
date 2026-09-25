//! Verified desktop client for the daemon's deterministic local IPC endpoint.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use companion_protocol::{
    read_message, write_message, DaemonIdentityError, DaemonIdentityView, IpcRequest, IpcResponse,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};

const EXPECTED_DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    Unavailable(String),
    Incompatible(String),
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

async fn connect(data_dir: &Path) -> Result<interprocess::local_socket::tokio::Stream, String> {
    let name = companion_protocol::socket_name(data_dir)
        .to_ns_name::<GenericNamespaced>()
        .map_err(|error| error.to_string())?;
    interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .map_err(|error| error.to_string())
}

async fn send_raw(data_dir: &Path, request: IpcRequest) -> Result<IpcResponse, String> {
    let mut stream = connect(data_dir).await?;
    write_message(&mut stream, &request)
        .await
        .map_err(|error| error.to_string())?;
    read_message(&mut stream)
        .await
        .map_err(|error| error.to_string())
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

fn validate_packaged_version(identity: &DaemonIdentityView) -> Result<(), ProbeError> {
    identity
        .validate_daemon_version(EXPECTED_DAEMON_VERSION)
        .map_err(|error| match error {
            DaemonIdentityError::DaemonVersionMismatch { expected, actual } => {
                ProbeError::VersionMismatch { expected, actual }
            }
            other => ProbeError::Incompatible(other.to_string()),
        })
}

async fn probe_daemon_inner(data_dir: &Path) -> Result<DaemonIdentityView, ProbeError> {
    let mut stream = connect(data_dir)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    write_message(&mut stream, &IpcRequest::Identity)
        .await
        .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
    let identity = read_identity(&mut stream).await?;
    validate_packaged_version(&identity)?;
    Ok(identity)
}

pub async fn probe_daemon(data_dir: &Path) -> Result<DaemonIdentityView, ProbeError> {
    tokio::time::timeout(PROBE_TIMEOUT, probe_daemon_inner(data_dir))
        .await
        .map_err(|_| {
            ProbeError::Unavailable(
                "local daemon identity handshake exceeded its deadline".to_string(),
            )
        })?
}

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

pub async fn wait_for_stopped(data_dir: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if connect(data_dir).await.is_err() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("local daemon did not stop before the deadline".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Verifies the daemon identity on the same connection before forwarding the
/// requested operation. No endpoint or process fallback is possible here.
pub async fn send_request(data_dir: &Path, request: IpcRequest) -> Result<IpcResponse, String> {
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
        validate_packaged_version(&identity)?;

        write_message(&mut stream, &request)
            .await
            .map_err(|error| ProbeError::Unavailable(error.to_string()))?;
        read_message(&mut stream)
            .await
            .map_err(|error| ProbeError::Unavailable(error.to_string()))
    }

    tokio::time::timeout(REQUEST_TIMEOUT, send_request_inner(data_dir, request))
        .await
        .map_err(|_| "local daemon request exceeded its deadline".to_string())?
        .map_err(|error| error.to_string())
}

/// Sends the explicit shutdown request only after the caller has validated
/// Gateway product/protocol identity. It is used to retire a stale daemon
/// before launching the sidecar packaged with this desktop release.
pub async fn send_shutdown_request(data_dir: &Path) -> Result<IpcResponse, String> {
    tokio::time::timeout(
        PROBE_TIMEOUT,
        send_raw(data_dir, IpcRequest::DaemonShutdown),
    )
    .await
    .map_err(|_| "local daemon shutdown request exceeded its deadline".to_string())?
}

#[cfg(test)]
mod tests {
    use companion_protocol::{DAEMON_PRODUCT_ID, LOCAL_IPC_PROTOCOL_VERSION};

    use super::*;

    #[test]
    fn stale_packaged_version_is_distinct_from_wrong_product() {
        let identity = DaemonIdentityView {
            product_id: DAEMON_PRODUCT_ID.to_string(),
            protocol_version: LOCAL_IPC_PROTOCOL_VERSION,
            daemon_version: "0.0.0".to_string(),
            instance_id: "instance".to_string(),
        };
        assert_eq!(
            validate_packaged_version(&identity),
            Err(ProbeError::VersionMismatch {
                expected: EXPECTED_DAEMON_VERSION.to_string(),
                actual: "0.0.0".to_string(),
            })
        );
    }
}
