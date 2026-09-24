//! The CLI's only path to the daemon. It never embeds authorization logic
//! itself — every request here maps 1:1 to a daemon-side
//! [`companion_protocol::IpcRequest`] variant, and the daemon's
//! [`handlers`](../../daemon/src/handlers.rs) module is what actually
//! decides the outcome.

use std::path::Path;

use companion_protocol::{read_message, write_message, IpcRequest, IpcResponse};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};

pub async fn send_request(data_dir: &Path, request: IpcRequest) -> anyhow::Result<IpcResponse> {
    let name = companion_protocol::socket_name(data_dir).to_ns_name::<GenericNamespaced>()?;
    let mut stream = interprocess::local_socket::tokio::Stream::connect(name).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the Gateway daemon ({e}). Is it running? Try `kicad-mcp-gateway daemon start`."
        )
    })?;

    write_message(&mut stream, &request).await?;
    let response: IpcResponse = read_message(&mut stream).await?;
    Ok(response)
}

/// Turns an `IpcResponse::Error` into an `Err` so the CLI exits non-zero
/// and prints a clear message, instead of every call site re-checking for
/// the error variant.
pub fn ok_or_bail(response: IpcResponse) -> anyhow::Result<IpcResponse> {
    if let IpcResponse::Error(e) = &response {
        anyhow::bail!("{} ({})", e.message, e.code);
    }
    Ok(response)
}
