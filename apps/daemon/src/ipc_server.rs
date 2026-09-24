//! Local IPC transport: a named pipe on Windows, a Unix domain socket
//! elsewhere, via the `interprocess` crate. There is no TCP fallback and
//! no public listener — see `docs/security/trust-boundaries.md`.

use std::path::PathBuf;
use std::sync::Arc;

use companion_protocol::{read_message, write_message, CodecError, IpcRequest};
use interprocess::local_socket::tokio::{prelude::*, Stream};
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};
use tokio::task::JoinSet;

use crate::handlers::handle_request;
use crate::state::DaemonState;

/// Takes an owned `data_dir` so callers can `tokio::spawn` this (which
/// requires a `'static` future) as well as `await` it in place.
pub async fn run_ipc_server(state: Arc<DaemonState>, data_dir: PathBuf) -> anyhow::Result<()> {
    let name = companion_protocol::socket_name(&data_dir).to_ns_name::<GenericNamespaced>()?;
    let listener = ListenerOptions::new().name(name).create_tokio()?;
    let shutdown = Arc::clone(&state.shutdown);
    let mut connections = JoinSet::new();

    tracing::info!("local ipc listener ready");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = accepted?;
                let state = Arc::clone(&state);
                connections.spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        tracing::warn!(error = %e, "ipc connection ended with an error");
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(error = %error, "ipc connection task failed");
                }
            }
            _ = shutdown.cancelled() => {
                tracing::info!("ipc server shutting down");
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Ok(());
            }
        }
    }
}

async fn handle_connection(mut stream: Stream, state: Arc<DaemonState>) -> anyhow::Result<()> {
    loop {
        let request: IpcRequest = match read_message(&mut stream).await {
            Ok(request) => request,
            Err(CodecError::ConnectionClosed) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let response = handle_request(&state, request).await;
        write_message(&mut stream, &response).await?;
    }
}
