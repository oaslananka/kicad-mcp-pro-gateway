//! Library target so integration tests (and, if useful later, the desktop
//! shell) can reuse the same IPC client the `kicad-mcp-companion` binary
//! uses, without duplicating it.

pub mod ipc_client;
