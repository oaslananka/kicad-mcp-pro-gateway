//! `companion-protocol`: wire types shared across the daemon's local IPC
//! API and its CLI/desktop clients, plus the newline-delimited JSON framing
//! they're sent over. See `docs/protocol/README.md`.

pub mod codec;
pub mod envelope;
pub mod ipc;
pub mod ipc_naming;

pub use codec::{read_message, write_message, CodecError, MAX_MESSAGE_BYTES};
pub use envelope::{Envelope, EnvelopeError, MessageType, PROTOCOL_VERSION};
pub use ipc::{
    AuditSummaryView, DaemonIdentityError, DaemonIdentityView, DaemonStatusView, IpcErrorView,
    IpcRequest, IpcResponse, PairingBegunView, PairingStatusView, PendingApprovalView, SessionView,
    WorkspaceInfo, WorkspaceView, DAEMON_PRODUCT_ID, LOCAL_IPC_PROTOCOL_VERSION,
};
pub use ipc_naming::socket_name;
