//! `companion-transport`: the transport abstraction, a deterministic mock
//! transport, and reconnect/backoff. No production cloud transport is
//! implemented in this repository — see `docs/protocol/README.md`.

pub mod error;
pub mod mock;
pub mod reconnect;
pub mod transport;

pub use error::TransportError;
pub use mock::MockTransport;
pub use reconnect::{jittered_delay, BackoffPolicy, ReconnectingTransport};
pub use transport::{Transport, TransportHealth};
