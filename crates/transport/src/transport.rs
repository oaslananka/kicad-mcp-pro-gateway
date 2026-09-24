use companion_core::TransportState;
use companion_protocol::Envelope;

use crate::error::TransportError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportHealth {
    pub connected: bool,
    pub last_error: Option<String>,
}

/// Abstracts the pipe between Gateway and a relay/cloud. Implementors
/// never decide authorization — a connected transport is not an active
/// session (see `docs/security/trust-boundaries.md`).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self) -> Result<(), TransportError>;
    async fn disconnect(&self) -> Result<(), TransportError>;
    async fn send(&self, envelope: Envelope) -> Result<(), TransportError>;
    async fn receive(&self) -> Result<Envelope, TransportError>;
    fn state(&self) -> TransportState;
    async fn health(&self) -> TransportHealth;
}
