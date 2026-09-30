use companion_core::{TransportState, VerifiedPrincipal};
use companion_protocol::Envelope;

use crate::error::TransportError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportHealth {
    pub connected: bool,
    pub last_error: Option<String>,
}

/// One inbound envelope plus the authenticated remote-actor context derived
/// by the transport verifier for this exact receive.
///
/// Keeping these facts in one value prevents a caller from reading an
/// envelope and then racing a separate "current peer" lookup. The mock
/// transport supplies `None` unless a test explicitly scripts authenticated
/// evidence; a future production transport must only populate
/// `verified_principal` after validating credentials/evidence itself.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundEnvelope {
    pub envelope: Envelope,
    pub verified_principal: Option<VerifiedPrincipal>,
}

impl From<Envelope> for InboundEnvelope {
    fn from(envelope: Envelope) -> Self {
        Self {
            envelope,
            verified_principal: None,
        }
    }
}

/// Abstracts the pipe between Gateway and a relay/cloud. Implementors
/// never decide authorization — a connected transport is not an active
/// session (see `docs/security/trust-boundaries.md`).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self) -> Result<(), TransportError>;
    async fn disconnect(&self) -> Result<(), TransportError>;
    async fn send(&self, envelope: Envelope) -> Result<(), TransportError>;
    async fn receive(&self) -> Result<InboundEnvelope, TransportError>;
    fn state(&self) -> TransportState;
    async fn health(&self) -> TransportHealth;
}
