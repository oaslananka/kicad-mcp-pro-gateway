use companion_core::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connect failed: {0}")]
    ConnectFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("no message available")]
    NoMessage,
    #[error("transport is not connected")]
    NotConnected,
}

impl CompanionError for TransportError {
    fn code(&self) -> &'static str {
        match self {
            TransportError::ConnectFailed(_) => "TRANSPORT_CONNECT_FAILED",
            TransportError::SendFailed(_) => "TRANSPORT_SEND_FAILED",
            TransportError::ReceiveFailed(_) => "TRANSPORT_RECEIVE_FAILED",
            TransportError::NoMessage => "TRANSPORT_NO_MESSAGE",
            TransportError::NotConnected => "TRANSPORT_NOT_CONNECTED",
        }
    }

    fn retryable(&self) -> bool {
        matches!(
            self,
            TransportError::ConnectFailed(_)
                | TransportError::SendFailed(_)
                | TransportError::ReceiveFailed(_)
        )
    }
}
