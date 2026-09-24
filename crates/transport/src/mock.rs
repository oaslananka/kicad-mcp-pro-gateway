//! A deterministic, in-memory, scriptable [`Transport`] for tests and for
//! development end-to-end scenarios before a real cloud relay exists. See
//! project principle 15 — there is no production cloud transport in this
//! repository.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use companion_core::TransportState;
use companion_protocol::Envelope;

use crate::error::TransportError;
use crate::transport::{Transport, TransportHealth};

pub struct MockTransport {
    state: Mutex<TransportState>,
    connect_failures_remaining: Mutex<u32>,
    receive_failures_remaining: Mutex<u32>,
    connect_attempts: AtomicU32,
    outbox: Mutex<VecDeque<Envelope>>,
    inbox: Mutex<VecDeque<Envelope>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self {
            state: Mutex::new(TransportState::Disconnected),
            connect_failures_remaining: Mutex::new(0),
            receive_failures_remaining: Mutex::new(0),
            connect_attempts: AtomicU32::new(0),
            outbox: Mutex::new(VecDeque::new()),
            inbox: Mutex::new(VecDeque::new()),
        }
    }
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next `n` calls to [`Transport::connect`] fail before connects
    /// succeed again.
    pub fn fail_next_connects(&self, n: u32) {
        *self
            .connect_failures_remaining
            .lock()
            .expect("mock mutex poisoned") = n;
    }

    pub fn connect_attempt_count(&self) -> u32 {
        self.connect_attempts.load(Ordering::SeqCst)
    }

    pub fn fail_next_receives(&self, n: u32) {
        *self
            .receive_failures_remaining
            .lock()
            .expect("mock mutex poisoned") = n;
    }

    pub fn push_incoming(&self, envelope: Envelope) {
        self.inbox
            .lock()
            .expect("mock mutex poisoned")
            .push_back(envelope);
    }

    pub fn sent_messages(&self) -> Vec<Envelope> {
        self.outbox
            .lock()
            .expect("mock mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl Transport for MockTransport {
    async fn connect(&self) -> Result<(), TransportError> {
        self.connect_attempts.fetch_add(1, Ordering::SeqCst);
        let mut remaining = self
            .connect_failures_remaining
            .lock()
            .expect("mock mutex poisoned");
        if *remaining > 0 {
            *remaining -= 1;
            *self.state.lock().expect("mock mutex poisoned") = TransportState::Failed;
            return Err(TransportError::ConnectFailed(
                "scripted mock failure".into(),
            ));
        }
        *self.state.lock().expect("mock mutex poisoned") = TransportState::Connected;
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), TransportError> {
        *self.state.lock().expect("mock mutex poisoned") = TransportState::Disconnected;
        Ok(())
    }

    async fn send(&self, envelope: Envelope) -> Result<(), TransportError> {
        if self.state() != TransportState::Connected {
            return Err(TransportError::NotConnected);
        }
        self.outbox
            .lock()
            .expect("mock mutex poisoned")
            .push_back(envelope);
        Ok(())
    }

    async fn receive(&self) -> Result<Envelope, TransportError> {
        let mut remaining = self
            .receive_failures_remaining
            .lock()
            .expect("mock mutex poisoned");
        if *remaining > 0 {
            *remaining -= 1;
            *self.state.lock().expect("mock mutex poisoned") = TransportState::Failed;
            return Err(TransportError::ReceiveFailed(
                "scripted mock receive failure".into(),
            ));
        }
        drop(remaining);

        self.inbox
            .lock()
            .expect("mock mutex poisoned")
            .pop_front()
            .ok_or(TransportError::NoMessage)
    }

    fn state(&self) -> TransportState {
        *self.state.lock().expect("mock mutex poisoned")
    }

    async fn health(&self) -> TransportHealth {
        TransportHealth {
            connected: self.state() == TransportState::Connected,
            last_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use companion_protocol::MessageType;

    #[tokio::test]
    async fn connect_then_send_then_receive_round_trips() {
        let transport = MockTransport::new();
        transport.connect().await.unwrap();
        assert_eq!(transport.state(), TransportState::Connected);

        let envelope = Envelope::new(MessageType::Heartbeat, json!({}));
        transport.send(envelope.clone()).await.unwrap();
        assert_eq!(transport.sent_messages(), vec![envelope]);

        let incoming = Envelope::new(MessageType::OperationResult, json!({ "ok": true }));
        transport.push_incoming(incoming.clone());
        let received = transport.receive().await.unwrap();
        assert_eq!(received, incoming);
    }

    #[tokio::test]
    async fn send_before_connect_is_rejected() {
        let transport = MockTransport::new();
        let result = transport
            .send(Envelope::new(MessageType::Heartbeat, json!({})))
            .await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn scripted_receive_failure_marks_transport_failed_then_can_reconnect() {
        let transport = MockTransport::new();
        transport.connect().await.unwrap();
        transport.fail_next_receives(1);

        let result = transport.receive().await;
        assert!(matches!(result, Err(TransportError::ReceiveFailed(_))));
        assert_eq!(transport.state(), TransportState::Failed);

        transport.connect().await.unwrap();
        assert_eq!(transport.state(), TransportState::Connected);
    }

    #[tokio::test]
    async fn scripted_connect_failures_are_honored_then_recover() {
        let transport = MockTransport::new();
        transport.fail_next_connects(2);

        assert!(transport.connect().await.is_err());
        assert!(transport.connect().await.is_err());
        assert!(transport.connect().await.is_ok());
        assert_eq!(transport.connect_attempt_count(), 3);
        assert_eq!(transport.state(), TransportState::Connected);
    }
}
