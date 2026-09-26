//! The single place where transport connectivity and authorization meet —
//! which is to say, the place where they deliberately do not meet.
//!
//! Connectivity is recorded as [`TransportState`], the model the transport
//! crate already uses for exactly this purpose. Authority is recorded as
//! [`companion_core::AccessGrant`]. Neither function below takes a grant or
//! returns one, so this module cannot mint, extend, refresh, widen, or
//! resurrect authorization no matter which events it is given — that is a
//! property of the signatures, not of a runtime check that could be skipped.
//!
//! See `docs/architecture/session-lifecycle.md`.

use companion_core::TransportState;

/// Something the transport pipe did. These are connectivity facts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConnectivityEvent {
    /// A connection attempt is in progress.
    Connecting,
    /// The pipe came up.
    Connected,
    /// The pipe went down.
    Disconnected,
    /// A reconnect attempt is in progress.
    Reconnecting,
    /// A connection attempt failed.
    ConnectFailed,
}

impl TransportConnectivityEvent {
    /// The connectivity state this event leads to, given the current one.
    /// No grant is in scope here, and none can be.
    fn next_state(self, current: TransportState) -> TransportState {
        match self {
            Self::Connected => TransportState::Connected,
            Self::Disconnected => TransportState::Disconnected,
            Self::ConnectFailed => TransportState::Failed,
            Self::Connecting => TransportState::Connecting,
            // A reconnect attempt is only distinguishable from a cold connect
            // if the pipe was up before.
            Self::Reconnecting => {
                if current == TransportState::Disconnected {
                    TransportState::Reconnecting
                } else {
                    TransportState::Connecting
                }
            }
        }
    }
}

/// Folds one transport event into the Gateway's existing [`TransportState`]
/// model. Deliberately no grant parameter: connectivity is recorded here and
/// authority is recorded in [`companion_core::AccessGrant`], and nothing in
/// this module can cross between them.
pub fn transport_state_after(
    current: TransportState,
    event: TransportConnectivityEvent,
) -> TransportState {
    event.next_state(current)
}

/// Folds a whole sequence of transport events, e.g. a reconnect storm.
pub fn fold_transport_events(
    current: TransportState,
    events: impl IntoIterator<Item = TransportConnectivityEvent>,
) -> TransportState {
    events.into_iter().fold(current, transport_state_after)
}

/// Whether a transport is currently usable for carrying messages. This is a
/// statement about the pipe, never about authority: an unauthorized principal
/// over a perfectly healthy pipe is still unauthorized.
pub fn is_pipe_usable(state: TransportState) -> bool {
    matches!(state, TransportState::Connected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_reconnect_storm_only_moves_connectivity() {
        let storm = [
            TransportConnectivityEvent::Connected,
            TransportConnectivityEvent::Disconnected,
            TransportConnectivityEvent::Reconnecting,
            TransportConnectivityEvent::Connected,
            TransportConnectivityEvent::Disconnected,
            TransportConnectivityEvent::ConnectFailed,
            TransportConnectivityEvent::Connecting,
            TransportConnectivityEvent::Connected,
        ];
        assert_eq!(
            fold_transport_events(TransportState::Disconnected, storm),
            TransportState::Connected
        );
        assert_eq!(
            fold_transport_events(TransportState::Disconnected, [storm[0]]),
            TransportState::Connected
        );
        assert_eq!(
            fold_transport_events(TransportState::Connected, [storm[1]]),
            TransportState::Disconnected
        );
    }

    #[test]
    fn reconnecting_a_down_pipe_is_distinguishable_from_a_cold_connect() {
        assert_eq!(
            transport_state_after(
                TransportState::Disconnected,
                TransportConnectivityEvent::Reconnecting
            ),
            TransportState::Reconnecting
        );
        assert_eq!(
            transport_state_after(
                TransportState::Failed,
                TransportConnectivityEvent::Reconnecting
            ),
            TransportState::Connecting
        );
    }

    #[test]
    fn pipe_usability_says_nothing_about_authority() {
        assert!(is_pipe_usable(TransportState::Connected));
        assert!(!is_pipe_usable(TransportState::Reconnecting));
        assert!(!is_pipe_usable(TransportState::Disconnected));
        assert!(!is_pipe_usable(TransportState::Failed));
    }
}
