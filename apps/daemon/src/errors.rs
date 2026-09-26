use companion_core::CompanionError;
use companion_identity::IdentityError;
use companion_sessions::{GrantError, SessionError};
use companion_storage::StorageError;
use companion_workspace::WorkspaceError;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Session(#[from] SessionError),
    /// Explicit authorization authority failed a constraint, a transition, or
    /// its persistence.
    #[error(transparent)]
    Authorization(#[from] GrantError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("secure device identity storage is not available on this platform yet")]
    SecretStoreUnavailable,
    #[error("session not found")]
    SessionNotFound,
    #[error("no access grant is in force for this session")]
    AuthorizationNotEstablished,
    #[error("this decision concerns transport only and cannot change authorization")]
    NoAuthorizationDecision,
    #[error("durable audit record could not be persisted ({code}); operation was not executed")]
    AuditPersistence { code: &'static str },
    #[error("internal error: {0}")]
    Internal(String),
}

impl CompanionError for DaemonError {
    fn code(&self) -> &'static str {
        match self {
            DaemonError::Identity(e) => e.code(),
            DaemonError::Session(e) => e.code(),
            DaemonError::Authorization(e) => e.code(),
            DaemonError::Workspace(e) => e.code(),
            DaemonError::Storage(e) => e.code(),
            DaemonError::SecretStoreUnavailable => "IDENTITY_SECRET_STORE_UNAVAILABLE",
            DaemonError::SessionNotFound => "SESSION_NOT_FOUND",
            DaemonError::AuthorizationNotEstablished => "AUTHORIZATION_NOT_ESTABLISHED",
            DaemonError::NoAuthorizationDecision => "AUTHORIZATION_NOT_A_DECISION_FOR_THIS_STATE",
            // Carries the underlying audit error class (AUDIT_STORAGE /
            // AUDIT_NOT_FOUND) so a caller can tell an audit-gate refusal
            // apart from a generic IPC failure.
            DaemonError::AuditPersistence { code } => code,
            DaemonError::Internal(_) => "IPC_INTERNAL",
        }
    }

    fn retryable(&self) -> bool {
        match self {
            DaemonError::Identity(e) => e.retryable(),
            DaemonError::Session(e) => e.retryable(),
            DaemonError::Authorization(e) => e.retryable(),
            DaemonError::Workspace(e) => e.retryable(),
            DaemonError::Storage(e) => e.retryable(),
            _ => false,
        }
    }
}

impl DaemonError {
    pub fn to_ipc_error(&self) -> companion_protocol::IpcErrorView {
        companion_protocol::IpcErrorView {
            code: self.code().to_string(),
            message: self.to_string(),
            retryable: self.retryable(),
        }
    }
}
