use companion_core::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit event not found")]
    NotFound,
    #[error("storage error: {0}")]
    Storage(String),
}

impl CompanionError for AuditError {
    fn code(&self) -> &'static str {
        match self {
            AuditError::NotFound => "AUDIT_NOT_FOUND",
            AuditError::Storage(_) => "AUDIT_STORAGE",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}
