//! Shared error taxonomy.
//!
//! Every error type exposed across a CLI/IPC/desktop boundary implements
//! [`CompanionError`] so those surfaces can render a stable code, a safe
//! human message, a retryable flag, and non-sensitive context uniformly,
//! without ever needing to know the concrete error enum.

/// A stable, cross-surface description of an error.
///
/// Implementors must never place secret material (private keys, tokens,
/// pairing codes) in [`CompanionError::context`] or in the `Display`
/// message used to construct the error, since both may be logged or
/// returned over the local IPC API / CLI output.
pub trait CompanionError: std::error::Error {
    /// A stable machine-readable code, e.g. `"WORKSPACE_PATH_ESCAPES_ROOT"`.
    fn code(&self) -> &'static str;

    /// Whether retrying the same request might succeed without user action.
    fn retryable(&self) -> bool;

    /// Non-sensitive structured context for the caller. Defaults to null.
    fn context(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("workspace root not found: {path}")]
    struct FakeWorkspaceError {
        path: String,
    }

    impl CompanionError for FakeWorkspaceError {
        fn code(&self) -> &'static str {
            "WORKSPACE_ROOT_NOT_FOUND"
        }

        fn retryable(&self) -> bool {
            false
        }

        fn context(&self) -> serde_json::Value {
            serde_json::json!({ "path": self.path })
        }
    }

    #[test]
    fn implementor_exposes_stable_code_and_safe_context() {
        let err = FakeWorkspaceError {
            path: "C:/missing".into(),
        };
        assert_eq!(err.code(), "WORKSPACE_ROOT_NOT_FOUND");
        assert!(!err.retryable());
        assert_eq!(err.context()["path"], "C:/missing");
    }

    #[test]
    fn default_context_is_null() {
        #[derive(Debug, thiserror::Error)]
        #[error("boom")]
        struct NoContextError;

        impl CompanionError for NoContextError {
            fn code(&self) -> &'static str {
                "TEST_BOOM"
            }
            fn retryable(&self) -> bool {
                true
            }
        }

        assert_eq!(NoContextError.context(), serde_json::Value::Null);
    }
}
