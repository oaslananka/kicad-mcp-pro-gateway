//! Strongly-typed identifiers.
//!
//! Every domain identifier is a distinct newtype over a ULID so that ids
//! for different concepts (a device vs. a session vs. a workspace) can
//! never be mixed up by the type system, even though they share the same
//! underlying representation.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Error returned when parsing a typed id from its string form fails.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdParseError {
    #[error("id is missing the expected \"{expected_prefix}_\" prefix")]
    MissingPrefix { expected_prefix: &'static str },
    #[error("id body is not a valid ULID: {0}")]
    InvalidUlid(String),
}

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(into = "String", try_from = "String")]
        pub struct $name(Ulid);

        impl $name {
            /// Generates a new, time-sortable id.
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            /// Wraps an existing ULID without generating a new one.
            pub fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            pub fn as_ulid(&self) -> Ulid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let body =
                    s.strip_prefix(concat!($prefix, "_"))
                        .ok_or(IdParseError::MissingPrefix {
                            expected_prefix: $prefix,
                        })?;
                let ulid = Ulid::from_string(body)
                    .map_err(|e| IdParseError::InvalidUlid(e.to_string()))?;
                Ok(Self(ulid))
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.to_string()
            }
        }
    };
}

typed_id!(DeviceId, "dev");
typed_id!(AccountId, "acct");
typed_id!(WorkspaceId, "ws");
typed_id!(SessionId, "sess");
typed_id!(GrantId, "grant");
typed_id!(LeaseId, "lease");
typed_id!(TaskId, "task");
typed_id!(OperationId, "op");
typed_id!(CheckpointId, "chk");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_round_trips_through_display_and_fromstr() {
        let id = DeviceId::new();
        let s = id.to_string();
        assert!(s.starts_with("dev_"));
        let parsed: DeviceId = s.parse().expect("valid id parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn distinct_id_types_are_not_interchangeable_at_compile_time() {
        fn takes_device_id(_: DeviceId) {}
        let d = DeviceId::new();
        takes_device_id(d);
        // WorkspaceId::new() could not be passed to takes_device_id: this is
        // enforced by the compiler, not this test, but we exercise the
        // constructor here so the crate would fail to compile if the macro
        // ever stopped generating distinct types.
        let _w = WorkspaceId::new();
    }

    #[test]
    fn ids_sort_lexically_by_creation_order() {
        let a = DeviceId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = DeviceId::new();
        assert!(a.to_string() < b.to_string());
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let session_id = SessionId::new();
        let as_string = session_id.to_string();
        let parsed: Result<DeviceId, _> = as_string.parse();
        assert_eq!(
            parsed,
            Err(IdParseError::MissingPrefix {
                expected_prefix: "dev"
            })
        );
    }

    #[test]
    fn malformed_body_is_rejected() {
        let parsed: Result<DeviceId, _> = "dev_not-a-ulid".parse();
        assert!(matches!(parsed, Err(IdParseError::InvalidUlid(_))));
    }

    #[test]
    fn serde_round_trip() {
        let id = WorkspaceId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: WorkspaceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
