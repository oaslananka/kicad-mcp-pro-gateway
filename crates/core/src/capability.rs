//! Capability namespace and profile expansion.
//!
//! Capabilities are a closed set defined here, not an open string space —
//! [`Capability::parse`] is the only way to turn an arbitrary string into a
//! `Capability`, and it returns `None` for anything not in [`Capability::ALL`].
//! This is what makes "unknown capability" a representable, deniable state
//! throughout the policy engine instead of a string that can silently pass
//! through.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(&'static str);

impl Capability {
    pub const PROJECT_READ: Capability = Capability("project.read");
    pub const SCHEMATIC_READ: Capability = Capability("schematic.read");
    pub const SCHEMATIC_WRITE: Capability = Capability("schematic.write");
    pub const PCB_READ: Capability = Capability("pcb.read");
    pub const PCB_WRITE: Capability = Capability("pcb.write");
    pub const ERC_RUN: Capability = Capability("erc.run");
    pub const DRC_RUN: Capability = Capability("drc.run");
    pub const VALIDATION_RUN: Capability = Capability("validation.run");
    pub const MANUFACTURING_READ: Capability = Capability("manufacturing.read");
    pub const MANUFACTURING_EXPORT: Capability = Capability("manufacturing.export");
    pub const WORKSPACE_READ: Capability = Capability("workspace.read");
    pub const PROJECT_WRITE: Capability = Capability("project.write");

    pub const ALL: &'static [Capability] = &[
        Capability::PROJECT_READ,
        Capability::SCHEMATIC_READ,
        Capability::SCHEMATIC_WRITE,
        Capability::PCB_READ,
        Capability::PCB_WRITE,
        Capability::ERC_RUN,
        Capability::DRC_RUN,
        Capability::VALIDATION_RUN,
        Capability::MANUFACTURING_READ,
        Capability::MANUFACTURING_EXPORT,
        Capability::WORKSPACE_READ,
        Capability::PROJECT_WRITE,
    ];

    pub fn as_str(&self) -> &'static str {
        self.0
    }

    /// Parses a capability name. Returns `None` for any name not in
    /// [`Capability::ALL`] — there is no fallback/wildcard capability.
    pub fn parse(name: &str) -> Option<Capability> {
        Self::ALL.iter().copied().find(|c| c.0 == name)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Capability::parse(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown capability: {raw}")))
    }
}

pub type CapabilitySet = BTreeSet<Capability>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityProfile {
    Inspect,
    Design,
    Manufacturing,
    Custom(CapabilitySet),
}

impl CapabilityProfile {
    pub fn effective_capabilities(&self) -> CapabilitySet {
        match self {
            CapabilityProfile::Inspect => [
                Capability::PROJECT_READ,
                Capability::SCHEMATIC_READ,
                Capability::PCB_READ,
                Capability::VALIDATION_RUN,
                Capability::ERC_RUN,
                Capability::DRC_RUN,
                Capability::WORKSPACE_READ,
            ]
            .into_iter()
            .collect(),
            CapabilityProfile::Design => {
                let mut caps = CapabilityProfile::Inspect.effective_capabilities();
                caps.insert(Capability::SCHEMATIC_WRITE);
                caps.insert(Capability::PCB_WRITE);
                caps.insert(Capability::PROJECT_WRITE);
                caps
            }
            CapabilityProfile::Manufacturing => {
                let mut caps = CapabilityProfile::Design.effective_capabilities();
                caps.insert(Capability::MANUFACTURING_READ);
                caps.insert(Capability::MANUFACTURING_EXPORT);
                caps
            }
            CapabilityProfile::Custom(set) => set.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_profile_is_read_and_validation_only() {
        let caps = CapabilityProfile::Inspect.effective_capabilities();
        assert!(caps.contains(&Capability::SCHEMATIC_READ));
        assert!(caps.contains(&Capability::ERC_RUN));
        assert!(!caps.contains(&Capability::SCHEMATIC_WRITE));
        assert!(!caps.contains(&Capability::MANUFACTURING_EXPORT));
    }

    #[test]
    fn design_profile_is_superset_of_inspect_and_excludes_manufacturing() {
        let inspect = CapabilityProfile::Inspect.effective_capabilities();
        let design = CapabilityProfile::Design.effective_capabilities();
        assert!(inspect.is_subset(&design));
        assert!(design.contains(&Capability::SCHEMATIC_WRITE));
        assert!(!design.contains(&Capability::MANUFACTURING_EXPORT));
    }

    #[test]
    fn manufacturing_profile_includes_export() {
        let caps = CapabilityProfile::Manufacturing.effective_capabilities();
        assert!(caps.contains(&Capability::MANUFACTURING_EXPORT));
        assert!(caps.contains(&Capability::SCHEMATIC_WRITE));
    }

    #[test]
    fn custom_profile_is_exactly_the_given_set() {
        let mut set = CapabilitySet::new();
        set.insert(Capability::PROJECT_READ);
        let profile = CapabilityProfile::Custom(set.clone());
        assert_eq!(profile.effective_capabilities(), set);
    }

    #[test]
    fn unknown_capability_string_does_not_parse() {
        assert_eq!(Capability::parse("shell.exec"), None);
        assert_eq!(Capability::parse("schematic.delete_everything"), None);
    }

    #[test]
    fn unknown_capability_fails_deserialization_rather_than_defaulting() {
        let result: Result<Capability, _> = serde_json::from_str("\"shell.exec\"");
        assert!(result.is_err());
    }

    #[test]
    fn known_capability_round_trips_through_json() {
        let json = serde_json::to_string(&Capability::SCHEMATIC_WRITE).unwrap();
        assert_eq!(json, "\"schematic.write\"");
        let back: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Capability::SCHEMATIC_WRITE);
    }
}
