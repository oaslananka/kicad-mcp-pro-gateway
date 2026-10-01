//! Risk classification, kept deliberately separate from [`crate::Capability`]:
//! holding a capability does not imply an operation at that capability's
//! highest risk executes without an extra approval step.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Normal,
    High,
    Critical,
}

impl RiskLevel {
    /// Parses a lowercase risk level name (as used in the tool registry
    /// asset). Returns `None` for anything else — there is no fallback risk
    /// level; a malformed entry must fail loudly, not default to `Low`.
    pub fn parse(name: &str) -> Option<RiskLevel> {
        match name {
            "low" => Some(RiskLevel::Low),
            "normal" => Some(RiskLevel::Normal),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RiskFactor {
    BulkArgumentCardinality {
        subject: String,
        observed_count: u64,
        threshold: u64,
        escalated_to: RiskLevel,
    },
    ConfirmedOverwrite {
        subject: String,
        escalated_to: RiskLevel,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskAssessment {
    policy_version: u32,
    base_risk: RiskLevel,
    effective_risk: RiskLevel,
    factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RiskAssessmentError {
    #[error("effective risk cannot be below base risk")]
    EffectiveRiskBelowBase,
    #[error("reviewed risk rule requires an effect absent from normalized operation effects")]
    RequiredEffectMissing,
    #[error("reviewed risk rule argument is missing")]
    RequiredArgumentMissing,
    #[error("reviewed risk rule argument must be an array")]
    ArgumentNotArray,
    #[error("reviewed risk rule argument must be a boolean")]
    ArgumentNotBoolean,
    #[error("reviewed risk rule argument cardinality cannot be represented")]
    ArgumentCardinalityOverflow,
}

impl RiskAssessment {
    pub fn new(
        policy_version: u32,
        base_risk: RiskLevel,
        effective_risk: RiskLevel,
        factors: Vec<RiskFactor>,
    ) -> Result<Self, RiskAssessmentError> {
        if effective_risk < base_risk {
            return Err(RiskAssessmentError::EffectiveRiskBelowBase);
        }
        Ok(Self {
            policy_version,
            base_risk,
            effective_risk,
            factors,
        })
    }

    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    pub const fn base_risk(&self) -> RiskLevel {
        self.base_risk
    }

    pub const fn effective_risk(&self) -> RiskLevel {
        self.effective_risk
    }

    pub fn factors(&self) -> &[RiskFactor] {
        &self.factors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_levels_order_from_low_to_critical() {
        assert!(RiskLevel::Low < RiskLevel::Normal);
        assert!(RiskLevel::Normal < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn parses_known_risk_level_names() {
        assert_eq!(RiskLevel::parse("low"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::parse("critical"), Some(RiskLevel::Critical));
    }

    #[test]
    fn unknown_risk_level_name_does_not_parse() {
        assert_eq!(RiskLevel::parse("catastrophic"), None);
    }

    #[test]
    fn risk_assessment_rejects_effective_risk_below_base() {
        assert_eq!(
            RiskAssessment::new(2, RiskLevel::High, RiskLevel::Normal, vec![]),
            Err(RiskAssessmentError::EffectiveRiskBelowBase)
        );
    }

    #[test]
    fn risk_assessment_accepts_equal_or_higher_effective_risk() {
        let equal = RiskAssessment::new(2, RiskLevel::Normal, RiskLevel::Normal, vec![])
            .expect("equal risk preserves the static floor");
        assert_eq!(equal.policy_version(), 2);
        assert_eq!(equal.base_risk(), RiskLevel::Normal);
        assert_eq!(equal.effective_risk(), RiskLevel::Normal);
        assert!(equal.factors().is_empty());

        let raised = RiskAssessment::new(2, RiskLevel::Normal, RiskLevel::High, vec![])
            .expect("higher effective risk is allowed");
        assert_eq!(raised.effective_risk(), RiskLevel::High);
    }

    #[test]
    fn legacy_bulk_factor_json_deserializes_unchanged() {
        let raw = r#"{"code":"bulk_argument_cardinality","subject":"item_ids","observed_count":3,"threshold":2,"escalated_to":"High"}"#;
        let factor: RiskFactor = serde_json::from_str(raw).unwrap();
        assert_eq!(
            factor,
            RiskFactor::BulkArgumentCardinality {
                subject: "item_ids".into(),
                observed_count: 3,
                threshold: 2,
                escalated_to: RiskLevel::High,
            }
        );
    }

    #[test]
    fn bulk_factor_serializes_to_legacy_shape() {
        let factor = RiskFactor::BulkArgumentCardinality {
            subject: "item_ids".into(),
            observed_count: 3,
            threshold: 2,
            escalated_to: RiskLevel::High,
        };
        assert_eq!(
            serde_json::to_value(factor).unwrap(),
            serde_json::json!({
                "code": "bulk_argument_cardinality",
                "subject": "item_ids",
                "observed_count": 3,
                "threshold": 2,
                "escalated_to": "High"
            })
        );
    }

    #[test]
    fn confirmed_overwrite_factor_round_trips_without_argument_value() {
        let factor = RiskFactor::ConfirmedOverwrite {
            subject: "confirm_overwrite".into(),
            escalated_to: RiskLevel::High,
        };
        let encoded = serde_json::to_value(&factor).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "code": "confirmed_overwrite",
                "subject": "confirm_overwrite",
                "escalated_to": "High"
            })
        );
        assert_eq!(
            serde_json::from_value::<RiskFactor>(encoded).unwrap(),
            factor
        );
    }
}
