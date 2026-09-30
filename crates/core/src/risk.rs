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
        assert_eq!(equal.policy_version, 2);
        assert_eq!(equal.base_risk, RiskLevel::Normal);
        assert_eq!(equal.effective_risk, RiskLevel::Normal);
        assert!(equal.factors.is_empty());

        let raised = RiskAssessment::new(2, RiskLevel::Normal, RiskLevel::High, vec![])
            .expect("higher effective risk is allowed");
        assert_eq!(raised.effective_risk, RiskLevel::High);
    }
}
