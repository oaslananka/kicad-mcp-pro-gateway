//! Deterministic operation-risk assessment from reviewed registry rules.

use companion_core::{
    RiskAssessment, RiskAssessmentError, RiskFactor, RiskFactorCode, RiskLevel,
};
use serde_json::{Map, Value};

use crate::operation_effects::NormalizedOperationEffects;
use crate::tool_registry::{RiskRule, OPERATION_RISK_POLICY_VERSION};

pub fn assess_operation_risk(
    rules: &[RiskRule],
    arguments: &Map<String, Value>,
    normalized_effects: &NormalizedOperationEffects,
    base_risk: RiskLevel,
) -> Result<RiskAssessment, RiskAssessmentError> {
    let mut effective_risk = base_risk;
    let mut factors = Vec::new();

    for rule in rules {
        match rule {
            RiskRule::ArgumentCardinality {
                argument,
                minimum_count,
                requires_effect,
                escalate_to,
            } => {
                if normalized_effects.paths_for(*requires_effect).next().is_none() {
                    return Err(RiskAssessmentError::RequiredEffectMissing);
                }
                let value = arguments
                    .get(argument)
                    .ok_or(RiskAssessmentError::RequiredArgumentMissing)?;
                let values = value
                    .as_array()
                    .ok_or(RiskAssessmentError::ArgumentNotArray)?;
                let observed_count = u64::try_from(values.len())
                    .map_err(|_| RiskAssessmentError::ArgumentCardinalityOverflow)?;

                if observed_count >= *minimum_count {
                    effective_risk = effective_risk.max(*escalate_to);
                    factors.push(RiskFactor {
                        code: RiskFactorCode::BulkArgumentCardinality,
                        subject: argument.clone(),
                        observed_count,
                        threshold: *minimum_count,
                        escalated_to: *escalate_to,
                    });
                }
            }
        }
    }

    RiskAssessment::new(
        OPERATION_RISK_POLICY_VERSION,
        base_risk,
        effective_risk,
        factors,
    )
}
