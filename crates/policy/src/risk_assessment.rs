//! Deterministic operation-risk assessment from reviewed registry rules.

use companion_core::{RiskAssessment, RiskAssessmentError, RiskFactor, RiskLevel};
use serde_json::{Map, Value};

use crate::operation_effects::NormalizedOperationEffects;
use crate::tool_registry::{BooleanRiskFactor, RiskRule, OPERATION_RISK_POLICY_VERSION};

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
                breadth_dimension: _,
                minimum_count,
                requires_effect,
                escalate_to,
            } => {
                if normalized_effects
                    .paths_for(*requires_effect)
                    .next()
                    .is_none()
                {
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
                    factors.push(RiskFactor::BulkArgumentCardinality {
                        subject: argument.clone(),
                        observed_count,
                        threshold: *minimum_count,
                        escalated_to: *escalate_to,
                    });
                }
            }
            RiskRule::BooleanEquals {
                argument,
                expected,
                default,
                requires_effect,
                escalate_to,
                factor,
            } => {
                if normalized_effects
                    .paths_for(*requires_effect)
                    .next()
                    .is_none()
                {
                    return Err(RiskAssessmentError::RequiredEffectMissing);
                }

                let resolved = match arguments.get(argument) {
                    Some(value) => value
                        .as_bool()
                        .ok_or(RiskAssessmentError::ArgumentNotBoolean)?,
                    None => *default,
                };

                if resolved == *expected {
                    effective_risk = effective_risk.max(*escalate_to);
                    let factor = match factor {
                        BooleanRiskFactor::ConfirmedOverwrite => RiskFactor::ConfirmedOverwrite {
                            subject: argument.clone(),
                            escalated_to: *escalate_to,
                        },
                    };
                    factors.push(factor);
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
