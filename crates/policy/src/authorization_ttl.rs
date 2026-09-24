//! Local authorization-lifetime policy for remote session requests.
//!
//! A remote request supplies only a requested duration. The effective duration
//! is the minimum of that request, the selected capability profile's ceiling,
//! and the ceiling for the profile's locally assigned risk class. Profile/risk
//! assignments are validated configuration, never remote claims.

use companion_core::{AuthorizationTtlConfig, CapabilityProfile};

/// The policy result retained for session construction and local logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveAuthorizationTtl {
    /// The exact integer received from the remote request. Keeping this in the
    /// result makes boundary behavior observable without lossy conversion.
    pub requested_minutes: i64,
    /// The policy-bounded duration used to calculate `Session::expires_at`.
    pub effective_minutes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationTtlPolicy {
    config: AuthorizationTtlConfig,
}

impl AuthorizationTtlPolicy {
    pub fn new(config: AuthorizationTtlConfig) -> Self {
        Self { config }
    }

    /// Clamps a remote request to the lower of its profile and risk ceilings.
    /// Values below one minute are normalized to one; this comparison cannot
    /// overflow for any `i64`, including both integer extremes.
    pub fn effective_ttl(
        &self,
        capability_profile: &CapabilityProfile,
        requested_minutes: i64,
    ) -> EffectiveAuthorizationTtl {
        let profile = self.config.profile(capability_profile);
        let effective_minutes = requested_minutes
            .max(1)
            .min(profile.max_minutes())
            .min(self.config.risk_ceiling(profile.risk()));

        EffectiveAuthorizationTtl {
            requested_minutes,
            effective_minutes,
        }
    }
}

impl Default for AuthorizationTtlPolicy {
    fn default() -> Self {
        Self::new(AuthorizationTtlConfig::default())
    }
}
