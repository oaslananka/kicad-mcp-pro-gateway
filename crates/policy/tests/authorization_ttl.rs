use std::collections::BTreeSet;

use companion_core::config::{self, CliOverrides, CompanionConfig};
use companion_core::CapabilityProfile;
use companion_policy::AuthorizationTtlPolicy;

const VALID_TTL_POLICY_CONFIG: &str = r#"
[authorization_ttl]
low_risk_max_minutes = 120
normal_risk_max_minutes = 60
high_risk_max_minutes = 15
critical_risk_max_minutes = 1

[authorization_ttl.inspect]
max_minutes = 180
risk = "low"

[authorization_ttl.design]
max_minutes = 120
risk = "normal"

[authorization_ttl.manufacturing]
max_minutes = 30
risk = "high"

[authorization_ttl.custom]
max_minutes = 5
risk = "critical"
"#;

fn load_config(contents: &str) -> CompanionConfig {
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(data_dir.path().join("config.toml"), contents).unwrap();

    config::load(CliOverrides {
        data_dir: Some(data_dir.path().to_path_buf()),
        ..Default::default()
    })
    .expect("test policy configuration is valid")
}

#[test]
fn default_policy_bounds_each_profile_and_risk_class() {
    let policy = AuthorizationTtlPolicy::default();

    for (profile, expected) in [
        (CapabilityProfile::Inspect, 120),
        (CapabilityProfile::Design, 60),
        (CapabilityProfile::Manufacturing, 15),
        (CapabilityProfile::Custom(BTreeSet::new()), 1),
    ] {
        let effective = policy.effective_ttl(&profile, i64::MAX);
        assert_eq!(effective.effective_minutes, expected, "{profile:?}");
    }
}

#[test]
fn negative_and_minimum_boundaries_normalize_to_one_minute() {
    let policy = AuthorizationTtlPolicy::default();

    for requested in [i64::MIN, -1, 0, 1] {
        let effective = policy.effective_ttl(&CapabilityProfile::Inspect, requested);
        assert_eq!(effective.requested_minutes, requested);
        assert_eq!(effective.effective_minutes, 1, "requested={requested}");
    }
}

#[test]
fn exact_maximum_is_preserved_and_oversized_values_are_clamped() {
    let policy = AuthorizationTtlPolicy::default();

    let exact = policy.effective_ttl(&CapabilityProfile::Design, 60);
    assert_eq!(exact.effective_minutes, 60);

    let oversized = policy.effective_ttl(&CapabilityProfile::Design, 61);
    assert_eq!(oversized.effective_minutes, 60);
}

#[test]
fn configurable_profile_and_risk_ceilings_are_applied_independently() {
    let profile_binds = load_config(
        &VALID_TTL_POLICY_CONFIG
            .replace("low_risk_max_minutes = 120", "low_risk_max_minutes = 240"),
    );
    assert_eq!(
        AuthorizationTtlPolicy::new(profile_binds.authorization_ttl)
            .effective_ttl(&CapabilityProfile::Inspect, i64::MAX)
            .effective_minutes,
        180,
        "the profile ceiling must still bind when the risk ceiling is looser"
    );

    let risk_binds = load_config(&VALID_TTL_POLICY_CONFIG.replace(
        "[authorization_ttl.inspect]\nmax_minutes = 180",
        "[authorization_ttl.inspect]\nmax_minutes = 240",
    ));
    assert_eq!(
        AuthorizationTtlPolicy::new(risk_binds.authorization_ttl)
            .effective_ttl(&CapabilityProfile::Inspect, i64::MAX)
            .effective_minutes,
        120,
        "the risk ceiling must still bind when the profile ceiling is looser"
    );
}

#[test]
fn critical_risk_has_a_material_one_minute_ceiling() {
    let policy = AuthorizationTtlPolicy::default();
    let effective = policy.effective_ttl(&CapabilityProfile::Custom(BTreeSet::new()), i64::MAX);
    assert_eq!(effective.effective_minutes, 1);
}
