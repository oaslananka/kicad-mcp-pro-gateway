//! Layered configuration: CLI flags > environment variables > config file > defaults.
//!
//! `load` resolves `data_dir` from CLI/env/defaults first, then reads
//! `<data_dir>/config.toml`. The internal source resolver keeps precedence
//! deterministic without mutating process environment variables in tests.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;
use url::Url;

use crate::capability::CapabilityProfile;
use crate::error::CompanionError;
use crate::risk::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Disabled,
    Mock,
}

impl TransportMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportMode::Disabled => "disabled",
            TransportMode::Mock => "mock",
        }
    }
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransportMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(TransportMode::Disabled),
            "mock" => Ok(TransportMode::Mock),
            other => Err(ConfigError::InvalidTransportMode(other.to_string())),
        }
    }
}

/// Hard upper bound for a locally configured authorization TTL. One year is
/// deliberately well below `i64` duration arithmetic limits, while making
/// accidental unit mistakes (for example seconds expressed as minutes) fail
/// closed during configuration loading.
pub const MAX_AUTHORIZATION_TTL_MINUTES: i64 = 525_600;

const DEFAULT_INSPECT_MAX_MINUTES: i64 = 240;
const DEFAULT_DESIGN_MAX_MINUTES: i64 = 120;
const DEFAULT_MANUFACTURING_MAX_MINUTES: i64 = 30;
const DEFAULT_CUSTOM_MAX_MINUTES: i64 = 5;
const DEFAULT_LOW_RISK_MAX_MINUTES: i64 = 120;
const DEFAULT_NORMAL_RISK_MAX_MINUTES: i64 = 60;
const DEFAULT_HIGH_RISK_MAX_MINUTES: i64 = 15;
const DEFAULT_CRITICAL_RISK_MAX_MINUTES: i64 = 1;

/// A profile-specific ceiling plus the locally assigned risk class for that
/// profile. The risk class is policy-owned configuration, never remote input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationTtlProfile {
    max_minutes: i64,
    risk: RiskLevel,
}

impl AuthorizationTtlProfile {
    pub fn max_minutes(&self) -> i64 {
        self.max_minutes
    }

    pub fn risk(&self) -> RiskLevel {
        self.risk
    }
}

/// Validated local TTL policy. The effective ceiling is the lower of the
/// selected profile's ceiling and the ceiling for its locally assigned risk
/// class. Fields are private so an invalid policy cannot be constructed by a
/// caller after configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationTtlConfig {
    inspect: AuthorizationTtlProfile,
    design: AuthorizationTtlProfile,
    manufacturing: AuthorizationTtlProfile,
    custom: AuthorizationTtlProfile,
    low_risk_max_minutes: i64,
    normal_risk_max_minutes: i64,
    high_risk_max_minutes: i64,
    critical_risk_max_minutes: i64,
}

impl AuthorizationTtlConfig {
    pub fn profile(&self, profile: &CapabilityProfile) -> AuthorizationTtlProfile {
        match profile {
            CapabilityProfile::Inspect => self.inspect,
            CapabilityProfile::Design => self.design,
            CapabilityProfile::Manufacturing => self.manufacturing,
            CapabilityProfile::Custom(_) => self.custom,
        }
    }

    pub fn risk_ceiling(&self, risk: RiskLevel) -> i64 {
        match risk {
            RiskLevel::Low => self.low_risk_max_minutes,
            RiskLevel::Normal => self.normal_risk_max_minutes,
            RiskLevel::High => self.high_risk_max_minutes,
            RiskLevel::Critical => self.critical_risk_max_minutes,
        }
    }
}

impl Default for AuthorizationTtlConfig {
    fn default() -> Self {
        Self {
            inspect: AuthorizationTtlProfile {
                max_minutes: DEFAULT_INSPECT_MAX_MINUTES,
                risk: RiskLevel::Low,
            },
            design: AuthorizationTtlProfile {
                max_minutes: DEFAULT_DESIGN_MAX_MINUTES,
                risk: RiskLevel::Normal,
            },
            manufacturing: AuthorizationTtlProfile {
                max_minutes: DEFAULT_MANUFACTURING_MAX_MINUTES,
                risk: RiskLevel::High,
            },
            // A custom profile can contain any capability, so the local default
            // is deliberately critical and materially shorter than the named
            // profiles.
            custom: AuthorizationTtlProfile {
                max_minutes: DEFAULT_CUSTOM_MAX_MINUTES,
                risk: RiskLevel::Critical,
            },
            low_risk_max_minutes: DEFAULT_LOW_RISK_MAX_MINUTES,
            normal_risk_max_minutes: DEFAULT_NORMAL_RISK_MAX_MINUTES,
            high_risk_max_minutes: DEFAULT_HIGH_RISK_MAX_MINUTES,
            critical_risk_max_minutes: DEFAULT_CRITICAL_RISK_MAX_MINUTES,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub data_dir: Option<PathBuf>,
    pub log_level: Option<String>,
    pub core_bridge_endpoint: Option<String>,
    pub transport_mode: Option<TransportMode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionConfig {
    pub data_dir: PathBuf,
    pub log_level: String,
    pub core_bridge_endpoint: Url,
    pub transport_mode: TransportMode,
    pub authorization_ttl: AuthorizationTtlConfig,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid core bridge endpoint url: {0}")]
    InvalidEndpoint(String),
    #[error("invalid transport mode: {0}")]
    InvalidTransportMode(String),
    #[error("invalid authorization TTL policy: {0}")]
    InvalidAuthorizationTtlPolicy(String),
    #[error("invalid config file")]
    InvalidConfigFile,
    #[error("failed to read config file {path}: {message}")]
    ConfigFileRead { path: PathBuf, message: String },
}

impl CompanionError for ConfigError {
    fn code(&self) -> &'static str {
        match self {
            ConfigError::InvalidEndpoint(_) => "CONFIG_INVALID_ENDPOINT",
            ConfigError::InvalidTransportMode(_) => "CONFIG_INVALID_TRANSPORT_MODE",
            ConfigError::InvalidAuthorizationTtlPolicy(_) => {
                "CONFIG_INVALID_AUTHORIZATION_TTL_POLICY"
            }
            ConfigError::InvalidConfigFile => "CONFIG_INVALID_FILE",
            ConfigError::ConfigFileRead { .. } => "CONFIG_FILE_READ_FAILED",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_CORE_BRIDGE_ENDPOINT: &str = "http://127.0.0.1:3334/mcp";
const DEFAULT_TRANSPORT_MODE: TransportMode = TransportMode::Disabled;
/// Durable hand-off marker used when a user explicitly stops a daemon that
/// may be supervised by an open desktop process.
pub const DAEMON_STOP_MARKER_FILE: &str = "daemon.stopped";
const ENV_DATA_DIR: &str = "GATEWAY_DATA_DIR";
const ENV_LOG_LEVEL: &str = "GATEWAY_LOG_LEVEL";
const ENV_CORE_BRIDGE_ENDPOINT: &str = "GATEWAY_CORE_BRIDGE_ENDPOINT";
const ENV_TRANSPORT_MODE: &str = "GATEWAY_TRANSPORT_MODE";

/// Production entry point: layers real process environment variables under
/// `overrides`.
pub fn load(overrides: CliOverrides) -> Result<CompanionConfig, ConfigError> {
    let env: HashMap<String, String> = std::env::vars().collect();
    load_with_env(overrides, &env)
}

fn load_with_env(
    overrides: CliOverrides,
    env: &HashMap<String, String>,
) -> Result<CompanionConfig, ConfigError> {
    let data_dir = resolved_data_dir(&overrides, env);
    let path = data_dir.join("config.toml");
    let file_contents = match fs::read_to_string(&path) {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(ConfigError::ConfigFileRead {
                path,
                message: err.to_string(),
            });
        }
    };

    load_from_sources(overrides, env, file_contents.as_deref())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    log_level: Option<String>,
    core_bridge_endpoint: Option<String>,
    transport_mode: Option<String>,
    authorization_ttl: Option<AuthorizationTtlFileConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationTtlFileConfig {
    inspect: AuthorizationTtlProfileFileConfig,
    design: AuthorizationTtlProfileFileConfig,
    manufacturing: AuthorizationTtlProfileFileConfig,
    custom: AuthorizationTtlProfileFileConfig,
    low_risk_max_minutes: i64,
    normal_risk_max_minutes: i64,
    high_risk_max_minutes: i64,
    critical_risk_max_minutes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationTtlProfileFileConfig {
    max_minutes: i64,
    risk: String,
}

impl TryFrom<AuthorizationTtlFileConfig> for AuthorizationTtlConfig {
    type Error = ConfigError;

    fn try_from(value: AuthorizationTtlFileConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            inspect: value.inspect.try_into()?,
            design: value.design.try_into()?,
            manufacturing: value.manufacturing.try_into()?,
            custom: value.custom.try_into()?,
            low_risk_max_minutes: validated_ttl_ceiling(
                value.low_risk_max_minutes,
                "low_risk_max_minutes",
            )?,
            normal_risk_max_minutes: validated_ttl_ceiling(
                value.normal_risk_max_minutes,
                "normal_risk_max_minutes",
            )?,
            high_risk_max_minutes: validated_ttl_ceiling(
                value.high_risk_max_minutes,
                "high_risk_max_minutes",
            )?,
            critical_risk_max_minutes: validated_ttl_ceiling(
                value.critical_risk_max_minutes,
                "critical_risk_max_minutes",
            )?,
        })
    }
}

impl TryFrom<AuthorizationTtlProfileFileConfig> for AuthorizationTtlProfile {
    type Error = ConfigError;

    fn try_from(value: AuthorizationTtlProfileFileConfig) -> Result<Self, Self::Error> {
        let risk = RiskLevel::parse(&value.risk).ok_or_else(|| {
            ConfigError::InvalidAuthorizationTtlPolicy(format!(
                "profile risk {:?} must be low, normal, high, or critical",
                value.risk
            ))
        })?;
        Ok(Self {
            max_minutes: validated_ttl_ceiling(value.max_minutes, "profile.max_minutes")?,
            risk,
        })
    }
}

fn validated_ttl_ceiling(value: i64, field: &str) -> Result<i64, ConfigError> {
    if (1..=MAX_AUTHORIZATION_TTL_MINUTES).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidAuthorizationTtlPolicy(format!(
            "{field} must be between 1 and {MAX_AUTHORIZATION_TTL_MINUTES} minutes"
        )))
    }
}

/// Pure precedence resolution without a file layer: `overrides` > `env` > defaults.
pub fn load_from(
    overrides: CliOverrides,
    env: &HashMap<String, String>,
) -> Result<CompanionConfig, ConfigError> {
    load_from_sources(overrides, env, None)
}

fn load_from_sources(
    overrides: CliOverrides,
    env: &HashMap<String, String>,
    file_contents: Option<&str>,
) -> Result<CompanionConfig, ConfigError> {
    let file = match file_contents {
        Some(contents) => {
            toml::from_str::<FileConfig>(contents).map_err(|_| ConfigError::InvalidConfigFile)?
        }
        None => FileConfig::default(),
    };

    let data_dir = resolved_data_dir(&overrides, env);

    let log_level = overrides
        .log_level
        .or_else(|| env.get(ENV_LOG_LEVEL).cloned())
        .or(file.log_level)
        .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string());

    let endpoint_str = overrides
        .core_bridge_endpoint
        .or_else(|| env.get(ENV_CORE_BRIDGE_ENDPOINT).cloned())
        .or(file.core_bridge_endpoint)
        .unwrap_or_else(|| DEFAULT_CORE_BRIDGE_ENDPOINT.to_string());
    let core_bridge_endpoint = Url::parse(&endpoint_str)
        .map_err(|_| ConfigError::InvalidEndpoint(endpoint_str.clone()))?;

    let transport_mode = match overrides.transport_mode {
        Some(mode) => mode,
        None => match env.get(ENV_TRANSPORT_MODE) {
            Some(raw) => raw.parse()?,
            None => match file.transport_mode {
                Some(raw) => raw.parse()?,
                None => DEFAULT_TRANSPORT_MODE,
            },
        },
    };

    let authorization_ttl = file
        .authorization_ttl
        .map(AuthorizationTtlConfig::try_from)
        .transpose()?
        .unwrap_or_default();

    Ok(CompanionConfig {
        data_dir,
        log_level,
        core_bridge_endpoint,
        transport_mode,
        authorization_ttl,
    })
}

fn resolved_data_dir(overrides: &CliOverrides, env: &HashMap<String, String>) -> PathBuf {
    overrides
        .data_dir
        .clone()
        .or_else(|| env.get(ENV_DATA_DIR).map(PathBuf::from))
        .unwrap_or_else(default_data_dir)
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kicad-mcp-gateway")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_AUTHORIZATION_TTL_CONFIG: &str = r#"
[authorization_ttl]
low_risk_max_minutes = 90
normal_risk_max_minutes = 45
high_risk_max_minutes = 10
critical_risk_max_minutes = 1

[authorization_ttl.inspect]
max_minutes = 241
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

    #[test]
    fn defaults_apply_when_nothing_is_set() {
        let config = load_from(CliOverrides::default(), &HashMap::new()).unwrap();
        assert_eq!(config.log_level, "info");
        assert_eq!(
            config.core_bridge_endpoint.as_str(),
            "http://127.0.0.1:3334/mcp"
        );
        assert_eq!(config.transport_mode, TransportMode::Disabled);
        let inspect = config
            .authorization_ttl
            .profile(&CapabilityProfile::Inspect);
        assert_eq!(inspect.max_minutes(), DEFAULT_INSPECT_MAX_MINUTES);
        assert_eq!(inspect.risk(), RiskLevel::Low);
        assert_eq!(
            config.authorization_ttl.risk_ceiling(RiskLevel::Critical),
            DEFAULT_CRITICAL_RISK_MAX_MINUTES
        );
    }

    #[test]
    fn mock_transport_requires_explicit_configuration() {
        let mut env = HashMap::new();
        env.insert(ENV_TRANSPORT_MODE.to_string(), "mock".to_string());
        let config = load_from(CliOverrides::default(), &env).unwrap();
        assert_eq!(config.transport_mode, TransportMode::Mock);
    }

    #[test]
    fn env_var_overrides_default() {
        let mut env = HashMap::new();
        env.insert(ENV_LOG_LEVEL.to_string(), "debug".to_string());
        let config = load_from(CliOverrides::default(), &env).unwrap();
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn cli_override_beats_env() {
        let mut env = HashMap::new();
        env.insert(ENV_LOG_LEVEL.to_string(), "debug".to_string());
        let overrides = CliOverrides {
            log_level: Some("trace".to_string()),
            ..Default::default()
        };
        let config = load_from(overrides, &env).unwrap();
        assert_eq!(config.log_level, "trace");
    }

    #[test]
    fn malformed_endpoint_produces_typed_error_not_panic() {
        let overrides = CliOverrides {
            core_bridge_endpoint: Some("not a url".to_string()),
            ..Default::default()
        };
        let result = load_from(overrides, &HashMap::new());
        assert_eq!(
            result,
            Err(ConfigError::InvalidEndpoint("not a url".to_string()))
        );
    }

    #[test]
    fn non_loopback_endpoint_is_accepted_at_parse_time() {
        // Loopback-only enforcement is core-bridge's responsibility, not config's.
        let overrides = CliOverrides {
            core_bridge_endpoint: Some("http://example.com/mcp".to_string()),
            ..Default::default()
        };
        let config = load_from(overrides, &HashMap::new()).unwrap();
        assert_eq!(config.core_bridge_endpoint.host_str(), Some("example.com"));
    }

    #[test]
    fn invalid_transport_mode_is_a_typed_error() {
        let mut env = HashMap::new();
        env.insert(ENV_TRANSPORT_MODE.to_string(), "quantum-relay".to_string());
        let result = load_from(CliOverrides::default(), &env);
        assert_eq!(
            result,
            Err(ConfigError::InvalidTransportMode(
                "quantum-relay".to_string()
            ))
        );
    }

    #[test]
    fn missing_config_file_uses_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "gateway-config-missing-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));

        let mut env = HashMap::new();
        env.insert(ENV_DATA_DIR.to_string(), dir.to_string_lossy().into_owned());

        let config = load_with_env(CliOverrides::default(), &env).expect("missing file is allowed");
        assert_eq!(config.data_dir, dir);
        assert_eq!(config.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(config.transport_mode, DEFAULT_TRANSPORT_MODE);
    }

    #[test]
    fn load_with_env_reads_config_from_resolved_data_dir() {
        let dir = std::env::temp_dir().join(format!(
            "gateway-config-test-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), "log_level = \"debug\"\n").unwrap();

        let mut env = HashMap::new();
        env.insert(ENV_DATA_DIR.to_string(), dir.to_string_lossy().into_owned());

        let config = load_with_env(CliOverrides::default(), &env).expect("file config loads");
        assert_eq!(config.data_dir, dir);
        assert_eq!(config.log_level, "debug");

        std::fs::remove_dir_all(config.data_dir).unwrap();
    }

    #[test]
    fn env_overrides_file_value() {
        let mut env = HashMap::new();
        env.insert(ENV_LOG_LEVEL.to_string(), "debug".to_string());

        let config = load_from_sources(
            CliOverrides::default(),
            &env,
            Some("log_level = \"warn\"\n"),
        )
        .unwrap();

        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn cli_overrides_env_and_file_value() {
        let mut env = HashMap::new();
        env.insert(ENV_LOG_LEVEL.to_string(), "debug".to_string());
        let overrides = CliOverrides {
            log_level: Some("trace".to_string()),
            ..Default::default()
        };

        let config = load_from_sources(overrides, &env, Some("log_level = \"warn\"\n")).unwrap();

        assert_eq!(config.log_level, "trace");
    }

    #[test]
    fn malformed_file_returns_typed_error() {
        let result = load_from_sources(
            CliOverrides::default(),
            &HashMap::new(),
            Some("log_level = ["),
        );

        assert_eq!(result, Err(ConfigError::InvalidConfigFile));
    }

    #[test]
    fn file_values_override_defaults() {
        let file = r#"
log_level = "debug"
core_bridge_endpoint = "http://127.0.0.1:4444/mcp"
transport_mode = "mock"
"#;

        let config = load_from_sources(CliOverrides::default(), &HashMap::new(), Some(file))
            .expect("valid config file");

        assert_eq!(config.log_level, "debug");
        assert_eq!(
            config.core_bridge_endpoint.as_str(),
            "http://127.0.0.1:4444/mcp"
        );
        assert_eq!(config.transport_mode, TransportMode::Mock);
    }

    #[test]
    fn authorization_ttl_file_values_override_defaults() {
        let config = load_from_sources(
            CliOverrides::default(),
            &HashMap::new(),
            Some(VALID_AUTHORIZATION_TTL_CONFIG),
        )
        .expect("valid authorization TTL policy");

        let inspect = config
            .authorization_ttl
            .profile(&CapabilityProfile::Inspect);
        assert_eq!(inspect.max_minutes(), 241);
        assert_eq!(inspect.risk(), RiskLevel::Low);
        assert_eq!(config.authorization_ttl.risk_ceiling(RiskLevel::Normal), 45);
    }

    #[test]
    fn authorization_ttl_accepts_inclusive_ceiling_boundaries() {
        for valid in [1, MAX_AUTHORIZATION_TTL_MINUTES] {
            let file = VALID_AUTHORIZATION_TTL_CONFIG
                .replace("max_minutes = 241", &format!("max_minutes = {valid}"));
            let config = load_from_sources(CliOverrides::default(), &HashMap::new(), Some(&file))
                .expect("inclusive TTL boundary is valid");
            assert_eq!(
                config
                    .authorization_ttl
                    .profile(&CapabilityProfile::Inspect)
                    .max_minutes(),
                valid
            );
        }
    }

    #[test]
    fn partial_authorization_ttl_policy_fails_closed() {
        let result = load_from_sources(
            CliOverrides::default(),
            &HashMap::new(),
            Some("[authorization_ttl]\nlow_risk_max_minutes = 30\n"),
        );

        assert_eq!(result, Err(ConfigError::InvalidConfigFile));
    }

    #[test]
    fn invalid_authorization_ttl_boundaries_and_risk_fail_closed() {
        for invalid in ["0", "-1", "9223372036854775807"] {
            let file = VALID_AUTHORIZATION_TTL_CONFIG
                .replace("max_minutes = 241", &format!("max_minutes = {invalid}"));
            assert!(
                matches!(
                    load_from_sources(CliOverrides::default(), &HashMap::new(), Some(&file)),
                    Err(ConfigError::InvalidAuthorizationTtlPolicy(_))
                ),
                "ceiling {invalid} must fail closed"
            );
        }

        let unknown_risk = VALID_AUTHORIZATION_TTL_CONFIG
            .replace("risk = \"critical\"", "risk = \"catastrophic\"");
        assert!(matches!(
            load_from_sources(
                CliOverrides::default(),
                &HashMap::new(),
                Some(&unknown_risk)
            ),
            Err(ConfigError::InvalidAuthorizationTtlPolicy(_))
        ));
    }

    #[test]
    fn unknown_authorization_ttl_keys_fail_instead_of_silently_defaulting() {
        let result = load_from_sources(
            CliOverrides::default(),
            &HashMap::new(),
            Some("authorization_ttl_typo = 30\n"),
        );
        assert_eq!(result, Err(ConfigError::InvalidConfigFile));

        let unknown_nested_key = VALID_AUTHORIZATION_TTL_CONFIG.replace(
            "critical_risk_max_minutes = 1",
            "critical_risk_max_minutes_typo = 1",
        );
        assert_eq!(
            load_from_sources(
                CliOverrides::default(),
                &HashMap::new(),
                Some(&unknown_nested_key)
            ),
            Err(ConfigError::InvalidConfigFile)
        );
    }

    #[test]
    fn error_codes_are_stable_and_not_retryable() {
        let endpoint = ConfigError::InvalidEndpoint("x".into());
        assert_eq!(endpoint.code(), "CONFIG_INVALID_ENDPOINT");
        assert!(!endpoint.retryable());

        assert_eq!(ConfigError::InvalidConfigFile.code(), "CONFIG_INVALID_FILE");
        let ttl = ConfigError::InvalidAuthorizationTtlPolicy("zero".into());
        assert_eq!(ttl.code(), "CONFIG_INVALID_AUTHORIZATION_TTL_POLICY");
        assert!(!ttl.retryable());
        let read = ConfigError::ConfigFileRead {
            path: PathBuf::from("config.toml"),
            message: "denied".to_string(),
        };
        assert_eq!(read.code(), "CONFIG_FILE_READ_FAILED");
        assert!(!read.retryable());
    }
}
