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

use crate::error::CompanionError;

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
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid core bridge endpoint url: {0}")]
    InvalidEndpoint(String),
    #[error("invalid transport mode: {0}")]
    InvalidTransportMode(String),
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
const ENV_DATA_DIR: &str = "COMPANION_DATA_DIR";
const ENV_LOG_LEVEL: &str = "COMPANION_LOG_LEVEL";
const ENV_CORE_BRIDGE_ENDPOINT: &str = "COMPANION_CORE_BRIDGE_ENDPOINT";
const ENV_TRANSPORT_MODE: &str = "COMPANION_TRANSPORT_MODE";

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
struct FileConfig {
    log_level: Option<String>,
    core_bridge_endpoint: Option<String>,
    transport_mode: Option<String>,
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

    Ok(CompanionConfig {
        data_dir,
        log_level,
        core_bridge_endpoint,
        transport_mode,
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
        .join("kicad-mcp-companion")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_nothing_is_set() {
        let config = load_from(CliOverrides::default(), &HashMap::new()).unwrap();
        assert_eq!(config.log_level, "info");
        assert_eq!(
            config.core_bridge_endpoint.as_str(),
            "http://127.0.0.1:3334/mcp"
        );
        assert_eq!(config.transport_mode, TransportMode::Disabled);
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
            "companion-config-missing-{}-{}",
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
            "companion-config-test-{}-{}",
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
    fn error_codes_are_stable_and_not_retryable() {
        let endpoint = ConfigError::InvalidEndpoint("x".into());
        assert_eq!(endpoint.code(), "CONFIG_INVALID_ENDPOINT");
        assert!(!endpoint.retryable());

        assert_eq!(ConfigError::InvalidConfigFile.code(), "CONFIG_INVALID_FILE");
        let read = ConfigError::ConfigFileRead {
            path: PathBuf::from("config.toml"),
            message: "denied".to_string(),
        };
        assert_eq!(read.code(), "CONFIG_FILE_READ_FAILED");
        assert!(!read.retryable());
    }
}
