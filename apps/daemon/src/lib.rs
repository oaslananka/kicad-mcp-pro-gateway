//! The Gateway daemon: the single authoritative local runtime. See
//! `docs/architecture/component-boundaries.md`.

pub mod errors;
pub mod handlers;
pub mod identity_backend;
pub mod ipc_server;
pub mod remote_processor;
pub mod state;
pub mod tool_reconciliation;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use companion_audit::AuditRepository;
use companion_core::{CompanionConfig, SystemClock, TransportMode, TransportState};
use companion_core_bridge::{CoreBridgeClient, CoreBridgeConfig};
use companion_identity::{SecretStore, SqliteDeviceIdentityStore};
use companion_policy::{AuthorizationTtlPolicy, PolicyEngine, TomlToolRegistry};
use companion_sessions::TransportConnectivityEvent;
use companion_sessions::{migrate_legacy_sessions, AuthorizationRepository, SessionRepository};
use companion_storage::Storage;
use companion_transport::{jittered_delay, BackoffPolicy, MockTransport, Transport};
use companion_workspace::WorkspaceRepository;

use crate::state::{DaemonState, ShutdownSignal};

const CORE_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Builds daemon state in the documented startup order: storage, identity,
/// then the repositories/engines that depend on storage. Returns the state
/// and the socket/pipe name ready for [`ipc_server::run_ipc_server`].
pub fn build_state(config: &CompanionConfig) -> anyhow::Result<Arc<DaemonState>> {
    std::fs::create_dir_all(&config.data_dir)?;
    let storage = Arc::new(Storage::open(&config.data_dir)?);
    let identity_store =
        identity_backend::build_identity_store(Arc::clone(&storage), &config.data_dir)?;
    build_state_from_parts(config, storage, identity_store)
}

/// Builds daemon state with an explicitly supplied secret-store backend.
///
/// This exists so integration tests and embedders can provide a controlled
/// backend without weakening the production binary's platform-specific
/// secure-storage policy. `run()` never calls this function.
pub fn build_state_with_secret_store<S>(
    config: &CompanionConfig,
    secret_store: S,
) -> anyhow::Result<Arc<DaemonState>>
where
    S: SecretStore + 'static,
{
    std::fs::create_dir_all(&config.data_dir)?;
    let storage = Arc::new(Storage::open(&config.data_dir)?);
    let identity_store = Arc::new(SqliteDeviceIdentityStore::new(
        Arc::clone(&storage),
        secret_store,
    ));
    build_state_from_parts(config, storage, identity_store)
}

fn build_state_from_parts(
    config: &CompanionConfig,
    storage: Arc<Storage>,
    identity_store: Arc<dyn companion_identity::DeviceIdentityStore + Send + Sync>,
) -> anyhow::Result<Arc<DaemonState>> {
    let workspace_repo = Arc::new(WorkspaceRepository::new(Arc::clone(&storage)));
    let session_repo = Arc::new(SessionRepository::new(Arc::clone(&storage)));
    let authorization_repo = Arc::new(AuthorizationRepository::new(Arc::clone(&storage)));
    // Additive, fail-closed, idempotent: transport-era `sessions` rows that
    // carried authority become explicit grants before anything is served, so
    // an upgraded daemon never has to fall back to reading a legacy row as
    // authority. Revocations and expiries migrate as revocations and
    // expiries.
    let migration = migrate_legacy_sessions(&session_repo, &authorization_repo)
        .map_err(|error| anyhow::anyhow!("authorization migration failed: {error}"))?;
    if migration.grants_written > 0
        || migration.rows_without_authority > 0
        || !migration.refused_session_ids.is_empty()
    {
        tracing::info!(
            grants_written = migration.grants_written,
            grants_already_present = migration.grants_already_present,
            rows_without_authority = migration.rows_without_authority,
            refused_legacy_rows = migration.refused_session_ids.len(),
            "transport-era session rows mapped onto explicit authorization grants"
        );
    }
    for refused in &migration.refused_session_ids {
        tracing::error!(
            session = %refused,
            "legacy session row could not be interpreted as authorization; it carries no authority"
        );
    }
    let policy_engine = Arc::new(PolicyEngine::with_authorization_ttl_policy(
        TomlToolRegistry::try_embedded()?,
        AuthorizationTtlPolicy::new(config.authorization_ttl),
    ));
    let audit_repo = Arc::new(AuditRepository::new(Arc::clone(&storage)));
    let core_bridge = Arc::new(CoreBridgeClient::new(CoreBridgeConfig::new(
        config.core_bridge_endpoint.clone(),
    ))?);
    let mut core_health_probe_config = CoreBridgeConfig::new(config.core_bridge_endpoint.clone());
    core_health_probe_config.timeout = CORE_HEALTH_PROBE_TIMEOUT;

    Ok(Arc::new(DaemonState {
        instance_id: ulid::Ulid::new().to_string(),
        storage,
        identity_store,
        workspace_repo,
        session_repo,
        authorization_repo,
        policy_engine,
        audit_repo,
        core_bridge,
        core_health_probe_config,
        clock: Arc::new(SystemClock),
        shutdown: Arc::new(ShutdownSignal::new()),
        transport: std::sync::Mutex::new(None),
        transport_state: std::sync::Mutex::new(TransportState::Disconnected),
        pending_operations: std::sync::Mutex::new(HashMap::new()),
    }))
}

fn transport_for_mode(mode: TransportMode) -> Option<Arc<dyn Transport>> {
    match mode {
        TransportMode::Disabled => None,
        TransportMode::Mock => Some(Arc::new(MockTransport::new())),
    }
}

/// Owns the daemon's local IPC lifetime together with an optional outbound
/// transport. A missing transport is a supported local-only mode.
pub async fn run_runtime(
    state: Arc<DaemonState>,
    data_dir: std::path::PathBuf,
    transport: Option<Arc<dyn Transport>>,
) -> anyhow::Result<()> {
    let Some(transport) = transport else {
        return ipc_server::run_ipc_server(state, data_dir).await;
    };

    let ipc = ipc_server::run_ipc_server(Arc::clone(&state), data_dir);
    let remote = run_transport_lifecycle(Arc::clone(&state), transport);
    tokio::try_join!(ipc, remote)?;
    Ok(())
}

async fn run_transport_lifecycle(
    state: Arc<DaemonState>,
    transport: Arc<dyn Transport>,
) -> anyhow::Result<()> {
    let backoff = BackoffPolicy::default();
    let mut failure_attempt = 0u32;

    loop {
        let connect_result = tokio::select! {
            _ = state.shutdown.cancelled() => break,
            result = transport.connect() => result,
        };
        if connect_result.is_ok() {
            tracing::debug!(transport_state = ?state.transport_state(), "outbound transport connected");
        }

        match connect_result {
            Ok(()) => {
                failure_attempt = 0;
                // Connectivity only. Nothing here reads, writes, extends, or
                // resurrects an access grant: a reconnect changes the pipe,
                // never the authority that outlives it.
                state.record_transport_event(TransportConnectivityEvent::Connected);
                let processor_result = remote_processor::run_remote_processor(
                    Arc::clone(&state),
                    Arc::clone(&transport),
                )
                .await;
                if let Err(error) = processor_result {
                    tracing::warn!(error = %error, "outbound transport receive failed; reconnecting");
                }
                *state.transport.lock().expect("transport mutex poisoned") = None;
                if let Err(error) = transport.disconnect().await {
                    tracing::warn!(error = %error, "outbound transport disconnect failed");
                }
                state.record_transport_event(TransportConnectivityEvent::Disconnected);
                if state.shutdown.is_requested() {
                    break;
                }
                state.record_transport_event(TransportConnectivityEvent::Reconnecting);
            }
            Err(error) => {
                state.record_transport_event(TransportConnectivityEvent::ConnectFailed);
                tracing::warn!(error = %error, "outbound transport connect failed; retrying");
            }
        }

        let delay = jittered_delay(backoff.delay_for_attempt(failure_attempt), failure_attempt);
        failure_attempt = failure_attempt.saturating_add(1);
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            _ = tokio::time::sleep(delay) => {}
        }
    }

    *state.transport.lock().expect("transport mutex poisoned") = None;
    Ok(())
}

/// Runs the daemon until shutdown is requested (via `DaemonShutdown` IPC
/// request or Ctrl-C). A single-instance conflict on `config.data_dir`
/// surfaces as an error from [`build_state`] before anything else starts.
pub async fn run(config: CompanionConfig) -> anyhow::Result<()> {
    let state = build_state(&config)?;
    tracing::info!(
        instance_id = %state.instance_id,
        data_dir = %config.data_dir.display(),
        "daemon starting"
    );

    let transport = transport_for_mode(config.transport_mode);
    match config.transport_mode {
        TransportMode::Disabled => {
            tracing::info!("outbound relay transport disabled; local IPC remains available");
        }
        TransportMode::Mock => {
            tracing::warn!(
                "explicit development mock transport enabled; no production relay is configured"
            );
        }
    }

    let shutdown = Arc::clone(&state.shutdown);
    let runtime = run_runtime(Arc::clone(&state), config.data_dir.clone(), transport);
    tokio::pin!(runtime);

    tokio::select! {
        result = &mut runtime => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            tracing::info!("received ctrl-c, shutting down");
            shutdown.request();
            runtime.await
        }
    }
}

#[cfg(test)]
mod runtime_mode_tests {
    use companion_core::TransportMode;

    use super::*;

    #[test]
    fn disabled_transport_mode_builds_no_outbound_transport() {
        assert!(transport_for_mode(TransportMode::Disabled).is_none());
    }

    #[test]
    fn explicit_mock_transport_mode_builds_a_disconnected_mock_transport() {
        let transport = transport_for_mode(TransportMode::Mock)
            .expect("explicit mock mode should build a development transport");
        assert_eq!(
            transport.state(),
            companion_core::TransportState::Disconnected
        );
    }
}
