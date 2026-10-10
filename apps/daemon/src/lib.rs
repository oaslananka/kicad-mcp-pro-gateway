//! The Gateway daemon: the single authoritative local runtime. See
//! `docs/architecture/component-boundaries.md`.

pub mod cloud_pairing_status;
pub mod errors;
pub mod handlers;
pub mod identity_backend;
pub mod ipc_server;
pub mod relay_transport;
pub mod remote_processor;
pub mod state;
pub mod tool_reconciliation;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use companion_audit::AuditRepository;
use companion_checkpoints::FilesystemCheckpointStore;
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
    // One line per refused row, without the row's identity: `refused` is
    // "<session id>: <reason>", and a session id is a capability identifier
    // that must not become a log line. The rows themselves are still listed
    // verbatim in the startup migration report and stay in `sessions`.
    for refused in &migration.refused_session_ids {
        let reason = refused
            .split_once(": ")
            .map(|(_, reason)| reason)
            .unwrap_or("unclassified");
        tracing::error!(
            reason,
            "legacy session row could not be interpreted as authorization; it carries no authority"
        );
    }
    let policy_engine = Arc::new(PolicyEngine::with_authorization_ttl_policy(
        TomlToolRegistry::try_embedded()?,
        AuthorizationTtlPolicy::new(config.authorization_ttl),
    ));
    let audit_repo = Arc::new(AuditRepository::new(Arc::clone(&storage)));
    let checkpoint_store = Arc::new(FilesystemCheckpointStore::new(
        Arc::clone(&storage),
        config.data_dir.join("checkpoints"),
    ));
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
        checkpoint_store,
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
        TransportMode::Relay => None, // constructed with device identity below
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

/// One checkpoint row that cannot be used to restore, and why.
#[derive(Debug)]
pub struct UnusableSnapshot {
    pub checkpoint_id: companion_core::CheckpointId,
    pub workspace_id: companion_core::WorkspaceId,
    pub reason: String,
}

/// What startup found when it read the persisted audit and checkpoint state.
#[derive(Debug, Default)]
pub struct RecoveryIntegrity {
    /// Operations whose audit row records an authorization but no execution
    /// outcome — the signature of a process that died between the two writes.
    ///
    /// Reported, not fatal: nothing reconciles these rows yet, so refusing to
    /// start would wedge the daemon permanently after a single crash. Startup
    /// must not call that a clean recovery either, so it is logged loudly and
    /// the count is returned for an operator-visible degraded state.
    pub incomplete_operations: usize,
    /// Checkpoint rows a restore would refuse. Fatal — see
    /// [`check_recovery_integrity`].
    pub unusable_snapshots: Vec<UnusableSnapshot>,
}

/// Reads the persisted recovery state and fails closed.
///
/// An unreadable audit or checkpoint store returns an error rather than
/// degrading to a log line: the daemon must never start and behave as though
/// recovery were verified when it was not. Callers treat that error as fatal.
///
/// The caller decides what to do with a successfully-read-but-unusable result;
/// [`run`] refuses to start on it.
pub fn check_recovery_integrity(state: &DaemonState) -> anyhow::Result<RecoveryIntegrity> {
    let incomplete_operations = state
        .audit_repo
        .list_incomplete()
        .map_err(|error| anyhow::anyhow!("cannot read audit state for recovery check: {error}"))?
        .len();
    let unusable_snapshots = state
        .checkpoint_store
        .unusable_snapshots()
        .map_err(|error| {
            anyhow::anyhow!("cannot read checkpoint state for recovery check: {error}")
        })?
        .into_iter()
        .map(|(checkpoint_id, workspace_id, reason)| UnusableSnapshot {
            checkpoint_id,
            workspace_id,
            reason: reason.to_string(),
        })
        .collect();
    Ok(RecoveryIntegrity {
        incomplete_operations,
        unusable_snapshots,
    })
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

    let integrity = check_recovery_integrity(&state).inspect_err(|error| {
        tracing::error!(
            %error,
            "recovery state could not be read; refusing to start"
        );
    })?;

    if !integrity.unusable_snapshots.is_empty() {
        for unusable in &integrity.unusable_snapshots {
            tracing::error!(
                checkpoint_id = %unusable.checkpoint_id,
                workspace_id = %unusable.workspace_id,
                reason = %unusable.reason,
                "checkpoint snapshot cannot be used for recovery"
            );
        }
        anyhow::bail!(
            "refusing to start: {} checkpoint snapshot(s) cannot be used for recovery",
            integrity.unusable_snapshots.len()
        );
    }

    if integrity.incomplete_operations > 0 {
        tracing::warn!(
            count = integrity.incomplete_operations,
            "operations were left without an execution outcome by an earlier run; \
             they stay in the audit trail unreconciled and this is a degraded recovery state"
        );
    }

    let transport: Option<Arc<dyn Transport>> = match config.transport_mode {
        TransportMode::Relay => Some(Arc::new(relay_transport::RelayTransport::new(
            config
                .relay_url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("relay_url missing"))?,
            Arc::clone(&state.identity_store),
        ))),
        other => transport_for_mode(other),
    };
    match config.transport_mode {
        TransportMode::Disabled => {
            tracing::info!("outbound relay transport disabled; local IPC remains available");
        }
        TransportMode::Mock => {
            tracing::warn!(
                "explicit development mock transport enabled; no production relay is configured"
            );
        }
        TransportMode::Relay => {
            tracing::info!("authenticated cloud heartbeat transport enabled; remote operations remain disabled");
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
mod recovery_integrity_tests {
    use companion_core::{
        AuditEvent, Capability, ExecutionStatus, OperationId, PolicyResultKind, RiskLevel,
    };
    use companion_identity::InMemorySecretStore;
    use companion_workspace::WorkspaceAuthorization;
    use time::OffsetDateTime;

    use super::*;

    fn state(data_dir: &std::path::Path) -> Arc<DaemonState> {
        let config = companion_core::config::load(companion_core::config::CliOverrides {
            data_dir: Some(data_dir.to_path_buf()),
            core_bridge_endpoint: Some("http://127.0.0.1:1/mcp".into()),
            ..Default::default()
        })
        .unwrap();
        build_state_with_secret_store(&config, InMemorySecretStore::new()).unwrap()
    }

    fn allowed_but_unexecuted_event() -> AuditEvent {
        AuditEvent {
            operation_id: OperationId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id: None,
            workspace_id: None,
            remote_principal: None,
            principal_assurance: companion_core::PrincipalAssurance::Unverified,
            verified_principal_issuer: None,
            verified_principal_subject: None,
            principal_verification_source: None,
            authentication_strength: None,
            requested_tool: "schematic.read".into(),
            capability: Some(Capability::SCHEMATIC_READ),
            risk: Some(RiskLevel::Low),
            risk_policy_version: None,
            base_risk: None,
            risk_factors: vec![],
            policy_result: PolicyResultKind::Allow,
            approval_decision: None,
            execution_status: ExecutionStatus::NotExecuted,
            error_class: None,
            duration_ms: None,
        }
    }

    #[test]
    fn a_fresh_data_dir_reports_a_clean_recovery_state() {
        let dir = tempfile::tempdir().unwrap();

        let integrity = check_recovery_integrity(&state(dir.path())).unwrap();

        assert_eq!(integrity.incomplete_operations, 0);
        assert!(integrity.unusable_snapshots.is_empty());
    }

    #[test]
    fn an_operation_left_without_an_execution_outcome_is_counted_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        state
            .audit_repo
            .record(&allowed_but_unexecuted_event())
            .unwrap();

        let integrity = check_recovery_integrity(&state).unwrap();

        assert_eq!(integrity.incomplete_operations, 1);
        assert!(
            integrity.unusable_snapshots.is_empty(),
            "an incomplete audit row is degraded, not an unusable checkpoint"
        );
    }

    #[test]
    fn an_unreadable_audit_store_is_an_error_rather_than_a_degraded_pass() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        // A store that cannot answer "is recovery verified?" must never be
        // reported as verified.
        let conn = state.storage.connection();
        conn.lock()
            .unwrap()
            .execute_batch("DROP TABLE audit_events")
            .unwrap();

        let error = check_recovery_integrity(&state).unwrap_err();

        assert!(
            error.to_string().contains("cannot read audit state"),
            "got {error}"
        );
    }

    #[test]
    fn an_unreadable_checkpoint_store_is_an_error_rather_than_a_degraded_pass() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let conn = state.storage.connection();
        conn.lock()
            .unwrap()
            .execute_batch("DROP TABLE checkpoints")
            .unwrap();

        let error = check_recovery_integrity(&state).unwrap_err();

        assert!(
            error.to_string().contains("cannot read checkpoint state"),
            "got {error}"
        );
    }

    /// Creates a real checkpoint row and then removes its snapshot data,
    /// standing in for a snapshot that did not survive a crash or a prune.
    fn checkpoint_with_missing_snapshot(
        state: &DaemonState,
    ) -> companion_checkpoints::CheckpointMetadata {
        let workspace_dir = tempfile::tempdir().unwrap();
        std::fs::write(workspace_dir.path().join("board.kicad_pcb"), "v1").unwrap();
        let workspace = WorkspaceAuthorization::new("proj".into(), workspace_dir.path()).unwrap();
        let metadata = state
            .checkpoint_store
            .create(&workspace, None, None)
            .unwrap();
        std::fs::remove_dir_all(&metadata.root_snapshot_path).unwrap();
        metadata
    }

    #[test]
    fn a_checkpoint_whose_snapshot_is_gone_is_reported_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let metadata = checkpoint_with_missing_snapshot(&state);

        let integrity = check_recovery_integrity(&state).unwrap();

        assert_eq!(integrity.unusable_snapshots.len(), 1);
        assert_eq!(
            integrity.unusable_snapshots[0].checkpoint_id,
            metadata.checkpoint_id
        );
        assert!(integrity.unusable_snapshots[0].reason.contains("missing"));
    }

    #[test]
    fn a_checkpoint_with_an_absolute_snapshot_path_is_usable() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let workspace_dir = tempfile::tempdir().unwrap();
        std::fs::write(workspace_dir.path().join("board.kicad_pcb"), "v1").unwrap();
        let workspace = WorkspaceAuthorization::new("proj".into(), workspace_dir.path()).unwrap();
        state
            .checkpoint_store
            .create(&workspace, None, None)
            .unwrap();

        let integrity = check_recovery_integrity(&state).unwrap();

        assert!(integrity.unusable_snapshots.is_empty());
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
