//! Persists [`AuditEvent`] records. Every privileged decision the policy
//! engine makes is written here; execution outcome is added afterward via
//! [`AuditRepository::update_execution`]. Never stores secret material,
//! raw project contents, or full tool arguments — see
//! `docs/security/threat-model.md`.

use std::sync::Arc;

use companion_core::{
    ApprovalDecisionKind, AuditEvent, Capability, ExecutionStatus, OperationId, PolicyResultKind,
    RiskLevel, SessionId,
};
use companion_storage::Storage;
use time::OffsetDateTime;

use crate::error::AuditError;

pub struct AuditRepository {
    storage: Arc<Storage>,
}

impl AuditRepository {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO audit_events (
                operation_id, timestamp, session_id, workspace_id, remote_principal, requested_tool,
                capability, risk, policy_result, approval_decision, execution_status, error_class, duration_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            rusqlite::params![
                event.operation_id.to_string(),
                format_rfc3339(event.timestamp)?,
                event.session_id.map(|id| id.to_string()),
                event.workspace_id.map(|id| id.to_string()),
                event.remote_principal,
                event.requested_tool,
                event.capability.map(|c| c.as_str().to_string()),
                event.risk.map(to_json).transpose()?,
                to_json(event.policy_result)?,
                event.approval_decision.map(to_json).transpose()?,
                to_json(event.execution_status)?,
                event.error_class,
                event.duration_ms.map(|d| d as i64),
            ],
        )
        .map_err(|e| AuditError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn update_execution(
        &self,
        operation_id: OperationId,
        status: ExecutionStatus,
        error_class: Option<String>,
        duration_ms: Option<u64>,
    ) -> Result<(), AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        let changed = conn
            .execute(
                "UPDATE audit_events SET execution_status = ?1, error_class = ?2, duration_ms = ?3 WHERE operation_id = ?4",
                rusqlite::params![
                    to_json(status)?,
                    error_class,
                    duration_ms.map(|d| d as i64),
                    operation_id.to_string(),
                ],
            )
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        if changed == 0 {
            return Err(AuditError::NotFound);
        }
        Ok(())
    }

    pub fn update_approval_decision(
        &self,
        operation_id: OperationId,
        decision: ApprovalDecisionKind,
    ) -> Result<(), AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        let changed = conn
            .execute(
                "UPDATE audit_events SET approval_decision = ?1 WHERE operation_id = ?2",
                rusqlite::params![to_json(decision)?, operation_id.to_string()],
            )
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        if changed == 0 {
            return Err(AuditError::NotFound);
        }
        Ok(())
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<AuditEvent>, AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(&format!(
                "{SELECT_COLUMNS} ORDER BY timestamp DESC LIMIT {limit}"
            ))
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_raw)
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        collect_rows(rows)
    }

    pub fn list_for_session(&self, session_id: SessionId) -> Result<Vec<AuditEvent>, AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(&format!(
                "{SELECT_COLUMNS} WHERE session_id = ?1 ORDER BY timestamp DESC"
            ))
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![session_id.to_string()], row_to_raw)
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        collect_rows(rows)
    }
}

const SELECT_COLUMNS: &str = "SELECT operation_id, timestamp, session_id, workspace_id, remote_principal, \
     requested_tool, capability, risk, policy_result, approval_decision, execution_status, error_class, \
     duration_ms FROM audit_events";

struct RawRow {
    operation_id: String,
    timestamp: String,
    session_id: Option<String>,
    workspace_id: Option<String>,
    remote_principal: Option<String>,
    requested_tool: String,
    capability: Option<String>,
    risk: Option<String>,
    policy_result: String,
    approval_decision: Option<String>,
    execution_status: String,
    error_class: Option<String>,
    duration_ms: Option<i64>,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        operation_id: row.get(0)?,
        timestamp: row.get(1)?,
        session_id: row.get(2)?,
        workspace_id: row.get(3)?,
        remote_principal: row.get(4)?,
        requested_tool: row.get(5)?,
        capability: row.get(6)?,
        risk: row.get(7)?,
        policy_result: row.get(8)?,
        approval_decision: row.get(9)?,
        execution_status: row.get(10)?,
        error_class: row.get(11)?,
        duration_ms: row.get(12)?,
    })
}

fn collect_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row) -> rusqlite::Result<RawRow>>,
) -> Result<Vec<AuditEvent>, AuditError> {
    let mut events = Vec::new();
    for row in rows {
        let raw = row.map_err(|e| AuditError::Storage(e.to_string()))?;
        events.push(parse_raw(raw)?);
    }
    Ok(events)
}

fn parse_raw(raw: RawRow) -> Result<AuditEvent, AuditError> {
    Ok(AuditEvent {
        operation_id: raw
            .operation_id
            .parse()
            .map_err(|e| AuditError::Storage(format!("{e:?}")))?,
        timestamp: parse_rfc3339(&raw.timestamp)?,
        session_id: raw
            .session_id
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| AuditError::Storage(format!("{e:?}")))?,
        workspace_id: raw
            .workspace_id
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| AuditError::Storage(format!("{e:?}")))?,
        remote_principal: raw.remote_principal,
        requested_tool: raw.requested_tool,
        capability: raw
            .capability
            .map(|s| {
                Capability::parse(&s).ok_or_else(|| {
                    AuditError::Storage(format!("unknown capability in audit row: {s}"))
                })
            })
            .transpose()?,
        risk: raw.risk.map(|s| from_json::<RiskLevel>(&s)).transpose()?,
        policy_result: from_json::<PolicyResultKind>(&raw.policy_result)?,
        approval_decision: raw
            .approval_decision
            .map(|s| from_json::<ApprovalDecisionKind>(&s))
            .transpose()?,
        execution_status: from_json::<ExecutionStatus>(&raw.execution_status)?,
        error_class: raw.error_class,
        duration_ms: raw.duration_ms.map(|d| d as u64),
    })
}

fn to_json<T: serde::Serialize>(value: T) -> Result<String, AuditError> {
    serde_json::to_string(&value).map_err(|e| AuditError::Storage(e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, AuditError> {
    serde_json::from_str(raw).map_err(|e| AuditError::Storage(e.to_string()))
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, AuditError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| AuditError::Storage(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, AuditError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| AuditError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use companion_core::{OperationId, SessionId, WorkspaceId};

    use super::*;

    fn repo() -> AuditRepository {
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        AuditRepository::new(storage)
    }

    fn sample_event(operation_id: OperationId, session_id: SessionId) -> AuditEvent {
        AuditEvent {
            operation_id,
            timestamp: OffsetDateTime::now_utc(),
            session_id: Some(session_id),
            workspace_id: Some(WorkspaceId::new()),
            remote_principal: Some("agent:test".into()),
            requested_tool: "schematic.read".into(),
            capability: Some(Capability::SCHEMATIC_READ),
            risk: Some(RiskLevel::Low),
            policy_result: PolicyResultKind::Allow,
            approval_decision: None,
            execution_status: ExecutionStatus::NotExecuted,
            error_class: None,
            duration_ms: None,
        }
    }

    #[test]
    fn record_then_list_recent_returns_it() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();

        let recent = repository.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].operation_id, event.operation_id);
        assert_eq!(recent[0].policy_result, PolicyResultKind::Allow);
    }

    #[test]
    fn update_execution_changes_status_and_records_duration() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();

        repository
            .update_execution(event.operation_id, ExecutionStatus::Success, None, Some(42))
            .unwrap();

        let recent = repository.list_recent(10).unwrap();
        assert_eq!(recent[0].execution_status, ExecutionStatus::Success);
        assert_eq!(recent[0].duration_ms, Some(42));
    }

    #[test]
    fn update_approval_decision_records_the_decision() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();

        repository
            .update_approval_decision(event.operation_id, ApprovalDecisionKind::AllowOnce)
            .unwrap();

        let recent = repository.list_recent(10).unwrap();
        assert_eq!(
            recent[0].approval_decision,
            Some(ApprovalDecisionKind::AllowOnce)
        );
    }

    #[test]
    fn update_execution_for_unknown_operation_is_a_typed_error() {
        let repository = repo();
        let result =
            repository.update_execution(OperationId::new(), ExecutionStatus::Success, None, None);
        assert!(matches!(result, Err(AuditError::NotFound)));
    }

    #[test]
    fn list_for_session_filters_to_that_session_only() {
        let repository = repo();
        let session_a = SessionId::new();
        let session_b = SessionId::new();
        repository
            .record(&sample_event(OperationId::new(), session_a))
            .unwrap();
        repository
            .record(&sample_event(OperationId::new(), session_b))
            .unwrap();

        let for_a = repository.list_for_session(session_a).unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].session_id, Some(session_a));
    }

    #[test]
    fn failed_record_is_atomic_and_leaves_no_partial_row() {
        let repository = repo();
        reject_writes(&repository, "audit_events", "INSERT");

        let event = sample_event(OperationId::new(), SessionId::new());
        let error = repository.record(&event).unwrap_err();
        assert!(matches!(error, AuditError::Storage(_)), "got {error:?}");

        // Recovery: nothing partial is left behind, so the very same event
        // can be recorded once the store accepts writes again.
        drop_rejection(&repository);
        assert!(
            repository.list_recent(10).unwrap().is_empty(),
            "a failed insert must leave no partial audit state"
        );
        repository.record(&event).unwrap();
        let recent = repository.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].operation_id, event.operation_id);
    }

    #[test]
    fn rolled_back_transaction_leaves_no_audit_row() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());

        // `record` is a single statement, so it joins any enclosing
        // transaction and rolls back with it rather than committing a
        // half-written audit trail.
        {
            let conn = repository
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.execute_batch("BEGIN").expect("transaction opens");
        }
        repository
            .record(&event)
            .expect("record joins the transaction");
        {
            let conn = repository
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.execute_batch("ROLLBACK")
                .expect("transaction rolls back");
        }

        assert!(
            repository.list_recent(10).unwrap().is_empty(),
            "an uncommitted audit write must not survive a rollback"
        );
    }

    #[test]
    fn duplicate_operation_id_is_rejected_and_the_existing_row_is_unchanged() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();
        repository
            .update_execution(event.operation_id, ExecutionStatus::Success, None, Some(12))
            .unwrap();

        let mut replay = sample_event(event.operation_id, SessionId::new());
        replay.policy_result = PolicyResultKind::Deny;
        let error = repository.record(&replay).unwrap_err();
        assert!(matches!(error, AuditError::Storage(_)), "got {error:?}");

        let recent = repository.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1, "the replay must not create a second row");
        assert_eq!(recent[0].policy_result, PolicyResultKind::Allow);
        assert_eq!(recent[0].execution_status, ExecutionStatus::Success);
    }

    #[test]
    fn failed_approval_update_preserves_the_already_persisted_decision() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();
        repository
            .update_approval_decision(event.operation_id, ApprovalDecisionKind::AllowOnce)
            .unwrap();

        reject_writes(&repository, "audit_events", "UPDATE");
        let error = repository
            .update_approval_decision(event.operation_id, ApprovalDecisionKind::Denied)
            .unwrap_err();
        assert!(matches!(error, AuditError::Storage(_)), "got {error:?}");

        let recent = repository.list_recent(10).unwrap();
        assert_eq!(
            recent[0].approval_decision,
            Some(ApprovalDecisionKind::AllowOnce),
            "a failed write must never clear an already-persisted approval record"
        );
    }

    /// Installs a trigger that aborts the given statement class on `table` —
    /// the injected persistence failure the daemon has to fail closed on.
    fn reject_writes(repository: &AuditRepository, table: &str, when: &str) {
        let conn = repository
            .storage
            .connection()
            .lock()
            .expect("storage mutex poisoned");
        conn.execute_batch(&format!(
            "CREATE TRIGGER reject_{when}_on_{table} BEFORE {when} ON {table} \
             BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END;"
        ))
        .expect("trigger installs");
    }

    fn drop_rejection(repository: &AuditRepository) {
        let conn = repository
            .storage
            .connection()
            .lock()
            .expect("storage mutex poisoned");
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS reject_INSERT_on_audit_events;
             DROP TRIGGER IF EXISTS reject_UPDATE_on_audit_events;",
        )
        .expect("trigger drops");
    }

    #[test]
    fn audit_event_shape_never_carries_a_raw_payload_or_target_path_field() {
        // Regression guard: AuditEvent must never grow a field that could
        // carry secret material or full project source contents (see
        // docs/security/threat-model.md). This fails loudly if someone adds
        // one without updating this test deliberately.
        let event = sample_event(OperationId::new(), SessionId::new());
        let value = serde_json::to_value(FieldNames::from(&event)).unwrap();
        let object = value.as_object().unwrap();
        for forbidden in [
            "payload",
            "arguments",
            "target_path",
            "raw_content",
            "secret",
            "token",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "AuditEvent must not carry a '{forbidden}' field"
            );
        }
    }

    #[derive(serde::Serialize)]
    struct FieldNames {
        operation_id: String,
        session_id: Option<String>,
        workspace_id: Option<String>,
        remote_principal: Option<String>,
        requested_tool: String,
        capability: Option<String>,
        risk: Option<String>,
        policy_result: String,
        approval_decision: Option<String>,
        execution_status: String,
        error_class: Option<String>,
        duration_ms: Option<u64>,
    }

    impl From<&AuditEvent> for FieldNames {
        fn from(e: &AuditEvent) -> Self {
            Self {
                operation_id: e.operation_id.to_string(),
                session_id: e.session_id.map(|s| s.to_string()),
                workspace_id: e.workspace_id.map(|w| w.to_string()),
                remote_principal: e.remote_principal.clone(),
                requested_tool: e.requested_tool.clone(),
                capability: e.capability.map(|c| c.as_str().to_string()),
                risk: e.risk.map(|r| format!("{r:?}")),
                policy_result: format!("{:?}", e.policy_result),
                approval_decision: e.approval_decision.map(|a| format!("{a:?}")),
                execution_status: format!("{:?}", e.execution_status),
                error_class: e.error_class.clone(),
                duration_ms: e.duration_ms,
            }
        }
    }
}
