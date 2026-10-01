//! Persists [`AuditEvent`] records. Every privileged decision the policy
//! engine makes is written here; execution outcome is added afterward via
//! [`AuditRepository::update_execution`]. Never stores secret material,
//! raw project contents, or full tool arguments — see
//! `docs/security/threat-model.md`.

use std::sync::Arc;

use companion_core::{
    ApprovalDecisionKind, AuditEvent, Capability, ExecutionStatus, OperationId, PolicyResultKind,
    PrincipalAssurance, PrincipalVerificationSource, RiskFactor, RiskLevel, SessionId,
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
        if !event.has_consistent_principal_evidence() {
            return Err(AuditError::Storage(
                "inconsistent audit principal verification evidence".into(),
            ));
        }
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO audit_events (
                operation_id, timestamp, session_id, workspace_id, remote_principal,
                principal_assurance, verified_principal_issuer, verified_principal_subject,
                principal_verification_source, authentication_strength, requested_tool,
                capability, risk, risk_policy_version, base_risk, risk_factors_json,
                policy_result, approval_decision, execution_status, error_class, duration_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            rusqlite::params![
                event.operation_id.to_string(),
                format_rfc3339(event.timestamp)?,
                event.session_id.map(|id| id.to_string()),
                event.workspace_id.map(|id| id.to_string()),
                event.remote_principal,
                event.principal_assurance.as_str(),
                event.verified_principal_issuer,
                event.verified_principal_subject,
                event
                    .principal_verification_source
                    .map(|source| source.as_str().to_string()),
                event.authentication_strength,
                event.requested_tool,
                event.capability.map(|c| c.as_str().to_string()),
                event.risk.map(to_json).transpose()?,
                event.risk_policy_version.map(i64::from),
                event.base_risk.map(to_json).transpose()?,
                to_json(&event.risk_factors)?,
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

    /// Operations whose audit row records an authorization but no execution
    /// outcome.
    ///
    /// [`ExecutionStatus`] is only written by [`Self::update_execution`] after
    /// the operation finishes, so `NotExecuted` on an `Allow` row is precisely
    /// the signature of a process that died between the two writes. There is
    /// no in-progress status to also match.
    pub fn list_incomplete(&self) -> Result<Vec<AuditEvent>, AuditError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| AuditError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(&format!(
                "{SELECT_COLUMNS} WHERE policy_result = ?1 AND execution_status = ?2"
            ))
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    to_json(PolicyResultKind::Allow)?,
                    to_json(ExecutionStatus::NotExecuted)?
                ],
                row_to_raw,
            )
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        collect_rows(rows)
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
     principal_assurance, verified_principal_issuer, verified_principal_subject, principal_verification_source, \
     authentication_strength, requested_tool, capability, risk, risk_policy_version, base_risk, risk_factors_json, \
     policy_result, approval_decision, execution_status, error_class, duration_ms FROM audit_events";

struct RawRow {
    operation_id: String,
    timestamp: String,
    session_id: Option<String>,
    workspace_id: Option<String>,
    remote_principal: Option<String>,
    principal_assurance: String,
    verified_principal_issuer: Option<String>,
    verified_principal_subject: Option<String>,
    principal_verification_source: Option<String>,
    authentication_strength: Option<String>,
    requested_tool: String,
    capability: Option<String>,
    risk: Option<String>,
    risk_policy_version: Option<i64>,
    base_risk: Option<String>,
    risk_factors_json: String,
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
        principal_assurance: row.get(5)?,
        verified_principal_issuer: row.get(6)?,
        verified_principal_subject: row.get(7)?,
        principal_verification_source: row.get(8)?,
        authentication_strength: row.get(9)?,
        requested_tool: row.get(10)?,
        capability: row.get(11)?,
        risk: row.get(12)?,
        risk_policy_version: row.get(13)?,
        base_risk: row.get(14)?,
        risk_factors_json: row.get(15)?,
        policy_result: row.get(16)?,
        approval_decision: row.get(17)?,
        execution_status: row.get(18)?,
        error_class: row.get(19)?,
        duration_ms: row.get(20)?,
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
    let event = AuditEvent {
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
        principal_assurance: PrincipalAssurance::parse(&raw.principal_assurance).ok_or_else(
            || {
                AuditError::Storage(format!(
                    "unknown principal assurance in audit row: {}",
                    raw.principal_assurance
                ))
            },
        )?,
        verified_principal_issuer: raw.verified_principal_issuer,
        verified_principal_subject: raw.verified_principal_subject,
        principal_verification_source: raw
            .principal_verification_source
            .map(|source| {
                PrincipalVerificationSource::parse(&source).ok_or_else(|| {
                    AuditError::Storage(format!(
                        "unknown principal verification source in audit row: {source}"
                    ))
                })
            })
            .transpose()?,
        authentication_strength: raw.authentication_strength,
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
        risk_policy_version: raw
            .risk_policy_version
            .map(|version| {
                u32::try_from(version).map_err(|_| {
                    AuditError::Storage(format!(
                        "invalid risk policy version in audit row: {version}"
                    ))
                })
            })
            .transpose()?,
        base_risk: raw
            .base_risk
            .map(|s| from_json::<RiskLevel>(&s))
            .transpose()?,
        risk_factors: from_json::<Vec<RiskFactor>>(&raw.risk_factors_json)?,
        policy_result: from_json::<PolicyResultKind>(&raw.policy_result)?,
        approval_decision: raw
            .approval_decision
            .map(|s| from_json::<ApprovalDecisionKind>(&s))
            .transpose()?,
        execution_status: from_json::<ExecutionStatus>(&raw.execution_status)?,
        error_class: raw.error_class,
        duration_ms: raw.duration_ms.map(|d| d as u64),
    };
    if !event.has_consistent_principal_evidence() {
        return Err(AuditError::Storage(
            "inconsistent audit principal verification evidence".into(),
        ));
    }
    Ok(event)
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
    use companion_core::{OperationId, RiskFactor, SessionId, WorkspaceId};

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
    fn verified_principal_metadata_round_trips_without_transport_binding() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.remote_principal = Some("caller-claimed-name".into());
        event.principal_assurance = PrincipalAssurance::Verified;
        event.verified_principal_issuer = Some("trusted-issuer".into());
        event.verified_principal_subject = Some("actor-7".into());
        event.principal_verification_source =
            Some(PrincipalVerificationSource::AuthenticatedTransport);
        event.authentication_strength = Some("phishing_resistant".into());

        repository.record(&event).unwrap();
        let recent = repository.list_recent(1).unwrap();
        assert_eq!(recent, vec![event]);

        let json = serde_json::to_string(&recent[0]).unwrap();
        assert!(!json.contains("transport_binding"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("signature"));
    }

    #[test]
    fn inconsistent_verified_principal_metadata_is_rejected_before_write() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.principal_assurance = PrincipalAssurance::Verified;

        let error = repository.record(&event).unwrap_err();
        assert!(matches!(error, AuditError::Storage(_)));
        assert!(repository.list_recent(10).unwrap().is_empty());
    }

    #[test]
    fn unverified_audit_cannot_smuggle_verified_metadata() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.verified_principal_subject = Some("forged-subject".into());

        let error = repository.record(&event).unwrap_err();
        assert!(matches!(error, AuditError::Storage(_)));
        assert!(repository.list_recent(10).unwrap().is_empty());
    }

    fn bulk_factor(count: u64) -> RiskFactor {
        RiskFactor::BulkArgumentCardinality {
            subject: "item_ids".into(),
            observed_count: count,
            threshold: 2,
            escalated_to: RiskLevel::High,
        }
    }

    #[test]
    fn dynamic_risk_evidence_round_trips_exactly() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.requested_tool = "pcb_delete_items".into();
        event.capability = Some(Capability::PCB_WRITE);
        event.risk = Some(RiskLevel::High);
        event.risk_policy_version = Some(2);
        event.base_risk = Some(RiskLevel::Normal);
        event.risk_factors = vec![bulk_factor(3)];

        repository.record(&event).unwrap();

        assert_eq!(repository.list_recent(1).unwrap(), vec![event]);
    }

    #[test]
    fn persisted_risk_factor_json_contains_only_safe_reviewed_evidence() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.risk = Some(RiskLevel::High);
        event.risk_policy_version = Some(2);
        event.base_risk = Some(RiskLevel::Normal);
        event.risk_factors = vec![bulk_factor(3)];
        repository.record(&event).unwrap();

        let raw: String = repository
            .storage
            .connection()
            .lock()
            .expect("storage mutex poisoned")
            .query_row(
                "SELECT risk_factors_json FROM audit_events WHERE operation_id = ?1",
                [event.operation_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        assert!(raw.contains("bulk_argument_cardinality"));
        assert!(raw.contains("item_ids"));
        assert!(raw.contains("\"observed_count\":3"));
        assert!(raw.contains("\"threshold\":2"));
        assert!(raw.contains("\"escalated_to\":\"High\""));
        for raw_id in [
            "00000000-0000-0000-0000-0000000000a1",
            "00000000-0000-0000-0000-0000000000b2",
        ] {
            assert!(
                !raw.contains(raw_id),
                "raw item ids must never enter audit factors"
            );
        }
    }

    #[test]
    fn malformed_stored_risk_factor_json_is_a_typed_read_error() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();

        repository
            .storage
            .connection()
            .lock()
            .expect("storage mutex poisoned")
            .execute(
                "UPDATE audit_events SET risk_factors_json = '{broken' WHERE operation_id = ?1",
                [event.operation_id.to_string()],
            )
            .unwrap();

        assert!(matches!(
            repository.list_recent(1),
            Err(AuditError::Storage(_))
        ));
    }

    #[test]
    fn historical_audit_row_keeps_effective_risk_without_invented_assessment() {
        let repository = repo();
        let operation_id = OperationId::new();
        repository
            .storage
            .connection()
            .lock()
            .expect("storage mutex poisoned")
            .execute(
                "INSERT INTO audit_events (
                    operation_id, timestamp, principal_assurance, requested_tool,
                    capability, risk, policy_result, execution_status
                 ) VALUES (?1, ?2, 'unverified', 'pcb_delete_items', 'pcb.write', ?3, ?4, ?5)",
                rusqlite::params![
                    operation_id.to_string(),
                    "2026-09-02T00:00:00Z",
                    "\"High\"",
                    "\"RequireApproval\"",
                    "\"NotExecuted\"",
                ],
            )
            .unwrap();

        let event = repository.list_recent(1).unwrap().pop().unwrap();
        assert_eq!(event.operation_id, operation_id);
        assert_eq!(event.risk, Some(RiskLevel::High));
        assert_eq!(event.risk_policy_version, None);
        assert_eq!(event.base_risk, None);
        assert!(event.risk_factors.is_empty());
    }

    #[test]
    fn approval_update_does_not_mutate_risk_assessment_evidence() {
        let repository = repo();
        let mut event = sample_event(OperationId::new(), SessionId::new());
        event.risk = Some(RiskLevel::High);
        event.risk_policy_version = Some(2);
        event.base_risk = Some(RiskLevel::Normal);
        event.risk_factors = vec![bulk_factor(3)];
        repository.record(&event).unwrap();

        repository
            .update_approval_decision(event.operation_id, ApprovalDecisionKind::AllowOnce)
            .unwrap();

        let stored = repository.list_recent(1).unwrap().pop().unwrap();
        assert_eq!(stored.risk, event.risk);
        assert_eq!(stored.risk_policy_version, event.risk_policy_version);
        assert_eq!(stored.base_risk, event.base_risk);
        assert_eq!(stored.risk_factors, event.risk_factors);
        assert_eq!(
            stored.approval_decision,
            Some(ApprovalDecisionKind::AllowOnce)
        );
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
    fn list_incomplete_returns_only_allowed_operations_with_no_execution_outcome() {
        let repository = repo();

        // Allowed, never executed: a crash between record() and
        // update_execution() leaves exactly this row behind.
        let crashed = sample_event(OperationId::new(), SessionId::new());
        repository.record(&crashed).unwrap();

        // Allowed and completed: no longer incomplete.
        let completed = sample_event(OperationId::new(), SessionId::new());
        repository.record(&completed).unwrap();
        repository
            .update_execution(
                completed.operation_id,
                ExecutionStatus::Success,
                None,
                Some(7),
            )
            .unwrap();

        // Denied: never executed by design, not a recovery concern.
        let denied = sample_event(OperationId::new(), SessionId::new());
        let mut denied = denied;
        denied.policy_result = PolicyResultKind::Deny;
        repository.record(&denied).unwrap();

        let incomplete = repository.list_incomplete().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].operation_id, crashed.operation_id);
        assert_eq!(incomplete[0].policy_result, PolicyResultKind::Allow);
        assert_eq!(incomplete[0].execution_status, ExecutionStatus::NotExecuted);
    }

    #[test]
    fn list_incomplete_is_empty_when_every_allowed_operation_recorded_an_outcome() {
        let repository = repo();
        let event = sample_event(OperationId::new(), SessionId::new());
        repository.record(&event).unwrap();
        repository
            .update_execution(
                event.operation_id,
                ExecutionStatus::Failed,
                Some("io".into()),
                None,
            )
            .unwrap();

        assert!(repository.list_incomplete().unwrap().is_empty());
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
            "transport_binding",
            "credential",
            "signature",
            "certificate",
            "proof",
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
        principal_assurance: String,
        verified_principal_issuer: Option<String>,
        verified_principal_subject: Option<String>,
        principal_verification_source: Option<String>,
        authentication_strength: Option<String>,
        requested_tool: String,
        capability: Option<String>,
        risk: Option<String>,
        risk_policy_version: Option<u32>,
        base_risk: Option<String>,
        risk_factors: Vec<RiskFactor>,
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
                principal_assurance: e.principal_assurance.as_str().to_string(),
                verified_principal_issuer: e.verified_principal_issuer.clone(),
                verified_principal_subject: e.verified_principal_subject.clone(),
                principal_verification_source: e
                    .principal_verification_source
                    .map(|source| source.as_str().to_string()),
                authentication_strength: e.authentication_strength.clone(),
                requested_tool: e.requested_tool.clone(),
                capability: e.capability.map(|c| c.as_str().to_string()),
                risk: e.risk.map(|r| format!("{r:?}")),
                risk_policy_version: e.risk_policy_version,
                base_risk: e.base_risk.map(|r| format!("{r:?}")),
                risk_factors: e.risk_factors.clone(),
                policy_result: format!("{:?}", e.policy_result),
                approval_decision: e.approval_decision.map(|a| format!("{a:?}")),
                execution_status: format!("{:?}", e.execution_status),
                error_class: e.error_class.clone(),
                duration_ms: e.duration_ms,
            }
        }
    }
}
