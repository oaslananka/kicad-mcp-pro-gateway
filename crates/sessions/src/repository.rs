//! Session persistence on top of `companion-storage`. Complex fields
//! (workspace id sets, capability sets/profile, approval policy, status)
//! are stored as JSON text columns; scalar fields get their own columns so
//! simple queries (e.g. "all active sessions") don't need to deserialize
//! every row just to filter.

use std::sync::Arc;

use companion_core::Session;
use companion_storage::Storage;
use time::OffsetDateTime;

use crate::state_machine::SessionError;

pub struct SessionRepository {
    storage: Arc<Storage>,
}

impl SessionRepository {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn save(&self, session: &Session) -> Result<(), SessionError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| SessionError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO sessions (
                session_id, device_id, remote_principal, workspace_ids, capability_profile,
                effective_capabilities, task_scope, issued_at, approved_at, expires_at,
                risk_policy_version, approval_policy, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(session_id) DO UPDATE SET
                remote_principal = excluded.remote_principal,
                workspace_ids = excluded.workspace_ids,
                capability_profile = excluded.capability_profile,
                effective_capabilities = excluded.effective_capabilities,
                task_scope = excluded.task_scope,
                approved_at = excluded.approved_at,
                expires_at = excluded.expires_at,
                risk_policy_version = excluded.risk_policy_version,
                approval_policy = excluded.approval_policy,
                status = excluded.status",
            rusqlite::params![
                session.session_id.to_string(),
                session.device_id.to_string(),
                session.remote_principal,
                to_json(&session.workspace_ids)?,
                to_json(&session.capability_profile)?,
                to_json(&session.effective_capabilities)?,
                session.task_scope,
                format_rfc3339(session.issued_at)?,
                session.approved_at.map(format_rfc3339).transpose()?,
                format_rfc3339(session.expires_at)?,
                session.risk_policy_version,
                to_json(&session.approval_policy)?,
                to_json(&session.status)?,
            ],
        )
        .map_err(|e| SessionError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load(
        &self,
        session_id: companion_core::SessionId,
    ) -> Result<Option<Session>, SessionError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| SessionError::Storage("mutex poisoned".into()))?;
        let query = format!("{SELECT_COLUMNS} WHERE session_id = ?1");
        let result = conn.query_row(
            &query,
            rusqlite::params![session_id.to_string()],
            row_to_raw,
        );
        match result {
            Ok(raw) => parse_raw(raw).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SessionError::Storage(e.to_string())),
        }
    }

    pub fn list_active(&self) -> Result<Vec<Session>, SessionError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| SessionError::Storage("mutex poisoned".into()))?;
        let query = format!("{SELECT_COLUMNS} WHERE status = ?1");
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| SessionError::Storage(e.to_string()))?;
        let active_status = to_json(&companion_core::SessionStatus::Active)?;
        let rows = stmt
            .query_map(rusqlite::params![active_status], row_to_raw)
            .map_err(|e| SessionError::Storage(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| SessionError::Storage(e.to_string()))?;
            sessions.push(parse_raw(raw)?);
        }
        Ok(sessions)
    }

    /// All sessions regardless of status. Used by callers (audit views,
    /// tests) that need to see e.g. `PendingApproval` or `Revoked` sessions
    /// too, not just `Active` ones.
    pub fn list_all(&self) -> Result<Vec<Session>, SessionError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| SessionError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(SELECT_COLUMNS)
            .map_err(|e| SessionError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_raw)
            .map_err(|e| SessionError::Storage(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| SessionError::Storage(e.to_string()))?;
            sessions.push(parse_raw(raw)?);
        }
        Ok(sessions)
    }
}

const SELECT_COLUMNS: &str = "SELECT session_id, device_id, remote_principal, workspace_ids, capability_profile, \
     effective_capabilities, task_scope, issued_at, approved_at, expires_at, risk_policy_version, approval_policy, \
     status FROM sessions";

struct RawSessionRow {
    session_id: String,
    device_id: String,
    remote_principal: String,
    workspace_ids: String,
    capability_profile: String,
    effective_capabilities: String,
    task_scope: String,
    issued_at: String,
    approved_at: Option<String>,
    expires_at: String,
    risk_policy_version: i64,
    approval_policy: String,
    status: String,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawSessionRow> {
    Ok(RawSessionRow {
        session_id: row.get(0)?,
        device_id: row.get(1)?,
        remote_principal: row.get(2)?,
        workspace_ids: row.get(3)?,
        capability_profile: row.get(4)?,
        effective_capabilities: row.get(5)?,
        task_scope: row.get(6)?,
        issued_at: row.get(7)?,
        approved_at: row.get(8)?,
        expires_at: row.get(9)?,
        risk_policy_version: row.get(10)?,
        approval_policy: row.get(11)?,
        status: row.get(12)?,
    })
}

fn parse_raw(raw: RawSessionRow) -> Result<Session, SessionError> {
    Ok(Session {
        session_id: raw
            .session_id
            .parse()
            .map_err(|e| SessionError::Storage(format!("{e:?}")))?,
        device_id: raw
            .device_id
            .parse()
            .map_err(|e| SessionError::Storage(format!("{e:?}")))?,
        remote_principal: raw.remote_principal,
        workspace_ids: from_json(&raw.workspace_ids)?,
        capability_profile: from_json(&raw.capability_profile)?,
        effective_capabilities: from_json(&raw.effective_capabilities)?,
        task_scope: raw.task_scope,
        issued_at: parse_rfc3339(&raw.issued_at)?,
        approved_at: raw.approved_at.as_deref().map(parse_rfc3339).transpose()?,
        expires_at: parse_rfc3339(&raw.expires_at)?,
        risk_policy_version: raw.risk_policy_version as u32,
        approval_policy: from_json(&raw.approval_policy)?,
        status: from_json(&raw.status)?,
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, SessionError> {
    serde_json::to_string(value).map_err(|e| SessionError::Storage(e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, SessionError> {
    serde_json::from_str(raw).map_err(|e| SessionError::Storage(e.to_string()))
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, SessionError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| SessionError::Storage(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, SessionError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| SessionError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{CapabilityProfile, DeviceId, FakeClock};

    use super::*;
    use crate::state_machine::new_unpaired_session;

    fn repo() -> SessionRepository {
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        SessionRepository::new(storage)
    }

    #[test]
    fn save_then_load_round_trips() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = new_unpaired_session(
            DeviceId::new(),
            "agent:test".into(),
            BTreeSet::from([companion_core::WorkspaceId::new()]),
            CapabilityProfile::Design,
            "wire up sensor board".into(),
            time::Duration::hours(1),
            &clock,
        );

        repository.save(&session).unwrap();
        let loaded = repository
            .load(session.session_id)
            .unwrap()
            .expect("session present");
        assert_eq!(loaded, session);
    }

    #[test]
    fn load_unknown_session_returns_none() {
        let repository = repo();
        let result = repository.load(companion_core::SessionId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_active_only_returns_active_sessions() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut active = new_unpaired_session(
            DeviceId::new(),
            "agent:one".into(),
            BTreeSet::new(),
            CapabilityProfile::Inspect,
            "task".into(),
            time::Duration::hours(1),
            &clock,
        );
        active.status = companion_core::SessionStatus::Active;
        let mut unpaired = new_unpaired_session(
            DeviceId::new(),
            "agent:two".into(),
            BTreeSet::new(),
            CapabilityProfile::Inspect,
            "task".into(),
            time::Duration::hours(1),
            &clock,
        );
        unpaired.status = companion_core::SessionStatus::Unpaired;

        repository.save(&active).unwrap();
        repository.save(&unpaired).unwrap();

        let active_sessions = repository.list_active().unwrap();
        assert_eq!(active_sessions.len(), 1);
        assert_eq!(active_sessions[0].session_id, active.session_id);

        assert_eq!(
            repository.list_all().unwrap().len(),
            2,
            "list_all returns every status, not just Active"
        );
    }

    #[test]
    fn save_twice_updates_in_place_rather_than_duplicating() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut session = new_unpaired_session(
            DeviceId::new(),
            "agent:test".into(),
            BTreeSet::new(),
            CapabilityProfile::Inspect,
            "task".into(),
            time::Duration::hours(1),
            &clock,
        );
        repository.save(&session).unwrap();

        session.status = companion_core::SessionStatus::Revoked;
        repository.save(&session).unwrap();

        let loaded = repository.load(session.session_id).unwrap().unwrap();
        assert_eq!(loaded.status, companion_core::SessionStatus::Revoked);
    }
}
