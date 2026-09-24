import { invoke } from "@tauri-apps/api/core";
import type {
  ConfigView,
  AuditSummaryView,
  DaemonStatusView,
  PairingBegunView,
  PairingStatusView,
  PendingApprovalView,
  SessionView,
  WorkspaceView,
} from "./types";

// Every function here is a 1:1 call into a Tauri command, which is itself
// a thin forwarder to the daemon's local IPC API. There is no logic here
// beyond that — see docs/architecture/component-boundaries.md.
export const api = {
  status: () => invoke<DaemonStatusView>("status"),
  pairingStatus: () => invoke<PairingStatusView>("pairing_status"),
  beginPairing: () => invoke<PairingBegunView>("begin_pairing"),

  listSessions: () => invoke<SessionView[]>("list_sessions"),
  approveSession: (sessionId: string) => invoke<void>("approve_session", { sessionId }),
  denySession: (sessionId: string, reason: string) => invoke<void>("deny_session", { sessionId, reason }),
  pauseSession: (sessionId: string) => invoke<void>("pause_session", { sessionId }),
  resumeSession: (sessionId: string) => invoke<void>("resume_session", { sessionId }),
  revokeSession: (sessionId: string) => invoke<void>("revoke_session", { sessionId }),

  listWorkspaces: () => invoke<WorkspaceView[]>("list_workspaces"),
  authorizeWorkspace: (path: string, displayName: string) =>
    invoke<WorkspaceView>("authorize_workspace", { path, displayName }),
  removeWorkspace: (workspaceId: string) => invoke<void>("remove_workspace", { workspaceId }),

  auditSummary: () => invoke<AuditSummaryView>("audit_summary"),

  listPendingApprovals: () => invoke<PendingApprovalView[]>("list_pending_approvals"),
  approveOperation: (operationId: string) => invoke<void>("approve_operation", { operationId }),
  denyOperation: (operationId: string, reason: string) => invoke<void>("deny_operation", { operationId, reason }),
  getConfig: () => invoke<ConfigView>("get_config"),
};
