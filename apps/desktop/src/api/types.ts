// Mirrors the view types in crates/protocol/src/ipc.rs. Kept as plain
// hand-written interfaces (no codegen) for V1 — if these drift from the
// Rust source of truth, typecheck failures on the Tauri command call sites
// are the signal to fix them.

export interface DaemonStatusView {
  device_fingerprint: string | null;
  paired: boolean;
  core_bridge_reachable: boolean;
  active_session_count: number;
  workspace_count: number;
}

export interface PairingStatusView {
  paired: boolean;
  device_fingerprint: string | null;
}

export interface PairingBegunView {
  pairing_code: string;
  mock_provider: boolean;
}

export interface SessionView {
  session_id: string;
  remote_principal: string;
  status: string;
  capability_profile: string;
  task_scope: string;
  expires_at: string;
}

export interface WorkspaceView {
  workspace_id: string;
  display_name: string;
  canonical_root: string;
  enabled: boolean;
}

export interface AuditSummaryView {
  total_events: number;
  note: string;
}

export interface PendingApprovalView {
  operation_id: string;
  session_id: string;
  tool_name: string;
  risk: string;
}


export interface ConfigView {
  data_dir: string;
  log_level: string;
  core_bridge_endpoint: string;
  transport_mode: string;
}
