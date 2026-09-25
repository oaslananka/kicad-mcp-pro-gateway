import { useState } from "react";
import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";
import type { PendingApprovalView, SessionView } from "../api/types";

function statusBadgeClass(status: string): string {
  if (status === "Active") return "badge active";
  if (status === "PendingApproval") return "badge pending";
  return "badge";
}

function riskBadgeClass(risk: string): string {
  if (risk === "High" || risk === "Critical") return "badge risk-high";
  return "badge";
}

export default function SessionsScreen() {
  const { data: sessions, error, refresh: refreshSessions } = usePolling(() => api.listSessions(), 2000);
  const { data: pendingOps, refresh: refreshOps } = usePolling(() => api.listPendingApprovals(), 2000);
  const [actionError, setActionError] = useState<string | null>(null);
  const [sessionDialog, setSessionDialog] = useState<SessionView | null>(null);
  const [opDialog, setOpDialog] = useState<PendingApprovalView | null>(null);

  const refreshAll = () => {
    refreshSessions();
    refreshOps();
  };

  const act = (promise: Promise<void>) => {
    setActionError(null);
    promise.then(refreshAll).catch((e) => setActionError(String(e)));
  };

  return (
    <div>
      <h2>Sessions</h2>
      {error && <div className="error-banner">Daemon not reachable: {error}</div>}
      {actionError && <div className="error-banner">{actionError}</div>}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Remote</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Task</th>
              <th>Effective expiry</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions?.map((s) => (
              <tr key={s.session_id}>
                <td>{s.remote_principal}</td>
                <td>{s.capability_profile}</td>
                <td>
                  <span className={statusBadgeClass(s.status)}>{s.status}</span>
                </td>
                <td>{s.task_scope}</td>
                <td className="mono">{s.expires_at}</td>
                <td>
                  {s.status === "PendingApproval" && (
                    <button className="action" onClick={() => setSessionDialog(s)}>
                      Review
                    </button>
                  )}
                  {s.status === "Active" && (
                    <>
                      <button className="action secondary" onClick={() => act(api.pauseSession(s.session_id))}>
                        Pause
                      </button>
                      <button className="action danger" onClick={() => act(api.revokeSession(s.session_id))}>
                        Revoke
                      </button>
                    </>
                  )}
                  {s.status === "Suspended" && (
                    <>
                      <button className="action" onClick={() => act(api.resumeSession(s.session_id))}>
                        Resume
                      </button>
                      <button className="action danger" onClick={() => act(api.revokeSession(s.session_id))}>
                        Revoke
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {sessions?.length === 0 && (
              <tr>
                <td colSpan={6}>No sessions yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {pendingOps && pendingOps.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0, fontSize: 14 }}>High-risk operations awaiting approval</h3>
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Risk</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {pendingOps.map((p) => (
                <tr key={p.operation_id}>
                  <td className="mono">{p.tool_name}</td>
                  <td>
                    <span className={riskBadgeClass(p.risk)}>{p.risk}</span>
                  </td>
                  <td>
                    <button className="action" onClick={() => setOpDialog(p)}>
                      Review
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sessionDialog && (
        <div className="modal-backdrop" onClick={() => setSessionDialog(null)} data-testid="session-dialog-backdrop">
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Remote access request</h3>
            <div className="row">
              <span className="label">Source</span>
              <span>{sessionDialog.remote_principal}</span>
            </div>
            <div className="row">
              <span className="label">Profile</span>
              <span>{sessionDialog.capability_profile}</span>
            </div>
            <div className="row">
              <span className="label">Task</span>
              <span>{sessionDialog.task_scope}</span>
            </div>
            {sessionDialog.workspaces && sessionDialog.workspaces.length > 0 && (
              <div className="row">
                <span className="label">Workspace(s)</span>
                <span className="mono" style={{ overflowWrap: "break-word" }}>
                  {sessionDialog.workspaces
                    .map((w) => `${w.display_name} (${w.workspace_id})`)
                    .join(", ")}
                </span>
              </div>
            )}
            <div className="row">
              <span className="label">Effective expiry</span>
              <span className="mono">{sessionDialog.expires_at}</span>
            </div>
            <div style={{ marginTop: 16 }}>
              <button
                className="action danger"
                onClick={() => {
                  act(api.denySession(sessionDialog.session_id, "denied by user"));
                  setSessionDialog(null);
                }}
              >
                Deny
              </button>
              <button
                className="action"
                onClick={() => {
                  act(api.approveSession(sessionDialog.session_id));
                  setSessionDialog(null);
                }}
              >
                Approve
              </button>
            </div>
          </div>
        </div>
      )}

      {opDialog && (
        <div className="modal-backdrop" onClick={() => setOpDialog(null)} data-testid="operation-dialog-backdrop">
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>High-risk action requires approval</h3>
            <div className="row">
              <span className="label">Action</span>
              <span className="mono">{opDialog.tool_name}</span>
            </div>
            <div className="row">
              <span className="label">Risk</span>
              <span className={riskBadgeClass(opDialog.risk)}>{opDialog.risk}</span>
            </div>
            <div className="row">
              <span className="label">Workspace</span>
              <span className="mono" style={{ overflowWrap: "break-word" }}>
                {opDialog.workspace_id}
              </span>
            </div>
            <div style={{ marginTop: 16 }}>
              <button
                className="action danger"
                onClick={() => {
                  act(api.denyOperation(opDialog.operation_id, "denied by user"));
                  setOpDialog(null);
                }}
              >
                Deny
              </button>
              <button
                className="action"
                onClick={() => {
                  act(api.approveOperation(opDialog.operation_id));
                  setOpDialog(null);
                }}
              >
                Allow Once
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
