import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";

export default function StatusScreen() {
  const { data: lifecycle } = usePolling(() => api.daemonLifecycle(), 1000);
  const { data: status, error } = usePolling(() => api.status(), 3000);
  const { data: sessions } = usePolling(() => api.listSessions(), 3000);

  return (
    <div>
      <h2>KiCad MCP Pro Gateway</h2>

      {lifecycle?.state === "failed" && (
        <div className="error-banner">Gateway daemon failed to start: {lifecycle.message}</div>
      )}
      {lifecycle?.state === "stopped" && (
        <div className="error-banner">Gateway daemon stopped: {lifecycle.message}</div>
      )}
      {error && <div className="error-banner">Daemon not reachable: {error}</div>}

      <div className="card">
        <div className="row">
          <span className="label">Connection</span>
          <span>
            {lifecycle?.state === "starting"
              ? "Starting"
              : lifecycle?.state === "stopped"
                ? "Stopped"
                : error || lifecycle?.state === "failed"
                  ? "Disconnected"
                  : lifecycle?.state === "ready"
                    ? "Connected"
                    : "Connecting"}
          </span>
        </div>
        <div className="row">
          <span className="label">Device</span>
          <span className="mono">{status?.device_fingerprint ?? "(not created yet)"}</span>
        </div>
        <div className="row">
          <span className="label">KiCad MCP Pro</span>
          <span>{status?.core_bridge_reachable ? "Detected" : "Offline"}</span>
        </div>
        <div className="row">
          <span className="label">Active workspaces</span>
          <span>{status?.workspace_count ?? "-"}</span>
        </div>
      </div>

      <div className="card">
        <div className="row">
          <span className="label">Remote session</span>
          <span>{sessions && sessions.length > 0 ? `${sessions.length} active` : "None"}</span>
        </div>
        {sessions?.map((s) => (
          <div className="row" key={s.session_id}>
            <span>
              {s.remote_principal} · {s.capability_profile}
            </span>
            <span className="mono">expires {s.expires_at}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
