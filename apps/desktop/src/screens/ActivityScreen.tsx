import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";

export default function ActivityScreen() {
  const { data, error } = usePolling(() => api.auditSummary(), 5000);

  return (
    <div>
      <h2>Activity</h2>
      {error && <div className="error-banner">Daemon not reachable: {error}</div>}
      <div className="card">
        <div className="row">
          <span className="label">Recorded events</span>
          <span>{data?.total_events ?? "-"}</span>
        </div>
        <div className="row">
          <span className="label">Note</span>
          <span>{data?.note}</span>
        </div>
      </div>
      <p className="mono">
        Full per-event browsing (tool, capability, risk, allow/deny, execution outcome) lands in a later iteration of
        this screen; the audit trail itself is already recorded for every policy decision — see
        docs/architecture/data-flow.md.
      </p>
    </div>
  );
}
