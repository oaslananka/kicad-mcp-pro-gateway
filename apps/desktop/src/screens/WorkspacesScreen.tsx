import { useState } from "react";
import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";

export default function WorkspacesScreen() {
  const { data: workspaces, error, refresh } = usePolling(() => api.listWorkspaces(), 4000);
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  const add = () => {
    setActionError(null);
    api
      .authorizeWorkspace(path, name || path)
      .then(() => {
        setPath("");
        setName("");
        refresh();
      })
      .catch((e) => setActionError(String(e)));
  };

  const remove = (workspaceId: string) => {
    setActionError(null);
    api.removeWorkspace(workspaceId).then(refresh).catch((e) => setActionError(String(e)));
  };

  return (
    <div>
      <h2>Workspaces</h2>
      {error && <div className="error-banner">Daemon not reachable: {error}</div>}
      {actionError && <div className="error-banner">{actionError}</div>}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Path</th>
              <th>Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {workspaces?.map((w) => (
              <tr key={w.workspace_id}>
                <td>{w.display_name}</td>
                <td className="mono">{w.canonical_root}</td>
                <td>{w.enabled ? "Yes" : "No"}</td>
                <td>
                  <button className="action danger" onClick={() => remove(w.workspace_id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {workspaces?.length === 0 && (
              <tr>
                <td colSpan={4}>No authorized workspaces yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0, fontSize: 14 }}>Authorize a new workspace</h3>
        <p className="mono">The daemon only ever accesses paths inside authorized workspace roots.</p>
        <input
          placeholder="Absolute path to a KiCad project directory"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          style={{ width: "100%", marginBottom: 8, padding: 6 }}
        />
        <input
          placeholder="Display name (optional)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: "100%", marginBottom: 8, padding: 6 }}
        />
        <button className="action" onClick={add} disabled={!path}>
          Authorize
        </button>
      </div>
    </div>
  );
}
