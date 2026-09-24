import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ConfigView } from "../api/types";

export default function SettingsScreen() {
  const [config, setConfig] = useState<ConfigView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    api
      .getConfig()
      .then((cfg) => {
        if (isMounted) {
          setConfig(cfg);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(typeof err === "string" ? err : String(err));
          setLoading(false);
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div>
      <h2>Settings</h2>

      {loading && <div className="card"><p>Loading configuration...</p></div>}

      {error && (
        <div className="card error">
          <p><strong>Error loading configuration:</strong> {error}</p>
        </div>
      )}

      {config && (
        <div className="card">
          <h3>Active Configuration</h3>
          <dl className="settings-grid">
            <div>
              <dt>Data Directory</dt>
              <dd className="mono">{config.data_dir}</dd>
            </div>
            <div>
              <dt>Log Level</dt>
              <dd className="mono">{config.log_level}</dd>
            </div>
            <div>
              <dt>Core Bridge Endpoint</dt>
              <dd className="mono">{config.core_bridge_endpoint}</dd>
            </div>
            <div>
              <dt>Transport Mode</dt>
              <dd className="mono">{config.transport_mode}</dd>
            </div>
          </dl>
        </div>
      )}

      <div className="card">
        <h3>Configuration Precedence</h3>
        <p>
          Configuration parameters are resolved using the following order of precedence:
        </p>
        <ol className="mono-list">
          <li><strong>CLI flags</strong> (e.g. <code>--log-level trace</code>)</li>
          <li><strong>Environment variables</strong> (e.g. <code>COMPANION_LOG_LEVEL=debug</code>)</li>
          <li><strong>Configuration file</strong> (<code>config.toml</code> inside Data Directory)</li>
          <li><strong>Built-in defaults</strong></li>
        </ol>
        <p className="hint">
          Changes made to <code>config.toml</code> take effect upon daemon restart.
        </p>
      </div>

      <div className="card">
        <h3>Privacy & Security Policy</h3>
        <p>
          Companion telemetry is <strong>off by default</strong>. No project files, schematics, PCB layouts,
          or audit records leave your machine unless specifically passed through an explicitly authorized transport flow.
        </p>
        <ul className="security-invariants">
          <li>Local core bridge remains restricted to loopback (127.0.0.1).</li>
          <li>Secrets and credentials are never stored in plaintext SQLite, logs, or config files.</li>
          <li>Unknown tools default to fail-closed state. Discovery does not imply authorization.</li>
        </ul>
      </div>
    </div>
  );
}
