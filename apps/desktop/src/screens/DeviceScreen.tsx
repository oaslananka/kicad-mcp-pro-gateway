import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";

export default function DeviceScreen() {
  const { data, error } = usePolling(() => api.pairingStatus(), 5000);

  return (
    <div>
      <h2>Device</h2>
      {error && <div className="error-banner">Daemon not reachable: {error}</div>}
      <div className="card">
        <div className="row">
          <span className="label">Fingerprint</span>
          <span className="mono">{data?.device_fingerprint ?? "(no device identity yet — visit Pairing)"}</span>
        </div>
        <div className="row">
          <span className="label">Paired</span>
          <span>{data?.paired ? "Yes" : "No"}</span>
        </div>
      </div>
      <p className="mono">
        Private device key material never leaves this machine and is never shown here — see
        docs/security/secure-storage.md.
      </p>
    </div>
  );
}
