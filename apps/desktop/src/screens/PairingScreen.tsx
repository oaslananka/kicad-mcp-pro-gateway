import { useState } from "react";
import { api } from "../api/client";
import type { PairingBegunView } from "../api/types";

export default function PairingScreen() {
  const [result, setResult] = useState<PairingBegunView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const startPairing = () => {
    setBusy(true);
    setError(null);
    api
      .beginPairing()
      .then(setResult)
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <div>
      <h2>Device pairing</h2>
      <p className="mono">
        Using local mock pairing provider — there is no production cloud backend yet. See docs/protocol/README.md.
      </p>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        {result ? (
          <>
            <div className="row">
              <span className="label">Pairing code</span>
              <span className="mono">{result.pairing_code}</span>
            </div>
            <div className="row">
              <span className="label">Provider</span>
              <span>{result.mock_provider ? "Mock (development)" : "Production"}</span>
            </div>
          </>
        ) : (
          <p>No pairing in progress.</p>
        )}
        <button className="action" onClick={startPairing} disabled={busy}>
          {busy ? "Starting…" : "Begin pairing"}
        </button>
      </div>
    </div>
  );
}
