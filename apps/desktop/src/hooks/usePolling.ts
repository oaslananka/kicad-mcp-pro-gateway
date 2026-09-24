import { useEffect, useState, useCallback } from "react";

/// Polls `fetcher` on an interval and exposes the latest result, an error
/// message (if the last call failed — most commonly "daemon not running"),
/// and a manual `refresh` function. Kept intentionally simple: this is a
/// status-display surface, not a place for retry/backoff policy.
export function usePolling<T>(fetcher: () => Promise<T>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    fetcher()
      .then((result) => {
        setData(result);
        setError(null);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
    // `fetcher` is intentionally excluded from deps: callers pass a fresh
    // closure on every render, and depending on it would defeat the
    // interval by re-subscribing constantly.
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { data, error, loading, refresh };
}
