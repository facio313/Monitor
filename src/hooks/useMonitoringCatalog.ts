import { useCallback, useEffect, useState } from 'react';
import { ApiError, getMonitoringCatalog, type MonitoringCatalog } from '../api';

export function useMonitoringCatalog(onUnauthorized: () => void, refreshKey: string | null = null) {
  const [catalog, setCatalog] = useState<MonitoringCatalog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);

  const refresh = useCallback(() => setVersion((current) => current + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    getMonitoringCatalog(controller.signal)
      .then((result) => {
        setCatalog(result);
        setError(null);
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return;
        if (reason instanceof ApiError && reason.status === 401) {
          onUnauthorized();
          return;
        }
        setError(reason instanceof Error ? reason.message : 'Monitoring catalog is unavailable.');
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [onUnauthorized, refreshKey, version]);

  return { catalog, error, loading, refresh };
}
