import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, getDashboard } from '../api';
import type { DashboardPayload, TimeRange } from '../types';

const REFRESH_INTERVAL = 60_000;

export interface DashboardState {
  data: DashboardPayload | null;
  error: string | null;
  initialLoading: boolean;
  refreshing: boolean;
  lastUpdated: Date | null;
  refresh: () => Promise<void>;
}
export function useDashboard(range: TimeRange, onUnauthorized: () => void): DashboardState {
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const lastUpdatedRef = useRef<number>(0);

  const refresh = useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setRefreshing(true);
    try {
      const payload = await getDashboard(range, controller.signal);
      setData(payload);
      setError(null);
      const updated = Date.now();
      lastUpdatedRef.current = updated;
      setLastUpdated(new Date(updated));
    } catch (requestError) {
      if (requestError instanceof DOMException && requestError.name === 'AbortError') return;
      if (requestError instanceof ApiError && requestError.status === 401) {
        onUnauthorized();
        return;
      }
      setError(requestError instanceof Error ? requestError.message : 'Telemetry is temporarily unavailable.');
    } finally {
      if (controllerRef.current === controller) {
        setInitialLoading(false);
        setRefreshing(false);
      }
    }
  }, [onUnauthorized, range]);

  useEffect(() => {
    setInitialLoading((current) => current || data === null);
    void refresh();

    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh();
    }, REFRESH_INTERVAL);

    const handleVisibility = () => {
      if (document.visibilityState === 'visible' && Date.now() - lastUpdatedRef.current >= REFRESH_INTERVAL) {
        void refresh();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      window.clearInterval(interval);
      document.removeEventListener('visibilitychange', handleVisibility);
      controllerRef.current?.abort();
    };
    // Refresh is recreated whenever the requested range changes.
  }, [range, refresh]);

  return { data, error, initialLoading, refreshing, lastUpdated, refresh };
}
