import type { SystemStatus } from './types';

export const UPDATE_CHECK_MAX_AGE_MS = 24 * 60 * 60_000;
export const REBOOT_OBSERVATION_MAX_AGE_MS = 5 * 60_000;

export function updateCheckIsFresh(checkedAt: string | null | undefined, nowMs = Date.now()): boolean {
  const checkedMs = typeof checkedAt === 'string' ? Date.parse(checkedAt) : Number.NaN;
  return Number.isFinite(checkedMs) && checkedMs <= nowMs && nowMs - checkedMs <= UPDATE_CHECK_MAX_AGE_MS;
}

export function rebootObservationIsFresh(system: SystemStatus | undefined, stale = false, nowMs = Date.now()): boolean {
  const observation = system?.reboot;
  const observedMs = observation?.observedAt ? Date.parse(observation.observedAt) : Number.NaN;
  return !stale && observation?.status === 'ok' && Number.isFinite(observedMs)
    && observedMs <= nowMs + 60_000 && nowMs - observedMs <= REBOOT_OBSERVATION_MAX_AGE_MS;
}

export function kernelRebootRequired(system: SystemStatus | undefined): boolean {
  const versions = system?.versions;
  return versions?.kernelRebootRequired === true || Boolean(versions?.kernelRunning
    && versions?.kernelLatestInstalled && versions.kernelRunning !== versions.kernelLatestInstalled);
}

/** The updater's persisted reboot flag is historical and is never consulted. */
export function currentRebootRequirement(system: SystemStatus | undefined, stale = false, nowMs = Date.now()): boolean | null {
  if (stale) return null;
  if (kernelRebootRequired(system)) return true;
  if (!rebootObservationIsFresh(system, stale, nowMs)) return null;
  return system?.reboot?.required ?? null;
}
