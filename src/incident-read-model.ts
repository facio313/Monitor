import type { PeakIncident } from './types';

const PHASE_ORDER: Record<PeakIncident['phase'], number> = {
  active: 0,
  'follow-up': 1,
  recovered: 2,
};

function isNewerIncidentRecord(candidate: PeakIncident, current: PeakIncident): boolean {
  const timestampOrder = candidate.observedAt.localeCompare(current.observedAt);
  if (timestampOrder !== 0) return timestampOrder > 0;
  return PHASE_ORDER[candidate.phase] > PHASE_ORDER[current.phase];
}

/**
 * Collapse transition snapshots to the latest known state for each incident.
 * The full input remains available to historical timelines and evidence views.
 */
export function latestIncidentRecords(incidents: readonly PeakIncident[]): PeakIncident[] {
  const latestById = new Map<string, PeakIncident>();
  for (const incident of incidents) {
    const current = latestById.get(incident.id);
    if (!current || isNewerIncidentRecord(incident, current)) latestById.set(incident.id, incident);
  }
  return [...latestById.values()].sort((left, right) => (
    right.observedAt.localeCompare(left.observedAt) || left.id.localeCompare(right.id)
  ));
}

export function unresolvedIncidents(incidents: readonly PeakIncident[]): PeakIncident[] {
  return latestIncidentRecords(incidents).filter((incident) => incident.phase !== 'recovered');
}
