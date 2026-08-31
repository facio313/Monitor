import { describe, expect, it } from 'vitest';
import { latestIncidentRecords, unresolvedIncidents } from './incident-read-model';
import type { PeakIncident } from './types';

function record(id: string, observedAt: string, phase: PeakIncident['phase']): PeakIncident {
  return { id, observedAt, phase } as PeakIncident;
}

describe('incident read model', () => {
  it('keeps only the newest transition for each incident without depending on input order', () => {
    const active = record('incident-a', '2026-08-30T08:00:00Z', 'active');
    const followUp = record('incident-a', '2026-08-30T08:01:00Z', 'follow-up');
    const recovered = record('incident-a', '2026-08-30T08:02:00Z', 'recovered');
    const other = record('incident-b', '2026-08-30T08:03:00Z', 'active');

    expect(latestIncidentRecords([followUp, other, active, recovered])).toEqual([other, recovered]);
  });

  it('treats active and follow-up latest states as unresolved but drops recovered incidents', () => {
    expect(unresolvedIncidents([
      record('incident-a', '2026-08-30T08:00:00Z', 'active'),
      record('incident-a', '2026-08-30T08:02:00Z', 'recovered'),
      record('incident-b', '2026-08-30T08:01:00Z', 'follow-up'),
    ])).toEqual([
      record('incident-b', '2026-08-30T08:01:00Z', 'follow-up'),
    ]);
  });

  it('prefers the furthest transition when duplicate timestamps are retained', () => {
    expect(latestIncidentRecords([
      record('incident-a', '2026-08-30T08:00:00Z', 'active'),
      record('incident-a', '2026-08-30T08:00:00Z', 'recovered'),
      record('incident-a', '2026-08-30T08:00:00Z', 'follow-up'),
    ])[0]?.phase).toBe('recovered');
  });
});
