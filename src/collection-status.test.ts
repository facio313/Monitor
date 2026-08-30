import { describe, expect, it } from 'vitest';
import {
  agentHeartbeatLabel,
  agentHeartbeatTone,
  containerCollectionLabel,
  containerCollectionTone,
} from './collection-status';

describe('collection status presentation', () => {
  it('keeps heartbeat lifecycle and failure states distinct', () => {
    expect(agentHeartbeatTone('healthy')).toBe('ok');
    expect(agentHeartbeatTone('delayed')).toBe('caution');
    expect(agentHeartbeatTone('disconnected')).toBe('danger');
    expect(agentHeartbeatTone('collection_error')).toBe('danger');
    expect(agentHeartbeatTone('maintenance')).toBe('caution');
    expect(agentHeartbeatTone('inactive')).toBe('caution');
    expect(agentHeartbeatTone('unknown')).toBe('unknown');
    expect(agentHeartbeatTone('healthy', true)).toBe('danger');
    expect(agentHeartbeatLabel('disconnected', 'ko')).toBe('수집 중단');
    expect(agentHeartbeatLabel('collection_error', 'en')).toBe('CONTRACT ERROR');
  });

  it('never presents a failed service collection as an empty healthy inventory', () => {
    expect(containerCollectionTone('fresh')).toBe('ok');
    expect(containerCollectionTone('last-known')).toBe('caution');
    expect(containerCollectionTone('unavailable')).toBe('danger');
    expect(containerCollectionTone('permission-denied')).toBe('danger');
    expect(containerCollectionLabel('unavailable', 'ko')).toBe('서비스 수집 불가');
    expect(containerCollectionLabel('permission-denied', 'en')).toBe('Service collection denied');
  });
});
