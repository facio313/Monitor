import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { SshAccessResponse } from '../ssh-access-types';
import { formatSshTime, normalizeSshIpInput, SshAccessEvidence, SshAccessHistory, sshCountryLabel, sshEventLabel } from './SshAccessHistory';

function response(): SshAccessResponse {
  return { schemaVersion: 1, status: 'fresh', stale: false, partial: false, observedAt: '2026-09-13T12:00:00Z', lastSuccessAt: '2026-09-13T12:00:00Z', errorClass: null,
    sources: [{ sourceId: 'journal:ssh', status: 'fresh', observedAt: '2026-09-13T12:00:00Z', lastSuccessAt: '2026-09-13T12:00:00Z', errorClass: null }],
    acceptedRecords: 1, deduplicatedRecords: 0, droppedRecords: 0, range: '24h', event: 'all', ip: null, from: '2026-09-12T12:00:00Z', to: '2026-09-13T12:00:00Z',
    page: 1, limit: 20, total: 1, rejectedRows: 0, deduplicatedRows: 0, truncated: false, scannedRows: 1, scannedBytes: 420, retentionDays: 30,
    records: [{ schemaVersion: 1, id: 'a'.repeat(64), observedAt: '2026-09-13T11:59:59.123456Z', sourceId: 'journal:ssh', sourceIp: '203.0.113.10', sourcePort: 51234,
      eventType: 'accepted', authMethod: 'publickey', countryCode: 'KR', countryStatus: 'estimated', databaseDate: '2026-09-01' }] };
}

describe('SSH access history UI', () => {
  it('shows IP, Korean country/code, event method and fixed KST timestamps', () => {
    const html = renderToStaticMarkup(createElement(SshAccessEvidence, { response: response(), locale: 'ko' }));
    for (const value of ['203.0.113.10', '대한민국 (KR) · 추정', '인증 성공', 'publickey', '51234', '2026-09-13 20:59:59 KST', '2026-09-01', '>1</td>']) expect(html).toContain(value);
    expect(formatSshTime('2026-09-13T00:00:00.123456Z')).toBe('2026-09-13 09:00:00 KST');
    expect(formatSshTime('bad')).toBe('—');
  });
  it('distinguishes private, unknown and stale geography without claiming an attacker location', () => {
    expect(sshCountryLabel({ countryCode: null, countryStatus: 'private' }, 'ko')).toContain('사설');
    expect(sshCountryLabel({ countryCode: null, countryStatus: 'stale' }, 'ko')).toBe('국가 미확인 · 오래된 DB');
    expect(sshCountryLabel({ countryCode: 'US', countryStatus: 'stale' }, 'en')).toContain('United States (US) · Stale database estimate');
    expect(sshCountryLabel({ countryCode: null, countryStatus: 'not_found' }, 'en')).toBe('Country not found');
    expect(sshCountryLabel({ countryCode: null, countryStatus: 'unavailable' }, 'en')).toBe('Country unavailable');
    expect(sshCountryLabel({ countryCode: 'XK', countryStatus: 'estimated' }, 'en')).toContain('Kosovo (XK) · Estimated');
    expect(sshEventLabel('preauth_closed', 'ko')).toBe('인증 전 연결 종료');
    expect(sshEventLabel('auth_failed', 'en')).toBe('Authentication failed');
  });
  it('explicitly warns about stale/partial/empty data and scanned-only counts', () => {
    const data = { ...response(), status: 'partial' as const, stale: true, partial: true, records: [], total: 0, rejectedRows: 2, droppedRecords: 3, truncated: true };
    const html = renderToStaticMarkup(createElement(SshAccessEvidence, { response: data, locale: 'en' }));
    for (const value of ['Partial', 'Status is stale', 'An empty result does not establish', 'Rejected records', 'Dropped during collection', 'Within scanned data:', 'file/row limits']) expect(html).toContain(value);
    expect(html).toContain('role="alert"');
  });
  it('provides readable filters, privacy caveats and mandatory DB-IP attribution', () => {
    const html = renderToStaticMarkup(createElement(SshAccessHistory, { locale: 'ko', onUnauthorized: () => undefined }));
    for (const value of ['SSH 출처·국가 접속 기록', '6h', '24h', '인증 성공', '인증 전 종료', '출처 IP 정확히 일치',
      '실제 위치를 뜻하지 않습니다', '고유 접속 시도 수가 아닙니다', '40,000행·16 MiB', 'DB-IP.com', 'href="https://db-ip.com"']) expect(html).toContain(value);
    expect(html).not.toContain('https://db-ip.com/203.');
  });
  it('canonicalizes user IPv6 input and mapped addresses without accepting URLs or hostnames', () => {
    expect(normalizeSshIpInput(' 8.8.8.8 ')).toBe('8.8.8.8');
    expect(normalizeSshIpInput('2001:0DB8:0:0::1')).toBe('2001:db8::1');
    expect(normalizeSshIpInput('::ffff:8.8.8.8')).toBe('8.8.8.8');
    for (const input of ['example.invalid', 'https://8.8.8.8', '8.8.8.8:22', 'fe80::1%eth0', '256.1.1.1', '008.8.8.8', '<script>']) expect(normalizeSshIpInput(input)).toBeNull();
  });
  it('spans the dashboard grid and contains horizontal scrolling within the table', () => {
    const css = readFileSync(new URL('./ssh-access.css', import.meta.url), 'utf8');
    expect(css).toContain('grid-column: 1 / -1');
    expect(css).toContain('min-width: 0');
    expect(css).toContain('overflow-x: auto');
    expect(css).toContain('@media (max-width: 600px)');
  });
});
