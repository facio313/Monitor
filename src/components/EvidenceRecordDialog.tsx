import { useEffect, useMemo, useRef } from 'react';
import type { MonitoringEvidenceSource } from '../api';
import { evidenceRecords } from '../evidence-records';
import type { DashboardPayload, MonitorLocale } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';
import './monitoring-evidence.css';

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

function recordTitle(record: unknown, index: number, locale: MonitorLocale): string {
  if (!record || typeof record !== 'object') return `${t(locale, '기록', 'Record')} ${index + 1}`;
  const value = record as Record<string, unknown>;
  const primary = value.ruleId ?? value.id ?? value.kind ?? value.action ?? value.target;
  return safeText(typeof primary === 'string' ? primary : null, `${t(locale, '기록', 'Record')} ${index + 1}`, 96);
}

function recordTimestamp(record: unknown): string | null {
  if (!record || typeof record !== 'object') return null;
  const value = record as Record<string, unknown>;
  for (const key of ['timestamp', 'observedAt', 'occurredAt', 'checkedAt', 'lastEvaluatedAt', 'generatedAt']) {
    if (typeof value[key] === 'string') return value[key] as string;
  }
  return null;
}

export function EvidenceRecordDialog({ source, data, locale, onClose }: {
  source: MonitoringEvidenceSource;
  data: DashboardPayload | null;
  locale: MonitorLocale;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const recordSet = useMemo(() => evidenceRecords(source, data, locale), [data, locale, source]);

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const frame = window.requestAnimationFrame(() => closeRef.current?.focus());
    const handleKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onCloseRef.current();
    };
    document.addEventListener('keydown', handleKey);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener('keydown', handleKey);
      previous?.focus();
    };
  }, []);

  return (
    <div className="evidence-dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="evidence-dialog" role="dialog" aria-modal="true" aria-labelledby="evidence-dialog-title">
        <header>
          <div>
            <span>{t(locale, '저장된 정규화 기록', 'STORED NORMALIZED RECORDS')}</span>
            <h2 id="evidence-dialog-title">{source.displayName[locale]}</h2>
            <p><code>{source.artifactLabel}</code> · {source.format.toUpperCase()}</p>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label={t(locale, '기록 닫기', 'Close records')}>×</button>
        </header>
        <div className="evidence-dialog-safety"><Icon name="shield" size={16} /><p><strong>{t(locale, '원본 호스트 파일이 아닙니다.', 'This is not the raw host file.')}</strong><span>{recordSet.note}</span></p></div>
        <div className="evidence-dialog-summary">
          <strong>{recordSet.records.length.toLocaleString()} {t(locale, '건 표시', 'records shown')}</strong>
          {recordSet.limited && <span>{t(locale, '안전한 화면 한도 200건 적용', 'Bounded to 200 records for safe viewing')}</span>}
        </div>
        <div className="evidence-record-list">
          {recordSet.records.map((record, index) => {
            const timestamp = recordTimestamp(record);
            return (
              <details key={`${recordTitle(record, index, locale)}:${timestamp ?? index}`} open={recordSet.records.length === 1}>
                <summary><strong>{recordTitle(record, index, locale)}</strong>{timestamp && <time dateTime={timestamp}>{formatDateTime(timestamp, locale)}</time>}<span>▾</span></summary>
                <pre>{JSON.stringify(record, null, 2)}</pre>
              </details>
            );
          })}
          {!recordSet.records.length && <div className="evidence-record-empty"><Icon name="info" size={20} /><strong>{t(locale, '이 화면에서 표시할 저장 기록이 없습니다.', 'No stored records are available in this view.')}</strong><span>{recordSet.note}</span></div>}
        </div>
      </section>
    </div>
  );
}
