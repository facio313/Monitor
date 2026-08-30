import type { CSSProperties } from 'react';
import { PSI_THRESHOLDS } from '../operational-thresholds';
import { useResponsivePageSize } from '../responsive-page-size';
import type { DashboardPayload, MonitorDetailPage, MonitorLocale } from '../types';
import { formatBytes } from '../utils';
import { CockpitPanel } from './CockpitVisuals';
import { Pagination, paginateItems, usePagination } from './Pagination';

type HeadroomTone = 'ok' | 'caution' | 'danger' | 'unknown';

interface OperationalHeadroomProps {
  data: DashboardPayload;
  locale: MonitorLocale;
  onOpen: (page: MonitorDetailPage) => void;
}

interface HeadroomReading {
  key: string;
  label: string;
  value: string;
  detail: string;
  level: number | null;
  tone: HeadroomTone;
  page: MonitorDetailPage;
}

function t(locale: MonitorLocale, ko: string, en: string): string {
  return locale === 'ko' ? ko : en;
}

function finite(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function percent(value: number | null | undefined, digits = 1): string {
  return finite(value) ? `${value.toFixed(digits)}%` : '—';
}

function tone(value: number | null, caution: number, danger: number): HeadroomTone {
  if (value === null) return 'unknown';
  if (value >= danger) return 'danger';
  if (value >= caution) return 'caution';
  return 'ok';
}

function toneText(value: HeadroomTone, locale: MonitorLocale): string {
  const labels: Record<HeadroomTone, readonly [string, string]> = {
    ok: ['정상', 'OK'],
    caution: ['주의', 'Caution'],
    danger: ['위험', 'Danger'],
    unknown: ['미확인', 'Unknown'],
  };
  return t(locale, labels[value][0], labels[value][1]);
}

function normalizedLevel(value: number | null, severe: number): number | null {
  return value === null ? null : Math.max(0, Math.min(1, value / severe));
}

function toneRank(value: HeadroomTone): number {
  return value === 'danger' ? 3 : value === 'caution' ? 2 : value === 'ok' ? 1 : 0;
}

function psiAssessment(
  some: number | null | undefined,
  full: number | null | undefined,
  someThreshold: { caution: number; danger: number },
  fullThreshold: { caution: number; danger: number },
): Pick<HeadroomReading, 'level' | 'tone'> {
  const someValue = finite(some) ? some : null;
  const fullValue = finite(full) ? full : null;
  const someTone = tone(someValue, someThreshold.caution, someThreshold.danger);
  const fullTone = tone(fullValue, fullThreshold.caution, fullThreshold.danger);
  const resultTone = toneRank(fullTone) > toneRank(someTone) ? fullTone : someTone;
  const levels = [
    normalizedLevel(someValue, someThreshold.danger),
    normalizedLevel(fullValue, fullThreshold.danger),
  ].filter((value): value is number => value !== null);
  return { level: levels.length ? Math.max(...levels) : null, tone: resultTone };
}

function HeadroomMeter({ reading, locale, onOpen }: { reading: HeadroomReading; locale: MonitorLocale; onOpen: (page: MonitorDetailPage) => void }) {
  const status = toneText(reading.tone, locale);
  return (
    <button
      className={`headroom-meter meter-${reading.tone}`}
      type="button"
      onClick={() => onOpen(reading.page)}
      aria-label={`${reading.label}: ${reading.value}. ${reading.detail}. ${status}.`}
    >
      <span className="headroom-meter-top"><span className="headroom-meter-label">{reading.label}</span><em>{status}</em></span>
      <strong>{reading.value}</strong>
      <small>{reading.detail}</small>
      <i aria-hidden="true"><b style={{ '--headroom-level': (reading.level ?? 0).toFixed(3) } as CSSProperties} /></i>
    </button>
  );
}

export function operationalHeadroomReadings(data: DashboardPayload, locale: MonitorLocale): HeadroomReading[] {
  const latest = data.latest;
  const logicalCpuCount = finite(data.host.logicalCpuCount) && data.host.logicalCpuCount > 0 ? data.host.logicalCpuCount : null;
  const loadRatio = finite(latest?.load1) && logicalCpuCount ? (latest.load1 / logicalCpuCount) * 100 : null;
  const cpuPsi = psiAssessment(latest?.cpuPressureSomeAvg10, latest?.cpuPressureFullAvg10, PSI_THRESHOLDS.cpuSome, PSI_THRESHOLDS.cpuFull);
  const memoryPsi = psiAssessment(latest?.memoryPressureSomeAvg10, latest?.memoryPressureFullAvg10, PSI_THRESHOLDS.memorySome, PSI_THRESHOLDS.memoryFull);
  const ioPsi = psiAssessment(latest?.ioPressureSomeAvg10, latest?.ioPressureFullAvg10, PSI_THRESHOLDS.ioSome, PSI_THRESHOLDS.ioFull);
  const swap = finite(latest?.swapPercent) ? latest.swapPercent : null;
  const observedCapacity = data.disks.filter((disk) => finite(disk.usedPercent) || finite(disk.availableBytes));
  const tightestDisk = observedCapacity.length
    ? observedCapacity.reduce((left, right) => {
      const leftUsed = finite(left.usedPercent) ? left.usedPercent : Number.NEGATIVE_INFINITY;
      const rightUsed = finite(right.usedPercent) ? right.usedPercent : Number.NEGATIVE_INFINITY;
      if (leftUsed !== rightUsed) return leftUsed > rightUsed ? left : right;
      const leftAvailable = finite(left.availableBytes) ? left.availableBytes : Number.POSITIVE_INFINITY;
      const rightAvailable = finite(right.availableBytes) ? right.availableBytes : Number.POSITIVE_INFINITY;
      return leftAvailable <= rightAvailable ? left : right;
    })
    : null;
  const maxInode = data.disks.reduce<number | null>((maximum, disk) => finite(disk.inodeUsedPercent) ? Math.max(maximum ?? 0, disk.inodeUsedPercent) : maximum, null);
  const readOnly = data.disks.filter((disk) => disk.readOnly === true);
  const mountModeObserved = readOnly.length > 0 || (data.disks.length > 0 && data.disks.every((disk) => disk.readOnly === false));

  return [
    {
      key: 'load-per-cpu',
      label: t(locale, '코어당 부하', 'Load per CPU'),
      value: loadRatio === null ? '—' : `${(loadRatio / 100).toFixed(2)}×`,
      detail: logicalCpuCount ? t(locale, `논리 CPU ${logicalCpuCount}개 기준`, `${logicalCpuCount} logical CPUs`) : t(locale, 'CPU 개수 미수집', 'CPU count unavailable'),
      level: normalizedLevel(loadRatio, 180),
      tone: tone(loadRatio, 75, 150),
      page: 'resources',
    },
    {
      key: 'cpu-psi',
      label: t(locale, 'CPU 실제 대기', 'CPU stall (PSI)'),
      value: percent(latest?.cpuPressureSomeAvg10),
      detail: t(locale, `full ${percent(latest?.cpuPressureFullAvg10)}`, `full ${percent(latest?.cpuPressureFullAvg10)}`),
      level: cpuPsi.level,
      tone: cpuPsi.tone,
      page: 'resources',
    },
    {
      key: 'memory-psi',
      label: t(locale, '메모리 실제 대기', 'Memory stall (PSI)'),
      value: percent(latest?.memoryPressureSomeAvg10),
      detail: t(locale, `full ${percent(latest?.memoryPressureFullAvg10)}`, `full ${percent(latest?.memoryPressureFullAvg10)}`),
      level: memoryPsi.level,
      tone: memoryPsi.tone,
      page: 'resources',
    },
    {
      key: 'io-psi',
      label: t(locale, 'I/O 실제 대기', 'I/O stall (PSI)'),
      value: percent(latest?.ioPressureSomeAvg10),
      detail: t(locale, `full ${percent(latest?.ioPressureFullAvg10)}`, `full ${percent(latest?.ioPressureFullAvg10)}`),
      level: ioPsi.level,
      tone: ioPsi.tone,
      page: 'storage',
    },
    {
      key: 'swap',
      label: t(locale, '스왑 사용', 'Swap utilization'),
      value: percent(swap),
      detail: finite(latest?.swapTotalBytes) && latest.swapTotalBytes > 0
        ? `${formatBytes(latest.swapUsedBytes)} / ${formatBytes(latest.swapTotalBytes)}`
        : t(locale, '스왑 없음 또는 미수집', 'No swap or unavailable'),
      level: normalizedLevel(swap, 100),
      tone: tone(swap, 45, 80),
      page: 'resources',
    },
    {
      key: 'free-space',
      label: t(locale, '가장 빠듯한 용량', 'Tightest capacity'),
      value: tightestDisk && finite(tightestDisk.usedPercent) ? percent(tightestDisk.usedPercent) : '—',
      detail: tightestDisk
        ? `${tightestDisk.mount} · ${finite(tightestDisk.availableBytes) ? t(locale, `${formatBytes(tightestDisk.availableBytes)} 남음`, `${formatBytes(tightestDisk.availableBytes)} available`) : t(locale, '가용 공간 미수집', 'Free space unavailable')}`
        : t(locale, '보고 없음', 'Not reported'),
      level: tightestDisk && finite(tightestDisk.usedPercent) ? normalizedLevel(tightestDisk.usedPercent, 100) : null,
      tone: tightestDisk && finite(tightestDisk.usedPercent) ? tone(tightestDisk.usedPercent, 75, 90) : 'unknown',
      page: 'storage',
    },
    {
      key: 'inodes',
      label: t(locale, '최고 아이노드 사용', 'Highest inode use'),
      value: percent(maxInode),
      detail: t(locale, '파일 개수 한계 여유', 'File-count headroom'),
      level: normalizedLevel(maxInode, 100),
      tone: tone(maxInode, 75, 90),
      page: 'storage',
    },
    {
      key: 'read-only',
      label: t(locale, '읽기 전용 마운트', 'Read-only mounts'),
      value: mountModeObserved ? readOnly.length.toLocaleString(locale === 'ko' ? 'ko-KR' : 'en-US') : '—',
      detail: readOnly.length
        ? readOnly.map((disk) => disk.mount).slice(0, 2).join(' · ')
        : mountModeObserved ? t(locale, '모두 쓰기 가능', 'All writable') : t(locale, '일부 또는 전체 미수집', 'Partially or fully unavailable'),
      level: mountModeObserved ? (readOnly.length ? 1 : 0) : null,
      tone: mountModeObserved ? (readOnly.length ? 'danger' : 'ok') : 'unknown',
      page: 'storage',
    },
  ];
}

export function OperationalHeadroom({ data, locale, onOpen }: OperationalHeadroomProps) {
  const readings = operationalHeadroomReadings(data, locale);
  const observed = readings.filter((reading) => reading.tone !== 'unknown').length;
  const pageSize = useResponsivePageSize({ desktop: 8, tablet: 6, phone: 6, narrowPhone: 4 });
  const pagination = usePagination({
    totalItems: readings.length,
    pageSize,
    resetKey: `${locale}:${pageSize}:${readings.map((reading) => `${reading.key}:${reading.value}:${reading.tone}`).join('|')}`,
  });
  const visibleReadings = paginateItems(readings, pagination);
  return (
    <CockpitPanel
      title={t(locale, '운영 여유와 실제 압박', 'Operational headroom and real stalls')}
      description={t(locale, '코어 기준 부하·PSI·스왑·공간·아이노드·읽기 전용 상태', 'CPU-normalized load, PSI, swap, capacity, inodes, and mount mode')}
      icon="activity"
      badge={`${observed}/${readings.length}`}
      detailPage="resources"
      onOpen={onOpen}
      locale={locale}
      className="operational-headroom-panel"
    >
      <div className="operational-headroom-grid">
        {visibleReadings.map((reading) => <HeadroomMeter key={reading.key} reading={reading} locale={locale} onOpen={onOpen} />)}
      </div>
      {readings.length > pageSize && <Pagination
        model={pagination}
        locale={locale}
        onPageChange={pagination.setPage}
        ariaLabel={t(locale, '운영 여유 계기 페이지', 'Operational headroom pages')}
        itemLabel={t(locale, '개 계기', 'readings')}
      />}
      <p className="cockpit-footnote">{t(locale, '사용률만으로 보이지 않는 실제 대기와 파일시스템 소진 위험을 함께 판단합니다.', 'These readings expose real stalls and filesystem exhaustion that utilization alone can hide.')}</p>
    </CockpitPanel>
  );
}
