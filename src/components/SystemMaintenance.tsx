import type { ReactNode } from 'react';
import { localized } from '../dashboard-model';
import type { MonitorLocale, SystemStatus } from '../types';
import { formatDateTime, safeText } from '../utils';
import { CockpitPanel } from './CockpitVisuals';
import { Icon } from './Icon';

type MaintenanceTone = 'ok' | 'caution' | 'danger' | 'unknown';

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function known(value: string | null): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

export function kernelVersionTone(system: SystemStatus): MaintenanceTone {
  const versions = system.versions;
  if (!known(versions.kernelRunning) || !known(versions.kernelLatestInstalled)) return 'unknown';
  if (versions.kernelRebootRequired === true || versions.kernelRunning !== versions.kernelLatestInstalled) return 'caution';
  return versions.kernelRebootRequired === null ? 'unknown' : 'ok';
}

export function bootloaderVersionTone(system: SystemStatus): MaintenanceTone {
  const versions = system.versions;
  if (!known(versions.bootloaderCurrent) || !known(versions.bootloaderLatest)) return 'unknown';
  return versions.bootloaderCurrent === versions.bootloaderLatest ? 'ok' : 'caution';
}

function toneLabel(tone: MaintenanceTone, locale: MonitorLocale): string {
  if (tone === 'ok') return t(locale, '현재 버전', 'Current');
  if (tone === 'caution') return t(locale, '변경 대기', 'Pending change');
  if (tone === 'danger') return t(locale, '확인 필요', 'Check required');
  return t(locale, '미확인', 'Unknown');
}

function VersionCard({
  label,
  value,
  detail,
  tone,
  locale,
}: {
  label: string;
  value: string;
  detail: string;
  tone: MaintenanceTone;
  locale: MonitorLocale;
}) {
  return (
    <article className={`system-version-card version-${tone}`}>
      <header>
        <span>{label}</span>
        <small className={`status-token status-${tone}`}>{toneLabel(tone, locale)}</small>
      </header>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

export interface SystemMaintenanceProps {
  system: SystemStatus;
  generatedAt: string;
  locale: MonitorLocale;
  updateControls?: ReactNode;
}

export function SystemMaintenance({ system, generatedAt, locale, updateControls }: SystemMaintenanceProps) {
  const versions = system.versions;
  const versionText = (value: string | null, fallback = t(locale, '미확인', 'Unknown')) => safeText(value, fallback);
  const kernelTone = kernelVersionTone(system);
  const bootloaderTone = bootloaderVersionTone(system);
  const nvmeTone: MaintenanceTone = known(versions.nvmeModel) || known(versions.nvmeFirmware) ? 'ok' : 'unknown';
  const collectorTone: MaintenanceTone = known(versions.collector) ? 'ok' : 'unknown';
  const kernelDetail = versions.kernelRebootRequired === true
    ? t(locale, `설치됨 ${versionText(versions.kernelLatestInstalled)} · 재부팅 필요`, `Installed ${versionText(versions.kernelLatestInstalled)} · reboot required`)
    : t(locale, `설치됨 ${versionText(versions.kernelLatestInstalled)}`, `Installed ${versionText(versions.kernelLatestInstalled)}`);
  const bootloaderDetail = t(
    locale,
    `최신 ${versionText(versions.bootloaderLatest)} · ${versionText(versions.bootloaderChannel, '채널 미확인')}`,
    `Latest ${versionText(versions.bootloaderLatest)} · ${versionText(versions.bootloaderChannel, 'channel unknown')}`,
  );

  return (
    <div className="detail-dashboard maintenance-dashboard">
      <CockpitPanel
        title={t(locale, '시스템 버전', 'System versions')}
        description={t(locale, '실행 중인 커널·부트로더·NVMe·수집기 버전', 'Running kernel, bootloader, NVMe, and collector versions')}
        icon="server"
        badge={t(locale, '읽기 전용', 'READ ONLY')}
        locale={locale}
      >
        <div className="system-version-grid">
          <VersionCard
            label={t(locale, '실행 중인 커널', 'Running kernel')}
            value={versionText(versions.kernelRunning)}
            detail={kernelDetail}
            tone={kernelTone}
            locale={locale}
          />
          <VersionCard
            label={t(locale, 'Raspberry Pi EEPROM', 'Raspberry Pi EEPROM')}
            value={versionText(versions.bootloaderCurrent)}
            detail={bootloaderDetail}
            tone={bootloaderTone}
            locale={locale}
          />
          <VersionCard
            label={t(locale, 'NVMe 장치', 'NVMe device')}
            value={versionText(versions.nvmeModel)}
            detail={t(locale, `펌웨어 ${versionText(versions.nvmeFirmware)}`, `Firmware ${versionText(versions.nvmeFirmware)}`)}
            tone={nvmeTone}
            locale={locale}
          />
          <VersionCard
            label={t(locale, 'Monitor 수집기', 'Monitor collector')}
            value={versionText(versions.collector)}
            detail={t(locale, `상태 생성 ${formatDateTime(generatedAt, locale)}`, `Snapshot generated ${formatDateTime(generatedAt, locale)}`)}
            tone={collectorTone}
            locale={locale}
          />
        </div>
        <p className="cockpit-footnote">
          {t(locale, '표시된 값은 현재 호스트에서 수집한 안전한 버전 정보입니다.', 'Values are sanitized version metadata collected from the current host.')}
        </p>
      </CockpitPanel>

      <CockpitPanel
        title={t(locale, '업데이트 관리', 'Update management')}
        description={t(locale, '업데이트 확인과 설치 상태를 이 화면에서 관리합니다.', 'Check and manage operating-system updates from this page.')}
        icon="refresh"
        badge={updateControls ? t(locale, '관리', 'MANAGE') : t(locale, '연결 준비 중', 'PENDING')}
        locale={locale}
      >
        {updateControls ?? (
          <div className="maintenance-update-placeholder" role="status">
            <span><Icon name="shield" size={24} /></span>
            <div>
              <h3>{t(locale, '안전한 업데이트 경로를 준비하고 있습니다', 'Secure update controls are being connected')}</h3>
              <p>{t(locale, '버전 정보는 지금 확인할 수 있습니다. 업데이트 확인과 설치 버튼은 권한 검증 및 진행 상태 기록이 연결되면 활성화됩니다.', 'Version information is available now. Check and install controls will activate after authorization and progress reporting are connected.')}</p>
            </div>
            <button type="button" disabled><Icon name="refresh" size={17} />{t(locale, '업데이트 확인', 'Check for updates')}</button>
          </div>
        )}
      </CockpitPanel>
    </div>
  );
}
