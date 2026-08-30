import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ApiError,
  applySystemUpdate,
  checkSystemUpdates,
  getSystemUpdates,
  prepareSystemUpdate,
  type SystemUpdateCategory,
  type SystemUpdateState,
  type SystemUpdatesResponse,
} from '../api';
import { localized } from '../dashboard-model';
import type { MonitorLocale } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';
import { Pagination, paginateItems, usePagination } from './Pagination';

type UpdateTone = 'ok' | 'caution' | 'danger' | 'unknown';

const CATEGORY_ORDER: SystemUpdateCategory[] = [
  'kernel',
  'firmware',
  'container-runtime',
  'network',
  'core-system',
  'other',
];

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

export function updateStateTone(state: SystemUpdateState | null): UpdateTone {
  if (state === 'failed' || state === 'interrupted') return 'danger';
  if (state === 'available' || state === 'checking' || state === 'applying') return 'caution';
  if (state === 'up-to-date' || state === 'succeeded') return 'ok';
  return 'unknown';
}

export function updateCategoryCounts(
  packages: Array<{ category: SystemUpdateCategory }>,
): Record<SystemUpdateCategory, number> {
  const counts: Record<SystemUpdateCategory, number> = {
    kernel: 0,
    firmware: 0,
    'container-runtime': 0,
    network: 0,
    'core-system': 0,
    other: 0,
  };
  for (const item of packages.slice(0, 512)) {
    if (CATEGORY_ORDER.includes(item.category)) counts[item.category] += 1;
  }
  return counts;
}

export function confirmationMatchesPlan(reviewedPlanId: string | null, currentPlanId: string | null): boolean {
  return reviewedPlanId !== null && reviewedPlanId === currentPlanId;
}

function stateLabel(state: SystemUpdateState | null, locale: MonitorLocale): string {
  const labels: Record<SystemUpdateState, [string, string]> = {
    idle: ['확인 전', 'Not checked'],
    checking: ['업데이트 확인 중', 'Checking'],
    available: ['업데이트 있음', 'Updates available'],
    'up-to-date': ['최신 상태', 'Up to date'],
    applying: ['안전 업데이트 적용 중', 'Applying safe updates'],
    succeeded: ['업데이트 완료', 'Update complete'],
    failed: ['업데이트 실패', 'Update failed'],
    interrupted: ['업데이트 중단', 'Update interrupted'],
  };
  const label = state ? labels[state] : null;
  return label ? t(locale, label[0], label[1]) : t(locale, '상태 없음', 'No status');
}

function categoryLabel(category: SystemUpdateCategory, locale: MonitorLocale): string {
  const labels: Record<SystemUpdateCategory, [string, string]> = {
    kernel: ['커널', 'Kernel'],
    firmware: ['펌웨어', 'Firmware'],
    'container-runtime': ['컨테이너', 'Container runtime'],
    network: ['네트워크', 'Network'],
    'core-system': ['핵심 시스템', 'Core system'],
    other: ['기타', 'Other'],
  };
  return t(locale, labels[category][0], labels[category][1]);
}

function statusCodeDetail(code: string, locale: MonitorLocale): string | null {
  const labels: Record<string, [string, string]> = {
    UPDATES_KEPT_BACK: ['설치 가능한 안전 업데이트는 없지만 보류된 패키지가 있습니다.', 'No safe updates are installable, but some packages are kept back.'],
    PACKAGE_MANAGER_BUSY: ['다른 패키지 작업이 진행 중입니다.', 'Another package operation is running.'],
    DPKG_AUDIT_FAILED: ['패키지 상태 점검이 필요합니다.', 'The package database needs attention.'],
    PLAN_NOT_FOUND: ['확인한 업데이트 계획을 찾지 못했습니다.', 'The confirmed update plan was not found.'],
    PLAN_STALE: ['업데이트 계획이 만료됐습니다. 다시 확인해 주세요.', 'The update plan expired. Check again.'],
    PLAN_CHANGED: ['패키지 계획이 바뀌어 설치를 중단했습니다.', 'Installation stopped because the package plan changed.'],
    ROOT_READ_ONLY: ['루트 파일시스템이 읽기 전용입니다.', 'The root filesystem is read-only.'],
    DISK_SPACE_LOW: ['업데이트에 필요한 여유 공간이 부족합니다.', 'There is not enough free space for the update.'],
    PLAN_TOO_LARGE: ['업데이트 계획이 안전 한도를 넘었습니다.', 'The update plan exceeds the safety limit.'],
    COMMAND_FAILED: ['패키지 명령이 실패했습니다. 호스트 진단이 필요합니다.', 'A package command failed. Host diagnostics are required.'],
    INTERRUPTED: ['이전 요청이 중단돼 새 확인이 필요합니다.', 'The previous request was interrupted; check again.'],
    INTERNAL_ERROR: ['업데이트 상태 기록에 실패했습니다.', 'The update state could not be recorded.'],
  };
  const label = labels[code];
  return label ? t(locale, label[0], label[1]) : null;
}

function safeError(error: unknown, locale: MonitorLocale): string {
  if (error instanceof ApiError) {
    if (error.code === 'PLAN_STALE' || error.code === 'PLAN_CHANGED') {
      return t(locale, '업데이트 계획이 바뀌었습니다. 다시 확인해 주세요.', 'The update plan changed. Check again.');
    }
    if (error.code === 'PACKAGE_MANAGER_BUSY' || error.code === 'BUSY') {
      return t(locale, '다른 패키지 작업이 진행 중입니다. 잠시 후 다시 시도해 주세요.', 'Another package operation is running. Try again shortly.');
    }
    if (error.code === 'CONFIRMATION_REQUIRED') {
      return t(locale, '확인 토큰이 만료됐습니다. 설치를 다시 확인해 주세요.', 'The confirmation expired. Confirm installation again.');
    }
    if (error.status === 403) {
      return t(locale, '이 작업을 실행할 권한이 없습니다.', 'You do not have permission for this operation.');
    }
  }
  return t(locale, '업데이트 서비스 요청을 완료하지 못했습니다.', 'The update service request could not be completed.');
}

export function SystemUpdateControls({ locale }: { locale: MonitorLocale }) {
  const [snapshot, setSnapshot] = useState<SystemUpdatesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<'check' | 'apply' | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [reviewedPlanId, setReviewedPlanId] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  const requestInFlight = useRef(false);

  async function refresh(signal?: AbortSignal): Promise<void> {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    try {
      const next = await getSystemUpdates(signal);
      if (!mounted.current) return;
      setSnapshot(next);
      setError(null);
    } catch (requestError) {
      if (signal?.aborted || !mounted.current) return;
      setError(safeError(requestError, locale));
    } finally {
      requestInFlight.current = false;
      if (mounted.current) setLoading(false);
    }
  }

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    void refresh(controller.signal);
    const poll = window.setInterval(() => void refresh(), 5_000);
    return () => {
      mounted.current = false;
      controller.abort();
      window.clearInterval(poll);
    };
    // Locale changes only affect presentation; they must not restart update polling.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const status = snapshot?.status ?? null;
  const capabilities = snapshot?.capabilities ?? {
    gatewayAvailable: false,
    canCheck: false,
    canApply: false,
  };
  const tone = updateStateTone(status?.state ?? null);
  const active = status?.state === 'checking' || status?.state === 'applying';
  const planUsable = status?.state === 'available'
    && typeof status.planId === 'string'
    && typeof status.planExpiresAt === 'string'
    && Date.parse(status.planExpiresAt) > Date.now();
  const categories = useMemo(
    () => updateCategoryCounts(Array.isArray(status?.packages) ? status.packages : []),
    [status?.packages],
  );
  const packages = useMemo(() => Array.isArray(status?.packages) ? status.packages : [], [status?.packages]);
  const packageSignature = useMemo(
    () => packages.map((item) => `${item.name}:${item.candidateVersion}`).join('\u001f'),
    [packages],
  );
  const packagePagination = usePagination({
    totalItems: packages.length,
    pageSize: 10,
    resetKey: `${status?.planId ?? 'no-plan'}\u001e${packageSignature}`,
  });
  const visiblePackages = useMemo(
    () => paginateItems(packages, packagePagination),
    [packagePagination.endIndex, packagePagination.startIndex, packages],
  );
  const impactfulCount = categories.kernel
    + categories.firmware
    + categories['container-runtime']
    + categories.network
    + categories['core-system'];
  const effectiveTone: UpdateTone = status?.summary
    && status.summary.packageCount === 0
    && status.summary.keptBackCount > 0
    ? 'caution'
    : tone;

  useEffect(() => {
    if (!confirming || confirmationMatchesPlan(reviewedPlanId, status?.planId ?? null)) return;
    setConfirming(false);
    setAcknowledged(false);
    setReviewedPlanId(null);
    setNotice(t(locale, '업데이트 계획이 바뀌어 기존 확인을 취소했습니다. 새 계획을 다시 검토해 주세요.', 'The update plan changed, so the previous confirmation was cancelled. Review the new plan.'));
  }, [confirming, locale, reviewedPlanId, status?.planId]);

  async function handleCheck(): Promise<void> {
    setBusy('check');
    setNotice(null);
    setError(null);
    setConfirming(false);
    try {
      await checkSystemUpdates();
      setNotice(t(locale, '업데이트 확인 요청을 접수했습니다.', 'The update check was queued.'));
      window.setTimeout(() => void refresh(), 700);
    } catch (requestError) {
      setError(safeError(requestError, locale));
    } finally {
      setBusy(null);
    }
  }

  async function handleApply(): Promise<void> {
    if (
      !planUsable
      || !acknowledged
      || !confirmationMatchesPlan(reviewedPlanId, status?.planId ?? null)
    ) return;
    const approvedPlanId = reviewedPlanId;
    if (approvedPlanId === null) return;
    setBusy('apply');
    setNotice(null);
    setError(null);
    try {
      const prepared = await prepareSystemUpdate(approvedPlanId);
      if (prepared.planId !== approvedPlanId) throw new ApiError('Update plan changed', 409, 'PLAN_CHANGED');
      await applySystemUpdate(prepared.planId, prepared.nonce);
      setConfirming(false);
      setAcknowledged(false);
      setReviewedPlanId(null);
      setNotice(t(locale, '안전 업데이트를 시작했습니다. 이 화면에서 진행 상태를 확인할 수 있습니다.', 'Safe updates started. Progress will appear here.'));
      window.setTimeout(() => void refresh(), 700);
    } catch (requestError) {
      setError(safeError(requestError, locale));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="system-update-controls">
      <section className={`update-status-card update-${effectiveTone}`} aria-live="polite">
        <div className="update-status-icon"><Icon name={active ? 'refresh' : tone === 'danger' ? 'alert' : 'shield'} size={25} className={active ? 'spin' : ''} /></div>
        <div>
          <span>{t(locale, '호스트 패키지 상태', 'HOST PACKAGE STATUS')}</span>
          <h3>{loading && !snapshot
            ? t(locale, '상태 확인 중', 'Loading status')
            : status?.state === 'up-to-date' && (status.summary?.keptBackCount ?? 0) > 0
              ? t(locale, '안전 적용 가능 없음 · 보류 있음', 'No safe updates · packages kept back')
              : stateLabel(status?.state ?? null, locale)}</h3>
          <p>
            {status?.state === 'failed' && statusCodeDetail(status.code, locale)
              ? statusCodeDetail(status.code, locale)
              : status?.checkedAt
              ? t(locale, `마지막 확인 ${formatDateTime(status.checkedAt, locale)}`, `Last checked ${formatDateTime(status.checkedAt, locale)}`)
              : t(locale, '아직 업데이트 목록을 확인하지 않았습니다.', 'No update plan has been checked yet.')}
          </p>
        </div>
        <button
          type="button"
          className="maintenance-primary-action"
          disabled={!capabilities.canCheck || active || busy !== null}
          onClick={() => void handleCheck()}
        >
          <Icon name="refresh" size={17} className={busy === 'check' ? 'spin' : ''} />
          {busy === 'check' ? t(locale, '요청 중', 'Queuing') : t(locale, '업데이트 확인', 'Check for updates')}
        </button>
      </section>

      {!capabilities.gatewayAvailable && (
        <div className="update-inline-note note-caution">
          <Icon name="alert" size={18} />
          <span>{t(locale, '호스트 업데이트 서비스가 연결되지 않아 조회만 가능합니다.', 'The host update service is unavailable; status remains read-only.')}</span>
        </div>
      )}
      {capabilities.gatewayAvailable && !capabilities.canCheck && (
        <div className="update-inline-note note-caution">
          <Icon name="lock" size={18} />
          <span>{t(locale, '업데이트 확인은 정규 관리자 계정에서만 실행할 수 있습니다.', 'Update checks require an eligible canonical admin identity.')}</span>
        </div>
      )}
      {status?.rebootRequired && (
        <div className="update-inline-note note-danger" role="alert">
          <Icon name="alert" size={18} />
          <span>{t(locale, '설치된 변경을 완료하려면 재부팅이 필요합니다. Monitor가 자동으로 재부팅하지는 않습니다.', 'A reboot is required to finish installed changes. Monitor never reboots automatically.')}</span>
        </div>
      )}
      {notice && <div className="update-inline-note note-ok"><Icon name="check" size={18} /><span>{notice}</span></div>}
      {error && <div className="update-inline-note note-danger" role="alert"><Icon name="alert" size={18} /><span>{error}</span></div>}

      {status?.summary && (
        <>
          <div className="update-summary-grid">
            <div><span>{t(locale, '업그레이드', 'UPGRADES')}</span><strong>{status.summary.upgradeCount}</strong></div>
            <div><span>{t(locale, '새 설치', 'NEW INSTALLS')}</span><strong>{status.summary.installCount}</strong></div>
            <div><span>{t(locale, '보류', 'KEPT BACK')}</span><strong>{status.summary.keptBackCount}</strong></div>
            <div><span>{t(locale, '제거', 'REMOVALS')}</span><strong className={status.summary.removeCount > 0 ? 'value-danger' : ''}>{status.summary.removeCount}</strong></div>
          </div>

          <div className="update-category-list" aria-label={t(locale, '업데이트 영향 분류', 'Update impact categories')}>
            {CATEGORY_ORDER.map((category) => categories[category] > 0 && (
              <span key={category} className={category === 'other' ? '' : 'impactful'}>
                {categoryLabel(category, locale)} <strong>{categories[category]}</strong>
              </span>
            ))}
          </div>

          {status.packages.length > 0 && (
            <details className="update-package-details">
              <summary>{t(locale, `패키지 목록 ${status.summary.packageCount}개`, `${status.summary.packageCount} packages`)}</summary>
              <div className="update-package-list">
                {visiblePackages.map((item) => (
                  <div key={`${item.name}:${item.candidateVersion}`}>
                    <strong>{safeText(item.name, '—', 160)}</strong>
                    <span>{safeText(item.installedVersion, t(locale, '신규', 'new'), 80)} → {safeText(item.candidateVersion, '—', 80)}</span>
                    <small>{categoryLabel(item.category, locale)}</small>
                  </div>
                ))}
              </div>
              <Pagination
                model={packagePagination}
                locale={locale}
                onPageChange={packagePagination.setPage}
                ariaLabel={t(locale, '업데이트 패키지 페이지', 'Update package pages')}
                itemLabel={t(locale, '개 패키지', 'packages')}
                className="update-package-pagination"
              />
              {status.summary.packagesTruncated && (
                <p>{t(locale, '호스트가 안전 한도까지 반환한 패키지를 페이지로 나눠 표시합니다. 전체 계획 해시는 모든 패키지를 포함합니다.', 'The host returned packages up to its safety limit; those entries are paginated here. The plan digest covers every package.')}</p>
              )}
            </details>
          )}

          {capabilities.canApply && planUsable && !confirming && (
            <div className="update-apply-row">
              <div>
                <strong>{t(locale, '안전 업데이트 설치', 'Install safe updates')}</strong>
                <span>{t(locale, '패키지 제거·배포판 업그레이드·자동 재부팅은 실행하지 않습니다.', 'No package removal, release upgrade, or automatic reboot is allowed.')}</span>
              </div>
              <button type="button" disabled={active || busy !== null} onClick={() => {
                setReviewedPlanId(status.planId);
                setAcknowledged(false);
                setConfirming(true);
              }}>
                <Icon name="shield" size={17} />{t(locale, '설치 검토', 'Review install')}
              </button>
            </div>
          )}
        </>
      )}

      {confirming && status?.summary && (
        <section className="update-confirmation" role="alertdialog" aria-labelledby="update-confirm-title">
          <div>
            <span>{t(locale, '최종 확인', 'FINAL CONFIRMATION')}</span>
            <h3 id="update-confirm-title">{t(locale, `${status.summary.packageCount}개 패키지를 안전 업데이트할까요?`, `Apply safe updates to ${status.summary.packageCount} packages?`)}</h3>
            <p>{impactfulCount > 0
              ? status.summary.packagesTruncated
                ? t(locale, `표시된 목록에 서비스 영향 가능 패키지가 최소 ${impactfulCount}개 있습니다. 서비스가 재시작될 수 있습니다.`, `The displayed portion contains at least ${impactfulCount} potentially service-impacting packages. Services may restart.`)
                : t(locale, `서비스에 영향을 줄 수 있는 분류가 ${impactfulCount}개 포함됩니다. 서비스가 재시작될 수 있습니다.`, `${impactfulCount} potentially service-impacting packages are included. Services may restart.`)
              : t(locale, '적용 중 일부 서비스가 재시작될 수 있습니다.', 'Some services may restart while updates are applied.')}</p>
          </div>
          <label>
            <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
            <span>{t(locale, '영향과 재부팅 가능성을 확인했으며, 이 계획을 적용합니다.', 'I reviewed the impact and reboot possibility and approve this plan.')}</span>
          </label>
          <div className="update-confirm-actions">
            <button type="button" disabled={busy !== null} onClick={() => { setConfirming(false); setAcknowledged(false); setReviewedPlanId(null); }}>{t(locale, '취소', 'Cancel')}</button>
            <button type="button" className="danger-confirm" disabled={!acknowledged || busy !== null} onClick={() => void handleApply()}>
              <Icon name="refresh" size={17} className={busy === 'apply' ? 'spin' : ''} />
              {busy === 'apply' ? t(locale, '시작 중', 'Starting') : t(locale, '안전 업데이트 시작', 'Start safe update')}
            </button>
          </div>
        </section>
      )}

      <p className="cockpit-footnote">
        {t(locale, '확인은 패키지 색인을 갱신하고 안전 업그레이드 계획만 만듭니다. 실제 설치는 최고 관리자 확인 후에만 실행됩니다.', 'Checking refreshes package indexes and creates a safe-upgrade plan. Installation runs only after chief-admin confirmation.')}
      </p>
    </div>
  );
}
