import { useEffect, useRef, type CSSProperties } from 'react';
import type { SystemEmotionAxisKey, SystemEmotionModel, SystemMood } from '../system-emotion';
import type { DashboardPayload, MonitorLocale, MonitorPage } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';

interface SystemEmotionEngineProps {
  data: DashboardPayload | null;
  locale: MonitorLocale;
  model: SystemEmotionModel;
  onNavigate: (page: MonitorPage) => void;
  paused?: boolean;
}

type PointerField = { x: number; y: number; active: boolean };

const AXIS_LABELS: Record<SystemEmotionAxisKey, readonly [string, string]> = {
  compute: ['연산', 'Compute'],
  memory: ['메모리', 'Memory'],
  thermal: ['열·전원', 'Thermal'],
  network: ['네트워크', 'Network'],
  storage: ['저장', 'Storage'],
  services: ['서비스', 'Services'],
  reliability: ['신뢰성', 'Reliability'],
};

const MOOD_COPY: Record<SystemMood, {
  code: string;
  title: readonly [string, string];
  summary: readonly [string, string];
}> = {
  dormant: {
    code: 'SIGNAL / LOW',
    title: ['신호를 기다리는 중', 'Listening for signal'],
    summary: ['관측 흐름이 끊겼거나 아직 첫 표본이 없습니다. 고요함을 정상으로 해석하지 않습니다.', 'The observation stream is delayed or has not started. Silence is not treated as health.'],
  },
  serene: {
    code: 'STATE / SERENE',
    title: ['고요한 정상 상태', 'Systems in quiet balance'],
    summary: ['주요 계통이 서로 어긋나지 않고 낮은 진폭으로 흐르고 있습니다.', 'Primary systems are moving together with low amplitude and little friction.'],
  },
  watchful: {
    code: 'STATE / WATCHFUL',
    title: ['잔잔한 긴장', 'Quietly watchful'],
    summary: ['즉시 장애는 아니지만 한 계통의 파형이 평상시보다 선명해졌습니다.', 'No immediate failure is evident, but one subsystem is speaking more loudly than usual.'],
  },
  strained: {
    code: 'STATE / STRAINED',
    title: ['흐름이 거칠어지는 중', 'Rising turbulence'],
    summary: ['여러 신호가 겹치며 균형이 흐트러지고 있습니다. 지배 계통을 먼저 확인하세요.', 'Several signals are converging and balance is falling. Inspect the dominant subsystem first.'],
  },
  critical: {
    code: 'STATE / CRITICAL',
    title: ['즉시 확인할 파동', 'Critical disturbance'],
    summary: ['위험 신호가 전체 흐름을 바꾸고 있습니다. 시각 효과보다 연결된 운영 근거를 우선하세요.', 'A danger signal is reshaping the whole field. Follow the linked operational evidence now.'],
  },
};

function t(locale: MonitorLocale, pair: readonly [string, string]): string {
  return locale === 'ko' ? pair[0] : pair[1];
}

function clamp(value: number, minimum = 0, maximum = 1): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function rgb(hex: string): [number, number, number] {
  const value = hex.replace('#', '');
  if (!/^[0-9a-f]{6}$/i.test(value)) return [255, 255, 255];
  return [
    Number.parseInt(value.slice(0, 2), 16),
    Number.parseInt(value.slice(2, 4), 16),
    Number.parseInt(value.slice(4, 6), 16),
  ];
}

function rgba(hex: string, alpha: number): string {
  const [red, green, blue] = rgb(hex);
  return `rgba(${red}, ${green}, ${blue}, ${clamp(alpha)})`;
}

function seeded(index: number, salt: number): number {
  const value = Math.sin(index * 91.733 + salt * 47.117) * 43758.5453;
  return value - Math.floor(value);
}

function drawEmotionField(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  elapsedSeconds: number,
  model: SystemEmotionModel,
  pointer: PointerField,
  reducedMotion: boolean,
) {
  const { palette } = model;
  const time = reducedMotion ? 1.7 : elapsedSeconds;
  const coreX = width < 720 ? width * 0.52 : width * 0.69;
  const coreY = width < 720 ? height * 0.31 : height * 0.5;
  const pointerX = pointer.active ? (pointer.x - 0.5) * width * 0.045 : 0;
  const pointerY = pointer.active ? (pointer.y - 0.5) * height * 0.055 : 0;
  const fieldX = coreX + pointerX;
  const fieldY = coreY + pointerY;
  const breath = reducedMotion ? 0.5 : (Math.sin((time / model.tempoSeconds) * Math.PI * 2) + 1) / 2;

  context.clearRect(0, 0, width, height);
  const backdrop = context.createLinearGradient(0, 0, width, height);
  backdrop.addColorStop(0, rgba(palette.background, 0.98));
  backdrop.addColorStop(0.58, rgba(palette.background, 0.82));
  backdrop.addColorStop(1, '#030807');
  context.fillStyle = backdrop;
  context.fillRect(0, 0, width, height);

  const halo = context.createRadialGradient(fieldX, fieldY, 2, fieldX, fieldY, Math.max(width, height) * 0.56);
  halo.addColorStop(0, rgba(palette.primary, 0.19 + breath * 0.08));
  halo.addColorStop(0.24, rgba(palette.secondary, 0.1 + model.energy * 0.07));
  halo.addColorStop(0.62, rgba(palette.primary, 0.025));
  halo.addColorStop(1, rgba(palette.background, 0));
  context.fillStyle = halo;
  context.fillRect(0, 0, width, height);

  context.save();
  context.globalCompositeOperation = 'screen';
  const ribbons = 5;
  for (let ribbon = 0; ribbon < ribbons; ribbon += 1) {
    const base = height * (0.39 + ribbon * 0.105);
    const amplitude = height * (0.016 + model.waveAmplitude * (0.026 + ribbon * 0.006));
    const frequency = 0.0085 + ribbon * 0.0014;
    const speed = (0.34 + ribbon * 0.08) * (0.5 + model.energy);
    context.beginPath();
    context.moveTo(-12, height + 12);
    for (let x = -12; x <= width + 12; x += Math.max(6, width / 180)) {
      const distance = Math.abs(x - fieldX) / Math.max(1, width);
      const envelope = 0.48 + Math.max(0, 1 - distance * 2.2) * 0.72;
      const primary = Math.sin(x * frequency + time * speed + ribbon * 1.3);
      const interference = Math.sin(x * frequency * 2.17 - time * speed * 0.64 + ribbon) * model.turbulence;
      const fine = Math.cos(x * frequency * 4.1 + time * 0.27 + ribbon * 2.2) * model.energy * 0.28;
      const y = base + (primary + interference * 0.72 + fine) * amplitude * envelope;
      context.lineTo(x, y);
    }
    context.lineTo(width + 12, height + 12);
    context.closePath();
    const ribbonGradient = context.createLinearGradient(0, base - amplitude, 0, height);
    const color = ribbon % 2 ? palette.secondary : palette.primary;
    ribbonGradient.addColorStop(0, rgba(color, 0.035 + model.energy * 0.04));
    ribbonGradient.addColorStop(0.38, rgba(color, 0.012));
    ribbonGradient.addColorStop(1, rgba(color, 0));
    context.fillStyle = ribbonGradient;
    context.fill();
    context.strokeStyle = rgba(color, 0.12 + ribbon * 0.015 + model.turbulence * 0.12);
    context.lineWidth = 0.7 + ribbon * 0.18;
    context.stroke();
  }
  context.restore();

  const coreRadius = Math.min(width, height) * (0.082 + model.energy * 0.018 + breath * 0.009);
  context.save();
  context.translate(fieldX, fieldY);
  context.globalCompositeOperation = 'screen';
  const rings = 4;
  for (let ring = rings; ring >= 1; ring -= 1) {
    const radius = coreRadius * (0.72 + ring * 0.34 + breath * 0.06);
    context.beginPath();
    context.arc(0, 0, radius, time * (0.09 + ring * 0.018), Math.PI * (1.12 + ring * 0.28));
    context.strokeStyle = rgba(ring % 2 ? palette.primary : palette.secondary, 0.09 + (rings - ring) * 0.055);
    context.lineWidth = Math.max(0.7, 2.5 - ring * 0.35);
    context.stroke();
  }
  const core = context.createRadialGradient(-coreRadius * 0.18, -coreRadius * 0.24, 1, 0, 0, coreRadius * 1.45);
  core.addColorStop(0, rgba(palette.accent, 0.94));
  core.addColorStop(0.12, rgba(palette.primary, 0.72));
  core.addColorStop(0.46, rgba(palette.secondary, 0.2));
  core.addColorStop(1, rgba(palette.primary, 0));
  context.fillStyle = core;
  context.beginPath();
  context.arc(0, 0, coreRadius * 1.45, 0, Math.PI * 2);
  context.fill();

  const particleLimit = reducedMotion ? Math.min(12, model.particleCount) : model.particleCount;
  for (let index = 0; index < particleLimit; index += 1) {
    const distance = coreRadius * (1.35 + seeded(index, 1) * 3.8);
    const velocity = 0.018 + seeded(index, 2) * 0.055 + model.turbulence * 0.045;
    const angle = seeded(index, 3) * Math.PI * 2 + time * velocity * (index % 2 ? 1 : -1);
    const elliptic = 0.48 + seeded(index, 4) * 0.38;
    const x = Math.cos(angle) * distance;
    const y = Math.sin(angle) * distance * elliptic;
    const size = 0.55 + seeded(index, 5) * 1.65 + model.energy * 0.55;
    context.fillStyle = rgba(index % 3 ? palette.primary : palette.secondary, 0.18 + seeded(index, 6) * 0.42);
    context.beginPath();
    context.arc(x, y, size, 0, Math.PI * 2);
    context.fill();
  }
  context.restore();

  context.save();
  context.globalCompositeOperation = 'screen';
  context.strokeStyle = rgba(palette.warning, 0.08 + model.turbulence * 0.16);
  context.lineWidth = 1;
  const disturbanceCount = 2 + Math.round(model.turbulence * 3);
  for (let ring = 0; ring < disturbanceCount; ring += 1) {
    const phase = (time * (0.08 + model.turbulence * 0.08) + ring / disturbanceCount) % 1;
    const radius = coreRadius * (1.5 + phase * 5.4);
    context.globalAlpha = (1 - phase) * (0.34 + model.turbulence * 0.45);
    context.beginPath();
    context.ellipse(fieldX, fieldY, radius, radius * 0.55, 0, 0, Math.PI * 2);
    context.stroke();
  }
  context.restore();
}

export function emotionThemeStyle(model: SystemEmotionModel): CSSProperties {
  return {
    '--emotion-bg': model.palette.background,
    '--emotion-primary': model.palette.primary,
    '--emotion-secondary': model.palette.secondary,
    '--emotion-accent': model.palette.accent,
    '--emotion-warning': model.palette.warning,
    '--emotion-primary-soft': rgba(model.palette.primary, 0.13),
    '--emotion-secondary-soft': rgba(model.palette.secondary, 0.1),
    '--emotion-warning-soft': rgba(model.palette.warning, 0.15),
    '--emotion-tempo': `${model.tempoSeconds.toFixed(2)}s`,
    '--emotion-turbulence': model.turbulence.toFixed(3),
  } as CSSProperties;
}

function moodMetric(value: number): string {
  return `${Math.round(clamp(value) * 100).toString().padStart(2, '0')}%`;
}

export function SystemEmotionEngine({ data, locale, model, onNavigate, paused = false }: SystemEmotionEngineProps) {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerRef = useRef<PointerField>({ x: 0.5, y: 0.5, active: false });
  const originRef = useRef<number | null>(null);
  const copy = MOOD_COPY[model.mood];
  const dominantLabel = model.dominantAxis
    ? t(locale, AXIS_LABELS[model.dominantAxis])
    : locale === 'ko' ? '없음' : 'None';

  useEffect(() => {
    const root = rootRef.current;
    const canvas = canvasRef.current;
    if (!root || !canvas) return undefined;
    const context = canvas.getContext('2d', { alpha: false });
    if (!context) return undefined;
    const motionQuery = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    let reducedMotion = motionQuery?.matches ?? false;
    let animationFrame = 0;
    let disposed = false;
    let width = 1;
    let height = 1;
    let lastPaint = 0;
    let intersecting = true;
    if (originRef.current === null) originRef.current = performance.now();
    const origin = originRef.current;

    const canAnimate = () => !reducedMotion && !document.hidden && intersecting && !paused;
    const syncAnimationState = () => {
      root.dataset.animationPaused = canAnimate() ? 'false' : 'true';
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      width = Math.max(1, bounds.width);
      height = Math.max(1, bounds.height);
      const coarsePointer = window.matchMedia?.('(pointer: coarse)').matches ?? false;
      const deviceScale = Math.min(window.devicePixelRatio || 1, coarsePointer ? 1.25 : 1.6);
      canvas.width = Math.max(1, Math.round(width * deviceScale));
      canvas.height = Math.max(1, Math.round(height * deviceScale));
      context.setTransform(deviceScale, 0, 0, deviceScale, 0, 0);
      drawEmotionField(context, width, height, (performance.now() - origin) / 1_000, model, pointerRef.current, reducedMotion);
    };

    const paint = (now: number) => {
      if (disposed) return;
      if (canAnimate() && now - lastPaint >= 42) {
        lastPaint = now;
        drawEmotionField(context, width, height, (now - origin) / 1_000, model, pointerRef.current, reducedMotion);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      reducedMotion = motionQuery?.matches ?? false;
      syncAnimationState();
      if (!document.hidden && intersecting && !paused) {
        drawEmotionField(context, width, height, (performance.now() - origin) / 1_000, model, pointerRef.current, reducedMotion);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };
    const onVisibility = () => restart();
    const onPointerMove = (event: PointerEvent) => {
      const bounds = root.getBoundingClientRect();
      pointerRef.current = {
        x: clamp((event.clientX - bounds.left) / Math.max(1, bounds.width)),
        y: clamp((event.clientY - bounds.top) / Math.max(1, bounds.height)),
        active: event.pointerType !== 'touch',
      };
    };
    const onPointerLeave = () => { pointerRef.current = { x: 0.5, y: 0.5, active: false }; };

    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(resize) : null;
    const intersectionObserver = typeof IntersectionObserver === 'function'
      ? new IntersectionObserver(([entry]) => {
        intersecting = entry?.isIntersecting ?? false;
        restart();
      }, { rootMargin: '120px 0px' })
      : null;
    observer?.observe(canvas);
    intersectionObserver?.observe(root);
    window.addEventListener('resize', resize, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    root.addEventListener('pointermove', onPointerMove, { passive: true });
    root.addEventListener('pointerleave', onPointerLeave, { passive: true });
    motionQuery?.addEventListener?.('change', restart);
    resize();
    restart();

    return () => {
      disposed = true;
      window.cancelAnimationFrame(animationFrame);
      observer?.disconnect();
      intersectionObserver?.disconnect();
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
      root.removeEventListener('pointermove', onPointerMove);
      root.removeEventListener('pointerleave', onPointerLeave);
      motionQuery?.removeEventListener?.('change', restart);
    };
  }, [model, paused]);

  return (
    <section
      ref={rootRef}
      className={`system-emotion-engine emotion-${model.mood}`}
      style={emotionThemeStyle(model)}
      aria-labelledby="system-emotion-title"
      data-mood={model.mood}
    >
      <canvas ref={canvasRef} className="system-emotion-canvas" aria-hidden="true" />
      <div className="system-emotion-grain" aria-hidden="true" />
      <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {t(locale, copy.title)}. {locale === 'ko' ? `지배 신호 ${dominantLabel}` : `Dominant signal ${dominantLabel}`}.
      </p>
      <header className="emotion-engine-header">
        <span><i aria-hidden="true" />{locale === 'ko' ? '시스템 감응 · 실시간 합성' : 'SYSTEM AFFECT · LIVE SYNTHESIS'}</span>
        <span className="emotion-engine-sample">{safeText(data?.host.hostname, 'HOST', 40)} · {formatDateTime(data?.latestObservedAt, locale)}</span>
      </header>

      <div className="emotion-engine-copy">
        <span className="emotion-state-code">{copy.code}</span>
        <h2 id="system-emotion-title">{t(locale, copy.title)}</h2>
        <p>{t(locale, copy.summary)}</p>
        {model.dominantPage ? (
          <button type="button" onClick={() => onNavigate(model.dominantPage!)}>
            <span>{locale === 'ko' ? `지배 신호 · ${dominantLabel}` : `Dominant signal · ${dominantLabel}`}</span>
            <Icon name="chevron" size={16} />
          </button>
        ) : (
          <span className="emotion-balanced-state">{locale === 'ko' ? '계통 균형 · 지배 신호 없음' : 'Systems balanced · no dominant signal'}</span>
        )}
      </div>

      <div className="emotion-engine-readings" aria-label={locale === 'ko' ? '합성 상태 수치' : 'Synthesized state readings'}>
        <div><span>{locale === 'ko' ? '균형도' : 'BALANCE'}</span><strong>{model.score.toString().padStart(2, '0')}</strong></div>
        <div><span>{locale === 'ko' ? '활성' : 'ENERGY'}</span><strong>{moodMetric(model.energy)}</strong></div>
        <div><span>{locale === 'ko' ? '난류' : 'TURBULENCE'}</span><strong>{moodMetric(model.turbulence)}</strong></div>
        <div><span>{locale === 'ko' ? '결맞음' : 'COHERENCE'}</span><strong>{moodMetric(model.coherence)}</strong></div>
      </div>

      <div className="emotion-axis-field" aria-label={locale === 'ko' ? '계통별 신호 강도' : 'Subsystem signal intensity'}>
        {model.axes.map((axis) => (
          <div key={axis.key} className={axis.key === model.dominantAxis ? 'dominant' : ''}>
            <span>{t(locale, AXIS_LABELS[axis.key])}</span>
            <i aria-hidden="true"><b style={{ '--axis-level': axis.intensity.toFixed(3) } as CSSProperties} /></i>
            <strong>{axis.observed ? Math.round(axis.intensity * 100).toString().padStart(2, '0') : '—'}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
