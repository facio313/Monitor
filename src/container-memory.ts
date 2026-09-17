import type { ContainerStatus } from './types';

/** Raw usage is retained; cache-unavailable samples keep the conservative total. */
export function containerMemoryBytes(container: ContainerStatus): number | null {
  const working = container.memoryWorkingSetBytes;
  const raw = container.memoryBytes;
  return typeof working === 'number' && Number.isFinite(working) && working >= 0
    && typeof raw === 'number' && working <= raw ? working : raw;
}

export function containerMemoryPercent(container: ContainerStatus): number | null {
  const bytes = containerMemoryBytes(container);
  const limit = container.memoryLimitBytes;
  if (typeof bytes === 'number' && typeof limit === 'number' && limit > 0) return 100 * bytes / limit;
  return container.memoryPercent;
}
