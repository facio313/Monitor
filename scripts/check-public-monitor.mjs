#!/usr/bin/env node

import { pathToFileURL } from 'node:url';

const DEFAULT_TARGET = 'https://bonifacio.work/monitor/';
const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_ATTEMPTS = 3;
const MAX_READINESS_BODY_BYTES = 256;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export class PublicMonitorProbeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PublicMonitorProbeError';
    this.code = code;
  }
}

function exactPositiveInteger(value, fallback, maximum) {
  if (value === undefined || value === '') return fallback;
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe numeric configuration is invalid');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe numeric configuration is out of range');
  }
  return parsed;
}

export function probeConfiguration(environment = process.env) {
  let target;
  try {
    target = new URL(environment.MONITOR_PUBLIC_URL || DEFAULT_TARGET);
  } catch {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'MONITOR_PUBLIC_URL is invalid');
  }
  const allowHttpForTests = environment.MONITOR_PROBE_ALLOW_HTTP === '1';
  if (target.username || target.password || target.hash) {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe URL must not contain credentials or a fragment');
  }
  if (target.protocol !== 'https:' && !(allowHttpForTests && target.protocol === 'http:')) {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe URL must use HTTPS');
  }
  if (!allowHttpForTests && target.hostname !== 'bonifacio.work') {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe URL must use the canonical Monitor host');
  }
  if (target.pathname !== '/monitor/' || target.search) {
    throw new PublicMonitorProbeError('CONFIG_INVALID', 'Probe URL must end at the canonical /monitor/ route');
  }
  return {
    target,
    readinessTarget: new URL('readyz', target),
    timeoutMs: exactPositiveInteger(environment.MONITOR_PROBE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 30_000),
    attempts: exactPositiveInteger(environment.MONITOR_PROBE_ATTEMPTS, DEFAULT_ATTEMPTS, 5),
  };
}

async function boundedResponseBody(response, maximumBytes = MAX_READINESS_BODY_BYTES) {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength)
      || Number(declaredLength) > maximumBytes)) {
    throw new PublicMonitorProbeError('BODY_INVALID', 'Readiness response body is oversized');
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw new PublicMonitorProbeError('BODY_INVALID', 'Readiness response body is oversized');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(body);
}

export async function validateReadiness(response) {
  if (response.status !== 200) {
    throw new PublicMonitorProbeError('READINESS_STATUS_INVALID', `Expected Monitor readiness, received HTTP ${response.status}`);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) {
    throw new PublicMonitorProbeError('CONTENT_TYPE_INVALID', 'Readiness response is not JSON');
  }
  const cacheControl = response.headers.get('cache-control') ?? '';
  if (!/(?:^|,)\s*no-store\s*(?:,|$)/iu.test(cacheControl)) {
    throw new PublicMonitorProbeError('CACHE_POLICY_INVALID', 'Readiness response is not explicitly uncacheable');
  }
  let value;
  try {
    value = JSON.parse(await boundedResponseBody(response));
  } catch (error) {
    if (error instanceof PublicMonitorProbeError) throw error;
    throw new PublicMonitorProbeError('BODY_INVALID', 'Readiness response body is invalid JSON');
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).length !== 1
    || value.status !== 'ready'
  ) {
    throw new PublicMonitorProbeError('BODY_INVALID', 'Readiness response did not contain the exact ready contract');
  }
}

export function validateSsoRedirect(target, response) {
  if (!REDIRECT_STATUSES.has(response.status)) {
    throw new PublicMonitorProbeError('STATUS_INVALID', `Expected an SSO redirect, received HTTP ${response.status}`);
  }
  const rawLocation = response.headers.get('location');
  if (!rawLocation) {
    throw new PublicMonitorProbeError('REDIRECT_MISSING', 'SSO redirect did not include a Location header');
  }
  let location;
  try {
    location = new URL(rawLocation, target);
  } catch {
    throw new PublicMonitorProbeError('REDIRECT_INVALID', 'SSO redirect Location is invalid');
  }
  if (
    location.protocol !== target.protocol
    || location.host !== target.host
    || location.pathname !== '/sso/'
  ) {
    throw new PublicMonitorProbeError('REDIRECT_INVALID', 'SSO redirect left the expected origin or path');
  }
  if (location.searchParams.get('rd') !== target.href || location.searchParams.get('rm') !== 'GET') {
    throw new PublicMonitorProbeError('REDIRECT_INVALID', 'SSO redirect did not preserve the exact Monitor return target');
  }
  const allowedKeys = new Set(['rd', 'rm']);
  if ([...location.searchParams.keys()].some((key) => !allowedKeys.has(key))) {
    throw new PublicMonitorProbeError('REDIRECT_INVALID', 'SSO redirect included an unexpected query parameter');
  }
  return location.href;
}

function boundedFailure(error) {
  if (error instanceof PublicMonitorProbeError) return error;
  if (error instanceof Error && error.name === 'TimeoutError') {
    return new PublicMonitorProbeError('TIMEOUT', 'Public Monitor probe timed out');
  }
  if (error instanceof Error && error.name === 'AbortError') {
    return new PublicMonitorProbeError('TIMEOUT', 'Public Monitor probe timed out');
  }
  return new PublicMonitorProbeError('NETWORK_FAILURE', 'Public Monitor probe failed before a valid response');
}

export async function runPublicMonitorProbe(configuration, fetcher = fetch, now = Date.now) {
  const startedAt = now();
  let lastFailure = null;
  for (let attempt = 1; attempt <= configuration.attempts; attempt += 1) {
    const attemptStartedAt = now();
    try {
      const requestOptions = {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(configuration.timeoutMs),
        headers: {
          'user-agent': 'monitor-external-dead-man/1',
        },
      };
      const readinessResponse = await fetcher(configuration.readinessTarget, {
        ...requestOptions,
        headers: { ...requestOptions.headers, accept: 'application/json' },
      });
      await validateReadiness(readinessResponse);
      const ssoResponse = await fetcher(configuration.target, {
        ...requestOptions,
        headers: { ...requestOptions.headers, accept: 'text/html,application/xhtml+xml' },
      });
      const redirect = validateSsoRedirect(configuration.target, ssoResponse);
      return {
        schemaVersion: 1,
        status: 'ok',
        checkedAt: new Date(now()).toISOString(),
        target: configuration.target.href,
        readinessTarget: configuration.readinessTarget.href,
        redirect,
        readinessHttpStatus: readinessResponse.status,
        ssoHttpStatus: ssoResponse.status,
        attempts: attempt,
        latencyMilliseconds: Math.max(0, now() - attemptStartedAt),
        totalMilliseconds: Math.max(0, now() - startedAt),
      };
    } catch (error) {
      lastFailure = boundedFailure(error);
      if (attempt < configuration.attempts) {
        const delay = Math.min(4_000, 500 * (2 ** (attempt - 1)));
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  throw lastFailure ?? new PublicMonitorProbeError('NETWORK_FAILURE', 'Public Monitor probe failed');
}

export async function main(environment = process.env) {
  try {
    const result = await runPublicMonitorProbe(probeConfiguration(environment));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const failure = boundedFailure(error);
    process.stderr.write(`${JSON.stringify({
      schemaVersion: 1,
      status: 'error',
      code: failure.code,
      message: failure.message,
      checkedAt: new Date().toISOString(),
    })}\n`);
    return 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (import.meta.url === invokedPath) {
  process.exitCode = await main();
}
