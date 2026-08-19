import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

const MAX_SECRET_FILE_BYTES = 64 * 1024;

export interface RuntimeConfig {
  getBootstrapPassword: () => string;
  authStateFile: string;
  sessionSecret: string;
  dataDir: string;
  sessionTtlMs: number;
  staleAfterMs: number;
  allowedOrigins: string[];
}

export interface ConfigOverrides {
  password?: string;
  authStateFile?: string;
  sessionSecret?: string;
  dataDir?: string;
  sessionTtlMs?: number;
  staleAfterMs?: number;
  allowedOrigins?: string[];
}

function secretFromEnvironment(fileName: string, valueName: string): string | undefined {
  const file = process.env[fileName];
  if (file) {
    const stat = statSync(file);
    if (!stat.isFile() || stat.size > MAX_SECRET_FILE_BYTES) {
      throw new Error(`${fileName} must reference a small regular file`);
    }
    const value = readFileSync(file, 'utf8').replace(/[\r\n]+$/, '');
    if (!value) throw new Error(`${fileName} is empty`);
    return value;
  }
  return process.env[valueName];
}

function positiveInteger(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadConfig(overrides: ConfigOverrides = {}): RuntimeConfig {
  const sessionSecret = overrides.sessionSecret
    ?? secretFromEnvironment('MONITOR_SESSION_SECRET_FILE', 'MONITOR_SESSION_SECRET');

  if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
    throw new Error('Monitor session secret must contain at least 32 bytes');
  }

  return {
    getBootstrapPassword: () => {
      const password = overrides.password
        ?? secretFromEnvironment('MONITOR_PASSWORD_FILE', 'MONITOR_PASSWORD');
      if (!password) throw new Error('Monitor bootstrap password is not configured');
      return password;
    },
    authStateFile: resolve(
      overrides.authStateFile
        ?? process.env.MONITOR_AUTH_STATE_FILE
        ?? '/var/lib/monitor-auth/password.json',
    ),
    sessionSecret,
    dataDir: resolve(overrides.dataDir ?? process.env.MONITOR_DATA_DIR ?? '/data'),
    sessionTtlMs: Math.max(1_000, Math.min(
      overrides.sessionTtlMs
        ?? positiveInteger(process.env.MONITOR_SESSION_TTL_SECONDS, 60 * 60) * 1_000,
      24 * 60 * 60 * 1_000,
    )),
    staleAfterMs: overrides.staleAfterMs
      ?? positiveInteger(process.env.MONITOR_STALE_AFTER_SECONDS, 5 * 60) * 1_000,
    allowedOrigins: overrides.allowedOrigins
      ?? (process.env.MONITOR_ALLOWED_ORIGINS ?? '')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
  };
}
