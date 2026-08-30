import {
  closeSync,
  constants as fileConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

const MAX_SECRET_FILE_BYTES = 64 * 1024;
const BUILD_AUTH_CONTRACT_FILE = '/etc/portfolio-auth-build';

interface CommonRuntimeConfig {
  dataDir: string;
  staleAfterMs: number;
  allowedOrigins: string[];
  legacyAuthStateFile: string;
  updateSocketPath: string;
}

export interface SsoRuntimeConfig extends CommonRuntimeConfig {
  ssoEnabled: true;
  edgeSecret: string;
}

export interface LocalRuntimeConfig extends CommonRuntimeConfig {
  ssoEnabled: false;
  edgeSecret: null;
  getBootstrapPassword: () => string;
  authStateFile: string;
  sessionSecret: string;
  sessionTtlMs: number;
}

export type RuntimeConfig = SsoRuntimeConfig | LocalRuntimeConfig;

export interface ConfigOverrides {
  password?: string;
  authStateFile?: string;
  sessionSecret?: string;
  dataDir?: string;
  sessionTtlMs?: number;
  staleAfterMs?: number;
  allowedOrigins?: string[];
  ssoEnabled?: boolean;
  edgeSecret?: string;
  updateSocketPath?: string;
}

function ssoEnabledFromPortfolioContract(): boolean {
  const branch = process.env.PORTFOLIO_BRANCH;
  const authMode = process.env.PORTFOLIO_AUTH_MODE;

  if (!branch || !/^[A-Za-z0-9._/-]+$/u.test(branch)) {
    throw new Error('PORTFOLIO_BRANCH must be provided by scripts/portfolio-auth-mode.sh');
  }
  if (authMode !== 'sso' && authMode !== 'local') {
    throw new Error('PORTFOLIO_AUTH_MODE must be sso or local');
  }

  const expectedMode = branch === 'main' || branch === 'dev' ? 'sso' : 'local';
  if (authMode !== expectedMode) {
    throw new Error(`Portfolio branch ${branch} requires ${expectedMode} authentication`);
  }

  if (existsSync(BUILD_AUTH_CONTRACT_FILE)) {
    const contract = readFileSync(BUILD_AUTH_CONTRACT_FILE, 'utf8');
    const expectedContract = `${branch}\n${authMode}\n`;
    if (contract !== expectedContract) {
      throw new Error('Runtime authentication contract does not match the image build contract');
    }
  }

  const legacyMode = process.env.MONITOR_SSO_ENABLED;
  if (legacyMode !== undefined) {
    const normalized = legacyMode.trim().toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
      throw new Error('MONITOR_SSO_ENABLED must be true or false when provided');
    }
    if ((normalized === 'true') !== (authMode === 'sso')) {
      throw new Error('MONITOR_SSO_ENABLED conflicts with PORTFOLIO_AUTH_MODE');
    }
  }

  return authMode === 'sso';
}

function secretFromEnvironment(fileName: string, valueName: string): string | undefined {
  const file = process.env[fileName];
  if (file) {
    const before = lstatSync(file);
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.size > MAX_SECRET_FILE_BYTES
      || (before.mode & 0o077) !== 0
    ) {
      throw new Error(`${fileName} must reference a private small regular file`);
    }
    const descriptor = openSync(file, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
    let value: string;
    try {
      const opened = fstatSync(descriptor);
      if (before.dev !== opened.dev || before.ino !== opened.ino || opened.size > MAX_SECRET_FILE_BYTES) {
        throw new Error(`${fileName} changed while it was opened`);
      }
      value = readFileSync(descriptor, 'utf8').replace(/[\r\n]+$/, '');
    } finally {
      closeSync(descriptor);
    }
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
  // ssoEnabled remains an explicit dependency-injection seam for unit tests.
  // Real process startup must use the repository-wide branch contract.
  const ssoEnabled = overrides.ssoEnabled ?? ssoEnabledFromPortfolioContract();
  const common = {
    dataDir: resolve(overrides.dataDir ?? process.env.MONITOR_DATA_DIR ?? '/data'),
    staleAfterMs: overrides.staleAfterMs
      ?? positiveInteger(process.env.MONITOR_STALE_AFTER_SECONDS, 5 * 60) * 1_000,
    allowedOrigins: overrides.allowedOrigins
      ?? (process.env.MONITOR_ALLOWED_ORIGINS ?? '')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
    legacyAuthStateFile: resolve(
      overrides.authStateFile
        ?? process.env.MONITOR_AUTH_STATE_FILE
        ?? '/var/lib/monitor-auth/password.json',
    ),
    updateSocketPath: resolve(
      overrides.updateSocketPath
        ?? process.env.MONITOR_UPDATE_SOCKET
        ?? '/run/monitor-update/gateway.sock',
    ),
  };

  if (ssoEnabled) {
    const edgeSecret = overrides.edgeSecret
      ?? secretFromEnvironment('MONITOR_EDGE_SECRET_FILE', 'MONITOR_EDGE_SECRET');
    if (!edgeSecret || Buffer.byteLength(edgeSecret) < 32) {
      throw new Error('Monitor edge secret must contain at least 32 bytes when SSO is enabled');
    }
    return { ...common, ssoEnabled: true, edgeSecret };
  }

  const sessionSecret = overrides.sessionSecret
    ?? secretFromEnvironment('MONITOR_SESSION_SECRET_FILE', 'MONITOR_SESSION_SECRET');
  if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
    throw new Error('Monitor session secret must contain at least 32 bytes');
  }

  return {
    ...common,
    ssoEnabled: false,
    edgeSecret: null,
    getBootstrapPassword: () => {
      const password = overrides.password
        ?? secretFromEnvironment('MONITOR_PASSWORD_FILE', 'MONITOR_PASSWORD');
      if (!password) throw new Error('Monitor bootstrap password is not configured');
      return password;
    },
    authStateFile: common.legacyAuthStateFile,
    sessionSecret,
    sessionTtlMs: Math.max(1_000, Math.min(
      overrides.sessionTtlMs
        ?? positiveInteger(process.env.MONITOR_SESSION_TTL_SECONDS, 60 * 60) * 1_000,
      24 * 60 * 60 * 1_000,
    )),
  };
}
