#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const environment = { ...process.env };

function ensurePrivateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${path} must be a real directory`);
  }
  chmodSync(path, 0o700);
}

function ensurePrivateSecret(path, bytes) {
  try {
    const descriptor = openSync(path, 'wx', 0o600);
    try {
      writeFileSync(descriptor, `${randomBytes(bytes).toString('base64url')}\n`, 'utf8');
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    if (!error || typeof error !== 'object' || error.code !== 'EEXIST') throw error;
  }

  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${path} must be a private regular file`);
  }
}

if (environment.PORTFOLIO_AUTH_MODE === 'local') {
  const runtimeRoot = join(repositoryRoot, '.runtime', 'monitor-dev');
  const authDirectory = join(runtimeRoot, 'auth');
  const dataDirectory = join(runtimeRoot, 'data');
  const passwordFile = join(runtimeRoot, 'password');
  const sessionSecretFile = join(runtimeRoot, 'session-secret');
  let generatedPasswordFile = null;

  for (const path of [runtimeRoot, authDirectory, dataDirectory]) ensurePrivateDirectory(path);

  if (!environment.MONITOR_PASSWORD_FILE && !environment.MONITOR_PASSWORD) {
    ensurePrivateSecret(passwordFile, 24);
    environment.MONITOR_PASSWORD_FILE = passwordFile;
    generatedPasswordFile = passwordFile;
  }
  if (!environment.MONITOR_SESSION_SECRET_FILE && !environment.MONITOR_SESSION_SECRET) {
    ensurePrivateSecret(sessionSecretFile, 32);
    environment.MONITOR_SESSION_SECRET_FILE = sessionSecretFile;
  }

  environment.MONITOR_AUTH_STATE_FILE ||= join(authDirectory, 'password.json');
  environment.MONITOR_DATA_DIR ||= dataDirectory;
  environment.MONITOR_ALLOWED_ORIGINS ||= 'http://127.0.0.1:5173,http://localhost:5173';
  environment.HOST ||= '127.0.0.1';

  if (generatedPasswordFile) {
    process.stdout.write(
      `Monitor local authentication is enabled; the generated bootstrap password is stored in ${generatedPasswordFile}\n`,
    );
  } else {
    process.stdout.write('Monitor local authentication is enabled with caller-supplied credentials\n');
  }
}

const result = spawnSync('npm', ['run', 'dev:raw'], {
  cwd: repositoryRoot,
  env: environment,
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.signal) process.kill(process.pid, result.signal);
process.exitCode = result.status ?? 1;
