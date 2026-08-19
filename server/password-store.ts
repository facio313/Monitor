import {
  constants,
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { basename, dirname, resolve } from 'node:path';

const STATE_VERSION = 1;
const MAX_STATE_BYTES = 4 * 1024;
const SCRYPT_N = 65_536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 32;
const SCRYPT_MAX_MEMORY = 96 * 1024 * 1024;
const SALT_BYTES = 16;
const SESSION_EPOCH_BYTES = 32;
const MAX_PENDING_OPERATIONS = 8;

interface PasswordState {
  version: 1;
  password: {
    algorithm: 'scrypt';
    n: number;
    r: number;
    p: number;
    keyLength: number;
    salt: string;
    digest: string;
  };
  sessionEpoch: string;
}

export type PasswordChangeResult = 'changed' | 'rejected';

export interface PasswordStoreOptions {
  syncDirectory?: (directory: string) => void;
  onDurabilityWarning?: () => void;
}

export class PasswordStoreBusyError extends Error {
  constructor() {
    super('Monitor authentication work queue is full');
    this.name = 'PasswordStoreBusyError';
  }
}

function decodeBase64Url(value: unknown, expectedBytes: number): Buffer | null {
  if (
    typeof value !== 'string'
    || !/^[A-Za-z0-9_-]+$/.test(value)
    || value.length > Math.ceil(expectedBytes * 4 / 3) + 1
  ) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === expectedBytes ? decoded : null;
}

function parseState(serialized: string): PasswordState {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error('Monitor authentication state is not valid JSON');
  }
  if (!value || typeof value !== 'object') {
    throw new Error('Monitor authentication state has an invalid shape');
  }
  const state = value as Partial<PasswordState>;
  const password = state.password;
  if (
    state.version !== STATE_VERSION
    || !password
    || password.algorithm !== 'scrypt'
    || password.n !== SCRYPT_N
    || password.r !== SCRYPT_R
    || password.p !== SCRYPT_P
    || password.keyLength !== SCRYPT_KEY_LENGTH
    || !decodeBase64Url(password.salt, SALT_BYTES)
    || !decodeBase64Url(password.digest, SCRYPT_KEY_LENGTH)
    || !decodeBase64Url(state.sessionEpoch, SESSION_EPOCH_BYTES)
  ) {
    throw new Error('Monitor authentication state is invalid or unsupported');
  }
  return state as PasswordState;
}

function validateStateDirectory(filePath: string): string {
  const directory = dirname(filePath);
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('Monitor authentication state directory must be a real directory');
  }
  if ((stat.mode & 0o777) !== 0o700) {
    throw new Error('Monitor authentication state directory permissions must be 0700');
  }
  if (realpathSync.native(directory) !== directory) {
    throw new Error('Monitor authentication state directory must not contain symlinks');
  }
  return directory;
}

function validateExistingStateFile(filePath: string): void {
  const stat = lstatSync(filePath);
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.size < 1
    || stat.size > MAX_STATE_BYTES
  ) {
    throw new Error('Monitor authentication state must be a small, unlinked regular file');
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error('Monitor authentication state permissions must not allow group or other access');
  }
}

function readStateFile(filePath: string): PasswordState {
  validateStateDirectory(filePath);
  validateExistingStateFile(filePath);
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || stat.size < 1
      || stat.size > MAX_STATE_BYTES
      || (stat.mode & 0o077) !== 0
    ) {
      throw new Error('Monitor authentication state changed while it was being opened');
    }
    return parseState(readFileSync(descriptor, 'utf8'));
  } finally {
    closeSync(descriptor);
  }
}

function stateFileExists(filePath: string): boolean {
  try {
    lstatSync(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function syncDirectory(directory: string): void {
  const descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function atomicWriteState(
  filePath: string,
  state: PasswordState,
  directorySync: (directory: string) => void,
): boolean {
  const directory = validateStateDirectory(filePath);
  if (stateFileExists(filePath)) validateExistingStateFile(filePath);

  const serialized = `${JSON.stringify(state)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > MAX_STATE_BYTES) {
    throw new Error('Monitor authentication state exceeds its size limit');
  }

  const temporaryPath = resolve(
    directory,
    `.${basename(filePath)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`,
  );
  let descriptor: number | undefined;
  let renamed = false;
  try {
    descriptor = openSync(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, serialized, { encoding: 'utf8' });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporaryPath, filePath);
    renamed = true;
    try {
      directorySync(directory);
      return true;
    } catch {
      // rename(2) already committed the new state. A directory fsync failure
      // weakens crash durability but must not split disk and in-memory state.
      return false;
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (!renamed) {
      try {
        unlinkSync(temporaryPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
  }
}

function deriveSync(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, SCRYPT_KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAX_MEMORY,
  });
}

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolvePromise, rejectPromise) => {
    scryptCallback(password, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAX_MEMORY,
    }, (error, key) => {
      if (error) rejectPromise(error);
      else resolvePromise(key);
    });
  });
}

function stateFromDigest(salt: Buffer, passwordDigest: Buffer): PasswordState {
  return {
    version: STATE_VERSION,
    password: {
      algorithm: 'scrypt',
      n: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      keyLength: SCRYPT_KEY_LENGTH,
      salt: salt.toString('base64url'),
      digest: passwordDigest.toString('base64url'),
    },
    sessionEpoch: randomBytes(SESSION_EPOCH_BYTES).toString('base64url'),
  };
}

function newStateSync(password: string): PasswordState {
  const salt = randomBytes(SALT_BYTES);
  return stateFromDigest(salt, deriveSync(password, salt));
}

async function newState(password: string): Promise<PasswordState> {
  const salt = randomBytes(SALT_BYTES);
  return stateFromDigest(salt, await derive(password, salt));
}

function passwordMeetsPolicy(password: unknown): password is string {
  return typeof password === 'string'
    && Buffer.byteLength(password, 'utf8') <= 256
    && [...password].length >= 16;
}

function epochMatches(candidate: unknown, expected: string): boolean {
  const normalized = typeof candidate === 'string' ? candidate : '';
  const candidateDigest = createHash('sha256').update(normalized, 'utf8').digest();
  const expectedDigest = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(candidateDigest, expectedDigest) && typeof candidate === 'string';
}

export class PasswordStore {
  readonly #filePath: string;
  readonly #syncDirectory: (directory: string) => void;
  readonly #onDurabilityWarning: () => void;
  #state: PasswordState;
  #tail: Promise<void> = Promise.resolve();
  #pendingOperations = 0;

  constructor(
    filePath: string,
    getBootstrapPassword: () => string,
    options: PasswordStoreOptions = {},
  ) {
    this.#filePath = resolve(filePath);
    this.#syncDirectory = options.syncDirectory ?? syncDirectory;
    this.#onDurabilityWarning = options.onDurabilityWarning ?? (() => {
      process.stderr.write(
        'Monitor authentication state was committed, but its directory durability sync failed\n',
      );
    });
    validateStateDirectory(this.#filePath);
    if (stateFileExists(this.#filePath)) {
      this.#state = readStateFile(this.#filePath);
    } else {
      const bootstrapPassword = getBootstrapPassword();
      if (!bootstrapPassword) throw new Error('Monitor bootstrap password is not configured');
      const initialState = newStateSync(bootstrapPassword);
      const durable = atomicWriteState(this.#filePath, initialState, this.#syncDirectory);
      this.#state = initialState;
      if (!durable) this.#warnAboutDurability();
    }
  }

  #warnAboutDurability(): void {
    try {
      this.#onDurabilityWarning();
    } catch {
      // A reporting callback cannot turn an already committed credential
      // change into a failed request or recreate a disk/memory split-brain.
    }
  }

  get sessionEpoch(): string {
    return this.#state.sessionEpoch;
  }

  async #exclusive<T>(operation: () => Promise<T>): Promise<T> {
    if (this.#pendingOperations >= MAX_PENDING_OPERATIONS) {
      throw new PasswordStoreBusyError();
    }
    this.#pendingOperations += 1;
    const previous = this.#tail;
    let release!: () => void;
    this.#tail = new Promise<void>((resolvePromise) => {
      release = resolvePromise;
    });
    await previous;
    try {
      return await operation();
    } finally {
      this.#pendingOperations -= 1;
      release();
    }
  }

  async #matches(password: string, state: PasswordState): Promise<boolean> {
    const salt = decodeBase64Url(state.password.salt, SALT_BYTES);
    const expected = decodeBase64Url(state.password.digest, SCRYPT_KEY_LENGTH);
    if (!salt || !expected) return false;
    const supplied = await derive(password, salt);
    return timingSafeEqual(supplied, expected);
  }

  authenticate(candidate: unknown): Promise<string | null> {
    return this.#exclusive(async () => {
      const normalized = typeof candidate === 'string' ? candidate : '';
      const matches = await this.#matches(normalized, this.#state);
      return matches && typeof candidate === 'string' ? this.#state.sessionEpoch : null;
    });
  }

  changePassword(
    currentPassword: unknown,
    nextPassword: unknown,
    authorizedEpoch: unknown,
  ): Promise<PasswordChangeResult> {
    return this.#exclusive(async () => {
      if (!epochMatches(authorizedEpoch, this.#state.sessionEpoch)) return 'rejected';
      const normalizedCurrent = typeof currentPassword === 'string' ? currentPassword : '';
      const currentMatches = await this.#matches(normalizedCurrent, this.#state);
      if (
        !currentMatches
        || !passwordMeetsPolicy(nextPassword)
        || nextPassword === normalizedCurrent
      ) return 'rejected';

      const nextState = await newState(nextPassword);
      const durable = atomicWriteState(this.#filePath, nextState, this.#syncDirectory);
      this.#state = nextState;
      if (!durable) this.#warnAboutDurability();
      return 'changed';
    });
  }
}
