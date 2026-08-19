import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import type { Request, Response } from 'express';

export const SESSION_COOKIE = 'monitor_session';

interface SessionPayload {
  v: 1;
  iat: number;
  exp: number;
  nonce: string;
}

export interface VerifiedSession {
  expiresAt: string;
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export function passwordMatches(candidate: unknown, expected: string): boolean {
  const normalized = typeof candidate === 'string' ? candidate : '';
  return timingSafeEqual(digest(normalized), digest(expected))
    && typeof candidate === 'string';
}

function sign(encodedPayload: string, secret: string): string {
  return createHmac('sha256', secret).update(encodedPayload, 'ascii').digest('base64url');
}

export function issueSession(secret: string, nowMs: number, ttlMs: number): {
  token: string;
  expiresAt: string;
} {
  const payload: SessionPayload = {
    v: 1,
    iat: Math.floor(nowMs / 1_000),
    exp: Math.floor((nowMs + ttlMs) / 1_000),
    nonce: randomBytes(16).toString('base64url'),
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return {
    token: `${encoded}.${sign(encoded, secret)}`,
    expiresAt: new Date(payload.exp * 1_000).toISOString(),
  };
}

function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

export function verifySession(
  request: Request,
  secret: string,
  nowMs: number,
): VerifiedSession | null {
  const token = parseCookies(request.headers.cookie).get(SESSION_COOKIE);
  if (!token || token.length > 2_048) return null;
  const separator = token.indexOf('.');
  if (separator < 1 || token.indexOf('.', separator + 1) !== -1) return null;
  const encoded = token.slice(0, separator);
  const suppliedSignature = token.slice(separator + 1);
  const expectedSignature = sign(encoded, secret);
  const supplied = Buffer.from(suppliedSignature, 'ascii');
  const expected = Buffer.from(expectedSignature, 'ascii');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;

  try {
    const parsed: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object') return null;
    const payload = parsed as Partial<SessionPayload>;
    const nowSeconds = Math.floor(nowMs / 1_000);
    if (
      payload.v !== 1
      || !Number.isSafeInteger(payload.iat)
      || !Number.isSafeInteger(payload.exp)
      || typeof payload.nonce !== 'string'
      || payload.nonce.length < 16
      || (payload.iat as number) > nowSeconds + 60
      || (payload.exp as number) <= nowSeconds
      || (payload.exp as number) - (payload.iat as number) > 24 * 60 * 60
    ) return null;
    return { expiresAt: new Date((payload.exp as number) * 1_000).toISOString() };
  } catch {
    return null;
  }
}

export function setSessionCookie(response: Response, token: string, ttlMs: number): void {
  response.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/monitor',
    maxAge: ttlMs,
  });
}

export function clearSessionCookie(response: Response): void {
  response.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/monitor',
  });
}
