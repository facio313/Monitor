import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';
import {
  clearSessionCookie,
  issueSession,
  setSessionCookie,
  verifySession,
} from './auth.js';
import { loadConfig, type ConfigOverrides } from './config.js';
import { readDashboard, telemetryIsReady } from './data.js';
import { PasswordStore, PasswordStoreBusyError } from './password-store.js';
import { DASHBOARD_RANGES, type DashboardRange } from './types.js';

export interface AppOptions extends ConfigOverrides {
  now?: () => number;
  publicDir?: string;
}

function apiError(response: Response, status: number, code: string, message: string): void {
  response.status(status).json({ error: message, code });
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function trustedSsoUser(request: Request, edgeSecret: string | null): string | null {
  const user = request.get('remote-user');
  const email = request.get('remote-email');
  const suppliedEdgeSecret = request.get('x-portfolio-edge-secret');
  if (!edgeSecret || !suppliedEdgeSecret || !safeEqual(suppliedEdgeSecret, edgeSecret)) return null;
  if (!user || !email) return null;
  const safeHeader = (value: string) => value.length <= 254 && !/[\u0000-\u001f\u007f]/u.test(value);
  return safeHeader(user) && safeHeader(email) ? user : null;
}

function mutationIsSameOrigin(request: Request, allowedOrigins: string[]): boolean {
  const fetchSite = request.get('sec-fetch-site');
  if (fetchSite === 'cross-site') return false;
  const origin = request.get('origin');
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;
  try {
    const parsed = new URL(origin);
    return parsed.host === request.get('host');
  } catch {
    return false;
  }
}

export function createApp(options: AppOptions = {}) {
  const config = loadConfig(options);
  const localAuth = config.ssoEnabled ? null : {
    passwordStore: new PasswordStore(config.authStateFile, config.getBootstrapPassword),
    sessionSecret: config.sessionSecret,
    sessionTtlMs: config.sessionTtlMs,
  };
  const now = options.now ?? Date.now;
  const publicDirectory = resolve(options.publicDir ?? join(process.cwd(), 'dist', 'public'));
  const indexFile = join(publicDirectory, 'index.html');
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'same-origin' },
  }));
  app.use(express.json({ limit: '8kb', strict: true }));

  app.get('/healthz', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });

  app.get('/readyz', (_request, response) => {
    if (!telemetryIsReady(config.dataDir)) {
      response.status(503).json({ status: 'not_ready' });
      return;
    }
    response.status(200).json({ status: 'ready' });
  });

  app.use('/monitor/api', (request, response, next) => {
    response.set('Cache-Control', 'no-store');
    if (
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)
      && !mutationIsSameOrigin(request, config.allowedOrigins)
    ) {
      apiError(response, 403, 'ORIGIN_REJECTED', 'Cross-origin request rejected');
      return;
    }
    next();
  });

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1_000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (_request, response) => {
      apiError(response, 429, 'RATE_LIMITED', 'Too many login attempts');
    },
  });

  const passwordChangeLimiter = rateLimit({
    windowMs: 15 * 60 * 1_000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (_request, response) => {
      apiError(response, 429, 'RATE_LIMITED', 'Too many password change attempts');
    },
  });

  app.post('/monitor/api/auth/login', loginLimiter, async (request, response) => {
    if (config.ssoEnabled) {
      apiError(response, 403, 'SSO_REQUIRED', 'Sign in through the portfolio single sign-on portal');
      return;
    }
    const body: unknown = request.body;
    const suppliedPassword = body && typeof body === 'object'
      ? (body as Record<string, unknown>).password
      : undefined;
    let sessionEpoch: string | null;
    try {
      sessionEpoch = await localAuth!.passwordStore.authenticate(suppliedPassword);
    } catch (error) {
      if (error instanceof PasswordStoreBusyError) {
        apiError(response, 429, 'RATE_LIMITED', 'Too many login attempts');
        return;
      }
      throw error;
    }
    if (!sessionEpoch) {
      apiError(response, 401, 'INVALID_CREDENTIALS', 'Invalid credentials');
      return;
    }
    const session = issueSession(localAuth!.sessionSecret, sessionEpoch, now(), localAuth!.sessionTtlMs);
    setSessionCookie(response, session.token, localAuth!.sessionTtlMs);
    response.status(200).json({ authenticated: true, expiresAt: session.expiresAt });
  });

  app.get('/monitor/api/auth/session', (request, response) => {
    if (config.ssoEnabled) {
      const user = trustedSsoUser(request, config.edgeSecret);
      response.status(200).json({
        authenticated: user !== null,
        expiresAt: null,
        mode: 'sso',
        user,
      });
      return;
    }
    const session = verifySession(
      request,
      localAuth!.sessionSecret,
      localAuth!.passwordStore.sessionEpoch,
      now(),
    );
    if (!session) {
      response.status(200).json({ authenticated: false, expiresAt: null });
      return;
    }
    response.status(200).json({ authenticated: true, expiresAt: session.expiresAt });
  });

  app.delete('/monitor/api/auth/session', (request, response) => {
    clearSessionCookie(response);
    response.status(204).end();
  });

  app.post('/monitor/api/auth/password', (request, response, next) => {
    if (config.ssoEnabled) {
      apiError(response, 403, 'SSO_MANAGED', 'Password changes are managed by the portfolio single sign-on service');
      return;
    }
    const authorizedEpoch = localAuth!.passwordStore.sessionEpoch;
    const session = verifySession(request, localAuth!.sessionSecret, authorizedEpoch, now());
    if (!session) {
      apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
      return;
    }
    response.locals.monitorAuthorizedEpoch = session.epoch;
    next();
  }, passwordChangeLimiter, async (request, response) => {
    const body: unknown = request.body;
    const record = body && typeof body === 'object' ? body as Record<string, unknown> : {};
    let result;
    try {
      result = await localAuth!.passwordStore.changePassword(
        record.currentPassword,
        record.newPassword,
        response.locals.monitorAuthorizedEpoch,
      );
    } catch (error) {
      if (error instanceof PasswordStoreBusyError) {
        apiError(response, 429, 'RATE_LIMITED', 'Too many password change attempts');
        return;
      }
      throw error;
    }
    if (result !== 'changed') {
      apiError(response, 400, 'PASSWORD_CHANGE_REJECTED', 'Password change rejected');
      return;
    }
    clearSessionCookie(response);
    response.status(204).end();
  });

  app.get('/monitor/api/dashboard', (request, response) => {
    const authorized = config.ssoEnabled
      ? trustedSsoUser(request, config.edgeSecret) !== null
      : verifySession(
        request,
        localAuth!.sessionSecret,
        localAuth!.passwordStore.sessionEpoch,
        now(),
      ) !== null;
    if (!authorized) {
      apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
      return;
    }
    const requestedRange = request.query.range;
    if (typeof requestedRange !== 'string' || !DASHBOARD_RANGES.includes(requestedRange as DashboardRange)) {
      apiError(response, 400, 'INVALID_RANGE', 'range must be one of 1h, 24h, 7d, or 30d');
      return;
    }
    response.status(200).json(readDashboard(
      config.dataDir,
      requestedRange as DashboardRange,
      now(),
      config.staleAfterMs,
    ));
  });

  app.use('/monitor/api', (_request, response) => {
    apiError(response, 404, 'NOT_FOUND', 'Not found');
  });

  app.use('/monitor', express.static(publicDirectory, {
    fallthrough: true,
    index: false,
    setHeaders: (response, filePath) => {
      if (basename(filePath) === 'index.html') {
        response.setHeader('Cache-Control', 'no-store');
      } else if (filePath.includes(`${sep}assets${sep}`)) {
        response.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      } else {
        response.setHeader('Cache-Control', 'public, max-age=3600');
      }
    },
  }));

  app.get(/^\/monitor(?:\/.*)?$/, (_request, response, next) => {
    if (!existsSync(indexFile)) {
      next();
      return;
    }
    response.set('Cache-Control', 'no-store');
    response.sendFile(indexFile);
  });

  app.use((_request, response) => {
    apiError(response, 404, 'NOT_FOUND', 'Not found');
  });

  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (
      error
      && typeof error === 'object'
      && ('status' in error && error.status === 413 || 'type' in error && error.type === 'entity.too.large')
    ) {
      apiError(response, 413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
      return;
    }
    if (error instanceof SyntaxError) {
      apiError(response, 400, 'INVALID_JSON', 'Request body must be valid JSON');
      return;
    }
    apiError(response, 500, 'INTERNAL_ERROR', 'Internal server error');
  });

  return app;
}
