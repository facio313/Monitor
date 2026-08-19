import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { existsSync } from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';
import {
  clearSessionCookie,
  issueSession,
  passwordMatches,
  setSessionCookie,
  verifySession,
} from './auth.js';
import { loadConfig, type ConfigOverrides } from './config.js';
import { readDashboard, telemetryIsReady } from './data.js';
import { DASHBOARD_RANGES, type DashboardRange } from './types.js';

export interface AppOptions extends ConfigOverrides {
  now?: () => number;
  publicDir?: string;
}

function apiError(response: Response, status: number, code: string, message: string): void {
  response.status(status).json({ error: message, code });
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

  app.post('/monitor/api/auth/login', loginLimiter, (request, response) => {
    const body: unknown = request.body;
    const suppliedPassword = body && typeof body === 'object'
      ? (body as Record<string, unknown>).password
      : undefined;
    if (!passwordMatches(suppliedPassword, config.password)) {
      apiError(response, 401, 'INVALID_CREDENTIALS', 'Invalid credentials');
      return;
    }
    const session = issueSession(config.sessionSecret, now(), config.sessionTtlMs);
    setSessionCookie(response, session.token, config.sessionTtlMs);
    response.status(200).json({ authenticated: true, expiresAt: session.expiresAt });
  });

  app.get('/monitor/api/auth/session', (request, response) => {
    const session = verifySession(request, config.sessionSecret, now());
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

  app.get('/monitor/api/dashboard', (request, response) => {
    if (!verifySession(request, config.sessionSecret, now())) {
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
