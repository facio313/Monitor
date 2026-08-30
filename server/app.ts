import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { existsSync } from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';
import {
  clearSessionCookie,
  issueSession,
  requestHasSessionCookie,
  setSessionCookie,
  verifySession,
} from './auth.js';
import { loadConfig, type ConfigOverrides } from './config.js';
import { readDashboard, telemetryIsReady } from './data.js';
import { readInfrastructureLedger } from './infrastructure-ledger.js';
import { inventoryLegacyAuth } from './legacy-auth.js';
import { PasswordStore, PasswordStoreBusyError } from './password-store.js';
import {
  permissionsForRole,
  ssoRoleAtLeast,
  trustedSsoIdentity,
} from './sso.js';
import {
  readSystemUpdateStatus,
  safeUpdateActor,
  sendUpdateGatewayRequest,
  UpdateGatewayError,
  updateGatewayIsAvailable,
  UpdateNonceStore,
  type UpdateGatewayRequest,
  type UpdateGatewayResponse,
} from './system-updates.js';
import { DASHBOARD_RANGES, type DashboardRange } from './types.js';

export interface AppOptions extends ConfigOverrides {
  now?: () => number;
  publicDir?: string;
  updateGateway?: (request: UpdateGatewayRequest) => Promise<UpdateGatewayResponse>;
  updateGatewayAvailable?: () => boolean;
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

function criticalMutationIsSameOrigin(request: Request, allowedOrigins: string[]): boolean {
  const origin = request.get('origin');
  const contentType = request.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  return request.get('sec-fetch-site') === 'same-origin'
    && typeof origin === 'string'
    && allowedOrigins.includes(origin)
    && contentType === 'application/json';
}

function exactBody(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  const actual = Object.keys(body).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
    ? body
    : null;
}

function validPlanId(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
}

export function createApp(options: AppOptions = {}) {
  const config = loadConfig(options);
  const localAuth = config.ssoEnabled ? null : {
    passwordStore: new PasswordStore(config.authStateFile, config.getBootstrapPassword),
    sessionSecret: config.sessionSecret,
    sessionTtlMs: config.sessionTtlMs,
  };
  const now = options.now ?? Date.now;
  const updateGateway = options.updateGateway
    ?? ((gatewayRequest: UpdateGatewayRequest) => sendUpdateGatewayRequest(
      config.updateSocketPath,
      gatewayRequest,
    ));
  const gatewayAvailable = options.updateGatewayAvailable
    ?? (() => updateGatewayIsAvailable(config.updateSocketPath));
  const updateNonces = new UpdateNonceStore(now);
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
    if (!telemetryIsReady(config.dataDir, now(), config.staleAfterMs)) {
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

  const updateActionLimiter = rateLimit({
    windowMs: 15 * 60 * 1_000,
    limit: 8,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_request, response) => {
      apiError(response, 429, 'RATE_LIMITED', 'Too many update requests');
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
      const identity = trustedSsoIdentity(request, config.edgeSecret);
      if (requestHasSessionCookie(request)) clearSessionCookie(response);
      response.status(200).json({
        authenticated: identity !== null,
        expiresAt: null,
        mode: 'sso',
        user: identity?.subject ?? null,
        groups: identity?.groups ?? [],
        role: identity?.role ?? null,
        permissions: identity
          ? permissionsForRole(identity.role, !identity.legacyAdminCompatibility)
          : [],
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
    if (config.ssoEnabled) {
      const identity = trustedSsoIdentity(request, config.edgeSecret);
      if (!identity) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
    } else {
      const session = verifySession(
        request,
        localAuth!.sessionSecret,
        localAuth!.passwordStore.sessionEpoch,
        now(),
      );
      if (!session) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
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

  app.get('/monitor/api/system-updates', (request, response) => {
    if (config.ssoEnabled) {
      const identity = trustedSsoIdentity(request, config.edgeSecret);
      if (!identity) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
      const available = gatewayAvailable();
      const actorAccepted = safeUpdateActor(identity.subject);
      response.status(200).json({
        status: readSystemUpdateStatus(config.dataDir),
        capabilities: {
          gatewayAvailable: available,
          canCheck: available && actorAccepted && ssoRoleAtLeast(identity, 'admin'),
          canApply: available
            && actorAccepted
            && !identity.legacyAdminCompatibility
            && ssoRoleAtLeast(identity, 'chief-admin'),
        },
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
      apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
      return;
    }
    response.status(200).json({
      status: readSystemUpdateStatus(config.dataDir),
      capabilities: { gatewayAvailable: false, canCheck: false, canApply: false },
    });
  });

  app.get('/monitor/api/infrastructure-ledger', (request, response) => {
    if (config.ssoEnabled) {
      const identity = trustedSsoIdentity(request, config.edgeSecret);
      if (!identity) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
      if (!ssoRoleAtLeast(identity, 'admin')) {
        apiError(response, 403, 'ROLE_REQUIRED', 'Admin role required');
        return;
      }
    } else {
      const session = verifySession(
        request,
        localAuth!.sessionSecret,
        localAuth!.passwordStore.sessionEpoch,
        now(),
      );
      if (!session) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
    }

    const ledger = readInfrastructureLedger(config.dataDir, now());
    if (!ledger) {
      apiError(response, 503, 'LEDGER_UNAVAILABLE', 'Infrastructure ledger is unavailable');
      return;
    }
    response.status(200).json(ledger);
  });

  function requireCriticalUpdateIdentity(request: Request, response: Response, minimum: 'admin' | 'chief-admin') {
    if (!config.ssoEnabled) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return null;
    }
    const identity = trustedSsoIdentity(request, config.edgeSecret);
    if (!identity) {
      apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
      return null;
    }
    if (!ssoRoleAtLeast(identity, minimum)) {
      apiError(response, 403, 'ROLE_REQUIRED', `${minimum === 'admin' ? 'Admin' : 'Chief admin'} role required`);
      return null;
    }
    if (minimum === 'chief-admin' && identity.legacyAdminCompatibility) {
      apiError(response, 403, 'CANONICAL_ROLE_REQUIRED', 'Canonical chief admin role required');
      return null;
    }
    if (!criticalMutationIsSameOrigin(request, config.allowedOrigins)) {
      apiError(response, 403, 'ORIGIN_REJECTED', 'Same-origin JSON request required');
      return null;
    }
    if (!safeUpdateActor(identity.subject)) {
      apiError(response, 403, 'IDENTITY_REJECTED', 'Update identity rejected');
      return null;
    }
    return identity;
  }

  function rejectGateway(response: Response, result: Extract<UpdateGatewayResponse, { accepted: false }>): void {
    const statuses: Record<string, number> = {
      BUSY: 409,
      QUEUE_FULL: 409,
      INVALID_PLAN: 409,
      INVALID_REQUEST: 400,
      INVALID_ACTION: 400,
      INVALID_ACTOR: 400,
      PEER_REJECTED: 403,
      INTERNAL_ERROR: 503,
    };
    const status = statuses[result.code] ?? 503;
    apiError(response, status, result.code in statuses ? result.code : 'UPDATE_UNAVAILABLE', 'Update request rejected');
  }

  async function queueUpdate(
    response: Response,
    request: UpdateGatewayRequest,
  ): Promise<void> {
    if (!gatewayAvailable()) {
      apiError(response, 503, 'UPDATE_UNAVAILABLE', 'Update service unavailable');
      return;
    }
    try {
      const result = await updateGateway(request);
      if (!result.accepted) {
        rejectGateway(response, result);
        return;
      }
      response.status(202).json(result);
    } catch (error) {
      if (error instanceof UpdateGatewayError) {
        apiError(response, 503, 'UPDATE_UNAVAILABLE', 'Update service unavailable');
        return;
      }
      apiError(response, 503, 'UPDATE_UNAVAILABLE', 'Update service unavailable');
    }
  }

  app.post('/monitor/api/system-updates/check', updateActionLimiter, async (request, response) => {
    const identity = requireCriticalUpdateIdentity(request, response, 'admin');
    if (!identity) return;
    if (!exactBody(request.body, [])) {
      apiError(response, 400, 'INVALID_REQUEST', 'Request body must be an empty JSON object');
      return;
    }
    await queueUpdate(response, {
      schemaVersion: 1,
      action: 'check',
      actor: identity.subject,
      planId: null,
    });
  });

  app.post('/monitor/api/system-updates/prepare', updateActionLimiter, (request, response) => {
    const identity = requireCriticalUpdateIdentity(request, response, 'chief-admin');
    if (!identity) return;
    const body = exactBody(request.body, ['planId']);
    if (!body || !validPlanId(body.planId)) {
      apiError(response, 400, 'INVALID_PLAN', 'A valid update plan is required');
      return;
    }
    const status = readSystemUpdateStatus(config.dataDir);
    if (
      !status
      || status.state !== 'available'
      || status.planId !== body.planId
      || status.planExpiresAt === null
      || Date.parse(status.planExpiresAt) <= now()
    ) {
      apiError(response, 409, 'PLAN_STALE', 'Update plan is no longer available');
      return;
    }
    const authorization = updateNonces.issue(identity.subject, body.planId);
    response.status(200).json({ planId: body.planId, ...authorization });
  });

  app.post('/monitor/api/system-updates/apply', updateActionLimiter, async (request, response) => {
    const identity = requireCriticalUpdateIdentity(request, response, 'chief-admin');
    if (!identity) return;
    const body = exactBody(request.body, ['planId', 'nonce']);
    if (!body || !validPlanId(body.planId) || typeof body.nonce !== 'string') {
      apiError(response, 400, 'INVALID_REQUEST', 'Valid plan and confirmation token required');
      return;
    }
    const status = readSystemUpdateStatus(config.dataDir);
    if (
      !status
      || status.state !== 'available'
      || status.planId !== body.planId
      || status.planExpiresAt === null
      || Date.parse(status.planExpiresAt) <= now()
    ) {
      apiError(response, 409, 'PLAN_STALE', 'Update plan is no longer available');
      return;
    }
    if (!updateNonces.consume(body.nonce, identity.subject, body.planId)) {
      apiError(response, 409, 'CONFIRMATION_REQUIRED', 'Fresh confirmation required');
      return;
    }
    await queueUpdate(response, {
      schemaVersion: 1,
      action: 'apply-safe',
      actor: identity.subject,
      planId: body.planId,
    });
  });

  app.get('/monitor/api/operations/auth-inventory', (request, response) => {
    if (!config.ssoEnabled) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return;
    }
    const identity = trustedSsoIdentity(request, config.edgeSecret);
    if (!identity) {
      apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
      return;
    }
    if (!ssoRoleAtLeast(identity, 'admin')) {
      apiError(response, 403, 'ROLE_REQUIRED', 'Admin role required');
      return;
    }
    response.status(200).json(inventoryLegacyAuth(request, config.legacyAuthStateFile));
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
