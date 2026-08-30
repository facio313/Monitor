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
import {
  AgentControlError,
  AgentControlPlane,
  trustedAgentCertificate,
  type TrustedAgentCertificate,
} from './agent-control.js';
import { readDashboard, telemetryIsReady } from './data.js';
import {
  GenericLogQueryError,
  readGenericLogPage,
  type GenericLogQuery,
} from './generic-logs.js';
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
  genericLogOwnerUid?: number;
  agentBodyGate?: AgentBodyGate;
  agentBodyTimeoutMs?: number;
  updateGateway?: (request: UpdateGatewayRequest) => Promise<UpdateGatewayResponse>;
  updateGatewayAvailable?: () => boolean;
}

export const MAX_AGENT_BODY_REQUESTS_IN_FLIGHT = 4;
export const MAX_AGENT_BODY_REQUESTS_PER_CERTIFICATE = 1;
export const MAX_AGENT_CONTROL_BODY_BYTES = 8 * 1024;
export const MAX_AGENT_BODY_WALL_TIME_MS = 15_000;

export class AgentBodyGate {
  private inFlight = 0;
  private readonly inFlightByKey = new Map<string, number>();

  constructor(
    private readonly maximum: number,
    private readonly maximumPerKey = maximum,
  ) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64) {
      throw new Error('Agent body gate maximum is invalid');
    }
    if (
      !Number.isSafeInteger(maximumPerKey)
      || maximumPerKey < 1
      || maximumPerKey > maximum
    ) {
      throw new Error('Agent body gate per-key maximum is invalid');
    }
  }

  tryAcquire(key = 'default'): (() => void) | null {
    if (typeof key !== 'string' || key.length < 1 || key.length > 256) {
      throw new Error('Agent body gate key is invalid');
    }
    const keyedInFlight = this.inFlightByKey.get(key) ?? 0;
    if (this.inFlight >= this.maximum || keyedInFlight >= this.maximumPerKey) {
      return null;
    }
    this.inFlight += 1;
    this.inFlightByKey.set(key, keyedInFlight + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.inFlight -= 1;
      const remaining = (this.inFlightByKey.get(key) ?? 1) - 1;
      if (remaining === 0) this.inFlightByKey.delete(key);
      else this.inFlightByKey.set(key, remaining);
    };
  }
}

function apiError(response: Response, status: number, code: string, message: string): void {
  response.status(status).json({ error: message, code });
}

function rejectAgentControlError(response: Response, error: unknown, now: number): boolean {
  if (!(error instanceof AgentControlError)) return false;
  if (error.retryAfterSeconds !== undefined) {
    response.set('Retry-After', String(error.retryAfterSeconds));
  }
  response.status(error.status).json({
    error: error.message,
    code: error.code,
    serverTime: new Date(now).toISOString(),
  });
  return true;
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

const genericLogQueryKeys = new Set([
  'limit', 'cursor', 'text', 'sourceId', 'sourceKind', 'priority', 'severity',
  'from', 'to',
]);

function singleGenericLogQueryValue(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new GenericLogQueryError('invalid_parameter');
  return value;
}

function repeatedGenericLogQueryValue(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'string') return [value];
  if (
    !Array.isArray(value)
    || value.length > 32
    || value.some((item) => typeof item !== 'string')
  ) throw new GenericLogQueryError('invalid_parameter');
  return value as string[];
}

function genericLogQuery(request: Request): GenericLogQuery {
  if (Object.keys(request.query).some((key) => !genericLogQueryKeys.has(key))) {
    throw new GenericLogQueryError('unknown_parameter');
  }
  const rawLimit = singleGenericLogQueryValue(request.query.limit);
  if (rawLimit !== undefined && !/^[1-9][0-9]{0,2}$/u.test(rawLimit)) {
    throw new GenericLogQueryError('invalid_limit');
  }
  return {
    limit: rawLimit === undefined ? undefined : Number(rawLimit),
    cursor: singleGenericLogQueryValue(request.query.cursor),
    text: singleGenericLogQueryValue(request.query.text),
    sourceIds: repeatedGenericLogQueryValue(request.query.sourceId),
    sourceKinds: repeatedGenericLogQueryValue(request.query.sourceKind) as GenericLogQuery['sourceKinds'],
    priorities: repeatedGenericLogQueryValue(request.query.priority) as GenericLogQuery['priorities'],
    severities: repeatedGenericLogQueryValue(request.query.severity) as GenericLogQuery['severities'],
    from: singleGenericLogQueryValue(request.query.from),
    to: singleGenericLogQueryValue(request.query.to),
  };
}

export function createApp(options: AppOptions = {}) {
  const config = loadConfig(options);
  const agentControl = config.agentControl
    ? new AgentControlPlane(config.agentControl, options.now ?? Date.now)
    : null;
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
  const agentCertificates = new WeakMap<Request, TrustedAgentCertificate>();
  const agentBodyGate = options.agentBodyGate
    ?? new AgentBodyGate(
      MAX_AGENT_BODY_REQUESTS_IN_FLIGHT,
      MAX_AGENT_BODY_REQUESTS_PER_CERTIFICATE,
    );
  const agentBodyTimeoutMs = options.agentBodyTimeoutMs ?? MAX_AGENT_BODY_WALL_TIME_MS;
  if (
    !Number.isSafeInteger(agentBodyTimeoutMs)
    || agentBodyTimeoutMs < 25
    || agentBodyTimeoutMs > MAX_AGENT_BODY_WALL_TIME_MS
  ) {
    throw new Error('Agent body timeout is invalid');
  }

  const certificateForAgentRequest = (request: Request): TrustedAgentCertificate => {
    const certificate = agentCertificates.get(request);
    if (!certificate) {
      throw new AgentControlError(
        401,
        'MTLS_PROXY_AUTH_REQUIRED',
        'A trusted proxy-verified client certificate is required',
      );
    }
    return certificate;
  };

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
  if (config.agentControl) {
    app.use('/monitor/api/agent', (request, response, next) => {
      try {
        const certificate = trustedAgentCertificate(
          request,
          config.agentControl!.proxyEdgeSecret,
          now(),
        );
        agentCertificates.set(request, certificate);
        response.once('finish', () => agentCertificates.delete(request));
        response.once('close', () => agentCertificates.delete(request));
        next();
      } catch (error) {
        response.set('Connection', 'close');
        if (!rejectAgentControlError(response, error, now())) {
          apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent authentication is unavailable');
        }
      }
    });
    app.use('/monitor/api/agent', (request, response, next) => {
      const release = agentBodyGate.tryAcquire(
        certificateForAgentRequest(request).fingerprintSha256,
      );
      if (release === null) {
        response.set('Retry-After', '1');
        response.set('Connection', 'close');
        apiError(response, 503, 'AGENT_BODY_BUSY', 'Too many agent request bodies are in flight');
        return;
      }
      let released = false;
      const releaseRequest = () => {
        if (released) return;
        released = true;
        clearTimeout(bodyTimer);
        release();
      };
      const bodyTimer = setTimeout(() => {
        releaseRequest();
        request.socket.destroy();
      }, agentBodyTimeoutMs);
      bodyTimer.unref();
      request.once('end', () => clearTimeout(bodyTimer));
      request.once('aborted', releaseRequest);
      response.once('finish', releaseRequest);
      response.once('close', releaseRequest);
      next();
    });
    const agentEnrollmentLimiter = rateLimit({
      windowMs: 15 * 60 * 1_000,
      limit: 20,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      keyGenerator: (request) => certificateForAgentRequest(request).fingerprintSha256,
      handler: (_request, response) => {
        apiError(response, 429, 'RATE_LIMITED', 'Too many agent enrollment attempts');
      },
    });
    const agentIngestLimiter = rateLimit({
      windowMs: 60 * 1_000,
      limit: 300,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      keyGenerator: (request) => certificateForAgentRequest(request).fingerprintSha256,
      handler: (_request, response) => {
        apiError(response, 429, 'RATE_LIMITED', 'Agent request rate exceeded');
      },
    });
    app.use('/monitor/api/agent/enroll', agentEnrollmentLimiter);
    app.use('/monitor/api/agent/certificate-rotations', agentEnrollmentLimiter);
    app.use('/monitor/api/agent/heartbeat', agentIngestLimiter);
    app.use('/monitor/api/agent/ingest', agentIngestLimiter);
    const boundedAgentWireBody = (
      maximumBytes: number,
      acceptedEncodings: ReadonlySet<string>,
    ) => (request: Request, response: Response, next: NextFunction) => {
      const rejectWireBody = (status: number, code: string, message: string) => {
        response.set('Connection', 'close');
        apiError(response, status, code, message);
      };
      const contentType = request.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
      if (contentType !== 'application/json') {
        rejectWireBody(415, 'UNSUPPORTED_CONTENT_TYPE', 'Only application/json is accepted');
        return;
      }
      const encoding = request.get('content-encoding')?.toLowerCase() ?? 'identity';
      if (!acceptedEncodings.has(encoding)) {
        rejectWireBody(415, 'UNSUPPORTED_CONTENT_ENCODING', 'Request content encoding is not supported');
        return;
      }
      const contentLength = request.get('content-length');
      if (contentLength === undefined) {
        rejectWireBody(411, 'CONTENT_LENGTH_REQUIRED', 'A bounded Content-Length is required');
        return;
      }
      if (
        !/^\d+$/u.test(contentLength)
        || Number(contentLength) > maximumBytes
      ) {
        rejectWireBody(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
        return;
      }
      next();
    };
    const smallAgentRoutes = [
      '/monitor/api/agent/enroll',
      '/monitor/api/agent/heartbeat',
      '/monitor/api/agent/certificate-rotations',
    ];
    app.use(
      smallAgentRoutes,
      boundedAgentWireBody(MAX_AGENT_CONTROL_BODY_BYTES, new Set(['identity'])),
      express.json({ limit: MAX_AGENT_CONTROL_BODY_BYTES, strict: true, inflate: false }),
    );
    app.use(
      '/monitor/api/agent/ingest',
      boundedAgentWireBody(config.agentControl.maxBatchBytes, new Set(['identity', 'gzip'])),
      express.json({
        limit: config.agentControl.maxBatchBytes,
        strict: true,
        inflate: true,
      }),
    );
  }
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

  const agentAdminMutationLimiter = rateLimit({
    windowMs: 15 * 60 * 1_000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_request, response) => {
      apiError(response, 429, 'RATE_LIMITED', 'Too many agent administration requests');
    },
  });

  const genericLogReadLimiter = rateLimit({
    windowMs: 60 * 1_000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_request, response) => {
      apiError(response, 429, 'RATE_LIMITED', 'Too many generic log queries');
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

  const requireGenericLogReadIdentity = (
    request: Request,
    response: Response,
    next: NextFunction,
  ): void => {
    if (config.ssoEnabled) {
      const identity = trustedSsoIdentity(request, config.edgeSecret);
      if (!identity) {
        apiError(response, 401, 'AUTH_REQUIRED', 'Authentication required');
        return;
      }
      if (!permissionsForRole(identity.role).includes('logs:read')) {
        apiError(response, 403, 'PERMISSION_REQUIRED', 'Log read permission required');
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
    next();
  };

  app.get(
    '/monitor/api/generic-logs',
    requireGenericLogReadIdentity,
    genericLogReadLimiter,
    (request, response) => {
      try {
        response.status(200).json(readGenericLogPage(
          config.dataDir,
          genericLogQuery(request),
          now(),
          options.genericLogOwnerUid ?? 0,
        ));
      } catch (error) {
        if (error instanceof GenericLogQueryError) {
          apiError(response, 400, 'INVALID_LOG_QUERY', 'Generic log query is invalid');
          return;
        }
        throw error;
      }
    },
  );

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

  function requireAgentAdminIdentity(
    request: Request,
    response: Response,
    minimum: 'admin' | 'chief-admin',
    mutation: boolean,
  ) {
    if (!agentControl || !config.ssoEnabled) {
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
    if (mutation && !criticalMutationIsSameOrigin(request, config.allowedOrigins)) {
      apiError(response, 403, 'ORIGIN_REJECTED', 'Same-origin JSON request required');
      return null;
    }
    return identity;
  }

  app.get('/monitor/api/agents', (request, response) => {
    if (!requireAgentAdminIdentity(request, response, 'admin', false)) return;
    try {
      response.status(200).json(agentControl!.listAgents());
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post('/monitor/api/agents/enrollment-tokens', agentAdminMutationLimiter, (request, response) => {
    if (!requireAgentAdminIdentity(request, response, 'chief-admin', true)) return;
    const body = exactBody(request.body, ['ttlSeconds']);
    if (!body) {
      apiError(response, 400, 'INVALID_REQUEST', 'Request must contain only ttlSeconds');
      return;
    }
    try {
      response.status(201).json(agentControl!.issueEnrollmentToken(body.ttlSeconds));
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post(
    '/monitor/api/agents/:agentId/certificate-rotation-tokens',
    agentAdminMutationLimiter,
    (request, response) => {
      if (!requireAgentAdminIdentity(request, response, 'chief-admin', true)) return;
      const agentId = request.params.agentId;
      const body = exactBody(request.body, ['ttlSeconds']);
      if (typeof agentId !== 'string' || !body) {
        apiError(response, 400, 'INVALID_REQUEST', 'Request must contain a valid agent ID and only ttlSeconds');
        return;
      }
      try {
        response.status(201).json(agentControl!.issueCertificateRotationToken(
          agentId,
          body.ttlSeconds,
        ));
      } catch (error) {
        if (!rejectAgentControlError(response, error, now())) {
          apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
        }
      }
    },
  );

  app.post('/monitor/api/agents/:agentId/revoke', agentAdminMutationLimiter, (request, response) => {
    if (!requireAgentAdminIdentity(request, response, 'chief-admin', true)) return;
    const agentId = request.params.agentId;
    const body = exactBody(request.body, ['reason']);
    if (typeof agentId !== 'string' || !body) {
      apiError(response, 400, 'INVALID_REQUEST', 'Request must contain a valid agent ID and only a revocation reason');
      return;
    }
    try {
      response.status(200).json(agentControl!.revoke(agentId, body.reason));
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post('/monitor/api/agent/enroll', (request, response) => {
    if (!agentControl || !config.agentControl) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return;
    }
    try {
      const certificate = certificateForAgentRequest(request);
      const result = agentControl.register(request.body, certificate, request.ip ?? null);
      response.status(result.duplicate ? 200 : 201).json(result);
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post('/monitor/api/agent/heartbeat', (request, response) => {
    if (!agentControl || !config.agentControl) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return;
    }
    try {
      const certificate = certificateForAgentRequest(request);
      response.status(200).json(agentControl.heartbeat(request.body, certificate));
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post('/monitor/api/agent/ingest', (request, response) => {
    if (!agentControl || !config.agentControl) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return;
    }
    try {
      const certificate = certificateForAgentRequest(request);
      const result = agentControl.ingest(request.body, certificate);
      response.status(result.duplicate ? 200 : 202).json(result);
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

  app.post('/monitor/api/agent/certificate-rotations', (request, response) => {
    if (!agentControl || !config.agentControl) {
      apiError(response, 404, 'NOT_FOUND', 'Not found');
      return;
    }
    try {
      const certificate = certificateForAgentRequest(request);
      response.status(200).json(agentControl.rotateCertificate(request.body, certificate));
    } catch (error) {
      if (!rejectAgentControlError(response, error, now())) {
        apiError(response, 503, 'AGENT_CONTROL_UNAVAILABLE', 'Agent control storage is unavailable');
      }
    }
  });

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
    if (
      error
      && typeof error === 'object'
      && 'status' in error
      && error.status === 415
    ) {
      apiError(response, 415, 'UNSUPPORTED_CONTENT_ENCODING', 'Request content encoding is not supported');
      return;
    }
    if (error instanceof SyntaxError) {
      apiError(response, 400, 'INVALID_JSON', 'Request body must be valid JSON');
      return;
    }
    if (
      error
      && typeof error === 'object'
      && 'status' in error
      && error.status === 400
    ) {
      apiError(response, 400, 'INVALID_BODY', 'Request body could not be decoded');
      return;
    }
    apiError(response, 500, 'INTERNAL_ERROR', 'Internal server error');
  });

  return app;
}
