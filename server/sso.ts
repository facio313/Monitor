import { timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';

export const SSO_ROLES = ['user', 'admin', 'chief-admin'] as const;
export type SsoRole = typeof SSO_ROLES[number];

export const SSO_GRANTS = [
  'access-react',
  'access-vue',
  'access-dukkeobi',
  'access-ddit-finalproject',
  'access-monitor',
  'access-pilgrimage',
  'access-multtara',
  'access-feelmyrythm',
  'access-garak',
] as const;
export type SsoGrant = typeof SSO_GRANTS[number];

const V2_MARKER = 'portfolio-v2';
const MONITOR_GRANT: SsoGrant = 'access-monitor';
const ROLE_RANK: Record<SsoRole, number> = { user: 0, admin: 1, 'chief-admin': 2 };
const GROUP_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/u;

interface ParsedSsoGroups {
  groups: string[];
  grants: SsoGrant[];
  role: SsoRole;
}

export interface TrustedSsoIdentity {
  subject: string;
  email: string;
  groups: string[];
  grants: SsoGrant[];
  role: SsoRole;
  legacyAdminCompatibility: boolean;
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function safeIdentityHeader(value: string | undefined, maximumLength: number): string | null {
  if (!value) return null;
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > maximumLength
    || /[\u0000-\u001f\u007f]/u.test(normalized)
  ) return null;
  return normalized;
}

function normalizedLegacyGroups(rawGroups: string): ParsedSsoGroups | null {
  if (rawGroups === 'user,developer') {
    return {
      groups: ['user', V2_MARKER, MONITOR_GRANT],
      grants: [MONITOR_GRANT],
      role: 'user',
    };
  }
  if (rawGroups === 'user,developer,admin') {
    return {
      groups: ['user', 'admin', 'chief-admin', V2_MARKER],
      grants: [],
      role: 'chief-admin',
    };
  }
  // A v1 `user` could not open Monitor, so preserving it means rejecting it.
  return null;
}

export function parseSsoGroups(rawGroups: string | undefined): ParsedSsoGroups | null {
  if (!rawGroups || rawGroups.length > 1024) return null;
  const groups = rawGroups.split(',');
  if (
    groups.some((group) => !group || !GROUP_PATTERN.test(group))
    || new Set(groups).size !== groups.length
  ) return null;

  if (rawGroups === 'user' || rawGroups === 'user,developer' || rawGroups === 'user,developer,admin') {
    return normalizedLegacyGroups(rawGroups);
  }

  if (groups[0] !== 'user') return null;
  let cursor = 1;
  let role: SsoRole = 'user';
  if (groups[cursor] === 'admin') {
    role = 'admin';
    cursor += 1;
    if (groups[cursor] === 'chief-admin') {
      role = 'chief-admin';
      cursor += 1;
    }
  }
  if (groups[cursor] !== V2_MARKER) return null;
  cursor += 1;

  const rawGrants = groups.slice(cursor);
  if (role === 'chief-admin') {
    if (rawGrants.length !== 0) return null;
    return { groups, grants: [], role };
  }

  let previousGrantIndex = -1;
  const grants: SsoGrant[] = [];
  for (const group of rawGrants) {
    const grantIndex = SSO_GRANTS.indexOf(group as SsoGrant);
    if (grantIndex <= previousGrantIndex) return null;
    previousGrantIndex = grantIndex;
    grants.push(group as SsoGrant);
  }
  if (!grants.includes(MONITOR_GRANT)) return null;
  return { groups, grants, role };
}

export function trustedSsoIdentity(
  request: Request,
  edgeSecret: string | null,
): TrustedSsoIdentity | null {
  const suppliedEdgeSecret = request.get('x-portfolio-edge-secret');
  if (!edgeSecret || !suppliedEdgeSecret || !safeEqual(suppliedEdgeSecret, edgeSecret)) return null;
  const subject = safeIdentityHeader(request.get('remote-user'), 255);
  const email = safeIdentityHeader(request.get('remote-email'), 320);
  const rawGroups = request.get('remote-groups');
  const parsedGroups = parseSsoGroups(rawGroups);
  if (!subject || !email || !parsedGroups) return null;
  return {
    subject,
    email,
    ...parsedGroups,
    legacyAdminCompatibility: rawGroups === 'user,developer,admin',
  };
}

export function ssoRoleAtLeast(identity: TrustedSsoIdentity, minimumRole: SsoRole): boolean {
  return ROLE_RANK[identity.role] >= ROLE_RANK[minimumRole];
}

export function permissionsForRole(role: SsoRole, allowSystemApply = true): string[] {
  const permissions = ['dashboard:read'];
  if (ROLE_RANK[role] >= ROLE_RANK.admin) {
    permissions.push('auth-inventory:read', 'infrastructure-ledger:read', 'system-updates:check');
  }
  if (allowSystemApply && ROLE_RANK[role] >= ROLE_RANK['chief-admin']) {
    permissions.push('system-updates:apply');
  }
  return permissions;
}
