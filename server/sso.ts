import { timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';

export const SSO_ROLES = ['user', 'developer', 'admin'] as const;
export type SsoRole = typeof SSO_ROLES[number];

const ROLE_RANK: Record<SsoRole, number> = { user: 0, developer: 1, admin: 2 };
const GROUP_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/u;

export interface TrustedSsoIdentity {
  subject: string;
  email: string;
  groups: SsoRole[];
  role: SsoRole;
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

export function parseSsoGroups(rawGroups: string | undefined): SsoRole[] | null {
  if (!rawGroups || rawGroups.length > 255) return null;
  const groups = rawGroups.split(',');
  if (
    groups.some((group) => !group || !GROUP_PATTERN.test(group))
    || new Set(groups).size !== groups.length
    || groups.length < 1
    || groups.length > SSO_ROLES.length
    || groups.some((group, index) => group !== SSO_ROLES[index])
  ) return null;
  return groups as SsoRole[];
}

export function trustedSsoIdentity(
  request: Request,
  edgeSecret: string | null,
): TrustedSsoIdentity | null {
  const suppliedEdgeSecret = request.get('x-portfolio-edge-secret');
  if (!edgeSecret || !suppliedEdgeSecret || !safeEqual(suppliedEdgeSecret, edgeSecret)) return null;
  const subject = safeIdentityHeader(request.get('remote-user'), 255);
  const email = safeIdentityHeader(request.get('remote-email'), 320);
  const groups = parseSsoGroups(request.get('remote-groups'));
  if (!subject || !email || !groups) return null;
  return { subject, email, groups, role: groups[groups.length - 1]! };
}

export function ssoRoleAtLeast(identity: TrustedSsoIdentity, minimumRole: SsoRole): boolean {
  return ROLE_RANK[identity.role] >= ROLE_RANK[minimumRole];
}

export function permissionsForRole(role: SsoRole): string[] {
  const permissions: string[] = [];
  if (ROLE_RANK[role] >= ROLE_RANK.developer) {
    permissions.push('dashboard:read', 'auth-inventory:read');
  }
  return permissions;
}
