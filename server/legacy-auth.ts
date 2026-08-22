import { lstatSync } from 'node:fs';
import type { Request } from 'express';
import { requestHasSessionCookie } from './auth.js';

export interface LegacyAuthInventory {
  localPasswordRecords: number;
  unsafeLocalAuthArtifacts: number;
  legacySessionCookies: number;
}

export function inventoryLegacyAuth(
  request: Request,
  authStateFile: string,
): LegacyAuthInventory {
  let localPasswordRecords = 0;
  let unsafeLocalAuthArtifacts = 0;
  try {
    const metadata = lstatSync(authStateFile);
    if (
      metadata.isFile()
      && !metadata.isSymbolicLink()
      && metadata.nlink === 1
      && metadata.size > 0
      && metadata.size <= 4 * 1024
      && (metadata.mode & 0o077) === 0
    ) {
      localPasswordRecords = 1;
    } else {
      unsafeLocalAuthArtifacts = 1;
    }
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
  }
  return {
    localPasswordRecords,
    unsafeLocalAuthArtifacts,
    legacySessionCookies: requestHasSessionCookie(request) ? 1 : 0,
  };
}
