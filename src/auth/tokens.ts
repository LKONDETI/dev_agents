/*
 * Implementation plan:
 * 1. Define InMemorySessionStore implementing ISessionStore (ADR-002); export
 *    defaultSessionStore so tests and future adapters can inject alternatives.
 * 2. generateRefreshToken: use crypto.randomBytes(32) and encode as hex,
 *    producing a 64-character unpredictable string (ADR-001 § Refresh Tokens).
 * 3. storeRefreshToken: accepts email + roles in addition to userId so the
 *    SessionRecord carries enough context for the /refresh route to build a new
 *    access-token payload without decoding the old token (ADR-002 § storeRefreshToken).
 * 4. rotateRefreshToken: look up the old token; reject if missing, revoked, or
 *    expired; generate + store a fresh token preserving email/roles; revoke the
 *    old one via revokeToken for the remaining TTL so it cannot be replayed;
 *    return the new token string.
 * 5. All store accesses delegate to defaultSessionStore (no direct Map calls).
 */

import { randomBytes } from 'crypto';

import { isRevoked, revokeToken } from './revocation';
import type { ISessionStore, SessionRecord } from './types';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Default refresh-token TTL in days.
 * Reads REFRESH_TOKEN_TTL_DAYS from the environment; falls back to 7 if unset
 * or if the value cannot be parsed as a positive integer (ADR-001 § Refresh Tokens).
 */
function getDefaultTtlDays(): number {
  const raw = process.env['REFRESH_TOKEN_TTL_DAYS'];

  if (raw !== undefined) {
    const parsed = parseInt(raw, 10);

    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return 7;
}

// ---------------------------------------------------------------------------
// Session store (ADR-002)
// ---------------------------------------------------------------------------

/**
 * Map-backed implementation of ISessionStore.
 * Swap `defaultSessionStore` for a Redis adapter to support horizontal
 * scaling without modifying rotation logic (ADR-002 § InMemorySessionStore).
 */
export class InMemorySessionStore implements ISessionStore {
  private readonly store = new Map<string, SessionRecord>();

  get(token: string): SessionRecord | undefined {
    return this.store.get(token);
  }

  set(token: string, record: SessionRecord): void {
    this.store.set(token, record);
  }

  delete(token: string): void {
    this.store.delete(token);
  }
}

/**
 * Module-level default session store instance.
 * Tests may create their own `InMemorySessionStore` and inject it via the
 * optional `store` parameter of `storeRefreshToken` / `rotateRefreshToken`,
 * or clear this instance between test cases.
 * TODO: replace with a Redis adapter before horizontal scaling (ADR-002 § Out of Scope).
 */
export const defaultSessionStore: ISessionStore = new InMemorySessionStore();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically random refresh token.
 *
 * Uses Node's `crypto.randomBytes` to produce 32 bytes of entropy,
 * then hex-encodes them into a 64-character string (ADR-001 § Refresh Tokens).
 *
 * @returns A hex-encoded 64-character random token string.
 */
export function generateRefreshToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Stores a new refresh-token session record in the session store.
 *
 * `email` and `roles` are persisted alongside `userId` so the /refresh
 * endpoint can build a new access-token payload without decoding the (possibly
 * expired) old access token (ADR-002 § storeRefreshToken Signature Update).
 *
 * The TTL is expressed in days and is converted to an absolute `expiresAt`
 * timestamp. The default TTL is read from `REFRESH_TOKEN_TTL_DAYS`; if the
 * variable is absent or invalid, it falls back to 7 days (ADR-001 § Refresh Tokens).
 *
 * @param userId  - The ID of the user this session belongs to.
 * @param email   - The user's email address (stored for /refresh payload rebuild).
 * @param roles   - The user's roles (stored for /refresh payload rebuild).
 * @param token   - The raw refresh token string (from {@link generateRefreshToken}).
 * @param ttlDays - Lifetime of the session in days.
 */
export function storeRefreshToken(
  userId: string,
  email: string,
  roles: string[],
  token: string,
  ttlDays: number,
): void {
  if (!userId || !token) {
    return;
  }

  const days = ttlDays > 0 ? ttlDays : getDefaultTtlDays();
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  const record: SessionRecord = {
    userId,
    email,
    roles,
    token,
    expiresAt,
    revoked: false,
  };

  defaultSessionStore.set(token, record);
}

/**
 * Rotates a refresh token: validates the old token, issues a new one, and
 * invalidates the old one so it cannot be reused (ADR-001 § Refresh Tokens).
 *
 * Rotation steps:
 * 1. Look up the old token in the session store — return `null` if not found.
 * 2. Reject if the session is marked revoked or has already expired.
 * 3. Check the revocation store via `isRevoked` for any out-of-band revocation.
 * 4. Generate and store a new token preserving userId, email, and roles from
 *    the old record so the caller can build a new access-token payload without
 *    decoding the old access token (ADR-002 § SessionRecord Enrichment).
 * 5. Revoke the old token for its remaining TTL seconds, then mark it revoked
 *    in the session store so in-memory checks are also consistent.
 *
 * @param oldToken - The refresh token presented by the client.
 * @returns The new `SessionRecord` (including the new token string), or `null`
 *          if the old token is invalid, revoked, or expired.
 */
export async function rotateRefreshToken(oldToken: string): Promise<SessionRecord | null> {
  if (!oldToken) {
    return null;
  }

  const record = defaultSessionStore.get(oldToken);

  if (!record) {
    return null;
  }

  // Reject tokens that are already revoked in the session store
  if (record.revoked) {
    return null;
  }

  // Reject tokens that have passed their natural expiry
  if (record.expiresAt <= new Date()) {
    return null;
  }

  // Reject tokens that have been revoked via the out-of-band revocation store
  const revoked = await isRevoked(oldToken);

  if (revoked) {
    return null;
  }

  // Calculate remaining TTL in seconds for the new session and old-token revocation
  const remainingMs = record.expiresAt.getTime() - Date.now();
  const remainingDays = remainingMs / (24 * 60 * 60 * 1000);

  // Generate and persist the replacement token, carrying over user context fields
  const newToken = generateRefreshToken();

  storeRefreshToken(record.userId, record.email, record.roles, newToken, remainingDays);

  // Revoke the old token in the revocation store for its remaining TTL (in seconds)
  const remainingSecs = Math.ceil(remainingMs / 1000);

  revokeToken(oldToken, remainingSecs);

  // Also mark it revoked in the session store so in-memory lookups are consistent
  record.revoked = true;
  defaultSessionStore.set(oldToken, record);

  // Return the new session record so the caller can access userId/email/roles
  // without a secondary store lookup or decoding the old access token (ADR-002).
  const newRecord = defaultSessionStore.get(newToken);

  return newRecord ?? null;
}
