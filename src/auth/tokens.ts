/*
 * Implementation plan:
 * 1. Back session storage with an in-memory Map<string, SessionRecord>; key is
 *    the token string so lookups are O(1).
 * 2. generateRefreshToken: use crypto.randomBytes(32) and encode as hex,
 *    producing a 64-character unpredictable string (ADR-001 § Refresh Tokens).
 * 3. storeRefreshToken: build a SessionRecord with expiresAt = now + ttlDays,
 *    defaulting ttlDays to REFRESH_TOKEN_TTL_DAYS env var (fallback: 7), then
 *    insert it into the session store.
 * 4. rotateRefreshToken: look up the old token; reject if missing, revoked, or
 *    expired; generate + store a fresh token; revoke the old one via revokeToken
 *    for the remaining TTL so it cannot be replayed; return the new token.
 * 5. Export all three functions as named exports; keep the session store internal.
 */

import { randomBytes } from 'crypto';

import { isRevoked, revokeToken } from './revocation';
import type { SessionRecord } from './types';

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
// In-memory session store
// ---------------------------------------------------------------------------

// TODO: replace with a Redis adapter before horizontal scaling (see ADR-001 § Out of Scope)

/** In-memory session store: refresh token string → SessionRecord. */
const sessionStore = new Map<string, SessionRecord>();

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
 * Stores a new refresh-token session record in the in-memory session store.
 *
 * The TTL is expressed in days and is converted to an absolute `expiresAt`
 * timestamp. The default TTL is read from `REFRESH_TOKEN_TTL_DAYS`; if the
 * variable is absent or invalid, it falls back to 7 days (ADR-001 § Refresh Tokens).
 *
 * @param userId  - The ID of the user this session belongs to.
 * @param token   - The raw refresh token string (from {@link generateRefreshToken}).
 * @param ttlDays - Lifetime of the session in days.
 */
export function storeRefreshToken(userId: string, token: string, ttlDays: number): void {
  if (!userId || !token) {
    return;
  }

  const days = ttlDays > 0 ? ttlDays : getDefaultTtlDays();
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  const record: SessionRecord = {
    userId,
    token,
    expiresAt,
    revoked: false,
  };

  sessionStore.set(token, record);
}

/**
 * Rotates a refresh token: validates the old token, issues a new one, and
 * invalidates the old one so it cannot be reused (ADR-001 § Refresh Tokens).
 *
 * Rotation steps:
 * 1. Look up the old token in the session store — return `null` if not found.
 * 2. Reject if the session is marked revoked or has already expired.
 * 3. Check the revocation store via `isRevoked` for any out-of-band revocation.
 * 4. Generate and store a new token with the same userId and remaining TTL.
 * 5. Revoke the old token for its remaining TTL seconds, then mark it revoked
 *    in the session store so in-memory checks are also consistent.
 *
 * @param oldToken - The refresh token presented by the client.
 * @returns The new refresh token string, or `null` if the old token is invalid.
 */
export async function rotateRefreshToken(oldToken: string): Promise<string | null> {
  if (!oldToken) {
    return null;
  }

  const record = sessionStore.get(oldToken);

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

  // Generate and persist the replacement token
  const newToken = generateRefreshToken();

  storeRefreshToken(record.userId, newToken, remainingDays);

  // Revoke the old token in the revocation store for its remaining TTL (in seconds)
  const remainingSecs = Math.ceil(remainingMs / 1000);

  revokeToken(oldToken, remainingSecs);

  // Also mark it revoked in the session store so in-memory lookups are consistent
  record.revoked = true;
  sessionStore.set(oldToken, record);

  return newToken;
}
