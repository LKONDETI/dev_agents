/*
 * Implementation plan:
 * 1. Back the revocation store with an in-memory Map<string, number> where the
 *    value is the absolute expiry timestamp (Date.now() + ttl * 1000).
 * 2. revokeToken: add the token to the store, then call cleanup to purge any
 *    entries that have already expired — keeps memory bounded on every write.
 * 3. isRevoked: look up the token; if present and not yet expired, return true;
 *    if the entry exists but has expired, treat it as not revoked (entry will
 *    be pruned on the next write).
 * 4. cleanup: iterate the Map and delete every entry whose expiry is in the past.
 * 5. Export revokeToken and isRevoked as named exports; keep cleanup internal.
 */

// TODO: swap Map for Redis adapter before horizontal scaling (see ADR-001)

/** In-memory revocation store: token → absolute expiry timestamp (ms). */
const store = new Map<string, number>();

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Removes all expired entries from the in-memory store.
 * Called on every write to keep memory bounded without a background timer.
 */
function cleanup(): void {
  const now = Date.now();

  for (const [token, expiresAt] of store) {
    if (expiresAt <= now) {
      store.delete(token);
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Marks a token as revoked for the given TTL.
 *
 * The token is stored with an absolute expiry timestamp of
 * `Date.now() + ttl * 1000`. Expired entries are pruned on every call so the
 * store does not grow without bound (see ADR-001 § Revocation Store).
 *
 * @param token - The raw token string to revoke (JWT or refresh token).
 * @param ttl   - Time-to-live in seconds; must be a positive integer.
 */
export function revokeToken(token: string, ttl: number): void {
  if (!token) {
    return;
  }

  const expiresAt = Date.now() + ttl * 1000;
  store.set(token, expiresAt);

  cleanup();
}

/**
 * Checks whether a token is currently revoked.
 *
 * Returns `true` only if the token is present in the store **and** its expiry
 * timestamp is still in the future. An expired entry is treated as not revoked
 * (the token's natural expiry has already passed) and will be removed on the
 * next write.
 *
 * @param token - The raw token string to look up.
 * @returns A promise that resolves to `true` if the token is revoked,
 *          `false` otherwise.
 */
export async function isRevoked(token: string): Promise<boolean> {
  if (!token) {
    return false;
  }

  const expiresAt = store.get(token);

  if (expiresAt === undefined) {
    return false;
  }

  return Date.now() < expiresAt;
}
