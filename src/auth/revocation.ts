/*
 * Implementation plan:
 * 1. Introduce InMemoryRevocationStore implementing IRevocationStore: move the
 *    module-level Map and cleanup() function into the class (ADR-004).
 * 2. Export a module-level defaultRevocationStore so callers can inject a
 *    different adapter (e.g. Redis) without changing middleware or routes.
 * 3. Keep revokeToken and isRevoked as thin delegation wrappers so all existing
 *    call sites in middleware.ts, tokens.ts, and routes.ts remain unchanged.
 * 4. Guard against empty/falsy tokens in both the class methods and wrappers
 *    to preserve the same defensive behaviour as before.
 * 5. Update the TODO reference from ADR-001 to ADR-004 now that the interface
 *    exists and the swap path is documented there.
 */

// TODO: swap defaultRevocationStore for a RedisRevocationStore before horizontal scaling (see ADR-004)

import type { IRevocationStore } from './types';

// ---------------------------------------------------------------------------
// InMemoryRevocationStore
// ---------------------------------------------------------------------------

/**
 * In-memory implementation of {@link IRevocationStore}.
 *
 * Tokens are stored as `token → absolute expiry timestamp (ms)`. Expired
 * entries are pruned on every {@link revoke} call (purge-on-write strategy)
 * to keep memory bounded without a background timer.
 *
 * Safe to use in tests — instantiate a fresh instance per test case to avoid
 * shared state. For production horizontal scaling, replace with a
 * RedisRevocationStore (see ADR-004 § Redis Adapter Path).
 */
export class InMemoryRevocationStore implements IRevocationStore {
  /** token → absolute expiry timestamp (ms). */
  private readonly store = new Map<string, number>();

  /**
   * Marks a token as revoked for the given TTL.
   *
   * Stores the token with an absolute expiry of `Date.now() + ttl * 1000`,
   * then prunes any already-expired entries so the map does not grow
   * without bound (see ADR-004 § Consequences).
   *
   * @param token - The raw token string to revoke (JWT or refresh token).
   * @param ttl   - Time-to-live in seconds; must be a positive integer.
   */
  revoke(token: string, ttl: number): void {
    if (!token) {
      return;
    }

    this.store.set(token, Date.now() + ttl * 1000);
    this.cleanup();
  }

  /**
   * Checks whether a token is currently revoked.
   *
   * Returns `true` only if the token is present **and** its expiry timestamp
   * is still in the future. An expired entry is treated as not revoked and
   * will be removed on the next {@link revoke} call.
   *
   * @param token - The raw token string to look up.
   * @returns A promise that resolves to `true` if the token is revoked,
   *          `false` otherwise.
   */
  async isRevoked(token: string): Promise<boolean> {
    if (!token) {
      return false;
    }

    const expiresAt = this.store.get(token);

    if (expiresAt === undefined) {
      return false;
    }

    return Date.now() < expiresAt;
  }

  /**
   * Removes all expired entries from the store.
   * Called on every {@link revoke} to keep memory bounded without a timer.
   */
  private cleanup(): void {
    const now = Date.now();

    for (const [token, expiresAt] of this.store) {
      if (expiresAt <= now) {
        this.store.delete(token);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Default instance
// ---------------------------------------------------------------------------

/**
 * The default revocation store used by the module-level helper functions.
 * Replace this export with a `RedisRevocationStore` instance to switch the
 * entire application to a distributed backend without changing any call site
 * (see ADR-004 § Redis Adapter Path).
 */
export const defaultRevocationStore: IRevocationStore = new InMemoryRevocationStore();

// ---------------------------------------------------------------------------
// Public API — thin delegation wrappers (call sites unchanged)
// ---------------------------------------------------------------------------

/**
 * Marks a token as revoked for the given TTL.
 *
 * Delegates to {@link defaultRevocationStore}. Existing call sites in
 * `middleware.ts`, `tokens.ts`, and `routes.ts` require no changes (ADR-004).
 *
 * @param token - The raw token string to revoke (JWT or refresh token).
 * @param ttl   - Time-to-live in seconds; must be a positive integer.
 */
export function revokeToken(token: string, ttl: number): void {
  defaultRevocationStore.revoke(token, ttl);
}

/**
 * Checks whether a token is currently revoked.
 *
 * Delegates to {@link defaultRevocationStore}. The `async` signature is
 * preserved so adapters with async backends (e.g. Redis) can slot in without
 * changing call sites (ADR-004 § Context).
 *
 * @param token - The raw token string to look up.
 * @returns A promise that resolves to `true` if the token is revoked,
 *          `false` otherwise.
 */
export async function isRevoked(token: string): Promise<boolean> {
  return defaultRevocationStore.isRevoked(token);
}
