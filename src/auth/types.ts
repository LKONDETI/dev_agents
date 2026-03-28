/*
 * Implementation plan:
 * 1. Define the core domain model (User) that maps to the DB row.
 * 2. Define AuthContext — the lightweight principal attached to every
 *    authenticated Fastify request after middleware verification.
 * 3. Define token-related shapes (TokenPair, JWTPayload, SessionRecord)
 *    as specified by ADR-001 (hybrid JWT + httpOnly refresh token pattern).
 * 4. Define ISessionStore interface per ADR-002 so implementations can be
 *    swapped (e.g. Redis) without modifying rotation logic.
 * 5. Augment FastifyRequest so `request.user` is typed project-wide
 *    without casting.
 * 6. Keep this file pure types/interfaces — zero runtime code.
 */

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

/** A persisted user record. passwordHash must never be returned in responses. */
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

// ---------------------------------------------------------------------------
// Request principal
// ---------------------------------------------------------------------------

/**
 * The verified identity attached to every authenticated request.
 * Populated by the auth middleware after JWT verification and revocation check.
 * See ADR-001 § Middleware Chain.
 */
export interface AuthContext {
  userId: string;
  email: string;
  roles: string[];
}

// ---------------------------------------------------------------------------
// Token shapes
// ---------------------------------------------------------------------------

/**
 * The payload returned to the client on a successful login or refresh.
 * accessToken is delivered in the response body; refreshToken is set as an
 * httpOnly, Secure, SameSite=Strict cookie (see ADR-001 § Refresh Tokens).
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * The decoded payload of a signed JWT access token (HS256, 15-min TTL).
 * `sub` mirrors `userId`; `iat` and `exp` are standard JWT registered claims.
 */
export interface JWTPayload {
  sub: string;
  email: string;
  roles: string[];
  iat: number;
  exp: number;
}

/**
 * A persisted refresh-token record in the session store.
 * Rotated on every use; `revoked` is set to true on logout or rotation.
 * `email` and `roles` are stored so the /refresh endpoint can build a new
 * access-token payload without decoding the (possibly expired) old access
 * token (ADR-002 § SessionRecord Enrichment).
 */
export interface SessionRecord {
  userId: string;
  email: string;
  roles: string[];
  token: string;
  expiresAt: Date;
  revoked: boolean;
}

// ---------------------------------------------------------------------------
// Session store abstraction (ADR-002)
// ---------------------------------------------------------------------------

/**
 * Abstraction over the refresh-token session store.
 * The default implementation is in-memory (`InMemorySessionStore` in tokens.ts);
 * swap for a Redis adapter by replacing `defaultSessionStore` in tokens.ts
 * (see ADR-002).
 */
export interface ISessionStore {
  get(token: string): SessionRecord | undefined;
  set(token: string, record: SessionRecord): void;
  delete(token: string): void;
}

// ---------------------------------------------------------------------------
// Revocation store abstraction (ADR-004)
// ---------------------------------------------------------------------------

/**
 * Abstraction over the token revocation store.
 * The default implementation is in-memory; swap for a Redis adapter by
 * replacing `defaultRevocationStore` in revocation.ts (see ADR-004).
 */
export interface IRevocationStore {
  /** Marks a token as revoked for the given TTL (seconds). */
  revoke(token: string, ttl: number): void;
  /**
   * Returns `true` if the token is currently revoked and its revocation entry
   * has not yet expired.
   */
  isRevoked(token: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Fastify module augmentation
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyRequest {
    /** Populated by the auth middleware; undefined on unauthenticated routes. */
    user?: AuthContext;
  }
}
