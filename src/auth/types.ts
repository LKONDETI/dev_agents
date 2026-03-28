/*
 * Implementation plan:
 * 1. Define the core domain model (User) that maps to the DB row.
 * 2. Define AuthContext — the lightweight principal attached to every
 *    authenticated Fastify request after middleware verification.
 * 3. Define token-related shapes (TokenPair, JWTPayload, SessionRecord)
 *    as specified by ADR-001 (hybrid JWT + httpOnly refresh token pattern).
 * 4. Augment FastifyRequest so `request.user` is typed project-wide
 *    without casting.
 * 5. Keep this file pure types/interfaces — zero runtime code.
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
 * A persisted refresh-token record in the revocation store.
 * Rotated on every use; `revoked` is set to true on logout or rotation.
 * TODO: replace in-memory Map with a Redis adapter before horizontal scaling
 * (see ADR-001 § Out of Scope).
 */
export interface SessionRecord {
  userId: string;
  token: string;
  expiresAt: Date;
  revoked: boolean;
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
