/*
 * Implementation plan:
 * 1. Load JWT_SECRET from process.env at module initialisation; throw a
 *    startup error immediately if it is absent so misconfiguration is caught
 *    before any request is served.
 * 2. signAccessToken: sign a JWTPayload with HS256 and a 15-minute TTL using
 *    jsonwebtoken; return the compact token string.
 * 3. verifyAccessToken: verify and decode the token; catch every possible
 *    failure (expired, tampered, malformed) and return null — never surface
 *    raw error detail to the caller (ADR-001 § Middleware Chain).
 * 4. Export both functions as named exports for tree-shaking friendliness.
 * 5. Keep this module side-effect-free beyond the env-guard at load time.
 */

import jwt from 'jsonwebtoken';

import type { JWTPayload } from './types';

// ---------------------------------------------------------------------------
// Environment guard — fail fast at startup if the secret is missing
// ---------------------------------------------------------------------------

const JWT_SECRET = process.env['JWT_SECRET'];

if (!JWT_SECRET) {
  throw new Error(
    'JWT_SECRET environment variable is not set. ' +
      'Set it before starting the server.',
  );
}

/** HS256 access-token TTL as specified in ADR-001 § Access Tokens. */
const ACCESS_TOKEN_TTL = '15m';

// ---------------------------------------------------------------------------
// Token operations
// ---------------------------------------------------------------------------

/**
 * Signs a JWT access token using HS256 with a 15-minute TTL.
 *
 * @param payload - The {@link JWTPayload} to embed in the token.
 * @returns A compact JWT string safe to return in the response body.
 *
 * Security note: the token is signed with the secret from JWT_SECRET; the
 * secret is never included in the token itself.
 */
export function signAccessToken(payload: JWTPayload): string {
  // Cast away the readonly constraint that TypeScript infers for the secret
  // after the env-guard above; JWT_SECRET is guaranteed non-empty here.
  return jwt.sign(payload, JWT_SECRET as string, {
    algorithm: 'HS256',
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

/**
 * Verifies and decodes a JWT access token.
 *
 * Returns the decoded {@link JWTPayload} on success, or `null` on any
 * failure — including expired tokens, invalid signatures, and malformed
 * input. Raw error detail is never surfaced to the caller (ADR-001
 * § Middleware Chain).
 *
 * @param token - The compact JWT string extracted from the Authorization header.
 * @returns The decoded payload, or `null` if verification fails for any reason.
 */
export function verifyAccessToken(token: string): JWTPayload | null {
  if (!token) {
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET as string, {
      algorithms: ['HS256'],
    });

    return decoded as JWTPayload;
  } catch {
    // Intentionally swallow all errors (TokenExpiredError, JsonWebTokenError,
    // NotBeforeError, etc.) — callers receive null and respond with a generic
    // 401. Do NOT log the raw error here; that is the middleware's concern.
    return null;
  }
}
