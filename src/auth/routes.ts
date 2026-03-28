/*
 * Implementation plan:
 * 1. Export an authRoutes Fastify plugin that registers all five endpoints
 *    from ADR-001: POST /register, POST /login, POST /refresh, POST /logout, GET /me.
 * 2. Register and login build a TokenPair: access token in the body, refresh
 *    token set as an httpOnly, Secure, SameSite=Strict cookie (ADR-001 § Refresh Tokens).
 * 3. /refresh reads the cookie, calls rotateRefreshToken, issues a new token pair.
 * 4. /logout revokes the current access token and the refresh token cookie.
 * 5. /me is protected by requireAuth and returns the AuthContext (no passwordHash).
 */

import type { FastifyInstance, FastifyPluginCallback, FastifyReply, FastifyRequest } from 'fastify';

import { signAccessToken, verifyAccessToken } from './jwt';
import { requireAuth } from './middleware';
import { verifyPassword } from './password';
import { revokeToken } from './revocation';
import { generateRefreshToken, rotateRefreshToken, storeRefreshToken } from './tokens';
import type { JWTPayload } from './types';
import { createUser, findUserByEmail } from './userStore';

// Note: jsonwebtoken is no longer imported here. The jwt.decode workaround in
// /refresh has been eliminated by enriching SessionRecord with email and roles
// (ADR-002 § SessionRecord Enrichment).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Name of the httpOnly cookie that carries the refresh token (ADR-001 § Refresh Tokens). */
const REFRESH_COOKIE = 'refreshToken';

/** Default refresh-token TTL in days; used when building the cookie max-age. */
const REFRESH_TTL_DAYS = (() => {
  const raw = process.env['REFRESH_TOKEN_TTL_DAYS'];

  if (raw !== undefined) {
    const parsed = parseInt(raw, 10);

    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return 7;
})();

/** Access-token TTL in seconds — matches the 15-minute value in jwt.ts (ADR-001 § Access Tokens). */
const ACCESS_TOKEN_TTL_SECS = 15 * 60;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Sets the refresh-token as an httpOnly, Secure, SameSite=Strict cookie.
 * The max-age is expressed in seconds.
 */
function setRefreshCookie(reply: FastifyReply, token: string): void {
  reply.setCookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: REFRESH_TTL_DAYS * 24 * 60 * 60,
  });
}

/** Clears the refresh-token cookie on logout. */
function clearRefreshCookie(reply: FastifyReply): void {
  reply.setCookie(REFRESH_COOKIE, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 0,
  });
}

// ---------------------------------------------------------------------------
// JSON Schema validation (ADR-005)
// ---------------------------------------------------------------------------

/**
 * Shared body schema for /register and /login.
 * Fastify (ajv) validates this before any handler code runs, so the handler
 * can safely destructure `email` and `password` without runtime guards.
 * `additionalProperties: false` rejects any extra fields in the request body.
 * `format: 'email'` requires ajv-formats to be registered on the server
 * instance (see server.ts — ADR-005 § Format Validation).
 */
const authBodySchema = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: { type: 'string', format: 'email' },
    password: { type: 'string', minLength: 8 },
  },
  additionalProperties: false,
} as const;

/**
 * TypeScript mirror of authBodySchema.
 * After schema validation passes, the handler is guaranteed:
 *   - email: a non-empty string that matches the email format
 *   - password: a string of at least 8 characters
 */
interface AuthBody {
  email: string;    // guaranteed: string, valid email format
  password: string; // guaranteed: string, minLength 8
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/**
 * Fastify plugin that registers all auth endpoints under the prefix configured
 * by the caller (typically /auth).
 *
 * Endpoints (ADR-001 § API Endpoints):
 *   POST /register  — creates a new user and returns a token pair
 *   POST /login     — verifies credentials and returns a token pair
 *   POST /refresh   — rotates the refresh-token cookie and returns a new pair
 *   POST /logout    — revokes the current access token and clears the cookie
 *   GET  /me        — returns the authenticated user's AuthContext
 */
export const authRoutes: FastifyPluginCallback = (
  fastify: FastifyInstance,
  _options: object,
  done: () => void,
): void => {
  // -------------------------------------------------------------------------
  // POST /register
  // -------------------------------------------------------------------------

  fastify.post(
    '/register',
    // Rate limit: 5 requests per IP per hour (ADR-006 § Per-Route Limits).
    // Tight limit blocks email-enumeration abuse with minimal friction for
    // legitimate users (account creation should be rare per IP).
    { config: { rateLimit: { max: 5, timeWindow: '1 hour' } }, schema: { body: authBodySchema } },
    async (request: FastifyRequest<{ Body: AuthBody }>, reply: FastifyReply) => {
      const { email, password } = request.body;

      let user;

      try {
        user = await createUser(email, password);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Registration failed';

        // Surface a 409 for duplicate emails; 400 for everything else
        const isDuplicate =
          err instanceof Error && err.message.includes('already registered');
        return reply.code(isDuplicate ? 409 : 400).send({ error: message });
      }

      // NOTE: iat and exp are intentionally omitted here; signAccessToken sets
      // expiresIn which causes jsonwebtoken to populate both fields automatically.
      // Providing exp in the payload alongside expiresIn causes jsonwebtoken to
      // throw "Bad options.expiresIn option — payload already has exp property".
      const payload = {
        sub: user.id,
        email: user.email,
        roles: [] as string[],
      };

      const accessToken = signAccessToken(payload as unknown as JWTPayload);
      const refreshToken = generateRefreshToken();

      storeRefreshToken(user.id, user.email, payload.roles, refreshToken, REFRESH_TTL_DAYS);
      setRefreshCookie(reply, refreshToken);

      return reply.code(201).send({ accessToken });
    },
  );

  // -------------------------------------------------------------------------
  // POST /login
  // -------------------------------------------------------------------------

  fastify.post(
    '/login',
    // Rate limit: 10 requests per IP per 15 minutes (ADR-006 § Per-Route Limits).
    // Allows ~40 attempts per hour before lockout — sufficient for a user who
    // misremembers their password while making brute force impractical.
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } }, schema: { body: authBodySchema } },
    async (request: FastifyRequest<{ Body: AuthBody }>, reply: FastifyReply) => {
      const { email, password } = request.body;

      const user = findUserByEmail(email);

      // Use a constant-time-equivalent response to avoid leaking whether the
      // email exists (generic 401 for both bad email and bad password).
      if (!user) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      const valid = await verifyPassword(password, user.passwordHash);

      if (!valid) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      // NOTE: iat and exp are intentionally omitted — signAccessToken sets
      // expiresIn which causes jsonwebtoken to populate both automatically.
      const payload = {
        sub: user.id,
        email: user.email,
        roles: [] as string[],
      };

      const accessToken = signAccessToken(payload as unknown as JWTPayload);
      const refreshToken = generateRefreshToken();

      storeRefreshToken(user.id, user.email, payload.roles, refreshToken, REFRESH_TTL_DAYS);
      setRefreshCookie(reply, refreshToken);

      return reply.code(200).send({ accessToken });
    },
  );

  // -------------------------------------------------------------------------
  // POST /refresh
  // -------------------------------------------------------------------------

  fastify.post(
    '/refresh',
    // Rate limit: 20 requests per IP per minute (ADR-006 § Per-Route Limits).
    // Generous enough for SPAs that refresh on every tab focus while blocking
    // automated refresh-token exhaustion attacks.
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const oldToken: string | undefined = (request.cookies as Record<string, string | undefined>)[
        REFRESH_COOKIE
      ];

      if (!oldToken) {
        return reply.code(401).send({ error: 'Refresh token missing' });
      }

      // rotateRefreshToken now returns the new SessionRecord (which contains
      // userId, email, and roles) so we no longer need to decode the old access
      // token to reconstruct the payload (ADR-002 § SessionRecord Enrichment).
      const newSession = await rotateRefreshToken(oldToken);

      if (!newSession) {
        clearRefreshCookie(reply);
        return reply.code(401).send({ error: 'Refresh token invalid or expired' });
      }

      const newPayload: JWTPayload = {
        sub: newSession.userId,
        email: newSession.email,
        roles: newSession.roles,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECS,
      };

      const newAccessToken = signAccessToken(newPayload);

      setRefreshCookie(reply, newSession.token);

      return reply.code(200).send({ accessToken: newAccessToken });
    },
  );

  // -------------------------------------------------------------------------
  // POST /logout
  // -------------------------------------------------------------------------

  fastify.post(
    '/logout',
    { preHandler: requireAuth },
    async (request: FastifyRequest, reply: FastifyReply) => {
      // Revoke the current access token for its remaining TTL
      const authHeader = request.headers['authorization']!;
      const token = authHeader.slice('Bearer '.length);

      const payload = verifyAccessToken(token);

      if (payload) {
        const remainingSecs = payload.exp - Math.floor(Date.now() / 1000);

        if (remainingSecs > 0) {
          revokeToken(token, remainingSecs);
        }
      }

      // Revoke the refresh token if present
      const refreshToken: string | undefined = (
        request.cookies as Record<string, string | undefined>
      )[REFRESH_COOKIE];

      if (refreshToken) {
        // Revoke for the full default TTL — the rotation store tracks the real expiry
        revokeToken(refreshToken, REFRESH_TTL_DAYS * 24 * 60 * 60);
      }

      clearRefreshCookie(reply);

      return reply.code(200).send({ message: 'Logged out' });
    },
  );

  // -------------------------------------------------------------------------
  // GET /me
  // -------------------------------------------------------------------------

  fastify.get(
    '/me',
    { preHandler: requireAuth },
    async (request: FastifyRequest, reply: FastifyReply) => {
      return reply.code(200).send(request.user);
    },
  );

  done();
};
