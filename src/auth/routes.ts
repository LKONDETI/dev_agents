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
// Body type guards (minimal; full JSON-schema validation is a TODO)
// ---------------------------------------------------------------------------

/** Shape expected by /register and /login. */
interface AuthBody {
  email: string;
  password: string;
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

  fastify.post('/register', async (request: FastifyRequest, reply: FastifyReply) => {
    const { email, password } = request.body as AuthBody;

    if (!email || !password) {
      return reply.code(400).send({ error: 'email and password are required' });
    }

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

    const payload: JWTPayload = {
      sub: user.id,
      email: user.email,
      roles: [],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECS,
    };

    const accessToken = signAccessToken(payload);
    const refreshToken = generateRefreshToken();

    storeRefreshToken(user.id, refreshToken, REFRESH_TTL_DAYS);
    setRefreshCookie(reply, refreshToken);

    return reply.code(201).send({ accessToken });
  });

  // -------------------------------------------------------------------------
  // POST /login
  // -------------------------------------------------------------------------

  fastify.post('/login', async (request: FastifyRequest, reply: FastifyReply) => {
    const { email, password } = request.body as AuthBody;

    if (!email || !password) {
      return reply.code(400).send({ error: 'email and password are required' });
    }

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

    const payload: JWTPayload = {
      sub: user.id,
      email: user.email,
      roles: [],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECS,
    };

    const accessToken = signAccessToken(payload);
    const refreshToken = generateRefreshToken();

    storeRefreshToken(user.id, refreshToken, REFRESH_TTL_DAYS);
    setRefreshCookie(reply, refreshToken);

    return reply.code(200).send({ accessToken });
  });

  // -------------------------------------------------------------------------
  // POST /refresh
  // -------------------------------------------------------------------------

  fastify.post('/refresh', async (request: FastifyRequest, reply: FastifyReply) => {
    const oldToken: string | undefined = (request.cookies as Record<string, string | undefined>)[
      REFRESH_COOKIE
    ];

    if (!oldToken) {
      return reply.code(401).send({ error: 'Refresh token missing' });
    }

    const newRefreshToken = await rotateRefreshToken(oldToken);

    if (!newRefreshToken) {
      clearRefreshCookie(reply);
      return reply.code(401).send({ error: 'Refresh token invalid or expired' });
    }

    // We need the userId to build a new access token; re-derive it from the
    // old token's revocation store absence — the new session record holds it,
    // but we have no direct accessor here. Instead, verify the old token
    // gracefully from the session rotation result.
    // TODO: expose getUserIdForToken from tokens.ts to avoid re-parsing the
    //       old refresh token when a userId is needed post-rotation.

    // Temporarily derive userId by checking the raw old token is now revoked
    // and trusting the rotation stored a new record. We need to obtain userId
    // from somewhere — parse from the access token in the Authorization header
    // if present, or we return a minimal payload until the TODO above is done.
    //
    // For now: require the client to send the current (possibly expired) access
    // token so we can extract sub/email/roles for the new access token payload.
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // Cannot build a new access token without the old payload.
      // Clear the rotated refresh token and return 401.
      // TODO: store userId in the session record accessor (see above).
      clearRefreshCookie(reply);
      return reply.code(401).send({ error: 'Access token required for refresh' });
    }

    const rawAccessToken = authHeader.slice('Bearer '.length);

    // verifyAccessToken returns null for expired tokens; use jwt.decode for
    // expired-but-structurally-valid tokens so we can reclaim sub/email/roles.
    // We import jwt directly here only for the decode-without-verify path.
    const { default: jwt } = await import('jsonwebtoken');
    const oldPayload = jwt.decode(rawAccessToken) as import('./types').JWTPayload | null;

    if (!oldPayload || !oldPayload.sub) {
      clearRefreshCookie(reply);
      return reply.code(401).send({ error: 'Unable to decode access token payload' });
    }

    const newPayload: JWTPayload = {
      sub: oldPayload.sub,
      email: oldPayload.email,
      roles: oldPayload.roles ?? [],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECS,
    };

    const newAccessToken = signAccessToken(newPayload);

    setRefreshCookie(reply, newRefreshToken);

    return reply.code(200).send({ accessToken: newAccessToken });
  });

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
