/*
 * Implementation plan:
 * 1. Export a Fastify preHandler hook — requireAuth — that protects routes.
 * 2. Extract the Bearer token from the Authorization header; reply 401 if absent.
 * 3. Call verifyAccessToken; reply 401 (generic message) on null — never leak detail.
 * 4. Call isRevoked on the raw token; reply 401 if true.
 * 5. Attach the decoded payload as AuthContext on request.user; call done().
 */

import type { FastifyReply, FastifyRequest } from 'fastify';

import { verifyAccessToken } from './jwt';
import { isRevoked } from './revocation';
import type { AuthContext } from './types';

/** Generic 401 message — never reveals which check failed (ADR-001 § Middleware Chain). */
const UNAUTHORIZED_MESSAGE = 'Unauthorized';

/**
 * Fastify preHandler hook that enforces JWT authentication on a route.
 *
 * Middleware chain (per ADR-001 § Middleware Chain):
 *   1. Extract Bearer token from Authorization header.
 *   2. Verify token signature and expiry.
 *   3. Check the revocation store.
 *   4. Attach {@link AuthContext} to `request.user`.
 *
 * A generic 401 is returned on any failure — raw error details are never
 * surfaced to the caller.
 *
 * @param request - The incoming Fastify request.
 * @param reply   - The Fastify reply, used to send a 401 on failure.
 */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const authHeader = request.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.code(401).send({ error: UNAUTHORIZED_MESSAGE });
  }

  const token = authHeader.slice('Bearer '.length);

  const payload = verifyAccessToken(token);

  if (!payload) {
    return reply.code(401).send({ error: UNAUTHORIZED_MESSAGE });
  }

  const revoked = await isRevoked(token);

  if (revoked) {
    return reply.code(401).send({ error: UNAUTHORIZED_MESSAGE });
  }

  const context: AuthContext = {
    userId: payload.sub,
    email: payload.email,
    roles: payload.roles,
  };

  request.user = context;
}
