/*
 * Implementation plan:
 * 1. Create a buildServer factory that registers plugins and routes; exporting
 *    it separately from the listen call makes the server testable without I/O.
 * 2. Register @fastify/cookie so setCookie works in auth routes.
 * 3. Register authRoutes under the /auth prefix.
 * 4. Export buildServer for tests; export start for the process entry point.
 * 5. Guard the process startup behind a `require.main` check so tests can
 *    import buildServer without side effects.
 */

import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import addFormats from 'ajv-formats';

import { authRoutes } from './auth/routes';

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

/**
 * Builds and configures the Fastify server instance without starting it.
 *
 * Separate from {@link start} so tests can call `buildServer()` directly
 * without binding to a port.
 *
 * @returns A fully configured but not-yet-listening {@link FastifyInstance}.
 */
export async function buildServer(): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: {
      level: process.env['LOG_LEVEL'] ?? 'info',
    },
    // Register ajv-formats so `format: 'email'` is enforced on body schemas
    // (ADR-005 § Format Validation). Without this, ajv silently ignores the
    // `format` keyword and invalid email strings would pass validation.
    // Set removeAdditional: false so `additionalProperties: false` causes a 400
    // response instead of silently stripping extra fields (ADR-005 § Consequences).
    ajv: {
      // ajv-formats' FormatsPlugin return type (Ajv) is narrower than Fastify's
      // expected Plugin<unknown> (void); cast is safe — the plugin mutates the
      // Ajv instance in place and Fastify does not use the return value.
      plugins: [addFormats as unknown as (ajv: unknown) => void],
      customOptions: { removeAdditional: false },
    },
  });

  // Register the cookie plugin before routes so setCookie is available
  await fastify.register(cookie);

  // Auth routes under /auth (ADR-001 § API Endpoints)
  await fastify.register(authRoutes, { prefix: '/auth' });

  return fastify;
}

// ---------------------------------------------------------------------------
// Process entry point
// ---------------------------------------------------------------------------

/**
 * Builds the server and starts listening on the configured port.
 *
 * @param port - TCP port to bind; defaults to PORT env var or 3000.
 * @param host - Host to bind; defaults to '0.0.0.0'.
 */
export async function start(
  port: number = parseInt(process.env['PORT'] ?? '3000', 10),
  host: string = '0.0.0.0',
): Promise<void> {
  const server = await buildServer();

  try {
    await server.listen({ port, host });
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

// Start the server only when this file is the process entry point
if (require.main === module) {
  void start();
}
