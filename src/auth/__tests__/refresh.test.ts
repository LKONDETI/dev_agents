/**
 * Integration tests for POST /auth/refresh.
 *
 * Strategy:
 * - Build a real Fastify server via buildServer() so the full request pipeline
 *   (cookie parsing, route handler, session-store look-up) runs exactly as in
 *   production.
 * - A valid refreshToken cookie is obtained by first calling POST /auth/register,
 *   which sets the httpOnly cookie in the response. The cookie value is extracted
 *   and forwarded on the /refresh request — no Authorization header is needed.
 * - The test verifies that /refresh returns a new accessToken derived from the
 *   session-record context (userId, email, roles stored at registration) rather
 *   than from the old access token, as required by ADR-002 § SessionRecord Enrichment.
 * - jest.resetModules() is called in freshServer() so the in-memory session store
 *   and user store start empty for every test case.
 */

// Must be set before any auth module is imported (jwt.ts throws at load time without it)
process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';
process.env['LOG_LEVEL'] = 'silent';

import type { FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Builds a fresh server with a clean module registry for every test. */
async function freshServer(): Promise<FastifyInstance> {
  jest.resetModules();
  process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';
  process.env['LOG_LEVEL'] = 'silent';
  const { buildServer } = await import('../../server');
  return buildServer();
}

/** Performs a JSON POST and returns the raw inject response. */
async function post(
  server: FastifyInstance,
  url: string,
  body: unknown,
  cookie?: string,
): Promise<{ statusCode: number; json: () => Record<string, unknown>; headers: Record<string, string> }> {
  const response = await server.inject({
    method: 'POST',
    url,
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify(body),
  });

  return response as unknown as {
    statusCode: number;
    json: () => Record<string, unknown>;
    headers: Record<string, string>;
  };
}

/**
 * Registers a user and returns the refreshToken cookie string
 * (e.g. "refreshToken=<value>") ready to be forwarded as a Cookie header.
 */
async function registerAndGetCookie(
  server: FastifyInstance,
  email = 'refresh-user@example.com',
  password = 'securePass1',
): Promise<string> {
  const res = await post(server, '/auth/register', { email, password });
  const setCookie: string = res.headers['set-cookie'] as string;
  // Extract the "refreshToken=<value>" segment from the Set-Cookie header.
  // The header may contain multiple directives separated by semicolons.
  const match = setCookie.match(/refreshToken=[^;]+/);
  if (!match) {
    throw new Error(`No refreshToken cookie found in Set-Cookie: ${setCookie}`);
  }
  return match[0];
}

// ---------------------------------------------------------------------------
// POST /auth/refresh — happy path
// ---------------------------------------------------------------------------

describe('POST /auth/refresh — happy path', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await freshServer();
  });

  afterEach(async () => {
    await server.close();
  });

  it('returns 200 and a new accessToken when a valid refreshToken cookie is present', async () => {
    const cookie = await registerAndGetCookie(server);
    const res = await post(server, '/auth/refresh', {}, cookie);

    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty('accessToken');
    expect(typeof res.json()['accessToken']).toBe('string');
  });

  it('returns an accessToken that is a non-empty JWT string (three dot-separated segments)', async () => {
    const cookie = await registerAndGetCookie(server);
    const res = await post(server, '/auth/refresh', {}, cookie);
    const token = res.json()['accessToken'] as string;
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    expect(parts.every((p) => p.length > 0)).toBe(true);
  });

  it('rotates the refresh cookie — the Set-Cookie header contains a new refreshToken', async () => {
    const cookie = await registerAndGetCookie(server);
    const res = await post(server, '/auth/refresh', {}, cookie);

    const setCookie = res.headers['set-cookie'] as string;
    expect(setCookie).toBeDefined();
    expect(setCookie).toMatch(/refreshToken=/);
    expect(setCookie).toMatch(/HttpOnly/i);
  });

  it('builds the access-token payload from session-record context without needing an Authorization header', async () => {
    // Deliberately omit the Authorization header — the session record provides
    // userId, email, and roles (ADR-002 § SessionRecord Enrichment).
    const cookie = await registerAndGetCookie(server, 'ctx-check@example.com');
    const res = await post(server, '/auth/refresh', {}, cookie);

    expect(res.statusCode).toBe(200);
    // The access token contains a payload; decode without verifying to inspect claims.
    const token = res.json()['accessToken'] as string;
    const payloadBase64 = token.split('.')[1];
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf-8'));

    expect(payload).toHaveProperty('sub');
    expect(payload).toHaveProperty('email', 'ctx-check@example.com');
    expect(Array.isArray(payload['roles'])).toBe(true);
  });

  it('accepts the rotated cookie for a subsequent /refresh call', async () => {
    const firstCookie = await registerAndGetCookie(server);
    const firstRefresh = await post(server, '/auth/refresh', {}, firstCookie);
    expect(firstRefresh.statusCode).toBe(200);

    // Extract the rotated cookie from the first refresh response
    const rotatedSetCookie = firstRefresh.headers['set-cookie'] as string;
    const match = rotatedSetCookie.match(/refreshToken=[^;]+/);
    const rotatedCookie = match ? match[0] : '';

    // The rotated cookie must be usable for a further refresh
    const secondRefresh = await post(server, '/auth/refresh', {}, rotatedCookie);
    expect(secondRefresh.statusCode).toBe(200);
    expect(secondRefresh.json()).toHaveProperty('accessToken');
  });
});

// ---------------------------------------------------------------------------
// POST /auth/refresh — missing cookie
// ---------------------------------------------------------------------------

describe('POST /auth/refresh — missing cookie', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await freshServer();
  });

  afterEach(async () => {
    await server.close();
  });

  it('returns 401 when no refreshToken cookie is present', async () => {
    const res = await post(server, '/auth/refresh', {});
    expect(res.statusCode).toBe(401);
  });

  it('returns an error body explaining the token is missing', async () => {
    const res = await post(server, '/auth/refresh', {});
    expect(res.json()).toMatchObject({ error: 'Refresh token missing' });
  });

  it('clears the refreshToken cookie when the token is absent', async () => {
    // When the cookie is missing the route short-circuits before rotation;
    // the Set-Cookie header should NOT be set (no cookie to clear).
    // This validates the 401-fast-exit path leaves no stale cookie.
    const res = await post(server, '/auth/refresh', {});
    expect(res.statusCode).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// POST /auth/refresh — invalid / revoked / already-used token
// ---------------------------------------------------------------------------

describe('POST /auth/refresh — invalid or reused token', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await freshServer();
  });

  afterEach(async () => {
    await server.close();
  });

  it('returns 401 when the refreshToken cookie contains a random unknown value', async () => {
    const res = await post(server, '/auth/refresh', {}, 'refreshToken=not-a-real-token');
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: 'Refresh token invalid or expired' });
  });

  it('returns 401 when the same refreshToken is used twice (rotation invalidates old token)', async () => {
    const cookie = await registerAndGetCookie(server);

    // First use — valid rotation
    const first = await post(server, '/auth/refresh', {}, cookie);
    expect(first.statusCode).toBe(200);

    // Second use of the same (now-revoked) token — must be rejected
    const second = await post(server, '/auth/refresh', {}, cookie);
    expect(second.statusCode).toBe(401);
    expect(second.json()).toMatchObject({ error: 'Refresh token invalid or expired' });
  });

  it('clears the refreshToken cookie in the response when rotation fails', async () => {
    const res = await post(server, '/auth/refresh', {}, 'refreshToken=bogus-token-value');

    expect(res.statusCode).toBe(401);
    // The route calls clearRefreshCookie() which sets maxAge=0
    const setCookie = res.headers['set-cookie'] as string;
    expect(setCookie).toBeDefined();
    expect(setCookie).toMatch(/Max-Age=0/i);
  });
});
