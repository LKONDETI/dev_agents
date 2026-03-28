/**
 * Integration tests for POST /auth/register and POST /auth/login.
 *
 * Strategy:
 * - Build a real Fastify server instance via buildServer() for each test,
 *   so JSON Schema validation (ajv + ajv-formats) and route handlers run
 *   exactly as they do in production.
 * - The userStore is an in-memory Map inside the module; Jest's module
 *   registry is reset between each test via jest.resetModules() combined with
 *   a fresh dynamic import, ensuring no user created in one test leaks into
 *   another.
 * - JWT_SECRET is set before any import so jwt.ts does not throw at load time.
 */

// Must be set before any auth module is imported (jwt.ts throws on load if absent)
process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';
// Silence Fastify's logger output during tests
process.env['LOG_LEVEL'] = 'silent';

import type { FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Re-imports buildServer with a clean module registry so the userStore Map
 *  is a fresh instance for each test. */
async function freshServer(): Promise<FastifyInstance> {
  jest.resetModules();
  // Re-set env after resetModules clears any module-cached env guards
  process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';
  const { buildServer } = await import('../../server');
  return buildServer();
}

/** Performs a JSON POST and returns the raw Fastify LightMyRequest response. */
async function post(
  server: FastifyInstance,
  url: string,
  body: unknown,
): Promise<{ statusCode: number; json: () => Record<string, unknown> }> {
  return server.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// POST /auth/register
// ---------------------------------------------------------------------------

describe('POST /auth/register', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await freshServer();
  });

  afterEach(async () => {
    await server.close();
  });

  // Happy path

  it('returns 201 and an accessToken when given a valid email and password', async () => {
    const res = await post(server, '/auth/register', {
      email: 'alice@example.com',
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(201);
    expect(res.json()).toHaveProperty('accessToken');
    expect(typeof res.json()['accessToken']).toBe('string');
  });

  it('sets a refreshToken httpOnly cookie on successful registration', async () => {
    const res = await post(server, '/auth/register', {
      email: 'bob@example.com',
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(201);
    const setCookieHeader = (res as unknown as { headers: Record<string, string> }).headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();
    expect(setCookieHeader).toMatch(/refreshToken=/);
    expect(setCookieHeader).toMatch(/HttpOnly/i);
  });

  // Invalid email format

  it('returns 400 when email is not a valid email address', async () => {
    const res = await post(server, '/auth/register', {
      email: 'not-an-email',
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when email is a plain string with no @ sign', async () => {
    const res = await post(server, '/auth/register', {
      email: 'justtext',
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(400);
  });

  // Password too short

  it('returns 400 when password is fewer than 8 characters', async () => {
    const res = await post(server, '/auth/register', {
      email: 'charlie@example.com',
      password: 'short',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when password is exactly 7 characters', async () => {
    const res = await post(server, '/auth/register', {
      email: 'diana@example.com',
      password: '1234567',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 201 when password is exactly 8 characters (boundary)', async () => {
    const res = await post(server, '/auth/register', {
      email: 'eve@example.com',
      password: '12345678',
    });

    expect(res.statusCode).toBe(201);
  });

  // Extra fields rejected (additionalProperties: false)

  it('returns 400 when the request body contains extra fields', async () => {
    const res = await post(server, '/auth/register', {
      email: 'frank@example.com',
      password: 'securePass1',
      role: 'admin',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when the request body contains only extra fields and no required fields', async () => {
    const res = await post(server, '/auth/register', {
      username: 'frank',
      secret: 'securePass1',
    });

    expect(res.statusCode).toBe(400);
  });

  // Empty fields

  it('returns 400 when email is an empty string', async () => {
    const res = await post(server, '/auth/register', {
      email: '',
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when password is an empty string', async () => {
    const res = await post(server, '/auth/register', {
      email: 'grace@example.com',
      password: '',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when both email and password are absent', async () => {
    const res = await post(server, '/auth/register', {});

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when email field is missing', async () => {
    const res = await post(server, '/auth/register', {
      password: 'securePass1',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when password field is missing', async () => {
    const res = await post(server, '/auth/register', {
      email: 'henry@example.com',
    });

    expect(res.statusCode).toBe(400);
  });

  // Duplicate email

  it('returns 409 when registering with an already registered email', async () => {
    await post(server, '/auth/register', {
      email: 'iris@example.com',
      password: 'securePass1',
    });

    const res = await post(server, '/auth/register', {
      email: 'iris@example.com',
      password: 'anotherPass2',
    });

    expect(res.statusCode).toBe(409);
  });
});

// ---------------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------------

describe('POST /auth/login', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await freshServer();
    // Seed one user for login tests
    await post(server, '/auth/register', {
      email: 'user@example.com',
      password: 'correctPassword1',
    });
  });

  afterEach(async () => {
    await server.close();
  });

  // Happy path

  it('returns 200 and an accessToken when credentials are correct', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty('accessToken');
    expect(typeof res.json()['accessToken']).toBe('string');
  });

  it('sets a refreshToken httpOnly cookie on successful login', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(200);
    const setCookieHeader = (res as unknown as { headers: Record<string, string> }).headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();
    expect(setCookieHeader).toMatch(/refreshToken=/);
    expect(setCookieHeader).toMatch(/HttpOnly/i);
  });

  // Wrong password

  it('returns 401 when password is incorrect', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'wrongPassword99',
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: 'Invalid credentials' });
  });

  // Unknown email

  it('returns 401 when email is not registered', async () => {
    const res = await post(server, '/auth/login', {
      email: 'nobody@example.com',
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: 'Invalid credentials' });
  });

  // Same generic 401 for both bad email and bad password (no information leak)

  it('returns the same error message for bad email and bad password', async () => {
    const badEmail = await post(server, '/auth/login', {
      email: 'nobody@example.com',
      password: 'correctPassword1',
    });

    const badPassword = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'wrongPassword99',
    });

    expect(badEmail.json()['error']).toBe(badPassword.json()['error']);
  });

  // Invalid email format

  it('returns 400 when email is not a valid email address', async () => {
    const res = await post(server, '/auth/login', {
      email: 'not-an-email',
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(400);
  });

  // Password too short

  it('returns 400 when password is fewer than 8 characters', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'short',
    });

    expect(res.statusCode).toBe(400);
  });

  // Extra fields rejected (additionalProperties: false)

  it('returns 400 when the request body contains extra fields', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: 'correctPassword1',
      rememberMe: true,
    });

    expect(res.statusCode).toBe(400);
  });

  // Empty fields

  it('returns 400 when email is an empty string', async () => {
    const res = await post(server, '/auth/login', {
      email: '',
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when password is an empty string', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
      password: '',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when both email and password are absent', async () => {
    const res = await post(server, '/auth/login', {});

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when email field is missing', async () => {
    const res = await post(server, '/auth/login', {
      password: 'correctPassword1',
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 400 when password field is missing', async () => {
    const res = await post(server, '/auth/login', {
      email: 'user@example.com',
    });

    expect(res.statusCode).toBe(400);
  });
});
