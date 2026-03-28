# ADR-005: JSON Schema Validation for Auth Request Bodies

**Status:** Accepted
**Date:** 2026-03-28

---

## Context

The `POST /auth/register` and `POST /auth/login` endpoints currently validate
request bodies with manual truthiness checks:

```ts
if (!email || !password) {
  return reply.code(400).send({ error: 'email and password are required' });
}
```

This approach has several weaknesses:

- Truthiness checks accept structurally invalid values (e.g. empty string `""`,
  whitespace-only strings, non-string types)
- No format validation — an input like `"notanemail"` passes silently and only
  fails later (or not at all)
- No minimum-length enforcement on passwords at the boundary layer
- Error messages are hand-rolled and inconsistent with Fastify's standard error
  shape
- The `request.body as AuthBody` cast is unsafe — TypeScript is given no
  guarantee the shape is correct at runtime

Fastify ships with built-in JSON Schema validation (powered by `ajv`) that runs
before any handler code and produces well-formed 400 responses automatically.

---

## Decision

Use **Fastify's built-in `schema.body` JSON Schema validation** on
`POST /auth/register` and `POST /auth/login`.

### Schema Definition

A shared `authBodySchema` object is defined once and referenced by both routes:

```ts
const authBodySchema = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: { type: 'string', format: 'email' },
    password: { type: 'string', minLength: 8 },
  },
  additionalProperties: false,
} as const;
```

### Route Registration

```ts
fastify.post('/register', { schema: { body: authBodySchema } }, handler);
fastify.post('/login',    { schema: { body: authBodySchema } }, handler);
```

### Error Response Shape

Fastify + ajv produces the following on validation failure (HTTP 400):

```json
{
  "statusCode": 400,
  "error": "Bad Request",
  "message": "body/email must match format \"email\""
}
```

This is Fastify's standard error envelope — no custom error serialiser is
needed.

### Handler Changes

After this change the manual `if (!email || !password)` guards and the
`as AuthBody` cast are removed. The body is narrowed to the validated shape
via a typed interface that mirrors the schema:

```ts
interface AuthBody {
  email: string;    // guaranteed: string, valid email format
  password: string; // guaranteed: string, minLength 8
}
```

### Format Validation

Fastify does not enable `ajv-formats` by default. To activate `format: 'email'`
validation, register `ajv-formats` when building the server:

```ts
import Fastify from 'fastify';
import addFormats from 'ajv-formats';

const fastify = Fastify({
  ajv: { plugins: [addFormats] },
});
```

`ajv-formats` is already a transitive dependency of common Fastify setups; add
it explicitly to `package.json` if not already present (`pnpm add ajv-formats`).

---

## Consequences

**Positive:**
- Validation runs before handler code — invalid bodies never reach business logic
- Format and length errors are caught at the boundary, not deep in the call stack
- Error responses are consistent with Fastify's standard shape (no custom
  serialiser needed)
- Removes the unsafe `as AuthBody` cast; the body type is guaranteed at runtime
- Schema object is reusable — can be exported and referenced in OpenAPI / Swagger
  generation later

**Negative / Trade-offs:**
- Requires `ajv-formats` to be explicitly listed in `package.json` for
  `format: 'email'` to be enforced; without it, the `format` keyword is silently
  ignored by ajv
- `additionalProperties: false` will reject clients that send extra fields —
  this is intentional but callers must be aware
- Minimum password length (8) is enforced at the HTTP layer only; the bcrypt
  hashing in `userStore.ts` remains unchanged and has no length gate of its own

---

## Out of Scope

- Validation on `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`
  (these endpoints have no user-supplied body requiring schema validation)
- Custom `ajv` keyword extensions (e.g. password-strength rules beyond minLength)
- OpenAPI / Swagger schema generation (tracked separately)
- Rate limiting on auth endpoints (tracked in ADR-006)
