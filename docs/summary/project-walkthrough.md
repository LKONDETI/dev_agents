# Project Walkthrough: JWT Auth System

This document explains what was built, why each decision was made, and how all
the pieces fit together. It follows the exact sequence the agent workflow
produced it in.

---

## What Was Built

A complete user authentication API on top of Fastify with:

- Email/password registration and login
- Short-lived JWT access tokens (15 min)
- Long-lived refresh tokens stored in httpOnly cookies (7–30 days, rotatable)
- Token revocation (immediate logout)
- Request body validation with JSON Schema
- Rate limiting on all public auth endpoints

---

## Step 1 — Architecture Decision: Core Auth Pattern (ADR-001)

**Problem:** Choose an auth strategy that is stateless enough to scale but
supports immediate logout.

**Decision:** Hybrid JWT + httpOnly Refresh Token + Revocation Store.

| Component | Choice | Reason |
|---|---|---|
| Password hashing | `bcryptjs`, cost 12 | Industry standard; slow enough to resist brute force |
| Access token | JWT HS256, 15 min TTL | Stateless; short TTL limits stolen-token window |
| Refresh token | `crypto.randomBytes(32)`, 7–30 days | Cryptographically random; rotated on every use |
| Refresh delivery | httpOnly Secure SameSite=Strict cookie | Inaccessible to JavaScript; blocks XSS theft |
| Revocation | In-memory Map with TTL cleanup | Allows immediate logout; swappable for Redis |

**Key trade-off:** The revocation store adds one lookup per protected request.
This is fast in-memory at MVP scale; a Redis adapter is needed before
horizontal scaling.

---

## Step 2 — File Structure

```
src/
  server.ts              # Fastify factory + process entry point
  auth/
    types.ts             # All interfaces and types (zero runtime code)
    jwt.ts               # signAccessToken, verifyAccessToken (HS256)
    password.ts          # hashPassword, verifyPassword (bcryptjs)
    revocation.ts        # IRevocationStore, InMemoryRevocationStore
    tokens.ts            # ISessionStore, InMemorySessionStore, rotation logic
    userStore.ts         # In-memory user store (keyed by normalised email)
    middleware.ts        # requireAuth Fastify preHandler
    routes.ts            # All 5 auth endpoints as a Fastify plugin
    __tests__/
      routes.test.ts     # Integration tests: register, login, rate limits
      refresh.test.ts    # Integration tests: /refresh endpoint
      tokens.test.ts     # Unit tests: InMemorySessionStore
      revocation.test.ts # Unit tests: InMemoryRevocationStore
docs/
  adr/                   # Architecture Decision Records
  summary/               # This folder
```

---

## Step 3 — Core Types (types.ts)

All shared shapes live in one pure-types file with zero runtime code.

```
User                  persisted user row (id, email, passwordHash, createdAt)
AuthContext           request principal attached by middleware (userId, email, roles)
JWTPayload            decoded JWT fields (sub, email, roles, iat, exp)
SessionRecord         refresh token record (userId, email, roles, token, expiresAt, revoked)
ISessionStore         interface: get / set / delete
IRevocationStore      interface: revoke / isRevoked
TokenPair             response shape (accessToken, refreshToken)
```

`SessionRecord` carries `email` and `roles` so the `/refresh` endpoint can
build a new access-token payload directly from the session record — no need to
decode the (possibly expired) old access token.

Fastify's `FastifyRequest` is augmented so `request.user` is typed project-wide
without casting.

---

## Step 4 — JWT Layer (jwt.ts)

**`signAccessToken(payload)`**
- Calls `jwt.sign` with `algorithm: 'HS256'` and `expiresIn: '15m'`
- `JWT_SECRET` is validated at module load — server exits immediately if unset
- `iat` and `exp` are set by `jsonwebtoken`, not by the caller (avoids the
  "payload already has exp property" error)

**`verifyAccessToken(token)`**
- Returns the decoded `JWTPayload` on success, `null` on any failure
- All errors are swallowed — no token rejection reason is ever exposed

---

## Step 5 — Session Store (tokens.ts)

**Why an interface?**
The in-memory `Map` was originally private to `tokens.ts`. Abstracting it into
`ISessionStore` / `InMemorySessionStore` (ADR-002) enables:
- Tests to inspect store state directly
- A future Redis adapter with no changes to rotation logic

**`storeRefreshToken(userId, email, roles, token, ttlDays)`**
Builds a `SessionRecord` with an absolute `expiresAt` and stores it keyed by
the token string.

**`rotateRefreshToken(oldToken)`**
1. Look up `oldToken` — return `null` if not found
2. Reject if `record.revoked === true`
3. Reject if `record.expiresAt <= now`
4. Check the revocation store (`isRevoked`) for out-of-band revocation
5. Generate a new token; store it with the same `userId/email/roles` and
   remaining TTL
6. Revoke the old token in both the revocation store and the session store
7. Return the new `SessionRecord` (not just the token string — callers need
   user context)

---

## Step 6 — Revocation Store (revocation.ts)

**Why an interface?**
Same reason as the session store (ADR-004): swappable for Redis, and the class
is directly testable per-instance.

**`InMemoryRevocationStore`**
Backed by `Map<string, number>` where the value is an absolute expiry
timestamp in milliseconds.

- `revoke(token, ttl)` — stores `Date.now() + ttl * 1000`; calls `cleanup()`
  on every write to keep memory bounded
- `isRevoked(token)` — returns `true` only if the entry exists **and** has not
  yet expired
- `cleanup()` — private; iterates the map and deletes expired entries

The two module-level functions (`revokeToken`, `isRevoked`) are thin wrappers
that delegate to `defaultRevocationStore`. All call sites in `middleware.ts`,
`tokens.ts`, and `routes.ts` are unchanged.

---

## Step 7 — Request Validation (ADR-005)

**Before:** Manual truthiness checks and unsafe `as AuthBody` casts.

```ts
// old — unsafe, incomplete
const { email, password } = request.body as AuthBody;
if (!email || !password) { return reply.code(400)... }
```

**After:** Fastify JSON Schema validation runs before the handler.

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

- `format: 'email'` requires `ajv-formats` to be registered in `buildServer()`
- `additionalProperties: false` rejects extra fields — Fastify's default strips
  them silently, so `customOptions: { removeAdditional: false }` is set
- Handler receives a guaranteed-valid `AuthBody` with no unsafe casts

---

## Step 8 — Auth Middleware (middleware.ts)

`requireAuth` is a Fastify `preHandler` that:

1. Extracts the `Bearer` token from the `Authorization` header
2. Calls `verifyAccessToken(token)` — returns null on any failure
3. Calls `isRevoked(token)` — returns true if the token has been revoked
4. Attaches `AuthContext` to `request.user`
5. Returns a **generic 401** on any failure — no detail leakage

Used on `POST /logout` and `GET /me`.

---

## Step 9 — API Routes (routes.ts)

### POST /auth/register
1. Schema validation runs (email + password enforced by ajv)
2. `createUser(email, password)` — hashes password, rejects duplicates (409)
3. Build `JWTPayload` (sub, email, roles); call `signAccessToken`
4. `storeRefreshToken(userId, email, roles, token, ttlDays)`
5. Set refresh cookie; return `{ accessToken }` with 201

### POST /auth/login
1. Schema validation runs
2. `findUserByEmail(email)` — 401 if not found (generic, no email enumeration)
3. `verifyPassword(password, hash)` — 401 if wrong (same generic message)
4. Build payload; sign access token; store and set refresh cookie
5. Return `{ accessToken }` with 200

### POST /auth/refresh
1. Read `refreshToken` cookie — 401 if missing
2. `rotateRefreshToken(oldToken)` — returns `SessionRecord | null`
3. Build new `JWTPayload` from `newSession.userId/email/roles`
4. Sign new access token; set new refresh cookie
5. Return `{ accessToken }` with 200
- No `Authorization` header required — user context comes from the session record

### POST /auth/logout *(requireAuth)*
1. Extract access token; calculate remaining TTL
2. `revokeToken(accessToken, remainingSecs)` if TTL > 0
3. `revokeToken(refreshToken, ...)` if cookie present
4. Clear refresh cookie; return `{ message: 'Logged out' }` with 200

### GET /auth/me *(requireAuth)*
Returns `request.user` (the `AuthContext`) with 200.

---

## Step 10 — Rate Limiting (ADR-006)

Registered globally in `buildServer()` via `@fastify/rate-limit` with per-route
overrides in `routes.ts`:

| Endpoint | Limit | Window | Rationale |
|---|---|---|---|
| `/register` | 5 req | 1 hour | Blocks enumeration (5 probes/hr is enough for legit users) |
| `/login` | 10 req | 15 min | ~40/hr; brute force impractical, honest typos still work |
| `/refresh` | 20 req | 1 min | Generous for SPAs; blocks automated exhaustion |

Returns HTTP 429 with Fastify's standard error envelope on breach.
`X-RateLimit-Limit/Remaining/Reset` headers on every response.

Redis store can replace the in-memory default with one line at registration.

---

## Step 11 — Test Coverage (70 tests, 4 suites)

| Suite | Tests | What it covers |
|---|---|---|
| `routes.test.ts` | 28 | Register, login, schema validation, rate limits |
| `refresh.test.ts` | 11 | /refresh happy path, rotation, replay protection |
| `tokens.test.ts` | 17 | InMemorySessionStore get/set/delete, SessionRecord fields |
| `revocation.test.ts` | 11 | InMemoryRevocationStore revoke/isRevoked/cleanup, TTL |

Two bugs were found by the tests and fixed before commit:
- **JWT `exp` conflict** — handlers were setting `iat`/`exp` in the payload
  object *and* passing `expiresIn` to `jwt.sign`. jsonwebtoken throws on
  duplicate exp. Fixed by removing manual `iat`/`exp` from handler payloads.
- **`removeAdditional: true`** — Fastify's default ajv config strips extra
  fields silently, making `additionalProperties: false` a no-op. Fixed by
  setting `customOptions: { removeAdditional: false }`.

---

## Known Gaps / Future Work

| Area | Status | Path forward |
|---|---|---|
| Redis session store | In-memory only | Implement `RedisSessionStore implements ISessionStore` |
| Redis revocation store | In-memory only | Implement `RedisRevocationStore implements IRevocationStore` |
| User store | In-memory Map | Replace with DB adapter (Postgres/SQLite) |
| /logout and /me tests | Not yet written | Add to `routes.test.ts` |
| Password strength | minLength: 8 only | Add regex pattern or custom ajv keyword |
| HTTPS enforcement | Depends on proxy | Document `trustProxy` requirement |
| OAuth / social login | Out of scope (ADR-001) | Separate feature |
| Password reset / email verification | Out of scope (ADR-001) | Separate feature |
