# ADR-006: Rate Limiting Strategy for Auth Endpoints

**Status:** Accepted
**Date:** 2026-03-28

---

## Context

The auth endpoints (`/register`, `/login`, `/refresh`) are unauthenticated and
accept arbitrary input. Without rate limiting they are vulnerable to:

- **Credential stuffing / brute force** on `/login` — an attacker can try
  thousands of email/password combinations per second
- **Account enumeration amplification** on `/register` — repeated calls reveal
  whether an email is already registered (409 vs 201)
- **Refresh token exhaustion** on `/refresh` — an attacker with a stolen
  refresh cookie can spin up new token pairs at high frequency

`/logout` and `/me` are protected by `requireAuth` and carry an access token
with a 15-minute TTL, so the blast radius of abuse is already bounded; they
are not rate-limited here.

The stack is TypeScript + Fastify. The official `@fastify/rate-limit` plugin
integrates natively, supports per-route configuration, and has a pluggable
store interface compatible with Redis.

---

## Decision

Use **`@fastify/rate-limit`** registered globally in `buildServer()` in
`src/server.ts`, with per-route overrides applied in `src/auth/routes.ts`.

### Installation

```
pnpm add @fastify/rate-limit
```

### Global Registration (server.ts)

Register the plugin after `@fastify/cookie` with a permissive global default.
Auth-specific limits are set per route:

```ts
import rateLimit from '@fastify/rate-limit';

await fastify.register(rateLimit, {
  global: true,
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (request) => request.ip,
});
```

### Per-Route Limits

| Endpoint | Max requests | Time window | Key |
|---|---|---|---|
| `POST /auth/register` | 5 | 1 hour | IP |
| `POST /auth/login` | 10 | 15 minutes | IP |
| `POST /auth/refresh` | 20 | 1 minute | IP |

Rationale:
- **Register (5 / hr)** — account creation should be rare per IP; tight limit
  blocks enumeration abuse with minimal friction for legitimate users
- **Login (10 / 15 min)** — allows ~40 attempts per hour before lockout,
  sufficient for a user who misremembers their password while making brute force
  impractical
- **Refresh (20 / min)** — generous enough for SPAs that may refresh on every
  tab focus, while blocking automated exhaustion

Per-route configuration in `routes.ts`:

```ts
fastify.post('/register', {
  config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
  schema: { body: authBodySchema },
}, registerHandler);

fastify.post('/login', {
  config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  schema: { body: authBodySchema },
}, loginHandler);

fastify.post('/refresh', {
  config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
}, refreshHandler);
```

### Error Response Shape

`@fastify/rate-limit` returns HTTP **429** with the following body by default:

```json
{
  "statusCode": 429,
  "error": "Too Many Requests",
  "message": "Rate limit exceeded, retry in 1 minute"
}
```

Standard Fastify error envelope — no custom error serialiser required.

Response headers on every rate-limited route:

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | Max requests allowed in the window |
| `X-RateLimit-Remaining` | Requests remaining before 429 |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `Retry-After` | Seconds until the client may retry (on 429 only) |

### Redis Store for Production

The in-memory store (default) does not share state across instances. Before
horizontal scaling, swap in the Redis store:

```ts
import Redis from 'ioredis';
import { RedisStore } from '@fastify/rate-limit';  // built-in adapter

const redis = new Redis(process.env['REDIS_URL']);

await fastify.register(rateLimit, {
  global: true,
  max: 100,
  timeWindow: '1 minute',
  redis,                   // @fastify/rate-limit accepts an ioredis client directly
  keyGenerator: (request) => request.ip,
});
```

No route-level changes needed — the store is injected at registration time.

---

## Consequences

**Positive:**
- Brute force and credential stuffing on `/login` are bounded by a 10-attempt
  window per IP with no custom middleware code
- Register enumeration abuse is limited to 5 probes per IP per hour
- `Retry-After` and `X-RateLimit-*` headers give clients actionable feedback
- In-memory → Redis migration is a one-line change at registration; routes are
  unchanged
- Plays well with Fastify's JSON Schema validation (ADR-005) — invalid bodies
  count against the limit, discouraging schema fuzzing

**Negative / Trade-offs:**
- IP-based keying is spoofable behind proxies; `request.ip` must be the real
  client IP. If the app is behind a reverse proxy or load balancer, Fastify's
  `trustProxy` option must be enabled so `request.ip` reflects `X-Forwarded-For`
- In-memory store does not survive process restart; limits reset on redeploy
  (acceptable at MVP scale, not for production)
- Shared IPs (corporate NAT, university networks) may hit limits for innocent
  users when an attacker operates from the same IP block

---

## Out of Scope

- User-ID-based rate limiting (requires authentication, not applicable to these
  endpoints at the point of rate-limiting)
- CAPTCHA or challenge-response after N failures
- IP blocklist / allowlist
- Redis store implementation (noted above as a one-line change; deferred)
- Rate limiting on `/logout` and `/me` (covered by access-token TTL)
