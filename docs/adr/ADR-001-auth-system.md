# ADR-001: User Authentication System

**Status:** Accepted
**Date:** 2026-03-27

---

## Context

The application requires a user authentication system supporting email/password login. The system must:

- Authenticate users securely without persisting plaintext credentials
- Issue session tokens with a manageable expiry strategy
- Support immediate logout (token invalidation)
- Be stateless enough to scale, but with a revocation mechanism for security

Key constraints:
- Single-service deployment (no distributed token verification needed at this stage)
- Stack: TypeScript + Fastify + Jest + pnpm + ESLint + Prettier

---

## Decision

Adopt the **Hybrid JWT + httpOnly Refresh Token + Revocation Store** pattern.

### Password Hashing
- Library: `bcryptjs`
- Cost factor: 12
- Plain passwords must never be stored, logged, or returned in responses

### Access Tokens (JWT)
- Library: `jsonwebtoken`
- Algorithm: HS256
- TTL: 15 minutes
- Delivered in the response body
- Secret loaded from environment variable `JWT_SECRET`

### Refresh Tokens
- Cryptographically random, 32+ bytes (via `crypto.randomBytes`)
- TTL: 7–30 days (configurable via `REFRESH_TOKEN_TTL_DAYS`)
- Stored in an **httpOnly, Secure, SameSite=Strict** cookie
- Rotated on every use (refresh endpoint issues a new token and revokes the old one)

### Revocation Store
- Interface: `revokeToken(token, ttl)` and `isRevoked(token): Promise<boolean>`
- MVP implementation: in-memory `Map` with TTL-based cleanup
- TODO: swap in a Redis adapter for production/multi-instance deployments

### Middleware Chain (route protection)
```
Request
  → Extract Bearer token from Authorization header
  → verifyAccessToken(token)         // validates signature + expiry
  → isRevoked(token)                 // checks revocation store
  → attach AuthContext to request    // { userId, email, roles }
  → proceed to handler
  → 401 on any failure (generic message, no detail leakage)
```

### API Endpoints
| Method | Path | Auth required |
|---|---|---|
| POST | /auth/register | No |
| POST | /auth/login | No |
| POST | /auth/refresh | No (uses cookie) |
| POST | /auth/logout | Yes |
| GET  | /auth/me | Yes |

---

## Consequences

**Positive:**
- Access tokens are stateless — no DB hit on every request
- Refresh token rotation limits the blast radius of a stolen refresh token
- Immediate logout is possible via the revocation store
- httpOnly cookies prevent XSS access to refresh tokens

**Negative / Trade-offs:**
- Revocation store adds a lookup on every protected request (mitigated by in-memory speed at MVP scale)
- In-memory store is not shared across multiple instances — Redis adapter required before horizontal scaling
- HS256 requires the JWT secret to be kept secure; RS256 would be preferable for multi-service setups

---

## Out of Scope

- OAuth / social login
- Multi-factor authentication
- Password reset and email verification
- Admin force-logout of other users
- Rate limiting (tracked separately)
- Redis adapter implementation (marked as TODO in `src/auth/revocation.ts`)
