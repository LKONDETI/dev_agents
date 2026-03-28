# ADR-002: Session Store Abstraction

**Status:** Accepted
**Date:** 2026-03-28

---

## Context

`src/auth/tokens.ts` manages refresh-token sessions using a module-level
in-memory `Map`:

```ts
const sessionStore = new Map<string, SessionRecord>();
```

This store is private to the module. The three public functions
(`generateRefreshToken`, `storeRefreshToken`, `rotateRefreshToken`) call it
directly with no indirection layer.

Problems with the current approach:

- **Not swappable** — replacing the `Map` with a Redis adapter requires
  modifying `tokens.ts` internals, touching the same file that owns the
  rotation logic
- **Not testable in isolation** — tests cannot inject a controlled store; they
  must rely on module-level side effects, making it hard to assert store state
  or simulate expiry/revocation scenarios
- **Horizontally unscalable** — a second process has its own `Map`; refresh
  tokens issued by one instance are invisible to others
- **Token context loss** — `SessionRecord` currently stores only `userId`;
  the `/refresh` endpoint has to `jwt.decode` the (possibly expired) access
  token to recover `email` and `roles` when building a new access token
  payload — a design smell noted as a TODO in `routes.ts`

---

## Decision

Introduce an **`ISessionStore` interface** and move the `Map`-backed
implementation into a named class. Inject a default instance into `tokens.ts`
so all three public functions delegate to it. Enrich `SessionRecord` with the
user fields needed by the `/refresh` endpoint.

### ISessionStore Interface

```ts
export interface ISessionStore {
  get(token: string): SessionRecord | undefined;
  set(token: string, record: SessionRecord): void;
  delete(token: string): void;
}
```

Defined in `src/auth/types.ts` alongside `SessionRecord`.

### InMemorySessionStore Class

```ts
export class InMemorySessionStore implements ISessionStore {
  private readonly store = new Map<string, SessionRecord>();

  get(token: string): SessionRecord | undefined {
    return this.store.get(token);
  }

  set(token: string, record: SessionRecord): void {
    this.store.set(token, record);
  }

  delete(token: string): void {
    this.store.delete(token);
  }
}
```

Defined in `src/auth/tokens.ts`. A module-level default instance is exported
for use by the rest of the application:

```ts
export const defaultSessionStore: ISessionStore = new InMemorySessionStore();
```

### SessionRecord Enrichment

`SessionRecord` gains three additional fields so the `/refresh` endpoint can
build a new access-token payload without decoding the old token:

```ts
export interface SessionRecord {
  userId: string;
  email: string;       // added
  roles: string[];     // added
  token: string;
  expiresAt: Date;
  revoked: boolean;
}
```

### storeRefreshToken Signature Update

```ts
// Before
storeRefreshToken(userId: string, token: string, ttlDays: number): void

// After
storeRefreshToken(
  userId: string,
  email: string,
  roles: string[],
  token: string,
  ttlDays: number,
): void
```

Call sites in `routes.ts` (`/register`, `/login`, `/refresh`) are updated
accordingly.

### tokens.ts Internal Change

All three functions switch from direct `sessionStore.get/set` calls to
`defaultSessionStore.get/set/delete`. No behavior changes.

---

## Consequences

**Positive:**
- `ISessionStore` can be swapped for a Redis adapter without touching rotation
  logic — only the injected instance changes
- Tests can pass an `InMemorySessionStore` (or a mock) directly, asserting
  store state and simulating edge cases
- `SessionRecord` enrichment eliminates the `jwt.decode` workaround in
  `/refresh`, removing a structural TODO and an unnecessary `jsonwebtoken`
  import in `routes.ts`
- Prepares the codebase for horizontal scaling with no further interface changes

**Negative / Trade-offs:**
- `storeRefreshToken` gains two parameters (`email`, `roles`); all three call
  sites in `routes.ts` must be updated at the same time as `tokens.ts`
- `defaultSessionStore` is a module-level singleton; tests that share the
  module must clear store state between test cases

---

## Out of Scope

- Redis adapter implementation (interface only; adapter is deferred)
- Dependency injection framework or service container
- Session store encryption at rest
- Multi-device session management (one active session per user)
- Revocation store abstraction (tracked in ADR-004)
