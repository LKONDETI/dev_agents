# ADR-004: Revocation Store Abstraction

**Status:** Accepted
**Date:** 2026-03-28

---

## Context

`src/auth/revocation.ts` tracks revoked tokens using a module-level in-memory
`Map<string, number>` where the value is an absolute expiry timestamp (ms):

```ts
const store = new Map<string, number>();
```

Two public functions are exported:

- `revokeToken(token, ttl)` — writes to the map; prunes expired entries on
  every write to keep memory bounded
- `isRevoked(token): Promise<boolean>` — reads from the map; returns `true`
  only if the entry exists and has not yet expired

The signature of `isRevoked` is already `async` (returns a `Promise`), which
was deliberate to allow a future async adapter (e.g. Redis) to slot in without
changing call sites.

Problems with the current approach:

- **Not swappable** — replacing the `Map` with Redis requires editing
  `revocation.ts` internals, the same file that owns the TTL and cleanup logic
- **Not testable in isolation** — the store is module-level state; tests share
  it across cases unless they reach into the module to clear it, or rely on
  real timing for TTL expiry
- **Horizontally unscalable** — each process has its own `Map`; a token
  revoked on one instance is not revoked on others, undermining logout and
  token rotation guarantees across multiple pods

---

## Decision

Introduce an **`IRevocationStore` interface** and move the `Map`-backed
implementation into an `InMemoryRevocationStore` class. The two module-level
functions (`revokeToken`, `isRevoked`) delegate to a default instance so
existing call sites in `middleware.ts`, `tokens.ts`, and `routes.ts` require
no changes.

### IRevocationStore Interface

```ts
export interface IRevocationStore {
  revoke(token: string, ttl: number): void;
  isRevoked(token: string): Promise<boolean>;
}
```

Defined in `src/auth/types.ts` alongside the other auth interfaces.

### InMemoryRevocationStore Class

```ts
export class InMemoryRevocationStore implements IRevocationStore {
  private readonly store = new Map<string, number>();

  revoke(token: string, ttl: number): void {
    if (!token) return;
    this.store.set(token, Date.now() + ttl * 1000);
    this.cleanup();
  }

  async isRevoked(token: string): Promise<boolean> {
    if (!token) return false;
    const expiresAt = this.store.get(token);
    if (expiresAt === undefined) return false;
    return Date.now() < expiresAt;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [token, expiresAt] of this.store) {
      if (expiresAt <= now) this.store.delete(token);
    }
  }
}
```

Defined in `src/auth/revocation.ts`. A module-level default instance is
exported:

```ts
export const defaultRevocationStore: IRevocationStore = new InMemoryRevocationStore();
```

### Module-Level Function Delegation

The two existing public functions become thin wrappers that delegate to
`defaultRevocationStore`, preserving all existing call sites:

```ts
export function revokeToken(token: string, ttl: number): void {
  defaultRevocationStore.revoke(token, ttl);
}

export async function isRevoked(token: string): Promise<boolean> {
  return defaultRevocationStore.isRevoked(token);
}
```

No changes are required in `middleware.ts`, `tokens.ts`, or `routes.ts`.

### Redis Adapter Path

A future Redis adapter implements the same interface:

```ts
export class RedisRevocationStore implements IRevocationStore {
  constructor(private readonly client: RedisClient) {}

  revoke(token: string, ttl: number): void {
    // SET token 1 EX ttl
  }

  async isRevoked(token: string): Promise<boolean> {
    // GET token → exists?
  }
}
```

Switching the application from in-memory to Redis is a one-line change:

```ts
// revocation.ts
export const defaultRevocationStore: IRevocationStore =
  new RedisRevocationStore(redisClient);
```

---

## Consequences

**Positive:**
- `IRevocationStore` can be swapped for a Redis adapter without touching
  middleware, tokens, or route logic
- Tests can instantiate `InMemoryRevocationStore` directly, call `revoke()`
  and `isRevoked()` on a fresh instance per test, and assert state without
  relying on module-level side effects or real time delays
- The `cleanup()` method moves from module scope into the class, making it
  testable as a side effect of `revoke()` calls
- Prepares for horizontal scaling with no further interface changes

**Negative / Trade-offs:**
- `defaultRevocationStore` is a module-level singleton; integration tests that
  import `revokeToken`/`isRevoked` directly still share state unless they
  instantiate their own `InMemoryRevocationStore`
- The `cleanup()` purge-on-write strategy is retained — this is acceptable at
  MVP scale but may require a background sweep for high-write production loads
- Redis adapter implementation is explicitly out of scope here

---

## Out of Scope

- Redis adapter implementation (interface defined here; adapter is deferred)
- Background TTL sweep / scheduled cleanup
- Distributed revocation list synchronisation
- Encrypting stored token values at rest
- Session store abstraction (tracked in ADR-002)
