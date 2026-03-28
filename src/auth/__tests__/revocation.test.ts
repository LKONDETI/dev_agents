/**
 * Unit tests for InMemoryRevocationStore (revocation.ts).
 *
 * Each test creates its own InMemoryRevocationStore instance so there is no
 * shared state between cases. Jest's fake timers are used to control Date.now()
 * so expiry and cleanup behaviour can be exercised deterministically.
 */

// Must be set before any auth module is imported (jwt.ts throws at load time without it)
process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';

import { InMemoryRevocationStore } from '../revocation';

// ---------------------------------------------------------------------------
// revoke + isRevoked — happy paths
// ---------------------------------------------------------------------------

describe('InMemoryRevocationStore.revoke / isRevoked', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('reports a just-revoked token as revoked', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('tok-1', 60);
    expect(await store.isRevoked('tok-1')).toBe(true);
  });

  it('reports a token as not revoked before it has been added', async () => {
    const store = new InMemoryRevocationStore();
    expect(await store.isRevoked('tok-unknown')).toBe(false);
  });

  it('reports a token as not revoked once its TTL has elapsed', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('tok-expired', 30); // 30-second TTL

    // Advance time by exactly 31 seconds (past expiry)
    jest.advanceTimersByTime(31_000);

    expect(await store.isRevoked('tok-expired')).toBe(false);
  });

  it('reports a token as still revoked when time is just inside the TTL', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('tok-active', 60); // 60-second TTL

    // Advance to 59 seconds — still within TTL
    jest.advanceTimersByTime(59_000);

    expect(await store.isRevoked('tok-active')).toBe(true);
  });

  it('does not affect other tokens when one token is revoked', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('tok-a', 60);
    expect(await store.isRevoked('tok-b')).toBe(false);
  });

  it('allows revoking the same token a second time with a new TTL', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('tok-rerevoke', 10); // 10-second TTL

    // First revocation: advance past expiry
    jest.advanceTimersByTime(11_000);
    expect(await store.isRevoked('tok-rerevoke')).toBe(false);

    // Revoke again with a longer TTL
    store.revoke('tok-rerevoke', 120);
    expect(await store.isRevoked('tok-rerevoke')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// revoke — guard against falsy tokens
// ---------------------------------------------------------------------------

describe('InMemoryRevocationStore.revoke — falsy token guard', () => {
  it('does not throw when revoke is called with an empty string', () => {
    const store = new InMemoryRevocationStore();
    expect(() => store.revoke('', 60)).not.toThrow();
  });

  it('does not mark an empty string as revoked', async () => {
    const store = new InMemoryRevocationStore();
    store.revoke('', 60);
    expect(await store.isRevoked('')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isRevoked — guard against falsy tokens
// ---------------------------------------------------------------------------

describe('InMemoryRevocationStore.isRevoked — falsy token guard', () => {
  it('returns false for an empty string without throwing', async () => {
    const store = new InMemoryRevocationStore();
    expect(await store.isRevoked('')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// cleanup — expired entries are pruned on write
// ---------------------------------------------------------------------------

describe('InMemoryRevocationStore cleanup (purge-on-write strategy)', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('removes expired entries from the store when a new token is revoked', async () => {
    const store = new InMemoryRevocationStore();

    // Add a token with a 5-second TTL
    store.revoke('tok-short', 5);

    // Advance time past expiry
    jest.advanceTimersByTime(6_000);

    // Writing a new token triggers cleanup; tok-short should now be purged
    store.revoke('tok-trigger-cleanup', 60);

    // The expired token is no longer considered revoked
    expect(await store.isRevoked('tok-short')).toBe(false);
    // The newly revoked token is still active
    expect(await store.isRevoked('tok-trigger-cleanup')).toBe(true);
  });

  it('keeps unexpired entries intact after cleanup runs', async () => {
    const store = new InMemoryRevocationStore();

    store.revoke('tok-long', 300); // 5-minute TTL
    store.revoke('tok-short', 2);  // 2-second TTL

    jest.advanceTimersByTime(3_000); // Only tok-short should expire

    // Trigger cleanup by revoking another token
    store.revoke('tok-new', 60);

    expect(await store.isRevoked('tok-long')).toBe(true);
    expect(await store.isRevoked('tok-short')).toBe(false);
  });
});
