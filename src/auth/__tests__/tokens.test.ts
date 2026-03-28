/**
 * Unit tests for InMemorySessionStore (tokens.ts).
 *
 * Each test instantiates its own InMemorySessionStore so there is no shared
 * state between cases. SessionRecord shape is validated to include the email
 * and roles fields added in ADR-002 § SessionRecord Enrichment.
 */

// Must be set before any auth module is imported (jwt.ts throws at load time without it)
process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production';

import { InMemorySessionStore } from '../tokens';
import type { SessionRecord } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRecord(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    userId: 'user-1',
    email: 'alice@example.com',
    roles: ['member'],
    token: 'tok-abc',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revoked: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// InMemorySessionStore — get
// ---------------------------------------------------------------------------

describe('InMemorySessionStore.get', () => {
  it('returns undefined for a token that has never been stored', () => {
    const store = new InMemorySessionStore();
    expect(store.get('unknown-token')).toBeUndefined();
  });

  it('returns the SessionRecord after it has been set', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-1' });
    store.set('tok-1', record);
    expect(store.get('tok-1')).toBe(record);
  });

  it('returns undefined for an empty string key', () => {
    const store = new InMemorySessionStore();
    expect(store.get('')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// InMemorySessionStore — set
// ---------------------------------------------------------------------------

describe('InMemorySessionStore.set', () => {
  it('stores a record and makes it retrievable by the same token key', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-set-1' });
    store.set('tok-set-1', record);
    expect(store.get('tok-set-1')).toBeDefined();
  });

  it('overwrites an existing record when set is called with the same key', () => {
    const store = new InMemorySessionStore();
    const first = makeRecord({ token: 'tok-overwrite', userId: 'user-1' });
    const second = makeRecord({ token: 'tok-overwrite', userId: 'user-2' });
    store.set('tok-overwrite', first);
    store.set('tok-overwrite', second);
    expect(store.get('tok-overwrite')?.userId).toBe('user-2');
  });

  it('stores records under distinct keys without cross-contamination', () => {
    const store = new InMemorySessionStore();
    const recA = makeRecord({ token: 'tok-a', userId: 'user-a' });
    const recB = makeRecord({ token: 'tok-b', userId: 'user-b' });
    store.set('tok-a', recA);
    store.set('tok-b', recB);
    expect(store.get('tok-a')?.userId).toBe('user-a');
    expect(store.get('tok-b')?.userId).toBe('user-b');
  });
});

// ---------------------------------------------------------------------------
// InMemorySessionStore — delete
// ---------------------------------------------------------------------------

describe('InMemorySessionStore.delete', () => {
  it('removes a previously stored record so get returns undefined', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-del' });
    store.set('tok-del', record);
    store.delete('tok-del');
    expect(store.get('tok-del')).toBeUndefined();
  });

  it('does not throw when deleting a token that was never stored', () => {
    const store = new InMemorySessionStore();
    expect(() => store.delete('does-not-exist')).not.toThrow();
  });

  it('only removes the specified token and leaves others intact', () => {
    const store = new InMemorySessionStore();
    store.set('tok-keep', makeRecord({ token: 'tok-keep' }));
    store.set('tok-remove', makeRecord({ token: 'tok-remove' }));
    store.delete('tok-remove');
    expect(store.get('tok-keep')).toBeDefined();
    expect(store.get('tok-remove')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SessionRecord shape — email and roles fields (ADR-002)
// ---------------------------------------------------------------------------

describe('SessionRecord shape', () => {
  it('stores and retrieves the email field from the record', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-1', email: 'bob@example.com' });
    store.set('tok-shape-1', record);
    expect(store.get('tok-shape-1')?.email).toBe('bob@example.com');
  });

  it('stores and retrieves the roles array from the record', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-2', roles: ['admin', 'editor'] });
    store.set('tok-shape-2', record);
    expect(store.get('tok-shape-2')?.roles).toEqual(['admin', 'editor']);
  });

  it('stores and retrieves an empty roles array without mutation', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-3', roles: [] });
    store.set('tok-shape-3', record);
    expect(store.get('tok-shape-3')?.roles).toEqual([]);
  });

  it('stores the userId field alongside email and roles', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-4', userId: 'uid-99' });
    store.set('tok-shape-4', record);
    expect(store.get('tok-shape-4')?.userId).toBe('uid-99');
  });

  it('stores the revoked field as false on a fresh record', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-5', revoked: false });
    store.set('tok-shape-5', record);
    expect(store.get('tok-shape-5')?.revoked).toBe(false);
  });

  it('stores the revoked field as true when explicitly set', () => {
    const store = new InMemorySessionStore();
    const record = makeRecord({ token: 'tok-shape-6', revoked: true });
    store.set('tok-shape-6', record);
    expect(store.get('tok-shape-6')?.revoked).toBe(true);
  });

  it('stores and retrieves the expiresAt Date field accurately', () => {
    const store = new InMemorySessionStore();
    const expiry = new Date('2030-01-01T00:00:00.000Z');
    const record = makeRecord({ token: 'tok-shape-7', expiresAt: expiry });
    store.set('tok-shape-7', record);
    expect(store.get('tok-shape-7')?.expiresAt).toEqual(expiry);
  });
});
