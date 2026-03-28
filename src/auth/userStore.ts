/*
 * Implementation plan:
 * 1. Back the user store with an in-memory Map<string, User> keyed by email
 *    (case-normalised to lowercase) — mirrors the session-store pattern in tokens.ts.
 * 2. createUser: validate inputs, reject duplicate emails, hash the password
 *    via hashPassword, build a User record, persist it, and return it.
 * 3. findUserByEmail: normalise the email and look it up; return null if absent.
 * 4. Export both as named exports; keep the store Map internal.
 * 5. TODO: replace Map with a real DB adapter before production (see ADR-001).
 */

import { randomUUID } from 'crypto';

import { hashPassword } from './password';
import type { User } from './types';

// TODO: replace with a real database adapter before production (see ADR-001)

/** In-memory user store: normalised email → User. */
const userStore = new Map<string, User>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalises an email address to lowercase for consistent key lookups. */
function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Creates and persists a new user with a hashed password.
 *
 * Returns the created {@link User} on success. Throws if the email is already
 * taken, if either argument is empty, or if hashing fails.
 *
 * @param email    - The user's email address.
 * @param password - The raw plain-text password (never stored).
 * @returns The newly created User record (passwordHash is included; strip it
 *          before sending any response).
 */
export async function createUser(email: string, password: string): Promise<User> {
  if (!email || !password) {
    throw new Error('createUser: email and password are required');
  }

  const key = normaliseEmail(email);

  if (userStore.has(key)) {
    throw new Error('createUser: email already registered');
  }

  const passwordHash = await hashPassword(password);

  const user: User = {
    id: randomUUID(),
    email: key,
    passwordHash,
    createdAt: new Date(),
  };

  userStore.set(key, user);

  return user;
}

/**
 * Looks up a user by email address.
 *
 * @param email - The email address to search for.
 * @returns The matching {@link User}, or `null` if no user exists with that email.
 */
export function findUserByEmail(email: string): User | null {
  if (!email) {
    return null;
  }

  return userStore.get(normaliseEmail(email)) ?? null;
}
