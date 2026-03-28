/*
 * Implementation plan:
 * 1. Import bcryptjs — pure-JS implementation, no native bindings required (ADR-001).
 * 2. Define COST_FACTOR constant (12) to keep it auditable in one place.
 * 3. hashPassword: generate a salt with cost 12 then return the hash; never
 *    log or surface the plain password at any point.
 * 4. verifyPassword: delegate to bcrypt.compare; return boolean, never throw
 *    on a mismatch (only re-throw unexpected errors).
 * 5. Export both as named exports for tree-shaking friendliness.
 */

import bcrypt from 'bcryptjs';

/** bcrypt cost factor as specified in ADR-001 § Password Hashing. */
const COST_FACTOR = 12;

/**
 * Hashes a plain-text password using bcrypt with cost factor 12.
 *
 * @param plain - The raw password supplied by the user.
 * @returns A bcrypt hash string safe to persist in the database.
 *
 * Security note: the plain password is never logged or returned.
 */
export async function hashPassword(plain: string): Promise<string> {
  if (!plain) {
    throw new Error('hashPassword: plain password must not be empty');
  }

  const salt = await bcrypt.genSalt(COST_FACTOR);
  return bcrypt.hash(plain, salt);
}

/**
 * Verifies a plain-text password against a stored bcrypt hash.
 *
 * @param plain - The raw password supplied by the user at login.
 * @param hash  - The stored bcrypt hash from the User record.
 * @returns `true` if the password matches the hash, `false` otherwise.
 *
 * Security note: always returns a boolean — never leaks which part failed.
 */
export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (!plain || !hash) {
    return false;
  }

  return bcrypt.compare(plain, hash);
}
