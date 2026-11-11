/**
 * Hashing primitives. Everything here is built on Node's `node:crypto`; the project
 * has no runtime dependencies.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalize } from './canonical.js';
import type { Checkpoint } from './types.js';

/** Prefix used by every hash stored in a ledger entry. */
export const HASH_PREFIX = 'sha256:';

/** Shape of a stored hash: `sha256:` followed by 64 lowercase hex characters. */
export const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** Lowercase hex SHA-256 of a UTF-8 string or raw buffer. */
export function sha256Hex(text: string | Buffer): string {
  return createHash('sha256').update(text).digest('hex');
}

/** Lowercase hex HMAC-SHA256 of a UTF-8 string. */
export function hmacSha256Hex(key: string | Buffer, text: string): string {
  return createHmac('sha256', key).update(text, 'utf8').digest('hex');
}

/**
 * Genesis previous-hash: `sha256("AGENTLEDGER:GENESIS:v1")`.
 * Computed at module load so it can never drift from the documented constant.
 */
export const GENESIS_HASH = `${HASH_PREFIX}${sha256Hex('AGENTLEDGER:GENESIS:v1')}`;

/** Hash an already canonical JSON string. */
export function hashCanonical(canonical: string): string {
  return `${HASH_PREFIX}${sha256Hex(canonical)}`;
}

/** Canonicalize then hash any JSON value. */
export function hashValue(value: unknown): string {
  return hashCanonical(canonicalize(value));
}

/** True when `value` is a syntactically valid ledger hash. */
export function isHash(value: unknown): value is string {
  return typeof value === 'string' && HASH_PATTERN.test(value);
}

/** True when `value` is a 64 character lowercase hex string (used for HMAC signatures). */
export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/** Timing-safe comparison for hex encoded digests of equal length. */
export function safeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Entry hash: SHA-256 over the canonical JSON of the entry without `hash` and `sig`.
 *
 * `sig` is excluded because it is derived from `hash`; including it would be circular.
 * Tampering with `sig` therefore only breaks signature verification, which is exactly
 * the property we want.
 */
export function computeEntryHash(entry: object): string {
  // A null-prototype object keeps keys such as "__proto__" as ordinary own
  // properties, so every field present in the record is covered by the hash.
  const stripped: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(entry)) {
    if (key === 'hash' || key === 'sig') continue;
    stripped[key] = value;
  }
  return hashValue(stripped);
}

/** Canonical body covered by a checkpoint HMAC. */
export function checkpointMac(
  key: string | Buffer,
  checkpoint: Pick<Checkpoint, 'v' | 'entries' | 'lastHash' | 'createdAt'>
): string {
  return hmacSha256Hex(
    key,
    canonicalize({
      v: checkpoint.v,
      entries: checkpoint.entries,
      lastHash: checkpoint.lastHash,
      createdAt: checkpoint.createdAt,
    })
  );
}
