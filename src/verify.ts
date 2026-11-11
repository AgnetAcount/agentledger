/**
 * Offline verification of a ledger: hash chain, sequence numbers, payload hashes,
 * HMAC signatures and checkpoints.
 *
 * `verifyLedger()` is pure and synchronous so it can be called from tests and from
 * any runtime without I/O. `verifyLedgerFile()` is a thin synchronous file wrapper,
 * and `Ledger.verify()` provides the asynchronous variant.
 */

import { canonicalize } from './canonical.js';
import {
  GENESIS_HASH,
  checkpointMac,
  computeEntryHash,
  hashValue,
  hmacSha256Hex,
  isHash,
  isHex64,
  safeEqualHex,
} from './crypto.js';
import { readTextSync } from './fileio.js';
import type {
  BuildCheckpointOptions,
  Checkpoint,
  LedgerEntry,
  VerifyError,
  VerifyOptions,
  VerifyResult,
} from './types.js';

const REQUIRED_FIELDS = [
  'v',
  'seq',
  'ts',
  'tool',
  'status',
  'durationMs',
  'args',
  'argsHash',
  'result',
  'resultHash',
  'error',
  'meta',
  'prevHash',
  'hash',
] as const;

/** Parsed ledger lines plus any parse-level problems. */
export interface ParsedLedger {
  entries: LedgerEntry[];
  errors: VerifyError[];
}

/** Strip a UTF-8 byte order mark from the first line of a ledger. */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Parse JSONL text into entries. Blank lines (including trailing newlines and CRLF
 * artefacts) are ignored, a leading BOM is stripped, and unparsable lines are
 * reported instead of throwing.
 */
export function readEntriesFromText(text: string): ParsedLedger {
  const entries: LedgerEntry[] = [];
  const errors: VerifyError[] = [];
  const lines = text.split('\n');

  lines.forEach((rawLine, index) => {
    const line = index === 0 ? stripBom(rawLine) : rawLine;
    if (line.trim() === '') return;
    try {
      const parsed: unknown = JSON.parse(line);
      if (!isRecord(parsed)) {
        errors.push({
          seq: null,
          code: 'INVALID_JSON',
          message: `Line ${index + 1} is not a JSON object`,
        });
        return;
      }
      entries.push(parsed as unknown as LedgerEntry);
    } catch (error) {
      errors.push({
        seq: null,
        code: 'INVALID_JSON',
        message: `Line ${index + 1} is not valid JSON: ${(error as Error).message}`,
      });
    }
  });

  return { entries, errors };
}

/**
 * Verify an in-memory ledger.
 *
 * `input` is either the raw file contents or an array of lines / already parsed
 * entries. The returned `entries` count is the number of records that were read.
 */
export function verifyLedger(
  input: string | readonly (string | LedgerEntry)[],
  options: VerifyOptions = {}
): VerifyResult {
  const hmacKey = options.hmacKey;
  const errors: VerifyError[] = [];
  const entries: LedgerEntry[] = [];
  const items: readonly (string | LedgerEntry)[] = typeof input === 'string' ? input.split('\n') : input;

  let expectedPrev = GENESIS_HASH;
  let recordIndex = 0;

  for (let lineIndex = 0; lineIndex < items.length; lineIndex += 1) {
    const item = items[lineIndex];
    if (item === undefined) continue;

    let parsed: unknown;
    if (typeof item === 'string') {
      const line = lineIndex === 0 ? stripBom(item) : item;
      if (line.trim() === '') continue;
      try {
        parsed = JSON.parse(line);
      } catch (error) {
        errors.push({
          seq: null,
          code: 'INVALID_JSON',
          message: `Line ${lineIndex + 1} is not valid JSON: ${(error as Error).message}`,
        });
        continue;
      }
    } else {
      parsed = item;
    }

    const position = recordIndex;
    recordIndex += 1;

    if (!isRecord(parsed)) {
      errors.push({
        seq: null,
        code: 'INVALID_JSON',
        message: `Record ${position} is not a JSON object`,
      });
      continue;
    }

    const entry = parsed;
    const seq = typeof entry.seq === 'number' && Number.isInteger(entry.seq) && entry.seq >= 0 ? entry.seq : null;

    const missing = REQUIRED_FIELDS.filter((field) => !(field in entry));
    if (missing.length > 0) {
      errors.push({
        seq,
        code: 'MISSING_FIELD',
        message: `Record ${position} is missing required field(s): ${missing.join(', ')}`,
      });
      continue;
    }

    if (entry.v !== 1) {
      errors.push({
        seq,
        code: 'UNSUPPORTED_VERSION',
        message: `Record ${position} uses unsupported format version ${JSON.stringify(entry.v)}; this build only reads v1`,
      });
    }

    if (seq === null) {
      errors.push({
        seq: null,
        code: 'OUT_OF_ORDER',
        message: `Record ${position} has no valid "seq" (expected a non-negative integer, found ${JSON.stringify(entry.seq)})`,
      });
    } else if (seq < position) {
      errors.push({
        seq,
        code: 'OUT_OF_ORDER',
        message: `Record ${position} repeats or rewinds the sequence (seq ${seq} after ${position} records): entries were reordered or duplicated`,
      });
    } else if (seq > position) {
      errors.push({
        seq,
        code: 'SEQ_GAP',
        message: `Record ${position} expects seq ${position} but found ${seq}: ${seq - position} record(s) are missing`,
      });
    }

    if (typeof entry.prevHash !== 'string' || !isHash(entry.prevHash)) {
      errors.push({
        seq,
        code: 'BAD_HASH',
        message: `Record ${position} has a malformed prevHash: ${JSON.stringify(entry.prevHash)}`,
      });
    } else if (entry.prevHash !== expectedPrev) {
      errors.push({
        seq,
        code: 'CHAIN_MISMATCH',
        message: `Record ${position} points at prevHash ${entry.prevHash} but the previous record hash is ${expectedPrev}`,
      });
    }

    if (typeof entry.hash !== 'string' || !isHash(entry.hash)) {
      errors.push({
        seq,
        code: 'BAD_HASH',
        message: `Record ${position} has a malformed hash: ${JSON.stringify(entry.hash)}`,
      });
    } else {
      const computed = computeEntryHash(entry);
      if (computed !== entry.hash) {
        errors.push({
          seq,
          code: 'BAD_HASH',
          message: `Record ${position} hash does not match its contents (expected ${computed}, found ${entry.hash})`,
        });
      }
    }

    if (entry.args !== null && entry.args !== undefined) {
      const argsHash = hashValue(entry.args);
      if (argsHash !== entry.argsHash) {
        errors.push({
          seq,
          code: 'BAD_HASH',
          message: `Record ${position} argsHash does not match args (expected ${argsHash}, found ${String(entry.argsHash)})`,
        });
      }
    }

    if (entry.result !== null && entry.result !== undefined) {
      const resultHash = hashValue(entry.result);
      if (resultHash !== entry.resultHash) {
        errors.push({
          seq,
          code: 'BAD_HASH',
          message: `Record ${position} resultHash does not match result (expected ${resultHash}, found ${String(entry.resultHash)})`,
        });
      }
    }

    if (hmacKey !== undefined) {
      const expectedSignature = hmacSha256Hex(hmacKey, String(entry.hash));
      if (typeof entry.sig !== 'string' || !isHex64(entry.sig)) {
        errors.push({
          seq,
          code: 'BAD_SIGNATURE',
          message: `Record ${position} is not signed but a HMAC key was provided`,
        });
      } else if (!safeEqualHex(entry.sig, expectedSignature)) {
        errors.push({
          seq,
          code: 'BAD_SIGNATURE',
          message: `Record ${position} HMAC signature does not match the provided key`,
        });
      }
    }

    entries.push(entry as unknown as LedgerEntry);
    if (typeof entry.hash === 'string' && isHash(entry.hash)) {
      expectedPrev = entry.hash;
    }
  }

  if (options.checkpoint !== undefined) {
    checkCheckpoint(options.checkpoint, recordIndex, entries, hmacKey, errors);
  }

  return { valid: errors.length === 0, entries: recordIndex, errors };
}

/** Verify a ledger file. Throws a decorated error when the file cannot be read. */
export function verifyLedgerFile(filePath: string, options: VerifyOptions = {}): VerifyResult {
  return verifyLedger(readTextSync(filePath), options);
}

/**
 * Build a checkpoint for a set of entries.
 *
 * The checkpoint commits to the entry count and to the hash of the last entry, and is
 * HMAC signed when a key is available. An empty ledger uses the genesis hash.
 */
export function buildCheckpoint(
  entries: readonly LedgerEntry[],
  options: BuildCheckpointOptions = {}
): Checkpoint {
  const last = entries.length > 0 ? entries[entries.length - 1] : undefined;
  if (last !== undefined && (typeof last.hash !== 'string' || !isHash(last.hash))) {
    throw new TypeError('buildCheckpoint() requires every entry to carry a valid "hash" field');
  }

  const lastHash = last === undefined ? GENESIS_HASH : last.hash;
  const clock = options.now ? options.now() : new Date();
  if (!(clock instanceof Date) || Number.isNaN(clock.getTime())) {
    throw new TypeError('checkpoint clock must return a valid Date');
  }

  const checkpoint: Checkpoint = {
    v: 1,
    entries: entries.length,
    lastHash,
    createdAt: clock.toISOString(),
  };

  if (options.hmacKey !== undefined) {
    checkpoint.hmac = checkpointMac(options.hmacKey, checkpoint);
  }

  return checkpoint;
}

function checkCheckpoint(
  checkpoint: Checkpoint,
  recordCount: number,
  entries: readonly LedgerEntry[],
  hmacKey: string | Buffer | undefined,
  errors: VerifyError[]
): void {
  if (!isRecord(checkpoint)) {
    errors.push({ seq: null, code: 'BAD_CHECKPOINT', message: 'Checkpoint is not a JSON object' });
    return;
  }

  if (checkpoint.v !== 1) {
    errors.push({
      seq: null,
      code: 'BAD_CHECKPOINT',
      message: `Checkpoint uses unsupported version ${JSON.stringify(checkpoint.v)}`,
    });
    return;
  }

  if (!Number.isInteger(checkpoint.entries) || checkpoint.entries < 0) {
    errors.push({ seq: null, code: 'BAD_CHECKPOINT', message: 'Checkpoint "entries" must be a non-negative integer' });
    return;
  }

  if (typeof checkpoint.lastHash !== 'string' || !isHash(checkpoint.lastHash)) {
    errors.push({ seq: null, code: 'BAD_CHECKPOINT', message: 'Checkpoint "lastHash" is not a valid ledger hash' });
    return;
  }

  if (typeof checkpoint.createdAt !== 'string' || Number.isNaN(Date.parse(checkpoint.createdAt))) {
    errors.push({ seq: null, code: 'BAD_CHECKPOINT', message: 'Checkpoint "createdAt" is not a valid timestamp' });
    return;
  }

  if (hmacKey !== undefined) {
    const expected = checkpointMac(hmacKey, checkpoint);
    if (typeof checkpoint.hmac !== 'string' || !isHex64(checkpoint.hmac)) {
      errors.push({
        seq: null,
        code: 'BAD_CHECKPOINT',
        message: 'Checkpoint is not signed but a HMAC key was provided',
      });
    } else if (!safeEqualHex(checkpoint.hmac, expected)) {
      errors.push({
        seq: null,
        code: 'BAD_CHECKPOINT',
        message: 'Checkpoint HMAC does not match the provided key',
      });
    }
  }

  if (checkpoint.entries > recordCount) {
    errors.push({
      seq: null,
      code: 'TRUNCATED',
      message: `Checkpoint covers ${checkpoint.entries} entries but the ledger only contains ${recordCount}: the tail was truncated`,
    });
    return;
  }

  if (checkpoint.entries === 0) {
    if (checkpoint.lastHash !== GENESIS_HASH) {
      errors.push({
        seq: null,
        code: 'BAD_CHECKPOINT',
        message: 'Checkpoint for an empty ledger must use the genesis hash',
      });
    }
    return;
  }

  const target = entries[checkpoint.entries - 1];
  if (target === undefined) {
    errors.push({
      seq: null,
      code: 'BAD_CHECKPOINT',
      message: `Checkpoint references entry ${checkpoint.entries} which could not be read`,
    });
    return;
  }

  if (target.hash !== checkpoint.lastHash) {
    errors.push({
      seq: typeof target.seq === 'number' ? target.seq : null,
      code: 'BAD_CHECKPOINT',
      message: `Checkpoint lastHash ${checkpoint.lastHash} does not match entry ${checkpoint.entries - 1} hash ${target.hash}`,
    });
  }
}

/**
 * Canonical body used for checkpoint signatures. Re-exported so tooling can inspect
 * exactly what a checkpoint signature covers.
 */
export function checkpointBody(checkpoint: Checkpoint): string {
  return canonicalize({
    v: checkpoint.v,
    entries: checkpoint.entries,
    lastHash: checkpoint.lastHash,
    createdAt: checkpoint.createdAt,
  });
}
