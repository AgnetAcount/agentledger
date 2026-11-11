/**
 * `agentledger` — tamper-evident, zero-dependency audit trail and replay log for
 * AI agent tool calls.
 *
 * ```ts
 * import { createLedger, verifyLedgerFile } from 'agentledger';
 *
 * const ledger = await createLedger({ path: 'audit.jsonl' });
 * await ledger.record({ tool: 'http.get', args: { url: 'https://example.com' } });
 * ```
 *
 * @packageDocumentation
 */

export { createLedger } from './ledger.js';
export { canonicalize, MAX_CANONICAL_DEPTH } from './canonical.js';
export {
  GENESIS_HASH,
  HASH_PREFIX,
  HASH_PATTERN,
  sha256Hex,
  hmacSha256Hex,
  hashCanonical,
  hashValue,
  isHash,
  isHex64,
  safeEqualHex,
  computeEntryHash,
  checkpointMac,
} from './crypto.js';
export { redact, redactString, isSecretKey } from './redact.js';
export {
  verifyLedger,
  verifyLedgerFile,
  readEntriesFromText,
  stripBom,
  buildCheckpoint,
  checkpointBody,
} from './verify.js';
export type { ParsedLedger } from './verify.js';
export { computeStats } from './stats.js';

export type {
  BuildCheckpointOptions,
  CaptureMode,
  Checkpoint,
  CreateLedgerOptions,
  EntryStatus,
  Ledger,
  LedgerEntry,
  LedgerErrorInfo,
  LedgerStats,
  RecordInput,
  VerifyError,
  VerifyErrorCode,
  VerifyOptions,
  VerifyResult,
} from './types.js';
