/**
 * Public types for `agentledger`.
 *
 * Every type here is part of the published API surface. The ledger entry layout is
 * format v1 and is intentionally stable: any change to field names or hashing rules
 * requires a new `v` value.
 */

/** How `args` / `result` payloads are captured before hashing and writing. */
export type CaptureMode = 'redacted' | 'full' | 'hash';

/** Outcome of a single tool call. */
export type EntryStatus = 'ok' | 'error';

/** Serialized error information attached to a failed tool call. */
export interface LedgerErrorInfo {
  name: string;
  message: string;
}

/**
 * One record in the ledger. Records are stored one per line (JSONL).
 *
 * `hash` is the SHA-256 of the canonical JSON of the entry without `hash` and `sig`.
 * `sig` is only present when the ledger was created with an HMAC key.
 */
export interface LedgerEntry {
  v: 1;
  seq: number;
  ts: string;
  tool: string;
  status: EntryStatus;
  durationMs: number;
  args: unknown;
  argsHash: string;
  result: unknown;
  resultHash: string | null;
  error: LedgerErrorInfo | null;
  meta: Record<string, unknown> | null;
  prevHash: string;
  hash: string;
  sig?: string;
}

/** Machine-readable verification failure codes. */
export type VerifyErrorCode =
  | 'INVALID_JSON'
  | 'MISSING_FIELD'
  | 'UNSUPPORTED_VERSION'
  | 'BAD_HASH'
  | 'CHAIN_MISMATCH'
  | 'SEQ_GAP'
  | 'OUT_OF_ORDER'
  | 'TRUNCATED'
  | 'BAD_SIGNATURE'
  | 'BAD_CHECKPOINT';

/** A single verification problem. `seq` is null when no entry could be identified. */
export interface VerifyError {
  seq: number | null;
  code: VerifyErrorCode;
  message: string;
}

/** Result returned by `verify()`, `verifyLedger()` and `verifyLedgerFile()`. */
export interface VerifyResult {
  valid: boolean;
  entries: number;
  errors: VerifyError[];
}

/**
 * A checkpoint commits to the entry count and to the hash of the last entry.
 * It is the only way to detect a truncated tail.
 */
export interface Checkpoint {
  v: 1;
  entries: number;
  lastHash: string;
  createdAt: string;
  /** HMAC-SHA256 over the canonical checkpoint body, hex encoded. */
  hmac?: string;
}

/** Aggregate statistics for a ledger file. */
export interface LedgerStats {
  entries: number;
  firstTs: string | null;
  lastTs: string | null;
  tools: Record<string, number>;
  ok: number;
  error: number;
  avgDurationMs: number;
  lastHash: string | null;
}

/** Options accepted by `verify()` and by the standalone verification helpers. */
export interface VerifyOptions {
  /** HMAC key used to validate `sig` fields and signed checkpoints. */
  hmacKey?: string | Buffer;
  /** Checkpoint to validate the ledger against, used for truncation detection. */
  checkpoint?: Checkpoint;
}

/** Options accepted by `createLedger()`. */
export interface CreateLedgerOptions {
  /** Path of the JSONL ledger file. Created when missing. */
  path: string;
  /** HMAC key. When set, every entry is signed and verification can prove authenticity. */
  hmacKey?: string | Buffer;
  /** Payload capture mode. Defaults to `"redacted"`. */
  capture?: CaptureMode;
  /** Injectable clock, used for deterministic tests. */
  now?: () => Date;
}

/** Input accepted by `ledger.record()`. */
export interface RecordInput {
  tool: string;
  args?: unknown;
  result?: unknown;
  status?: EntryStatus;
  durationMs?: number;
  error?: LedgerErrorInfo;
  meta?: Record<string, unknown> | null;
}

/** Handle returned by `createLedger()`. */
export interface Ledger {
  /** Absolute path of the backing file. */
  readonly path: string;
  /** Capture mode in effect for this ledger. */
  readonly capture: CaptureMode;
  record(input: RecordInput): Promise<LedgerEntry>;
  wrap<TArgs extends unknown[], TResult>(
    tool: string,
    fn: (...args: TArgs) => TResult | Promise<TResult>
  ): (...args: TArgs) => Promise<TResult>;
  read(): Promise<LedgerEntry[]>;
  verify(options?: VerifyOptions): Promise<VerifyResult>;
  stats(): Promise<LedgerStats>;
  checkpoint(): Promise<Checkpoint>;
  /**
   * Release the open file handle. Appending after `close()` reopens the file and
   * continues from the in-memory chain state. Call this before rotating or renaming
   * the ledger on platforms that lock open files.
   */
  close(): Promise<void>;
}

/** Options accepted by `buildCheckpoint()`. */
export interface BuildCheckpointOptions {
  hmacKey?: string | Buffer;
  now?: () => Date;
}
