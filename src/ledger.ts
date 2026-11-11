/**
 * The ledger: append-only, hash-chained, serialized JSONL writes.
 *
 * Design notes:
 *  - `record()` calls are queued through a promise chain, so concurrent appends can
 *    never interleave or produce partial lines.
 *  - The file is always opened with `O_APPEND | O_CREAT` and never through a symlink.
 *  - Sequence numbers, the previous hash and the "file ends with newline" state are
 *    loaded once, then maintained in memory behind the same queue.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import { canonicalize } from './canonical.js';
import {
  GENESIS_HASH,
  computeEntryHash,
  hashCanonical,
  hmacSha256Hex,
  isHash,
} from './crypto.js';
import { appendToFd, assertWritableTarget, closeFd, openForAppend, readText } from './fileio.js';
import { redact } from './redact.js';
import { computeStats } from './stats.js';
import { buildCheckpoint, readEntriesFromText, stripBom, verifyLedger } from './verify.js';
import type {
  CaptureMode,
  Checkpoint,
  CreateLedgerOptions,
  EntryStatus,
  Ledger,
  LedgerEntry,
  LedgerErrorInfo,
  LedgerStats,
  RecordInput,
  VerifyOptions,
  VerifyResult,
} from './types.js';

const CAPTURE_MODES: readonly CaptureMode[] = ['redacted', 'full', 'hash'];

interface LedgerState {
  nextSeq: number;
  lastHash: string;
  /** True when the existing file does not end with a newline, so the next write needs a separator. */
  pendingNewline: boolean;
}

interface EncodedValue {
  stored: unknown;
  canonical: string;
}

interface NormalizedInput {
  tool: string;
  args: unknown;
  result: unknown;
  hasResult: boolean;
  status: EntryStatus;
  durationMs: number;
  error: LedgerErrorInfo | null;
  meta: Record<string, unknown> | null;
}

/**
 * Prepare a payload for storage.
 *
 * The canonical string is always computed from the redacted value, so the stored hash
 * describes exactly what a reader can recompute — except in `hash` mode, where the
 * value is withheld but the hash remains a commitment to it.
 */
function encodeValue(value: unknown, capture: CaptureMode): EncodedValue {
  const prepared = capture === 'full' ? value : redact(value);
  if (prepared === undefined) return { stored: null, canonical: 'null' };
  const canonical = canonicalize(prepared);
  return { stored: capture === 'hash' ? null : (JSON.parse(canonical) as unknown), canonical };
}

function normalizeHmacKey(key: string | Buffer | undefined): string | Buffer | undefined {
  if (key === undefined) return undefined;
  if (typeof key === 'string') {
    if (key.length === 0) throw new TypeError('"hmacKey" must not be an empty string');
    return key;
  }
  if (Buffer.isBuffer(key)) {
    if (key.length === 0) throw new TypeError('"hmacKey" must not be an empty Buffer');
    return key;
  }
  throw new TypeError('"hmacKey" must be a string or a Buffer');
}

function normalizeInput(input: RecordInput): NormalizedInput {
  if (input === null || typeof input !== 'object') {
    throw new TypeError('record() requires an input object');
  }
  if (typeof input.tool !== 'string' || input.tool.trim() === '') {
    throw new TypeError('record() requires a non-empty "tool" string');
  }

  const status = input.status ?? 'ok';
  if (status !== 'ok' && status !== 'error') {
    throw new TypeError('"status" must be "ok" or "error"');
  }

  const rawDuration = input.durationMs ?? 0;
  if (typeof rawDuration !== 'number' || !Number.isFinite(rawDuration) || rawDuration < 0) {
    throw new TypeError('"durationMs" must be a non-negative finite number');
  }

  let error: LedgerErrorInfo | null = null;
  if (input.error !== undefined && input.error !== null) {
    const candidate = input.error;
    if (
      typeof candidate !== 'object' ||
      typeof candidate.name !== 'string' ||
      typeof candidate.message !== 'string'
    ) {
      throw new TypeError('"error" must be an object with string "name" and "message"');
    }
    error = { name: candidate.name, message: candidate.message };
  }

  let meta: Record<string, unknown> | null = null;
  if (input.meta !== undefined && input.meta !== null) {
    if (typeof input.meta !== 'object' || Array.isArray(input.meta)) {
      throw new TypeError('"meta" must be a plain object or null');
    }
    meta = { ...input.meta };
  }

  return {
    tool: input.tool,
    args: input.args,
    result: input.result,
    hasResult: input.result !== undefined,
    status,
    durationMs: Math.round(rawDuration * 1000) / 1000,
    error,
    meta,
  };
}

function toErrorInfo(error: unknown): LedgerErrorInfo {
  if (error instanceof Error) {
    return { name: error.name || 'Error', message: error.message };
  }
  return { name: 'Error', message: String(error) };
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.promises.lstat(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function parseState(text: string, filePath: string): LedgerState {
  const body = stripBom(text);
  const { entries, errors } = readEntriesFromText(text);
  const firstError = errors[0];
  if (firstError !== undefined) {
    throw new Error(
      `Cannot append to "${filePath}": ${firstError.message}. Run "agentledger verify ${filePath}" to inspect the damage.`
    );
  }

  const last = entries[entries.length - 1];
  if (last === undefined) {
    return { nextSeq: 0, lastHash: GENESIS_HASH, pendingNewline: body.length > 0 && !body.endsWith('\n') };
  }

  if (
    typeof last.seq !== 'number' ||
    !Number.isInteger(last.seq) ||
    last.seq < 0 ||
    typeof last.hash !== 'string' ||
    !isHash(last.hash)
  ) {
    throw new Error(
      `Cannot append to "${filePath}": the last record has no usable "seq"/"hash". Run "agentledger verify" to inspect the damage.`
    );
  }

  return {
    nextSeq: entries.length,
    lastHash: last.hash,
    pendingNewline: !body.endsWith('\n'),
  };
}

class FileLedger implements Ledger {
  readonly path: string;
  readonly capture: CaptureMode;
  readonly #key: string | Buffer | undefined;
  readonly #now: (() => Date) | undefined;
  #nextSeq: number;
  #lastHash: string;
  #pendingNewline: boolean;
  #queue: Promise<void> = Promise.resolve();
  /**
   * The file descriptor is held open between appends. Opening and closing a file per
   * record costs roughly an order of magnitude more than the hash itself on Windows,
   * which would miss the documented throughput target.
   */
  #fd: number | null = null;
  /** Set when an append fails mid-write; further appends refuse until the ledger is reopened. */
  #failure: Error | null = null;

  constructor(
    filePath: string,
    capture: CaptureMode,
    key: string | Buffer | undefined,
    now: (() => Date) | undefined,
    state: LedgerState
  ) {
    this.path = filePath;
    this.capture = capture;
    this.#key = key;
    this.#now = now;
    this.#nextSeq = state.nextSeq;
    this.#lastHash = state.lastHash;
    this.#pendingNewline = state.pendingNewline;
  }

  record(input: RecordInput): Promise<LedgerEntry> {
    return this.#enqueue(() => this.#append(input));
  }

  wrap<TArgs extends unknown[], TResult>(
    tool: string,
    fn: (...args: TArgs) => TResult | Promise<TResult>
  ): (...args: TArgs) => Promise<TResult> {
    if (typeof tool !== 'string' || tool.trim() === '') {
      throw new TypeError('wrap() requires a non-empty "tool" name');
    }
    if (typeof fn !== 'function') {
      throw new TypeError('wrap() requires a function to wrap');
    }

    const ledger = this;

    return async function wrapped(this: unknown, ...args: TArgs): Promise<TResult> {
      const startedAt = performance.now();
      let value: TResult;
      try {
        value = await fn.apply(this, args);
      } catch (error) {
        const durationMs = performance.now() - startedAt;
        try {
          await ledger.record({
            tool,
            args,
            status: 'error',
            durationMs,
            error: toErrorInfo(error),
          });
        } catch {
          // Audit failures must never replace the error the caller actually threw.
        }
        throw error;
      }

      const durationMs = performance.now() - startedAt;
      try {
        await ledger.record({ tool, args, result: value, status: 'ok', durationMs });
      } catch {
        // Auditing must never turn a successful tool call into a failure. A payload
        // that JSON cannot represent (BigInt, NaN, circular object) or a write error
        // skips the record; the caller still receives the tool's return value.
      }
      return value;
    };
  }

  read(): Promise<LedgerEntry[]> {
    return this.#enqueue(async () => {
      const text = await readText(this.path);
      const { entries, errors } = readEntriesFromText(text);
      const firstError = errors[0];
      if (firstError !== undefined) {
        throw new Error(
          `Cannot read "${this.path}": ${firstError.message}. Run "agentledger verify" for a full report.`
        );
      }
      return entries;
    });
  }

  verify(options: VerifyOptions = {}): Promise<VerifyResult> {
    return this.#enqueue(async () => {
      const text = await readText(this.path);
      return verifyLedger(text, {
        hmacKey: options.hmacKey ?? this.#key,
        checkpoint: options.checkpoint,
      });
    });
  }

  async stats(): Promise<LedgerStats> {
    const entries = await this.read();
    return computeStats(entries);
  }

  checkpoint(): Promise<Checkpoint> {
    return this.#enqueue(async () => {
      const text = await readText(this.path);
      const { entries, errors } = readEntriesFromText(text);
      const parseError = errors[0];
      if (parseError !== undefined) {
        throw new Error(`Refusing to checkpoint "${this.path}": ${parseError.message}`);
      }

      const result = verifyLedger(entries, { hmacKey: this.#key });
      if (!result.valid) {
        const issue = result.errors[0];
        const code = issue === undefined ? 'INVALID' : issue.code;
        const message = issue === undefined ? 'unknown verification failure' : issue.message;
        throw new Error(`Refusing to checkpoint "${this.path}": the ledger does not verify (${code}: ${message})`);
      }

      return buildCheckpoint(entries, { hmacKey: this.#key, now: this.#now });
    });
  }

  close(): Promise<void> {
    return this.#enqueue(async () => {
      const fd = this.#fd;
      this.#fd = null;
      if (fd !== null) closeFd(fd);
    });
  }

  #enqueue<T>(task: () => Promise<T>): Promise<T> {
    const result = this.#queue.then(task);
    this.#queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  #timestamp(): string {
    const value = this.#now ? this.#now() : new Date();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new TypeError('now() must return a valid Date');
    }
    return value.toISOString();
  }

  async #append(input: RecordInput): Promise<LedgerEntry> {
    if (this.#failure !== null) {
      throw new Error(
        `Ledger "${this.path}" is in a failed state after an append error (${this.#failure.message}); reopen it with createLedger() to continue`
      );
    }

    const normalized = normalizeInput(input);
    const timestamp = this.#timestamp();
    const args = encodeValue(normalized.args, this.capture);
    const result = encodeValue(normalized.result, this.capture);
    const redactDetails = this.capture !== 'full';

    const errorInfo =
      normalized.error === null
        ? null
        : redactDetails
          ? (redact(normalized.error) as LedgerErrorInfo)
          : normalized.error;
    const meta =
      normalized.meta === null
        ? null
        : redactDetails
          ? (redact(normalized.meta) as Record<string, unknown>)
          : normalized.meta;

    const seq = this.#nextSeq;
    const base = {
      v: 1 as const,
      seq,
      ts: timestamp,
      tool: normalized.tool,
      status: normalized.status,
      durationMs: normalized.durationMs,
      args: args.stored,
      argsHash: hashCanonical(args.canonical),
      result: result.stored,
      resultHash: normalized.hasResult ? hashCanonical(result.canonical) : null,
      error: errorInfo,
      meta,
      prevHash: this.#lastHash,
    };

    const hash = computeEntryHash(base);
    const entry: LedgerEntry = { ...base, hash };
    if (this.#key !== undefined) {
      entry.sig = hmacSha256Hex(this.#key, hash);
    }

    this.#appendLine(`${JSON.stringify(entry)}\n`);
    this.#nextSeq = seq + 1;
    this.#lastHash = hash;
    return entry;
  }

  #appendLine(line: string): void {
    const payload = this.#pendingNewline ? `\n${line}` : line;
    let fd = this.#fd;
    if (fd === null) {
      fd = openForAppend(this.path);
      this.#fd = fd;
    }

    try {
      appendToFd(fd, payload, this.path);
    } catch (error) {
      // A failed write may have left a partial line on disk. Release the descriptor
      // and refuse further appends; the caller must reopen the ledger (which will
      // surface the damage) instead of appending after a partial record.
      const stale = this.#fd;
      this.#fd = null;
      if (stale !== null) closeFd(stale);
      this.#failure = error instanceof Error ? error : new Error(String(error));
      throw error;
    }

    this.#pendingNewline = false;
  }
}

/**
 * Open (or create) a ledger file and return a handle for appending records.
 *
 * The whole file is read once to recover the sequence number and the previous hash.
 * Appending is O(1) afterwards.
 */
export async function createLedger(options: CreateLedgerOptions): Promise<Ledger> {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('createLedger() requires an options object with a "path"');
  }
  if (typeof options.path !== 'string' || options.path.trim() === '') {
    throw new TypeError('createLedger() requires a non-empty "path" string');
  }

  const capture = options.capture ?? 'redacted';
  if (!CAPTURE_MODES.includes(capture)) {
    throw new TypeError(
      `"capture" must be one of ${CAPTURE_MODES.map((mode) => `"${mode}"`).join(', ')} (received ${JSON.stringify(options.capture)})`
    );
  }

  if (options.now !== undefined && typeof options.now !== 'function') {
    throw new TypeError('"now" must be a function returning a Date');
  }

  const key = normalizeHmacKey(options.hmacKey);
  const filePath = path.resolve(options.path);

  const existed = await pathExists(filePath);
  assertWritableTarget(filePath);

  // Create the file eagerly so permission and symlink problems surface here, not on
  // the first record.
  const descriptor = openForAppend(filePath);
  closeFd(descriptor);

  const text = existed ? await readText(filePath) : '';
  const state: LedgerState = existed
    ? parseState(text, filePath)
    : { nextSeq: 0, lastHash: GENESIS_HASH, pendingNewline: false };

  return new FileLedger(filePath, capture, key, options.now, state);
}
