/**
 * `agentledger` command line interface.
 *
 * Exit codes are part of the contract:
 *   0 — success / ledger is valid
 *   1 — the ledger is tampered, invalid, or fails verification
 *   2 — usage error, missing file, or I/O failure
 */

import * as path from 'node:path';
import { readTextSync, writeTextSecure } from './fileio.js';
import { computeStats } from './stats.js';
import { buildCheckpoint, readEntriesFromText, verifyLedgerFile } from './verify.js';
import type { Checkpoint, LedgerEntry, VerifyResult } from './types.js';

/** Package version. Kept in sync with `package.json`. */
export const VERSION = '0.1.0';

const MAX_REPORTED_ERRORS = 25;

/** Output and environment a CLI invocation runs against. Injectable for tests. */
export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd: string;
  env: NodeJS.ProcessEnv;
}

class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode: number) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
  }
}

interface ParsedArgs {
  command: string | null;
  positionals: string[];
  options: Map<string, string | true>;
}

const VALUE_OPTIONS = new Set(['--n', '--checkpoint', '--key-env', '--out', '--format']);
const BOOLEAN_OPTIONS = new Set(['--json', '--help', '--version']);

function defaultIO(): CliIO {
  return {
    stdout: (text) => process.stdout.write(`${text}\n`),
    stderr: (text) => process.stderr.write(`${text}\n`),
    cwd: process.cwd(),
    env: process.env,
  };
}

function helpText(): string {
  return `agentledger v${VERSION} — tamper-evident audit trail for AI agent tool calls
Agnet Software Corp. <https://github.com/AgnetAcount/agentledger>

USAGE
  agentledger <command> [options]

COMMANDS
  verify <file> [--json] [--checkpoint <file>] [--key-env <ENV_NAME>]
      Verify the hash chain, payload hashes, signatures and an optional checkpoint.
  tail <file> [--n <count>] [--json]
      Print the most recent records (default 10).
  stats <file> [--json]
      Print counts, time range, per-tool usage and average latency.
  checkpoint <file> [--out <file>] [--key-env <ENV_NAME>]
      Verify the ledger and emit a signed checkpoint.
  export <file> --format json|csv [--out <file>]
      Export the ledger as JSON or CSV.

OPTIONS
  --n <count>          Number of records to show for "tail" (default 10)
  --checkpoint <file>  Checkpoint file to validate during "verify"
  --key-env <name>     Read the HMAC key from the named environment variable
  --out <file>         Write output to a file instead of stdout
  --format <format>    Export format: json or csv
  --json               Machine-readable output
  -h, --help           Show this help
  -v, --version        Show the version

EXIT CODES
  0  success / the ledger is valid
  1  the ledger is tampered, invalid, or fails verification
  2  usage error, missing file, or I/O failure`;
}

function parseArgv(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  let command: string | null = null;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === undefined) continue;

    if (arg === '-h') {
      options.set('--help', true);
      continue;
    }
    if (arg === '-v') {
      options.set('--version', true);
      continue;
    }

    if (arg.startsWith('--')) {
      const separator = arg.indexOf('=');
      const name = separator === -1 ? arg : arg.slice(0, separator);

      if (separator !== -1) {
        const value = arg.slice(separator + 1);
        if (!VALUE_OPTIONS.has(name)) {
          throw new CliError(`Option ${name} does not take a value`, 2);
        }
        options.set(name, value);
        continue;
      }

      if (VALUE_OPTIONS.has(name)) {
        const value = argv[index + 1];
        if (value === undefined || value.startsWith('--')) {
          throw new CliError(`Option ${name} requires a value`, 2);
        }
        options.set(name, value);
        index += 1;
        continue;
      }

      if (BOOLEAN_OPTIONS.has(name)) {
        options.set(name, true);
        continue;
      }

      throw new CliError(`Unknown option: ${name}`, 2);
    }

    if (arg.startsWith('-') && arg !== '-') {
      throw new CliError(`Unknown option: ${arg}`, 2);
    }

    if (command === null) {
      command = arg;
    } else {
      positionals.push(arg);
    }
  }

  return { command, positionals, options };
}

function requirePositional(args: ParsedArgs, index: number, message: string): string {
  const value = args.positionals[index];
  if (value === undefined || value.trim() === '') {
    throw new CliError(message, 2);
  }
  if (args.positionals.length > index + 1) {
    throw new CliError(`Unexpected argument: ${args.positionals[index + 1]}`, 2);
  }
  return value;
}

function stringOption(args: ParsedArgs, name: string): string | undefined {
  const value = args.options.get(name);
  return typeof value === 'string' ? value : undefined;
}

function readKeyFromEnv(io: CliIO, args: ParsedArgs): string | undefined {
  const envName = stringOption(args, '--key-env');
  if (envName === undefined) return undefined;
  const value = io.env[envName];
  if (value === undefined || value === '') {
    throw new CliError(`Environment variable ${envName} is not set or is empty`, 2);
  }
  return value;
}

function readCheckpointFile(checkpointPath: string): Checkpoint {
  const text = readTextSync(checkpointPath);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new CliError(`Checkpoint "${checkpointPath}" is not valid JSON: ${(error as Error).message}`, 1);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new CliError(`Checkpoint "${checkpointPath}" is not a JSON object`, 1);
  }
  return parsed as Checkpoint;
}

function readEntriesOrThrow(filePath: string): LedgerEntry[] {
  const text = readTextSync(filePath);
  const { entries, errors } = readEntriesFromText(text);
  const firstError = errors[0];
  if (firstError !== undefined) {
    throw new CliError(`Cannot read "${filePath}": ${firstError.message}`, 2);
  }
  return entries;
}

function formatVerifyReport(filePath: string, result: VerifyResult, signed: boolean): string {
  const lines = [
    `File:    ${filePath}`,
    `Status:  ${result.valid ? 'VALID' : 'INVALID'}`,
    `Entries: ${result.entries}`,
    `Signing: ${signed ? 'HMAC-SHA256 verified' : 'not checked (no --key-env supplied)'}`,
  ];

  if (!result.valid) {
    lines.push(`Errors:  ${result.errors.length}`);
    for (const error of result.errors.slice(0, MAX_REPORTED_ERRORS)) {
      const seq = error.seq === null ? '-' : String(error.seq);
      lines.push(`  - seq ${seq} [${error.code}] ${error.message}`);
    }
    if (result.errors.length > MAX_REPORTED_ERRORS) {
      lines.push(`  ... and ${result.errors.length - MAX_REPORTED_ERRORS} more`);
    }
  }

  return lines.join('\n');
}

function toCsv(entries: readonly LedgerEntry[]): string {
  const columns = [
    'seq',
    'ts',
    'tool',
    'status',
    'durationMs',
    'args',
    'result',
    'error',
    'prevHash',
    'hash',
    'sig',
  ];

  const escapeCell = (value: unknown): string => {
    if (value === null || value === undefined) return '';
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    if (/[",\r\n]/.test(text)) {
      return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
  };

  const rows = entries.map((entry) =>
    columns.map((column) => escapeCell((entry as unknown as Record<string, unknown>)[column])).join(',')
  );

  return [columns.join(','), ...rows].join('\n');
}

async function writeOutput(io: CliIO, text: string, outPath: string | undefined): Promise<void> {
  if (outPath === undefined) {
    io.stdout(text.replace(/\n$/, ''));
    return;
  }
  const absolute = path.resolve(io.cwd, outPath);
  await writeTextSecure(absolute, text.endsWith('\n') ? text : `${text}\n`);
  io.stdout(`Written to ${absolute}`);
}

function commandVerify(args: ParsedArgs, io: CliIO): number {
  const file = requirePositional(args, 0, 'verify requires a ledger file');
  const target = path.resolve(io.cwd, file);
  const key = readKeyFromEnv(io, args);
  const checkpointPath = stringOption(args, '--checkpoint');
  const checkpoint = checkpointPath === undefined ? undefined : readCheckpointFile(path.resolve(io.cwd, checkpointPath));

  const result = verifyLedgerFile(target, { hmacKey: key, checkpoint });

  if (args.options.has('--json')) {
    io.stdout(
      JSON.stringify(
        {
          file: target,
          valid: result.valid,
          entries: result.entries,
          signature: key === undefined ? 'none' : 'hmac-sha256',
          errors: result.errors,
        },
        null,
        2
      )
    );
  } else {
    io.stdout(formatVerifyReport(target, result, key !== undefined));
  }

  return result.valid ? 0 : 1;
}

function commandTail(args: ParsedArgs, io: CliIO): number {
  const file = requirePositional(args, 0, 'tail requires a ledger file');
  const target = path.resolve(io.cwd, file);
  const entries = readEntriesOrThrow(target);

  const rawCount = stringOption(args, '--n') ?? '10';
  const count = Number(rawCount);
  if (!Number.isInteger(count) || count <= 0) {
    throw new CliError(`--n must be a positive integer (received ${JSON.stringify(rawCount)})`, 2);
  }

  const slice = entries.slice(Math.max(0, entries.length - count));

  if (args.options.has('--json')) {
    io.stdout(JSON.stringify(slice, null, 2));
    return 0;
  }

  if (slice.length === 0) {
    io.stdout(`No records in ${target}`);
    return 0;
  }

  const lines = slice.map((entry) => {
    const duration = typeof entry.durationMs === 'number' ? `${entry.durationMs}ms` : '-';
    return `#${entry.seq}  ${entry.ts}  ${entry.tool}  ${entry.status}  ${duration}`;
  });
  io.stdout(lines.join('\n'));
  return 0;
}

function commandStats(args: ParsedArgs, io: CliIO): number {
  const file = requirePositional(args, 0, 'stats requires a ledger file');
  const target = path.resolve(io.cwd, file);
  const stats = computeStats(readEntriesOrThrow(target));

  if (args.options.has('--json')) {
    io.stdout(JSON.stringify(stats, null, 2));
    return 0;
  }

  const lines = [
    `Entries: ${stats.entries}`,
    `Range:   ${stats.firstTs ?? '-'} -> ${stats.lastTs ?? '-'}`,
    `Status:  ${stats.ok} ok, ${stats.error} error`,
    `Average: ${stats.avgDurationMs}ms`,
    `Last:    ${stats.lastHash ?? '-'}`,
  ];

  const toolNames = Object.keys(stats.tools);
  if (toolNames.length > 0) {
    lines.push('Tools:');
    for (const tool of toolNames) {
      lines.push(`  ${tool}  ${stats.tools[tool]}`);
    }
  }

  io.stdout(lines.join('\n'));
  return 0;
}

async function commandCheckpoint(args: ParsedArgs, io: CliIO): Promise<number> {
  const file = requirePositional(args, 0, 'checkpoint requires a ledger file');
  const target = path.resolve(io.cwd, file);
  const key = readKeyFromEnv(io, args);

  const result = verifyLedgerFile(target, { hmacKey: key });
  if (!result.valid) {
    io.stderr(`Refusing to checkpoint: "${target}" does not verify`);
    for (const error of result.errors.slice(0, MAX_REPORTED_ERRORS)) {
      const seq = error.seq === null ? '-' : String(error.seq);
      io.stderr(`  - seq ${seq} [${error.code}] ${error.message}`);
    }
    return 1;
  }

  const { entries } = readEntriesFromText(readTextSync(target));
  const checkpoint = buildCheckpoint(entries, { hmacKey: key, now: () => new Date() });
  await writeOutput(io, JSON.stringify(checkpoint, null, 2), stringOption(args, '--out'));
  return 0;
}

async function commandExport(args: ParsedArgs, io: CliIO): Promise<number> {
  const file = requirePositional(args, 0, 'export requires a ledger file');
  const target = path.resolve(io.cwd, file);
  const format = stringOption(args, '--format');

  if (format === undefined) {
    throw new CliError('export requires --format json|csv', 2);
  }
  if (format !== 'json' && format !== 'csv') {
    throw new CliError(`Unsupported export format "${format}"; expected "json" or "csv"`, 2);
  }

  const entries = readEntriesOrThrow(target);
  const output = format === 'json' ? JSON.stringify(entries, null, 2) : toCsv(entries);
  await writeOutput(io, output, stringOption(args, '--out'));
  return 0;
}

async function dispatch(argv: readonly string[], io: CliIO): Promise<number> {
  const args = parseArgv(argv);

  if (args.options.has('--help')) {
    io.stdout(helpText());
    return 0;
  }

  if (args.options.has('--version')) {
    io.stdout(`agentledger ${VERSION}`);
    return 0;
  }

  if (args.command === null) {
    io.stdout(helpText());
    return 0;
  }

  switch (args.command) {
    case 'verify':
      return commandVerify(args, io);
    case 'tail':
      return commandTail(args, io);
    case 'stats':
      return commandStats(args, io);
    case 'checkpoint':
      return commandCheckpoint(args, io);
    case 'export':
      return commandExport(args, io);
    default:
      throw new CliError(`Unknown command: ${args.command}`, 2);
  }
}

/**
 * Run the CLI. Returns the process exit code instead of calling `process.exit`, so the
 * behaviour is testable in-process and from spawned child processes alike.
 */
export async function runCli(argv: readonly string[] = process.argv.slice(2), io: CliIO = defaultIO()): Promise<number> {
  try {
    return await dispatch(argv, io);
  } catch (error) {
    if (error instanceof CliError) {
      io.stderr(`agentledger: ${error.message}`);
      if (error.exitCode === 2) io.stderr('Run "agentledger --help" for usage.');
      return error.exitCode;
    }
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`agentledger: ${message}`);
    return 2;
  }
}
