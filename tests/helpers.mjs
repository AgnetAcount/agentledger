import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** Create an isolated temporary directory for a test. */
export function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentledger-test-'));
}

/** Remove a temporary directory, tolerating Windows file-lock races. */
export function removeDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
}

/** Read a file as UTF-8 text. */
export function readText(file) {
  return fs.readFileSync(file, 'utf8');
}

/** Parse a JSONL file, ignoring a BOM and blank lines. */
export function readLines(file) {
  const text = readText(file).replace(/^\uFEFF/, '');
  return text
    .split(/\r?\n/)
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line));
}

/** Rewrite a JSONL file from entry objects. */
export function writeLines(file, entries) {
  fs.writeFileSync(file, `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`, 'utf8');
}

/** Seed a ledger with `count` deterministic records and return its path. */
export async function seedLedger(createLedger, dir, count = 3, options = {}) {
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file, ...options });
  for (let index = 0; index < count; index += 1) {
    await ledger.record({ tool: `tool.${index}`, args: { index }, result: { index } });
  }
  return file;
}
