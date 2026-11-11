import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildCheckpoint,
  GENESIS_HASH,
  verifyLedger,
  verifyLedgerFile,
} from '../dist/index.js';
import {
  createLedger,
  makeTempDir,
  readLines,
  readText,
  removeDir,
  seedLedger,
  writeLines,
} from './helpers.mjs';

/** Collect the verification error codes for compact assertions. */
function codes(result) {
  return result.errors.map((error) => error.code);
}

/** Rewrite a ledger file's trailing lines, keeping JSONL formatting. */
function truncate(file, keep) {
  const lines = readText(file)
    .split('\n')
    .filter((line) => line.trim() !== '');
  fs.writeFileSync(file, `${lines.slice(0, keep).join('\n')}\n`, 'utf8');
}

test('a freshly written ledger verifies', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = verifyLedgerFile(file);

  assert.equal(result.valid, true);
  assert.equal(result.entries, 3);
  assert.deepEqual(result.errors, []);
});

test('editing a field is detected as BAD_HASH', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const entries = readLines(file);
  entries[1].tool = 'tool.rewritten';
  writeLines(file, entries);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('BAD_HASH'));
  assert.equal(result.errors.find((error) => error.code === 'BAD_HASH').seq, 1);
});

test('editing args is detected through argsHash', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const entries = readLines(file);
  entries[2].args = { index: 999 };
  writeLines(file, entries);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.code === 'BAD_HASH' && error.message.includes('argsHash')));
});

test('deleting a middle entry is detected as a sequence gap', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);

  const entries = readLines(file);
  writeLines(file, [entries[0], entries[2], entries[3]]);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('SEQ_GAP'));
  assert.ok(codes(result).includes('CHAIN_MISMATCH'));
});

test('reordered entries are detected', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);

  const entries = readLines(file);
  const reordered = [entries[0], entries[2], entries[1], entries[3]];
  writeLines(file, reordered);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('SEQ_GAP'));
  assert.ok(codes(result).includes('OUT_OF_ORDER'));
});

test('a duplicated entry is detected as OUT_OF_ORDER', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const entries = readLines(file);
  writeLines(file, [entries[0], entries[1], entries[1], entries[2]]);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('OUT_OF_ORDER'));
});

test('a truncated tail is detected with a checkpoint', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);

  const ledger = await createLedger({ path: file });
  const checkpoint = await ledger.checkpoint();

  truncate(file, 2);

  const result = verifyLedgerFile(file, { checkpoint });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('TRUNCATED'));
});

test('a truncated tail without a checkpoint is undetectable (documented limit)', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);

  truncate(file, 2);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, true);
  assert.equal(result.entries, 2);
});

test('appending after truncation is caught by the checkpoint', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);

  const original = await createLedger({ path: file });
  const checkpoint = await original.checkpoint();

  truncate(file, 2);
  const reopened = await createLedger({ path: file });
  await reopened.record({ tool: 'replacement' });

  const result = verifyLedgerFile(file, { checkpoint });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('TRUNCATED'));
});

test('a wrong HMAC key is rejected', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2, { hmacKey: 'correct-key' });

  assert.equal(verifyLedgerFile(file, { hmacKey: 'correct-key' }).valid, true);

  const result = verifyLedgerFile(file, { hmacKey: 'wrong-key' });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('BAD_SIGNATURE'));
});

test('an unsigned ledger is rejected when a key is supplied', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const result = verifyLedgerFile(file, { hmacKey: 'some-key' });
  assert.equal(result.valid, false);
  assert.deepEqual(codes(result), ['BAD_SIGNATURE', 'BAD_SIGNATURE']);
});

test('an invalid JSON line is reported without crashing', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  fs.appendFileSync(file, '{"broken": \n', 'utf8');

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('INVALID_JSON'));
});

test('an unsupported format version is reported', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const entries = readLines(file);
  entries[0].v = 2;
  writeLines(file, entries);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('UNSUPPORTED_VERSION'));
});

test('a missing required field is reported', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const entries = readLines(file);
  delete entries[1].resultHash;
  writeLines(file, entries);

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('MISSING_FIELD'));
  assert.match(result.errors[0].message, /resultHash/);
});

test('a checkpoint with a foreign lastHash is rejected', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const ledger = await createLedger({ path: file });
  const checkpoint = await ledger.checkpoint();
  checkpoint.lastHash = `sha256:${'a'.repeat(64)}`;

  const result = verifyLedgerFile(file, { checkpoint });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('BAD_CHECKPOINT'));
});

test('an unsigned checkpoint is rejected when a key is supplied', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2, { hmacKey: 'checkpoint-key' });

  const ledger = await createLedger({ path: file, hmacKey: 'checkpoint-key' });
  const checkpoint = await ledger.checkpoint();
  delete checkpoint.hmac;

  const result = verifyLedgerFile(file, { checkpoint, hmacKey: 'checkpoint-key' });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('BAD_CHECKPOINT'));
});

test('a checkpoint claiming more entries than the ledger is a truncation', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const ledger = await createLedger({ path: file });
  const checkpoint = await ledger.checkpoint();
  checkpoint.entries = 99;

  const result = verifyLedgerFile(file, { checkpoint });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('TRUNCATED'));
});

test('an empty ledger file verifies with zero entries', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'empty.jsonl');
  fs.writeFileSync(file, '', 'utf8');

  const result = verifyLedgerFile(file);
  assert.deepEqual(result, { valid: true, entries: 0, errors: [] });

  const checkpoint = buildCheckpoint([], { now: () => new Date('2026-11-11T00:00:00.000Z') });
  assert.equal(checkpoint.entries, 0);
  assert.equal(checkpoint.lastHash, GENESIS_HASH);
  assert.equal(verifyLedgerFile(file, { checkpoint }).valid, true);
});

test('verifyLedger accepts already parsed entries', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = verifyLedger(readLines(file));
  assert.equal(result.valid, true);
  assert.equal(result.entries, 3);
});

test('verifyLedger accepts a raw JSONL string', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = verifyLedger(readText(file));
  assert.equal(result.valid, true);
  assert.equal(result.entries, 3);
});

test('a BOM and CRLF ledger verifies', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  fs.writeFileSync(file, `\uFEFF${readText(file).replace(/\n/g, '\r\n')}`, 'utf8');

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, true);
  assert.equal(result.entries, 3);
});

test('a JSON array line is rejected as not an object', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'array.jsonl');
  fs.writeFileSync(file, '[]\n', 'utf8');

  const result = verifyLedgerFile(file);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('INVALID_JSON'));
});

test('buildCheckpoint rejects entries without a valid hash', () => {
  assert.throws(
    () => buildCheckpoint([{ seq: 0, tool: 'x' }]),
    /valid "hash"/
  );
});

test('verifyLedgerFile explains a missing file', (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));

  assert.throws(
    () => verifyLedgerFile(path.join(dir, 'missing.jsonl')),
    /does not exist|ENOENT/
  );
});
