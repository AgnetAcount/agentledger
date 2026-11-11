import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import { createLedger, verifyLedgerFile } from '../dist/index.js';
import { makeTempDir, removeDir } from './helpers.mjs';

const APPEND_RECORDS = 1000;
const VERIFY_SAMPLES = 5;

test('append throughput stays above the smoke budget', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'append-perf.jsonl');
  const ledger = await createLedger({ path: file });

  const startedAt = performance.now();
  for (let index = 0; index < APPEND_RECORDS; index += 1) {
    await ledger.record({
      tool: 'perf.append',
      args: { index, payload: 'x'.repeat(32) },
      result: { accepted: true },
    });
  }
  const elapsedSeconds = (performance.now() - startedAt) / 1000;
  const recordsPerSecond = Math.round(APPEND_RECORDS / elapsedSeconds);

  console.log(
    `[perf] append: ${APPEND_RECORDS} records in ${elapsedSeconds.toFixed(3)}s -> ${recordsPerSecond} records/s`
  );

  assert.equal(verifyLedgerFile(file).entries, APPEND_RECORDS);
  assert.ok(
    recordsPerSecond > 500,
    `append throughput ${recordsPerSecond} records/s is below the 500 records/s smoke budget`
  );
});

test('verification throughput stays above the smoke budget', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'verify-perf.jsonl');
  const ledger = await createLedger({ path: file });

  for (let index = 0; index < APPEND_RECORDS; index += 1) {
    await ledger.record({ tool: 'perf.verify', args: { index } });
  }

  // Warm the OS file cache so the measurement reflects hashing, not disk spin-up.
  assert.equal(verifyLedgerFile(file).valid, true);

  const startedAt = performance.now();
  for (let sample = 0; sample < VERIFY_SAMPLES; sample += 1) {
    const result = verifyLedgerFile(file);
    assert.equal(result.valid, true);
    assert.equal(result.entries, APPEND_RECORDS);
  }
  const elapsedSeconds = (performance.now() - startedAt) / 1000;
  const entriesPerSecond = Math.round((APPEND_RECORDS * VERIFY_SAMPLES) / elapsedSeconds);

  console.log(
    `[perf] verify: ${APPEND_RECORDS * VERIFY_SAMPLES} entries in ${elapsedSeconds.toFixed(3)}s -> ${entriesPerSecond} entries/s`
  );

  assert.ok(
    entriesPerSecond > 5000,
    `verify throughput ${entriesPerSecond} entries/s is below the 5000 entries/s smoke budget`
  );
});
