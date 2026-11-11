import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  createLedger,
  GENESIS_HASH,
  isHash,
  verifyLedgerFile,
} from '../dist/index.js';
import { makeTempDir, readLines, readText, removeDir } from './helpers.mjs';

test('createLedger creates an empty ledger file with restrictive intent', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');

  const ledger = await createLedger({ path: file });

  assert.equal(path.isAbsolute(ledger.path), true);
  assert.equal(ledger.capture, 'redacted');
  assert.equal(fs.existsSync(file), true);
  assert.equal(fs.statSync(file).size, 0);
});

test('the first record uses the genesis hash as prevHash', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const entry = await ledger.record({ tool: 'http.get' });

  assert.equal(entry.seq, 0);
  assert.equal(entry.prevHash, GENESIS_HASH);
  assert.ok(isHash(entry.hash));
});

test('records form a hash chain', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const first = await ledger.record({ tool: 'a' });
  const second = await ledger.record({ tool: 'b' });
  const third = await ledger.record({ tool: 'c' });

  assert.equal(second.prevHash, first.hash);
  assert.equal(third.prevHash, second.hash);
  assert.deepEqual([first.seq, second.seq, third.seq], [0, 1, 2]);
});

test('entries expose the documented v1 shape', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const entry = await ledger.record({ tool: 'github.createIssue', args: { title: 'x' }, result: { id: 1 } });

  assert.deepEqual(Object.keys(entry).sort(), [
    'args',
    'argsHash',
    'durationMs',
    'error',
    'hash',
    'meta',
    'prevHash',
    'result',
    'resultHash',
    'seq',
    'status',
    'tool',
    'ts',
    'v',
  ]);
  assert.equal(entry.v, 1);
  assert.equal(entry.status, 'ok');
  assert.equal(entry.error, null);
  assert.equal(entry.meta, null);
  assert.match(entry.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.match(entry.argsHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(entry.resultHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal('sig' in entry, false);
});

test('read() returns entries in append order', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });

  for (const tool of ['one', 'two', 'three']) await ledger.record({ tool });

  const entries = await ledger.read();
  assert.deepEqual(entries.map((entry) => entry.tool), ['one', 'two', 'three']);
  assert.deepEqual(entries.map((entry) => entry.seq), [0, 1, 2]);
});

test('capture defaults to redacted and never writes the raw secret', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });

  const secret = 'sk-abcdefghijklmnopqrstuvwxyz0123456789';
  await ledger.record({
    tool: 'http.post',
    args: { url: 'https://example.com', password: 'hunter2', authorization: `Bearer ${secret}` },
  });

  const text = readText(file);
  assert.equal(text.includes(secret), false);
  assert.equal(text.includes('hunter2'), false);
  assert.equal(text.includes('[REDACTED:SECRET]'), true);
  assert.equal(verifyLedgerFile(file).valid, true);
});

test('capture "full" stores payloads verbatim', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file, capture: 'full' });

  const entry = await ledger.record({ tool: 'http.post', args: { password: 'hunter2' } });

  assert.deepEqual(entry.args, { password: 'hunter2' });
  assert.equal(readText(file).includes('hunter2'), true);
  assert.equal(verifyLedgerFile(file).valid, true);
});

test('capture "hash" stores null payloads with commitment hashes', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file, capture: 'hash' });

  const entry = await ledger.record({ tool: 'db.query', args: { sql: 'select 1' }, result: { rows: 1 } });

  assert.equal(entry.args, null);
  assert.equal(entry.result, null);
  assert.ok(isHash(entry.argsHash));
  assert.ok(isHash(entry.resultHash));
  assert.equal(readText(file).includes('select 1'), false);

  const verification = await ledger.verify();
  assert.equal(verification.valid, true);
});

test('record() defaults status to ok and durationMs to 0', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const entry = await ledger.record({ tool: 'noop' });

  assert.equal(entry.status, 'ok');
  assert.equal(entry.durationMs, 0);
  assert.equal(entry.args, null);
  assert.equal(entry.result, null);
  assert.equal(entry.resultHash, null);
});

test('record() stores structured error details', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const entry = await ledger.record({
    tool: 'http.get',
    status: 'error',
    durationMs: 12.34567,
    error: { name: 'TimeoutError', message: 'request timed out' },
  });

  assert.equal(entry.status, 'error');
  assert.deepEqual(entry.error, { name: 'TimeoutError', message: 'request timed out' });
  assert.equal(entry.durationMs, 12.346);
});

test('meta is redacted in redacted mode', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const entry = await ledger.record({
    tool: 'agent.run',
    meta: { runId: 'run-1', apiKey: 'sk-abcdefghijklmnopqrstuvwxyz0123', nested: { refresh_token: 'abc' } },
  });

  assert.equal(entry.meta.runId, 'run-1');
  assert.equal(entry.meta.apiKey, '[REDACTED:SECRET]');
  assert.equal(entry.meta.nested.refresh_token, '[REDACTED:SECRET]');
});

test('now() injection produces deterministic timestamps', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const fixed = new Date('2026-11-11T12:00:00.000Z');
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl'), now: () => fixed });

  const first = await ledger.record({ tool: 'a' });
  const second = await ledger.record({ tool: 'b' });

  assert.equal(first.ts, '2026-11-11T12:00:00.000Z');
  assert.equal(second.ts, first.ts);
});

test('an invalid now() result is rejected', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({
    path: path.join(dir, 'audit.jsonl'),
    now: () => new Date(Number.NaN),
  });

  await assert.rejects(ledger.record({ tool: 'a' }), /now\(\) must return a valid Date/);
});

test('hmacKey signs every entry', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl'), hmacKey: 'test-key' });

  const entry = await ledger.record({ tool: 'signed' });

  assert.match(entry.sig, /^[0-9a-f]{64}$/);
  assert.equal((await ledger.verify()).valid, true);
  assert.equal((await ledger.verify({ hmacKey: 'test-key' })).valid, true);
  assert.equal((await ledger.verify({ hmacKey: 'wrong-key' })).valid, false);
});

test('wrap() returns the resolved value and records an ok entry', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const add = ledger.wrap('math.add', (a, b) => a + b);
  const result = await add(2, 3);

  assert.equal(result, 5);
  const entries = await ledger.read();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].tool, 'math.add');
  assert.equal(entries[0].status, 'ok');
  assert.deepEqual(entries[0].args, [2, 3]);
  assert.equal(entries[0].result, 5);
  assert.equal(typeof entries[0].durationMs, 'number');
});

test('wrap() rethrows the exact original error after recording it', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });
  const boom = new RangeError('tool exploded');

  const failing = ledger.wrap('explode', () => {
    throw boom;
  });

  await assert.rejects(failing(), (error) => error === boom);

  const entries = await ledger.read();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].status, 'error');
  assert.deepEqual(entries[0].error, { name: 'RangeError', message: 'tool exploded' });
});

test('wrap() preserves this binding', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const wrapped = ledger.wrap('object.method', function (increment) {
    return this.base + increment;
  });

  assert.equal(await wrapped.call({ base: 40 }, 2), 42);
});

test('wrap() records rejected promises from async tools', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const failing = ledger.wrap('async.fail', async () => {
    await Promise.resolve();
    throw new Error('async failure');
  });

  await assert.rejects(failing(), /async failure/);
  const entries = await ledger.read();
  assert.equal(entries[0].status, 'error');
});

test('wrap() never fails a successful call when the payload cannot be recorded', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  const circular = {};
  circular.self = circular;
  const cases = [
    ['NaN argument', [Number.NaN]],
    ['BigInt argument', [10n]],
    ['circular argument', [circular]],
  ];

  for (const [name, args] of cases) {
    const wrapped = ledger.wrap('edge.tool', () => 'success');
    assert.equal(await wrapped(...args), 'success', `wrap threw for ${name}`);
  }

  const bigintResult = ledger.wrap('edge.result', () => 10n);
  assert.equal(await bigintResult(), 10n);

  assert.deepEqual(await ledger.read(), [], 'unserializable payloads are skipped, not written');

  await ledger.record({ tool: 'after.skip' });
  assert.deepEqual((await ledger.read()).map((entry) => entry.tool), ['after.skip']);
});

test('concurrent appends are serialized without interleaved or partial lines', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });

  await Promise.all(
    Array.from({ length: 40 }, (_, index) => ledger.record({ tool: `parallel.${index}`, args: { index } }))
  );

  const entries = readLines(file);
  assert.equal(entries.length, 40);
  assert.deepEqual(
    entries.map((entry) => entry.seq),
    Array.from({ length: 40 }, (_, index) => index)
  );
  assert.equal(verifyLedgerFile(file).valid, true);
});

test('reopening a ledger continues the sequence and the chain', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');

  const first = await createLedger({ path: file });
  await first.record({ tool: 'before' });

  const second = await createLedger({ path: file });
  const entry = await second.record({ tool: 'after' });

  assert.equal(entry.seq, 1);
  assert.equal(verifyLedgerFile(file).valid, true);
  assert.deepEqual((await second.read()).map((item) => item.tool), ['before', 'after']);
});

test('a BOM and CRLF line endings are handled', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });
  await ledger.record({ tool: 'windows' });

  const crlf = `\uFEFF${readText(file).replace(/\n/g, '\r\n')}`;
  fs.writeFileSync(file, crlf, 'utf8');

  assert.equal(verifyLedgerFile(file).valid, true);

  const reopened = await createLedger({ path: file });
  await reopened.record({ tool: 'after-crlf' });
  assert.equal(verifyLedgerFile(file).valid, true);
  assert.deepEqual(readLines(file).map((entry) => entry.tool), ['windows', 'after-crlf']);
});

test('a file without a trailing newline is repaired before the next append', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });
  await ledger.record({ tool: 'first' });

  fs.writeFileSync(file, readText(file).slice(0, -1), 'utf8');

  const reopened = await createLedger({ path: file });
  await reopened.record({ tool: 'second' });

  assert.equal(verifyLedgerFile(file).valid, true);
  assert.deepEqual(readLines(file).map((entry) => entry.tool), ['first', 'second']);
});

test('a 256 KiB payload is appended and verified', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });
  const payload = 'x'.repeat(256 * 1024);

  const entry = await ledger.record({ tool: 'big.payload', args: { payload } });

  assert.equal(entry.args.payload.length, 256 * 1024);
  assert.equal(verifyLedgerFile(file).valid, true);
});

test('stats() reports counts, time range and tool usage', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  await ledger.record({ tool: 'a', durationMs: 10 });
  await ledger.record({ tool: 'a', durationMs: 20 });
  await ledger.record({ tool: 'b', status: 'error', durationMs: 30, error: { name: 'E', message: 'm' } });

  const stats = await ledger.stats();

  assert.equal(stats.entries, 3);
  assert.deepEqual(stats.tools, { a: 2, b: 1 });
  assert.equal(stats.ok, 2);
  assert.equal(stats.error, 1);
  assert.equal(stats.avgDurationMs, 20);
  assert.equal(typeof stats.firstTs, 'string');
  assert.equal(typeof stats.lastTs, 'string');
  assert.ok(stats.firstTs <= stats.lastTs);
  assert.ok(isHash(stats.lastHash));
});

test('stats() counts tool names that collide with Object.prototype keys', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  await ledger.record({ tool: '__proto__' });
  await ledger.record({ tool: 'constructor' });
  await ledger.record({ tool: 'constructor' });

  const stats = await ledger.stats();

  assert.equal(Object.prototype.hasOwnProperty.call(stats.tools, '__proto__'), true);
  assert.equal(stats.tools['__proto__'], 1);
  assert.equal(stats.tools.constructor, 2);
  assert.equal({}.polluted, undefined);
});

test('checkpoint() produces a checkpoint that verifies against the ledger', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });
  await ledger.record({ tool: 'a' });
  await ledger.record({ tool: 'b' });

  const checkpoint = await ledger.checkpoint();

  assert.equal(checkpoint.v, 1);
  assert.equal(checkpoint.entries, 2);
  const entries = await ledger.read();
  assert.equal(checkpoint.lastHash, entries[1].hash);
  assert.equal(checkpoint.hmac, undefined);
  assert.equal((await ledger.verify({ checkpoint })).valid, true);
});

test('a signed checkpoint carries an HMAC', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl'), hmacKey: 'cp-key' });
  await ledger.record({ tool: 'a' });

  const checkpoint = await ledger.checkpoint();

  assert.match(checkpoint.hmac, /^[0-9a-f]{64}$/);
  assert.equal((await ledger.verify({ checkpoint })).valid, true);
});

test('checkpoint() refuses a ledger that does not verify', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });
  await ledger.record({ tool: 'original' });

  fs.writeFileSync(file, readText(file).replace('original', 'tampered'), 'utf8');

  await assert.rejects(ledger.checkpoint(), /Refusing to checkpoint/);
});

test('createLedger validates its options', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));

  await assert.rejects(createLedger({ path: '' }), /non-empty "path"/);
  await assert.rejects(createLedger({ path: path.join(dir, 'x.jsonl'), capture: 'bogus' }), /must be one of/);
  await assert.rejects(createLedger({ path: path.join(dir, 'x.jsonl'), hmacKey: '' }), /hmacKey/);
  await assert.rejects(
    createLedger({ path: path.join(dir, 'x.jsonl'), now: 'nope' }),
    /"now" must be a function/
  );
});

test('record() validates its input', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const ledger = await createLedger({ path: path.join(dir, 'audit.jsonl') });

  await assert.rejects(ledger.record({}), /non-empty "tool"/);
  await assert.rejects(ledger.record({ tool: 'x', status: 'maybe' }), /"status"/);
  await assert.rejects(ledger.record({ tool: 'x', durationMs: -1 }), /non-negative/);
  await assert.rejects(ledger.record({ tool: 'x', error: { name: 1 } }), /"error"/);
  await assert.rejects(ledger.record({ tool: 'x', meta: [] }), /"meta"/);
});

test('close() releases the handle and later appends reopen the file', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });

  await ledger.record({ tool: 'before-close' });
  await ledger.close();
  await ledger.close();
  await ledger.record({ tool: 'after-close' });

  assert.equal(verifyLedgerFile(file).valid, true);
  assert.deepEqual(readLines(file).map((entry) => entry.tool), ['before-close', 'after-close']);
});

test('the ledger file is never truncated by an append', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = path.join(dir, 'audit.jsonl');
  const ledger = await createLedger({ path: file });

  await ledger.record({ tool: 'one' });
  const sizeAfterFirst = fs.statSync(file).size;
  await ledger.record({ tool: 'two' });

  assert.ok(fs.statSync(file).size > sizeAfterFirst);
  assert.equal(readLines(file).length, 2);
});
