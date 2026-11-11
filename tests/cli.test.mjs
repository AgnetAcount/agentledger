import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createLedger,
  makeTempDir,
  readLines,
  readText,
  removeDir,
  seedLedger,
} from './helpers.mjs';

const projectRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const binPath = path.join(projectRoot, 'bin', 'agentledger.js');
const KEY_ENV = 'AGENTLEDGER_CLI_TEST_KEY';
const KEY_VALUE = 'cli-test-hmac-key';

function runCli(args, options = {}) {
  const result = spawnSync(process.execPath, [binPath, ...args], {
    encoding: 'utf8',
    cwd: options.cwd ?? projectRoot,
    env: { ...process.env, ...(options.env ?? {}) },
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function truncate(file, keep) {
  const lines = readText(file)
    .split('\n')
    .filter((line) => line.trim() !== '');
  fs.writeFileSync(file, `${lines.slice(0, keep).join('\n')}\n`, 'utf8');
}

test('--help exits 0 and documents every command', () => {
  const result = runCli(['--help']);

  assert.equal(result.status, 0);
  for (const command of ['verify', 'tail', 'stats', 'checkpoint', 'export']) {
    assert.match(result.stdout, new RegExp(`\\b${command}\\b`));
  }
  assert.match(result.stdout, /--key-env/);
  assert.match(result.stdout, /EXIT CODES/);
});

test('--version prints the package version', () => {
  const result = runCli(['--version']);

  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'agentledger 0.1.0');
});

test('running without arguments prints help and exits 0', () => {
  const result = runCli([]);

  assert.equal(result.status, 0);
  assert.match(result.stdout, /USAGE/);
});

test('verify reports a valid ledger and exits 0', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = runCli(['verify', file]);

  assert.equal(result.status, 0);
  assert.match(result.stdout, /Status:\s+VALID/);
  assert.match(result.stdout, /Entries:\s+3/);
});

test('verify exits 1 and names the failing code for a tampered ledger', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const entries = readLines(file);
  entries[1].tool = 'tampered';
  fs.writeFileSync(file, `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`, 'utf8');

  const result = runCli(['verify', file]);

  assert.equal(result.status, 1);
  assert.match(result.stdout, /Status:\s+INVALID/);
  assert.match(result.stdout, /BAD_HASH/);
});

test('verify exits 2 for a missing file', () => {
  const result = runCli(['verify', 'this-file-does-not-exist.jsonl']);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /does not exist|ENOENT/);
});

test('verify exits 2 for an unknown option', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 1);

  const result = runCli(['verify', file, '--bogus']);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option/);
});

test('verify --json emits machine-readable output only', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = runCli(['verify', file, '--json']);
  const payload = JSON.parse(result.stdout);

  assert.equal(result.status, 0);
  assert.equal(payload.valid, true);
  assert.equal(payload.entries, 3);
  assert.equal(payload.signature, 'none');
  assert.deepEqual(payload.errors, []);
  assert.equal(path.isAbsolute(payload.file), true);
});

test('verify --json reports tamper details', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const entries = readLines(file);
  entries[0].args = { index: 42 };
  fs.writeFileSync(file, `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`, 'utf8');

  const result = runCli(['verify', file, '--json']);
  const payload = JSON.parse(result.stdout);

  assert.equal(result.status, 1);
  assert.equal(payload.valid, false);
  assert.ok(payload.errors.some((error) => error.code === 'BAD_HASH'));
});

test('tail --n 2 --json returns the last two records', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 5);

  const result = runCli(['tail', file, '--n', '2', '--json']);
  const entries = JSON.parse(result.stdout);

  assert.equal(result.status, 0);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map((entry) => entry.seq), [3, 4]);
});

test('tail prints a human summary by default', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const result = runCli(['tail', file]);

  assert.equal(result.status, 0);
  assert.match(result.stdout, /#0 .*tool\.0/);
  assert.match(result.stdout, /#1 .*tool\.1/);
});

test('tail rejects a non-positive --n', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const result = runCli(['tail', file, '--n', '0']);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /positive integer/);
});

test('stats --json reports aggregate numbers', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = runCli(['stats', file, '--json']);
  const stats = JSON.parse(result.stdout);

  assert.equal(result.status, 0);
  assert.equal(stats.entries, 3);
  assert.equal(stats.ok, 3);
  assert.equal(stats.error, 0);
  assert.deepEqual(stats.tools, { 'tool.0': 1, 'tool.1': 1, 'tool.2': 1 });
});

test('stats human output includes the tool breakdown', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const result = runCli(['stats', file]);

  assert.equal(result.status, 0);
  assert.match(result.stdout, /Tools:/);
  assert.match(result.stdout, /tool\.1 {2}1/);
});

test('checkpoint writes a checkpoint and verify accepts it', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);
  const checkpointFile = path.join(dir, 'checkpoint.json');

  const written = runCli(['checkpoint', file, '--out', checkpointFile]);
  assert.equal(written.status, 0);

  const checkpoint = JSON.parse(readText(checkpointFile));
  assert.equal(checkpoint.v, 1);
  assert.equal(checkpoint.entries, 3);
  assert.match(checkpoint.lastHash, /^sha256:[0-9a-f]{64}$/);

  const verified = runCli(['verify', file, '--checkpoint', checkpointFile]);
  assert.equal(verified.status, 0);
  assert.match(verified.stdout, /VALID/);
});

test('verify with a checkpoint detects a truncated tail (exit 1)', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 4);
  const checkpointFile = path.join(dir, 'checkpoint.json');

  assert.equal(runCli(['checkpoint', file, '--out', checkpointFile]).status, 0);

  truncate(file, 2);

  const result = runCli(['verify', file, '--checkpoint', checkpointFile]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /TRUNCATED/);
});

test('checkpoint refuses a tampered ledger and exits 1', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const entries = readLines(file);
  entries[0].tool = 'tampered';
  fs.writeFileSync(file, `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`, 'utf8');

  const result = runCli(['checkpoint', file]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Refusing to checkpoint/);
  assert.match(result.stderr, /BAD_HASH/);
});

test('checkpoint --key-env signs the checkpoint and verify accepts it', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2, { hmacKey: KEY_VALUE });
  const checkpointFile = path.join(dir, 'checkpoint.json');

  const written = runCli(['checkpoint', file, '--out', checkpointFile, '--key-env', KEY_ENV], {
    env: { [KEY_ENV]: KEY_VALUE },
  });
  assert.equal(written.status, 0);

  const checkpoint = JSON.parse(readText(checkpointFile));
  assert.match(checkpoint.hmac, /^[0-9a-f]{64}$/);

  const verified = runCli(['verify', file, '--checkpoint', checkpointFile, '--key-env', KEY_ENV], {
    env: { [KEY_ENV]: KEY_VALUE },
  });
  assert.equal(verified.status, 0);
  assert.match(verified.stdout, /HMAC-SHA256 verified/);
});

test('verify --key-env with the wrong key exits 1', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2, { hmacKey: KEY_VALUE });

  const result = runCli(['verify', file, '--key-env', KEY_ENV, '--json'], {
    env: { [KEY_ENV]: 'wrong-key' },
  });
  const payload = JSON.parse(result.stdout);

  assert.equal(result.status, 1);
  assert.equal(payload.signature, 'hmac-sha256');
  assert.ok(payload.errors.every((error) => error.code === 'BAD_SIGNATURE'));
});

test('verify --key-env with an unset variable exits 2 and never echoes a key', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 1);

  const result = runCli(['verify', file, '--key-env', 'AGENTLEDGER_DEFINITELY_UNSET'], {
    env: { AGENTLEDGER_DEFINITELY_UNSET: '' },
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /not set or is empty/);
});

test('export --format csv emits a header and one row per record', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 3);

  const result = runCli(['export', file, '--format', 'csv']);
  const rows = result.stdout.trim().split(/\r?\n/);

  assert.equal(result.status, 0);
  assert.equal(rows.length, 4);
  assert.match(rows[0], /^seq,ts,tool,status,durationMs,args,result,error,prevHash,hash,sig$/);
  assert.match(rows[1], /^0,/);
});

test('export --format json emits the parsed entries', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);

  const result = runCli(['export', file, '--format', 'json']);
  const entries = JSON.parse(result.stdout);

  assert.equal(result.status, 0);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].tool, 'tool.0');
});

test('export rejects an unsupported format with exit 2', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 1);

  assert.equal(runCli(['export', file]).status, 2);
  assert.equal(runCli(['export', file, '--format', 'xml']).status, 2);
});

test('export --out writes the file and reports the path', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 2);
  const out = path.join(dir, 'export.csv');

  const result = runCli(['export', file, '--format', 'csv', '--out', out]);

  assert.equal(result.status, 0);
  assert.equal(fs.existsSync(out), true);
  assert.match(readText(out), /^seq,ts,tool/);
});

test('verify rejects extra positional arguments with exit 2', async (t) => {
  const dir = makeTempDir();
  t.after(() => removeDir(dir));
  const file = await seedLedger(createLedger, dir, 1);

  const result = runCli(['verify', file, 'extra.jsonl']);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unexpected argument/);
});

test('an unknown command exits 2', () => {
  const result = runCli(['frobnicate']);

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown command/);
});
