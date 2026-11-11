import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  computeEntryHash,
  GENESIS_HASH,
  hashValue,
  isHash,
  sha256Hex,
} from '../dist/index.js';

test('canonical JSON sorts object keys recursively', () => {
  const value = { b: 1, a: { d: 4, c: [3, { f: 6, e: 5 }] } };
  assert.equal(canonicalize(value), '{"a":{"c":[3,{"e":5,"f":6}],"d":4},"b":1}');
});

test('canonical JSON preserves array order', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
});

test('canonical JSON omits undefined object properties', () => {
  assert.equal(canonicalize({ a: 1, b: undefined, c: null }), '{"a":1,"c":null}');
});

test('canonical JSON turns undefined array items into null', () => {
  assert.equal(canonicalize([1, undefined, 3]), '[1,null,3]');
});

test('canonical JSON rejects NaN and Infinity', () => {
  assert.throws(() => canonicalize({ value: Number.NaN }), /NaN or Infinity/);
  assert.throws(() => canonicalize({ value: Number.POSITIVE_INFINITY }), /NaN or Infinity/);
  assert.throws(() => canonicalize(Number.NEGATIVE_INFINITY), /NaN or Infinity/);
});

test('canonical JSON rejects BigInt values', () => {
  assert.throws(() => canonicalize({ big: 10n }), /BigInt/);
});

test('canonical JSON rejects circular structures', () => {
  const node = { name: 'root' };
  node.self = node;
  assert.throws(() => canonicalize(node), /circular/);
});

test('canonical JSON rejects Map and Set instead of flattening silently', () => {
  assert.throws(() => canonicalize(new Map([['a', 1]])), /Map or Set/);
  assert.throws(() => canonicalize(new Set([1])), /Map or Set/);
});

test('canonical JSON rejects undefined at the top level', () => {
  assert.throws(() => canonicalize(undefined), /undefined/);
});

test('canonical JSON serializes Date as an ISO string', () => {
  const date = new Date('2026-11-11T12:00:00.000Z');
  assert.equal(canonicalize({ at: date }), '{"at":"2026-11-11T12:00:00.000Z"}');
});

test('canonical JSON normalizes negative zero', () => {
  assert.equal(canonicalize({ zero: -0 }), '{"zero":0}');
});

test('canonical JSON is independent of key insertion order', () => {
  const first = { z: 1, a: { y: 2, b: 3 }, m: [1, 2] };
  const second = { m: [1, 2], a: { b: 3, y: 2 }, z: 1 };
  assert.equal(canonicalize(first), canonicalize(second));
});

test('canonical JSON encodes unicode deterministically', () => {
  const value = { text: 'a"b\\c\n\u0001 ölçü 😀' };
  assert.equal(canonicalize(value), JSON.stringify({ text: value.text }));
  assert.equal(canonicalize(value), canonicalize({ text: value.text }));
});

test('sha256Hex matches the published empty-string vector', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('sha256Hex hashes strings and buffers identically', () => {
  assert.equal(sha256Hex('agentledger'), sha256Hex(Buffer.from('agentledger', 'utf8')));
});

test('GENESIS_HASH equals sha256("AGENTLEDGER:GENESIS:v1")', () => {
  assert.equal(GENESIS_HASH, `sha256:${sha256Hex('AGENTLEDGER:GENESIS:v1')}`);
  assert.equal(GENESIS_HASH, 'sha256:13cc4b38302419f5a628005a8715eec34d1775637105d76c53a3aac51d072746');
  assert.ok(isHash(GENESIS_HASH));
});

test('hashValue produces prefixed hashes over canonical JSON', () => {
  assert.equal(hashValue(null), `sha256:${sha256Hex('null')}`);
  assert.equal(hashValue({ b: 1, a: 2 }), `sha256:${sha256Hex('{"a":2,"b":1}')}`);
  assert.ok(isHash(hashValue({ a: 1 })));
  assert.equal(isHash('sha256:xyz'), false);
});

test('computeEntryHash ignores hash and sig fields', () => {
  const entry = { v: 1, tool: 'demo', hash: GENESIS_HASH, sig: 'deadbeef' };
  assert.equal(computeEntryHash(entry), hashValue({ v: 1, tool: 'demo' }));
});

test('computeEntryHash covers a top-level __proto__ own property', () => {
  const entry = JSON.parse('{"v":1,"tool":"demo","__proto__":{"injected":true}}');
  assert.equal(computeEntryHash(entry), hashValue(entry));
});
