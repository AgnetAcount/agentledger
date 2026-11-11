import test from 'node:test';
import assert from 'node:assert/strict';
import { isSecretKey, redact, redactString } from '../dist/index.js';

const OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD';
const OPENAI_PROJECT_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789';
const ANTHROPIC_KEY = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GITHUB_TOKEN = `ghp_${'a1B2c3D4e5F6'.repeat(3)}`;
const GITHUB_PAT = `github_pat_${'11ABCDEFG'.repeat(4)}`;
const SLACK_TOKEN = `xox${'b'}-123456789012-abcdefghijklmnop`;
const GOOGLE_KEY = `AIza${'B'.repeat(35)}`;
const STRIPE_KEY = `sk_live_${'abcdefghijklmnopqrstuvwx'}`;
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
const PEM = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----';
const BEARER = 'Bearer abc123def456ghi789';

test('credential key names are redacted', () => {
  for (const key of [
    'password',
    'passwd',
    'secret',
    'token',
    'api_key',
    'apikey',
    'access_key',
    'private_key',
    'client_secret',
    'refresh_token',
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'proxy-authorization',
    'aws_secret_access_key',
    'secret_key',
    'access_token',
    'auth_token',
    'id_token',
    'session_token',
  ]) {
    const redacted = redact({ [key]: 'sensitive-value' });
    assert.equal(redacted[key], '[REDACTED:SECRET]', `expected ${key} to be redacted`);
  }
});

test('key matching ignores case and separators', () => {
  assert.equal(isSecretKey('API_KEY'), true);
  assert.equal(isSecretKey('Api-Key'), true);
  assert.equal(isSecretKey('CLIENT_SECRET'), true);
  assert.equal(isSecretKey('Set-Cookie'), true);
  assert.equal(redact({ API_KEY: 'x' }).API_KEY, '[REDACTED:SECRET]');
});

test('ordinary property names are not redacted', () => {
  assert.equal(isSecretKey('tokenCount'), false);
  assert.equal(isSecretKey('secretary'), false);
  assert.equal(isSecretKey('author'), false);
  assert.equal(isSecretKey('cookiesEnabled'), false);
  assert.equal(isSecretKey('maxTokens'), false);

  const value = { tokenCount: 42, secretary: 'Ada', author: 'Grace', maxTokens: 100 };
  assert.deepEqual(redact(value), value);
});

test('OpenAI keys are redacted', () => {
  assert.equal(redactString(`key=${OPENAI_KEY}`), 'key=[REDACTED:OPENAI_KEY]');
  assert.equal(redactString(OPENAI_PROJECT_KEY), '[REDACTED:OPENAI_KEY]');
});

test('Anthropic keys are redacted', () => {
  assert.equal(redactString(ANTHROPIC_KEY), '[REDACTED:ANTHROPIC_KEY]');
});

test('AWS access keys are redacted', () => {
  assert.equal(redactString(`AKIA ${AWS_KEY} used`), 'AKIA [REDACTED:AWS_ACCESS_KEY] used');
});

test('GitHub tokens and fine grained PATs are redacted', () => {
  assert.equal(redactString(GITHUB_TOKEN), '[REDACTED:GITHUB_TOKEN]');
  assert.equal(redactString(GITHUB_PAT), '[REDACTED:GITHUB_TOKEN]');
});

test('Slack tokens are redacted', () => {
  assert.equal(redactString(SLACK_TOKEN), '[REDACTED:SLACK_TOKEN]');
});

test('Google API keys are redacted', () => {
  assert.equal(redactString(GOOGLE_KEY), '[REDACTED:GOOGLE_API_KEY]');
});

test('Stripe live keys are redacted', () => {
  assert.equal(redactString(STRIPE_KEY), '[REDACTED:STRIPE_KEY]');
  assert.equal(redactString('rk_live_abcdefghijklmnopqrst'), '[REDACTED:STRIPE_KEY]');
});

test('JWTs are redacted', () => {
  assert.equal(redactString(`Authorization: ${JWT}`), 'Authorization: [REDACTED:JWT]');
});

test('PEM private key blocks are redacted as a whole', () => {
  const redacted = redactString(`before\n${PEM}\nafter`);
  assert.equal(redacted, 'before\n[REDACTED:PRIVATE_KEY]\nafter');
});

test('Bearer credentials are redacted', () => {
  assert.equal(redactString(BEARER), '[REDACTED:BEARER_TOKEN]');
  assert.equal(redactString('bearer 0123456789abcdef0123456789abcdef'), '[REDACTED:BEARER_TOKEN]');
});

test('ordinary identifiers and prose are not redacted', () => {
  const samples = [
    'sk-learn is the scikit-learn compatibility alias',
    'Upgrade to sk-learn-python-tutorial-2024 for the full guide',
    'scikit-learn 1.4.2 and sklearn.linear_model',
    'version 1.2.3-beta.4+sha.abcdef',
    'See https://example.com/docs for details',
    'The tokenizer splits on whitespace',
    'Bearer authentication is required by the API',
    'id 550e8400-e29b-41d4-a716-446655440000',
    'commit 3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a',
    'file-name-with-dashes.ext',
  ];
  for (const sample of samples) {
    assert.equal(redactString(sample), sample, `unexpected redaction of: ${sample}`);
  }
});

test('values nested in arrays and objects are redacted recursively', () => {
  const value = {
    request: { headers: { authorization: 'Bearer abc123def456ghi789' }, url: 'https://example.com' },
    items: [{ key: OPENAI_KEY }, { note: `token ${AWS_KEY}` }],
  };

  const redacted = redact(value);

  assert.equal(redacted.request.headers.authorization, '[REDACTED:SECRET]');
  assert.equal(redacted.request.url, 'https://example.com');
  assert.equal(redacted.items[0].key, '[REDACTED:OPENAI_KEY]');
  assert.equal(redacted.items[1].note, 'token [REDACTED:AWS_ACCESS_KEY]');
});

test('null secret values stay null', () => {
  assert.deepEqual(redact({ password: null, token: null }), { password: null, token: null });
});

test('non-string primitives are preserved', () => {
  const value = { count: 3, enabled: true, ratio: 0.5, nothing: null, password: 1234 };
  const redacted = redact(value);
  assert.equal(redacted.count, 3);
  assert.equal(redacted.enabled, true);
  assert.equal(redacted.ratio, 0.5);
  assert.equal(redacted.nothing, null);
  assert.equal(redacted.password, '[REDACTED:SECRET]');
});

test('redact does not mutate its input', () => {
  const original = { password: 'hunter2', nested: { token: OPENAI_KEY } };
  const snapshot = JSON.parse(JSON.stringify(original));

  redact(original);

  assert.deepEqual(original, snapshot);
});

test('redact is idempotent', () => {
  const once = redact({ password: 'hunter2', note: `key ${OPENAI_KEY}` });
  assert.deepEqual(redact(once), once);
});

test('redact preserves __proto__ as data without polluting prototypes', () => {
  const input = JSON.parse('{"__proto__":{"polluted":true},"safe":1}');
  const output = redact(input);

  assert.equal(Object.getPrototypeOf(output), Object.prototype);
  assert.deepEqual(Object.keys(output).sort(), ['__proto__', 'safe']);
  assert.equal(JSON.stringify(output).includes('polluted'), true);
  assert.equal({}.polluted, undefined);
});

test('redact rejects circular structures', () => {
  const node = { password: 'x' };
  node.self = node;
  assert.throws(() => redact(node), /circular/);
});

test('redact rejects Map values instead of silently dropping them', () => {
  assert.throws(() => redact({ data: new Map([['a', 1]]) }), /Map or Set/);
});

test('redaction markers are stable strings usable in fixtures', () => {
  assert.equal(redactString(OPENAI_KEY), '[REDACTED:OPENAI_KEY]');
  assert.equal(redact({ token: 'x' }).token, '[REDACTED:SECRET]');
});
