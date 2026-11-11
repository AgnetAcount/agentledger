/**
 * Secret redaction.
 *
 * Redaction runs before hashing and before writing, so the on-disk ledger never
 * contains the raw credential. Two independent mechanisms are used:
 *
 *  1. Key based — a value is replaced entirely when its property name is a known
 *     credential name (`password`, `authorization`, `api_key`, ...).
 *  2. Content based — well-known token formats are replaced inside string values,
 *     including strings nested in arrays and objects.
 *
 * Both are deliberately conservative: matching is anchored to token prefixes and
 * minimum lengths so ordinary prose, version strings, UUIDs and identifiers such as
 * `sk-learn` are left untouched.
 */

const REDACTION_TOKEN = '[REDACTED:';

/** Key names (normalized: lowercase, non-alphanumerics stripped) that hold credentials. */
const SECRET_KEY_NAMES: ReadonlySet<string> = new Set([
  'authorization',
  'cookie',
  'setcookie',
  'password',
  'passwd',
  'secret',
  'token',
  'apikey',
  'xapikey',
  'accesskey',
  'awssecretaccesskey',
  'secretkey',
  'privatekey',
  'clientsecret',
  'refreshtoken',
  'accesstoken',
  'authtoken',
  'idtoken',
  'sessiontoken',
  'proxyauthorization',
]);

interface StringRule {
  kind: string;
  pattern: RegExp;
  /** Optional extra check on the matched token; returning false leaves the text untouched. */
  accept?: (token: string) => boolean;
}

/**
 * Content rules, applied in order. Earlier rules win, so prefixed families
 * (`sk-ant-`, `sk-proj-`) must be listed before their shorter siblings.
 */
const STRING_RULES: readonly StringRule[] = [
  {
    kind: 'PRIVATE_KEY',
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)/g,
  },
  {
    kind: 'JWT',
    pattern: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  },
  {
    kind: 'BEARER_TOKEN',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
    // Reject prose such as "Bearer authentication": a credential almost always
    // contains a digit or a symbol, plain English words do not.
    accept: (token) => /[0-9._~+/=-]/.test(token),
  },
  {
    kind: 'ANTHROPIC_KEY',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    kind: 'OPENAI_KEY',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    // Plain `sk-` keys are unhyphenated base62; hyphenated slugs such as
    // "sk-learn-python-tutorial-2024" are prose, not credentials. Known
    // hyphenated key families are still accepted.
    accept: (token) => /^sk-(?:proj|svcacct|admin)-/.test(token) || !token.slice(3).includes('-'),
  },
  {
    kind: 'GITHUB_TOKEN',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  },
  {
    kind: 'GITHUB_TOKEN',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    kind: 'AWS_ACCESS_KEY',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    kind: 'SLACK_TOKEN',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    kind: 'GOOGLE_API_KEY',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    kind: 'STRIPE_KEY',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{10,}\b/g,
  },
];

function redactionMarker(kind: string): string {
  return `${REDACTION_TOKEN}${kind}]`;
}

/** Normalize a property name for credential matching. */
function normalizeKeyName(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** True when a property name denotes a credential. */
export function isSecretKey(key: string): boolean {
  return SECRET_KEY_NAMES.has(normalizeKeyName(key));
}

/** Redact well-known credential formats inside a single string. */
export function redactString(value: string): string {
  let result = value;
  for (const rule of STRING_RULES) {
    result = result.replace(rule.pattern, (match) => {
      if (rule.accept && !rule.accept(match)) return match;
      return redactionMarker(rule.kind);
    });
  }
  return result;
}

/**
 * Recursively redact a JSON-compatible value and return a new value.
 *
 * `null` values are left as they are (there is nothing to leak), non-string
 * primitives are copied unchanged, and circular structures throw `TypeError`
 * instead of looping forever.
 */
export function redact(value: unknown): unknown {
  return walk(value, []);
}

function walk(value: unknown, stack: object[]): unknown {
  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;

  if (value instanceof Date) return value;

  const objectValue = value as object;
  if (stack.includes(objectValue)) {
    throw new TypeError('redact() cannot process circular structures');
  }

  stack.push(objectValue);
  try {
    if (Array.isArray(objectValue)) {
      return objectValue.map((item) => walk(item, stack));
    }

    if (objectValue instanceof Map || objectValue instanceof Set) {
      throw new TypeError('redact() cannot process Map or Set values; convert them to plain objects or arrays first');
    }

    const source = objectValue as Record<string, unknown>;
    const target: Record<string, unknown> = {};
    // defineProperty instead of assignment keeps keys such as "__proto__" as
    // ordinary own properties; assigning them would mutate the prototype and
    // silently drop the value from the audit record.
    const setKey = (key: string, value: unknown): void => {
      Object.defineProperty(target, key, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    };
    for (const key of Object.keys(source)) {
      const property = source[key];
      if (property === undefined) continue;
      if (property !== null && isSecretKey(key)) {
        setKey(key, redactionMarker('SECRET'));
        continue;
      }
      setKey(key, walk(property, stack));
    }
    return target;
  } finally {
    stack.pop();
  }
}
