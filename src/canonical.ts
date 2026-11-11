/**
 * Deterministic JSON serialization used for every hash in the ledger.
 *
 * Rules (format v1):
 *  - object keys are sorted lexicographically (UTF-16 code units) at every depth;
 *  - array order is preserved and `undefined` array items become `null`
 *    (the same behaviour as `JSON.stringify`);
 *  - object properties whose value is `undefined`, a function, or a symbol are omitted;
 *  - `NaN`, `Infinity`, `-Infinity` and `BigInt` are rejected with a `TypeError`;
 *  - `Date` instances serialize to their ISO-8601 string;
 *  - circular structures, `Map` and `Set` are rejected rather than silently flattened.
 *
 * The serializer never depends on property insertion order, so two logically equal
 * values always produce byte-identical output on every platform.
 */

/** Guard against pathological or circular inputs that slip past the cycle check. */
export const MAX_CANONICAL_DEPTH = 512;

/** Serialize `value` to canonical JSON. Throws `TypeError` for values JSON cannot represent. */
export function canonicalize(value: unknown): string {
  return serialize(value, [], 0);
}

function serialize(value: unknown, stack: object[], depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new TypeError(`Canonical JSON exceeds the maximum nesting depth of ${MAX_CANONICAL_DEPTH}`);
  }

  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      return serializeNumber(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      throw new TypeError('Canonical JSON cannot represent BigInt values; convert them to strings first');
    case 'undefined':
      throw new TypeError('Canonical JSON cannot represent undefined at the top level');
    case 'function':
      throw new TypeError('Canonical JSON cannot represent functions');
    case 'symbol':
      throw new TypeError('Canonical JSON cannot represent symbols');
    default:
      break;
  }

  const objectValue = value as object;
  if (stack.includes(objectValue)) {
    throw new TypeError('Canonical JSON cannot represent circular structures');
  }

  if (objectValue instanceof Date) {
    const time = objectValue.getTime();
    if (Number.isNaN(time)) throw new TypeError('Canonical JSON cannot represent an invalid Date');
    return JSON.stringify(objectValue.toISOString());
  }

  if (objectValue instanceof Map || objectValue instanceof Set) {
    throw new TypeError('Canonical JSON cannot represent Map or Set values; convert them to plain objects or arrays first');
  }

  const toJSON = (objectValue as { toJSON?: unknown }).toJSON;
  if (typeof toJSON === 'function') {
    stack.push(objectValue);
    try {
      return serialize((toJSON as () => unknown).call(objectValue), stack, depth + 1);
    } finally {
      stack.pop();
    }
  }

  stack.push(objectValue);
  try {
    if (Array.isArray(objectValue)) {
      const parts = objectValue.map((item) => {
        if (item === undefined || typeof item === 'function' || typeof item === 'symbol') return 'null';
        return serialize(item, stack, depth + 1);
      });
      return `[${parts.join(',')}]`;
    }

    const record = objectValue as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((key) => {
        const property = record[key];
        return property !== undefined && typeof property !== 'function' && typeof property !== 'symbol';
      })
      .sort();

    const parts = keys.map((key) => `${JSON.stringify(key)}:${serialize(record[key], stack, depth + 1)}`);
    return `{${parts.join(',')}}`;
  } finally {
    stack.pop();
  }
}

function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError('Canonical JSON cannot represent NaN or Infinity');
  }
  // Normalize negative zero so that -0 and 0 hash identically.
  if (Object.is(value, -0)) return '0';
  return JSON.stringify(value);
}
