# agentledger

[![CI](https://github.com/AgnetAcount/agentledger/actions/workflows/ci.yml/badge.svg)](https://github.com/AgnetAcount/agentledger/actions)
[![Version: 0.1.0](https://img.shields.io/badge/version-0.1.0-blue.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node: >=18.0.0](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)
[![Author: Agnet Software Corp.](https://img.shields.io/badge/org-Agnet%20Software%20Corp.-orange)](https://github.com/AgnetAcount)

> **Tamper-evident, zero-dependency audit trail and replay log for AI agent tool calls.**

`agentledger` writes one hash-chained JSON line per tool call, redacts credentials before
anything touches disk, and verifies the whole history offline in milliseconds — no server,
no database, no dependencies.

```bash
npx agentledger verify audit.jsonl
```

---

## Why

Autonomous agents move money, open pull requests, send email, and touch production. Most teams
"trust the logs": JSON files are mutable, timestamps can be rewritten, records can be deleted,
and secrets are routinely written in plaintext. When an incident happens there is no proof of
what the agent executed, in which order, or whether the record was altered afterwards.

`agentledger` closes that gap with the smallest possible primitive: an append-only file where
every record commits to the hash of the record before it. Anyone can verify it offline.
If it was edited, reordered, duplicated, or truncated, verification fails and says where.

- **Hash chain** — SHA-256 over canonical JSON, genesis-anchored, per-record `prevHash`.
- **Checkpoints** — commit to an entry count and the last hash to detect a truncated tail.
- **HMAC signing** — optional per-entry signatures and signed checkpoints.
- **Automatic redaction** — credential-shaped keys and tokens are replaced before hashing.
- **Capture modes** — `redacted` (default), `full` (opt-in, unsafe), `hash` (payload-free).
- **Offline CLI** — `verify`, `tail`, `stats`, `checkpoint`, `export` in one zero-dependency binary.
- **`wrap()` adapter** — instrument any tool function without changing its signature or errors.

---

## 30-second quickstart

### CLI

```bash
# Verify an existing ledger: exit 0 = intact, exit 1 = tampered, exit 2 = usage/IO error
npx agentledger verify audit.jsonl

# Inspect it
npx agentledger stats audit.jsonl
npx agentledger tail audit.jsonl --n 5

# Commit to its current state, then later prove the tail was not removed
npx agentledger checkpoint audit.jsonl --out audit.checkpoint.json
npx agentledger verify audit.jsonl --checkpoint audit.checkpoint.json

# Machine-readable output and exports
npx agentledger verify audit.jsonl --json
npx agentledger export audit.jsonl --format csv --out audit.csv
```

### API

```ts
import { createLedger } from 'agentledger';

const ledger = await createLedger({
  path: 'audit.jsonl',
  hmacKey: process.env.AGENTLEDGER_KEY, // optional, but see the threat model
  capture: 'redacted',                  // 'redacted' | 'full' | 'hash'
});

// Record a call manually
await ledger.record({
  tool: 'http.get',
  args: { url: 'https://example.com', authorization: 'Bearer ...' },
  result: { status: 200 },
  durationMs: 12,
});

// Or wrap the real function: return value, `this` binding and thrown error are preserved
const search = ledger.wrap('web.search', async (query: string) => tools.search(query));
const hits = await search('agent audit trails');

const report = await ledger.verify();
if (!report.valid) console.error(report.errors);
```

---

## Tamper demo

Every field below is a real command run against a 3-record ledger.

```console
$ node bin/agentledger.js verify audit.jsonl
File:    audit.jsonl
Status:  VALID
Entries: 3
Signing: not checked (no --key-env supplied)
```

Change one field in the file (`stripe.createCharge` → `stripe.refundAll`), then verify again:

```console
$ node bin/agentledger.js verify audit.jsonl
File:    audit.jsonl
Status:  INVALID
Entries: 3
Signing: not checked (no --key-env supplied)
Errors:  1
  - seq 1 [BAD_HASH] Record 1 hash does not match its contents (expected sha256:da50ba55..., found sha256:3ba8e6fe...)
```

A checkpoint was written while the ledger was healthy, then the last record was deleted:

```console
$ node bin/agentledger.js verify audit.jsonl --checkpoint checkpoint.json
File:    audit.jsonl
Status:  INVALID
Entries: 2
Signing: not checked (no --key-env supplied)
Errors:  1
  - seq - [TRUNCATED] Checkpoint covers 3 entries but the ledger only contains 2: the tail was truncated
```

Exit codes: `0` valid, `1` tampered/invalid, `2` usage or I/O failure.

---

## Entry schema (format v1)

Each line of the `.jsonl` file is one object:

```json
{
  "v": 1,
  "seq": 0,
  "ts": "2026-11-11T12:00:00.000Z",
  "tool": "github.createIssue",
  "status": "ok",
  "durationMs": 12.4,
  "args": { "repo": "agnet/agentledger", "password": "[REDACTED:SECRET]" },
  "argsHash": "sha256:510c663a...",
  "result": { "id": 42 },
  "resultHash": "sha256:17b4db06...",
  "error": null,
  "meta": { "runId": "run-42" },
  "prevHash": "sha256:13cc4b38...",
  "hash": "sha256:42955534...",
  "sig": "9f2c..."
}
```

| Field | Meaning |
| --- | --- |
| `v` | Format version. Only `1` is accepted. |
| `seq` | Zero-based position in the ledger. Must equal the record index. |
| `ts` | ISO-8601 timestamp from the injectable clock. |
| `tool` | Tool identifier the agent called. |
| `status` | `"ok"` or `"error"`. |
| `durationMs` | Wall-clock duration, rounded to microseconds. |
| `args` / `result` | Captured payloads, or `null` (see capture modes). |
| `argsHash` / `resultHash` | `sha256:` + SHA-256 of the canonical stored payload. |
| `error` | `{ name, message }` for failed calls, otherwise `null`. |
| `meta` | Free-form object (redacted unless `capture: "full"`). |
| `prevHash` | Hash of the previous record; the genesis hash for `seq 0`. |
| `hash` | `sha256(UTF8(canonicalJSON(entry without "hash" and "sig")))`. |
| `sig` | `HMAC-SHA256(key, hash)` in hex; present only when a key is configured. |

### Canonical JSON

Hashes are computed over a canonical serialization so that every platform and every
JSON parser agree:

- object keys sorted lexicographically at every depth; arrays keep their order;
- properties whose value is `undefined`, a function, or a symbol are omitted;
- `undefined` array items become `null` (same as `JSON.stringify`);
- `NaN`, `Infinity`, `-Infinity` and `BigInt` are rejected instead of silently changed;
- `Date` values serialize to ISO-8601 strings; `Map`/`Set`/circular structures are rejected.

### Genesis

`prevHash` of record `0` is the SHA-256 of the fixed genesis string:

```
sha256("AGENTLEDGER:GENESIS:v1")
  = 13cc4b38302419f5a628005a8715eec34d1775637105d76c53a3aac51d072746
```

so the first record's `prevHash` is
`sha256:13cc4b38302419f5a628005a8715eec34d1775637105d76c53a3aac51d072746`.
It is computed at module load from the string, never hard-coded separately.

### Why `sig` is excluded from `hash`

`hash` is computed over the entry **without `hash` and `sig`**, because `sig` is derived
from `hash`; including it would be circular. Tampering with `sig` therefore always fails
signature verification, which is the property we want. Everything else — including
`prevHash`, `argsHash` and `resultHash` — is covered by `hash`.

---

## Capture modes

| Mode | Stored `args` / `result` | On-disk risk | Use when |
| --- | --- | --- | --- |
| `redacted` (default) | Redacted copy | Low: known credential shapes replaced | Normal production use |
| `full` | Verbatim | **High: secrets are written to disk** | Isolated debugging with disposable data |
| `hash` | `null`, `argsHash`/`resultHash` retained | Lowest: no payload at all | Regulated data you must not persist |

`meta` and `error.message` are redacted in `redacted` and `hash` modes. In `hash` mode the
payload hashes are commitments: verification cannot recompute them from the entry, but any
change to them still breaks the entry hash (and the HMAC signature when configured).

---

## Redaction

Redaction runs **before hashing and before writing**, so the raw value never reaches disk
and cannot be recovered from the file.

- **Credential keys** (case-insensitive, separators ignored): `authorization`,
  `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `password`, `passwd`, `secret`,
  `secret_key`, `token`, `api_key`, `apikey`, `access_key`, `aws_secret_access_key`,
  `private_key`, `client_secret`, `refresh_token`, `access_token`, `auth_token`, `id_token`,
  `session_token`. The whole value becomes `[REDACTED:SECRET]`.
- **Credential shapes inside strings**: OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-`),
  AWS (`AKIA`/`ASIA` + 16), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `github_pat_`),
  Slack (`xox[baprs]-`), Google (`AIza` + 35), Stripe (`sk_live_`, `rk_live_`), JWTs,
  PEM `PRIVATE KEY` blocks, and `Bearer <token>` (scheme matched case-insensitively).

The matchers are conservative. Prose, version strings, UUIDs, commit hashes and
identifiers such as `sk-learn`, `sk-learn-python-tutorial-2024`, or `scikit-learn` are
**not** redacted. A `Bearer` value is
only redacted when it contains a digit or symbol, so the sentence "Bearer authentication is
required" survives untouched. Tests cover both true positives and false positives.

---

## CLI reference

```
agentledger verify <file> [--json] [--checkpoint <file>] [--key-env <ENV_NAME>]
agentledger tail <file> [--n <count>] [--json]
agentledger stats <file> [--json]
agentledger checkpoint <file> [--out <file>] [--key-env <ENV_NAME>]
agentledger export <file> --format json|csv [--out <file>]
agentledger --help
agentledger --version
```

| Command | Behaviour |
| --- | --- |
| `verify` | Validates JSON, schema, sequence, chain, payload hashes, signatures and an optional checkpoint. Prints a report and exits `0`/`1`/`2`. |
| `tail` | Prints the last `--n` records (default 10); `--json` emits an array. |
| `stats` | Entry count, time range, ok/error counts, average latency, per-tool counts. |
| `checkpoint` | Verifies the ledger first, then writes a checkpoint (signed when `--key-env` is set). Refuses to bless an invalid ledger. |
| `export` | JSON array or RFC 4180 CSV to stdout or `--out`. |

`--key-env` reads the HMAC key from the named environment variable and never prints it.
There is no network access and no telemetry.

---

## Programmatic API

```ts
import {
  createLedger,        // (options) => Promise<Ledger>
  verifyLedger,        // (rawText | lines | entries, options) => VerifyResult (synchronous, pure)
  verifyLedgerFile,    // (path, options) => VerifyResult
  canonicalize,        // (value) => canonical JSON string
  sha256Hex,           // (text | Buffer) => 64 hex chars
  redact,              // (value) => redacted deep copy
  buildCheckpoint,     // (entries, options) => Checkpoint
  computeStats,        // (entries) => LedgerStats
  GENESIS_HASH,        // "sha256:13cc..."
} from 'agentledger';
```

`Ledger` exposes `record()`, `wrap()`, `read()`, `verify(options?)`, `stats()`,
`checkpoint()` and `close()`. `close()` releases the append descriptor, which matters on
platforms that lock open files (call it before rotating or renaming a ledger).

`createLedger` options: `path`, `hmacKey` (string or `Buffer`), `capture`, and `now`
(injectable clock for deterministic tests).

`wrap()` never turns a successful tool call into a failure: if a payload cannot be
serialized (BigInt, `NaN`, a circular object) or the record cannot be written, that audit
record is skipped and the tool's return value is still returned. Failures of the wrapped
function always rethrow the original error object.

`VerifyResult` is `{ valid, entries, errors: [{ seq, code, message }] }` with the codes
`INVALID_JSON`, `MISSING_FIELD`, `UNSUPPORTED_VERSION`, `BAD_HASH`, `CHAIN_MISMATCH`,
`SEQ_GAP`, `OUT_OF_ORDER`, `TRUNCATED`, `BAD_SIGNATURE`, `BAD_CHECKPOINT`.

`LedgerStats` is `{ entries, firstTs, lastTs, tools, ok, error, avgDurationMs, lastHash }`.
`Checkpoint` is `{ v: 1, entries, lastHash, createdAt, hmac? }`.

---

## Performance

Measured on the development machine — 12th Gen Intel Core i5-1235U, Windows 11,
Node.js v26.1.0 — with realistic records (tool, arguments, result, meta, ~860 bytes per
line). Two consecutive runs differed by up to ~35% on the minimal-record append case; the
realistic rows stayed within ~6%. The numbers below are the second run.

| Records | File size | Append (records/s) | Verify (entries/s) |
| ---: | ---: | ---: | ---: |
| 1,000 | 836 KiB | 17,055 | 29,574 |
| 10,000 | 8.2 MiB | 22,554 | 45,245 |
| 50,000 | 41.4 MiB | 23,503 | 47,088 |
| 10,000 (minimal records, ~417 B) | 4.0 MiB | 60,113 | — |

`node bin/agentledger.js verify` on a 50,000-entry ledger completed in ~1.2 s wall clock,
including Node startup (1.23 s on the second run). The npm test suite includes an append and
verification throughput smoke test with conservative CI budgets (500 records/s, 5,000
entries/s) so slow runners do not produce false alarms. The product targets (≥2,000
append/s, ≥20,000 verify/s) are met with headroom.

Appends are serialized through a promise queue and written with a single `O_APPEND` write
on a long-lived descriptor. That is materially faster than opening and closing a handle per
record and guarantees the line reaches the OS before `record()` resolves. The library does
**not** call `fsync`; durability against power loss is delegated to the OS or an explicit
`close()`/checkpoint workflow.

---

## Security and threat model

### What the ledger detects

- a changed field in any record (`BAD_HASH`, plus `BAD_SIGNATURE` when signed);
- an edited `args` or `result` (`argsHash` / `resultHash`);
- a deleted middle record (`SEQ_GAP` + `CHAIN_MISMATCH`);
- reordered records (`SEQ_GAP` and `OUT_OF_ORDER`);
- a duplicated or rewound sequence number (`OUT_OF_ORDER`);
- a truncated tail **when a checkpoint is available** (`TRUNCATED`);
- a wrong HMAC key or a stripped signature (`BAD_SIGNATURE`);
- an invalid JSON line, unsupported version, or missing field.

### What it cannot detect

- **A local attacker who can rewrite the entire file (and all checkpoints) can forge a
  consistent ledger.** The hash chain proves internal consistency, not authorship.
  Configure `hmacKey` and keep the key off the machine (KMS, secret manager, CI secret) to
  make forgery require the key.
- **A rewritten suffix passes the chain check.** Editing the last record — or any record
  plus every hash after it — produces a chain that verifies. Without an HMAC key the chain
  proves internal consistency, not authorship. A checkpoint detects a rewritten suffix up
  to its entry count; signatures detect it at every record.
- **Truncation is invisible without a checkpoint.** Removing the last N records leaves a
  perfectly valid shorter chain. Write checkpoints regularly and store them somewhere the
  attacker cannot rewrite (object storage with versioning, a WORM bucket, a ticket, a
  different host).
- **Deletion of the whole file** is indistinguishable from "no activity". Pair checkpoints
  with an external expectation of how many entries should exist.
- **Redaction is signature-based, not semantic.** Unknown credential formats, split tokens,
  base64-encoded secrets, or secrets in unusual fields may pass through. Use `capture:
  "hash"` for data you must never persist.
- **No confidentiality.** Payloads are stored in plaintext (redacted in the default mode).
  Encrypt the volume or use `capture: "hash"` if the ledger itself is sensitive.
- **`capture: "full"` stores secrets.** It exists for controlled debugging only.

### Operational guidance

- Keep the HMAC key outside the machine that writes the ledger; rotate via key rotation and
  a fresh ledger if needed.
- Use one writer process per ledger file. The append queue serializes concurrent
  `record()` calls inside a single `Ledger` instance, but two processes that open the same
  file at the same time can both read the same tail and then emit duplicate sequence
  numbers, which verification reports as `OUT_OF_ORDER`/`CHAIN_MISMATCH`.
- Write a checkpoint on a schedule (and after significant actions), store it off-host, and
  verify against it in CI or during incident review.
- Ledger files are created with mode `0o600` and appends use `O_APPEND | O_CREAT`
  (`O_NOFOLLOW` on POSIX). Symbolic links are refused, so a ledger cannot be redirected to
  another path. Treat the directory permissions as part of the trust boundary.
- `createLedger()` recovers the sequence and last hash from the tail of the file; it does
  **not** fully re-verify the chain on open. Run `verify` before appending to a ledger you
  did not create yourself.
- The append descriptor stays open. If the file is deleted or renamed while a handle is
  open, further appends may keep writing to the old file rather than the new path
  (platform-dependent). Call `close()` before rotating or removing a live ledger.

---

## Requirements and installation

- Node.js **18 or newer**, ES Modules, **zero runtime dependencies**.

```bash
npm install agentledger          # library
npm install -g agentledger       # global CLI
npx agentledger --help           # no install
```

---

## Development

```bash
npm install
npm run build      # tsc, strict mode
npm test           # node --test tests/*.test.mjs
npm run typecheck  # tsc --noEmit
```

The suite covers canonical JSON, hash chain and genesis, every tamper case, redaction true
and false positives, capture modes, `wrap()` semantics, concurrent appends, BOM/CRLF/empty
files, CLI exit codes, and append/verify throughput.

---

## License

MIT © Agnet Software Corp. See [LICENSE](LICENSE).
