/**
 * Aggregate statistics over a ledger.
 *
 * Stats are read-only reporting: malformed records are tolerated (they are reported
 * by `verify`, not here) so that an operator can still inspect a damaged ledger.
 */

import type { LedgerEntry, LedgerStats } from './types.js';

function round(value: number, digits = 3): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** Compute counts, time range, per-tool usage and average latency. */
export function computeStats(entries: readonly LedgerEntry[]): LedgerStats {
  const toolCounts = new Map<string, number>();
  let ok = 0;
  let error = 0;
  let durationSum = 0;
  let durationCount = 0;
  let firstTs: string | null = null;
  let lastTs: string | null = null;
  let lastHash: string | null = null;

  for (const entry of entries) {
    if (typeof entry !== 'object' || entry === null) continue;

    if (typeof entry.tool === 'string' && entry.tool !== '') {
      toolCounts.set(entry.tool, (toolCounts.get(entry.tool) ?? 0) + 1);
    }

    if (entry.status === 'ok') ok += 1;
    else if (entry.status === 'error') error += 1;

    if (typeof entry.durationMs === 'number' && Number.isFinite(entry.durationMs)) {
      durationSum += entry.durationMs;
      durationCount += 1;
    }

    if (typeof entry.ts === 'string') {
      if (firstTs === null) firstTs = entry.ts;
      lastTs = entry.ts;
    }

    if (typeof entry.hash === 'string') lastHash = entry.hash;
  }

  const sortedTools: Record<string, number> = Object.fromEntries(
    [...toolCounts.entries()].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
  );

  return {
    entries: entries.length,
    firstTs,
    lastTs,
    tools: sortedTools,
    ok,
    error,
    avgDurationMs: durationCount === 0 ? 0 : round(durationSum / durationCount),
    lastHash,
  };
}
