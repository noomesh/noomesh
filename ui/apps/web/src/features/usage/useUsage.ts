// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';

/** How the rows are bucketed. Mirrors the `group` enum in openapi.json. */
export type UsageGroup = 'node' | 'model' | 'backend' | 'source' | 'user' | 'consumer';

/** `month` = current calendar month, `all` = all time, or an explicit `YYYY-MM`. */
export type UsageWindow = string;

export interface UsageRow {
  key: string;
  promptTokens: number;
  completionTokens: number;
  requests: number;
  /** Prompt + completion — what the bars are scaled against. */
  total: number;
}

export interface UsageSummary {
  window: string;
  group: string;
  promptTokens: number;
  completionTokens: number;
  requests: number;
  total: number;
  rows: UsageRow[];
}

/**
 * Token accounting from `GET /api/usage/summary`.
 *
 * Recent windows are raw per-completion rows; months past the gateway's raw
 * retention are served from its monthly rollup — same shape either way, so
 * there's nothing to branch on here.
 */
export function useUsage(window: UsageWindow, group: UsageGroup) {
  const client = useMetisClient();
  return useQuery<UsageSummary>({
    queryKey: ['usage', window, group],
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/usage/summary', {
        params: { query: { window, group } },
      });
      if (error || !data) throw new Error('Usage API unavailable');

      const rows: UsageRow[] = (data.rows ?? [])
        .map((r) => {
          const promptTokens = r.prompt_tokens ?? 0;
          const completionTokens = r.completion_tokens ?? 0;
          return {
            key: r.key || '—',
            promptTokens,
            completionTokens,
            requests: r.requests ?? 0,
            total: promptTokens + completionTokens,
          };
        })
        .sort((a, b) => b.total - a.total);

      const promptTokens = data.totals?.prompt_tokens ?? 0;
      const completionTokens = data.totals?.completion_tokens ?? 0;
      return {
        window: data.window || window,
        group: data.group || group,
        promptTokens,
        completionTokens,
        requests: data.totals?.requests ?? 0,
        total: promptTokens + completionTokens,
        rows,
      };
    },
  });
}

/** The last N calendar months as `YYYY-MM`, newest first. */
export function recentMonths(n: number, from = new Date()): string[] {
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const d = new Date(from.getFullYear(), from.getMonth() - i, 1);
    out.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`);
  }
  return out;
}

/** 4_812_366 -> "4.81M". Token counts get long fast. */
export function compactTokens(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}
