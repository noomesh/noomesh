// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

/**
 * The graph_prune staging area: entities and edges the prune task soft-deleted,
 * restorable until the retention purge removes them.
 *
 * `GET /api/v1/graph/prune/staged` + `POST /api/v1/graph/prune/restore` had no
 * client before this; recovering a wrongly pruned edge meant hand-written SQL.
 */

/** `staging_retention_days` default in graph_prune.rs. The API reports only
 *  `staged_at`, not the window a given task was configured with. */
export const RETENTION_DAYS = 30;
/** Rows requested per kind; the handler's own default. */
export const STAGED_LIMIT = 200;

const DAY_MS = 86_400_000;

export type PruneKind = 'entity' | 'edge';

export interface StagedPrune {
  kind: PruneKind;
  stagingId: string;
  /** What was staged: an entity name, or `src —rel→ dst` for an edge. */
  label: string;
  /** Entity type, or the edge's rel_type. */
  detail: string;
  reason: string;
  stagedAt: string;
  runId: string | null;
  /** Entities: edges + mentions captured in the snapshot. */
  edgeCount?: number;
  mentionCount?: number;
  /** Edges: confidence at staging time. */
  confidence?: number | null;
  /** When the retention purge may delete the row (staged_at + window), ms epoch. */
  purgeAt: number | null;
}

export interface StagedPrunes {
  rows: StagedPrune[];
  /** Un-restored totals across the whole table, not just the returned page. */
  entityTotal: number;
  edgeTotal: number;
  /** Server note — present when the staging table does not exist yet. */
  note: string | null;
}

/**
 * Postgres `timestamptz::text` ("2026-09-20 06:00:01.123456+00") → ms epoch.
 * That is not ISO 8601 and `Date.parse` is not required to accept it, so it is
 * normalised first: `T` separator, milliseconds only, `+HH:MM` offset.
 */
export function parsePgTime(s: string | null | undefined): number | null {
  if (!s) return null;
  const iso = s
    .trim()
    .replace(' ', 'T')
    .replace(/(\.\d{3})\d+/, '$1')
    .replace(/([+-]\d{2})$/, '$1:00');
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** Whole days until `purgeAt` (0 once it has passed), or null if unknown. */
export function daysLeft(purgeAt: number | null, now: number = Date.now()): number | null {
  if (purgeAt == null) return null;
  return Math.max(0, Math.ceil((purgeAt - now) / DAY_MS));
}

const sum = (m: Record<string, number> | undefined) =>
  Object.values(m ?? {}).reduce((a, n) => a + (Number(n) || 0), 0);

export const STAGED_KEY = ['graph', 'prune', 'staged'];

/** Everything currently staged and not yet restored, newest first. */
export function useStagedPrunes() {
  const client = useMetisClient();
  return useQuery<StagedPrunes>({
    queryKey: STAGED_KEY,
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/v1/graph/prune/staged', {
        params: { query: { limit: STAGED_LIMIT } },
      });
      if (error || !data) throw new Error('Prune staging API unavailable');

      const purge = (stagedAt: string | undefined) => {
        const t = parsePgTime(stagedAt);
        return t == null ? null : t + RETENTION_DAYS * DAY_MS;
      };

      const entities: StagedPrune[] = (data.staged ?? [])
        .filter((e) => e.staging_id)
        .map((e) => ({
          kind: 'entity',
          stagingId: e.staging_id!,
          label: e.canonical_name || e.entity_id || '?',
          detail: e.entity_type ?? '',
          reason: e.reason ?? '',
          stagedAt: e.staged_at ?? '',
          runId: e.run_id ?? null,
          edgeCount: e.edge_count ?? 0,
          mentionCount: e.mention_count ?? 0,
          purgeAt: purge(e.staged_at),
        }));

      const edges: StagedPrune[] = (data.staged_edges ?? [])
        .filter((e) => e.staging_id)
        .map((e) => ({
          kind: 'edge',
          stagingId: e.staging_id!,
          label: `${e.src_name || '?'} —${e.rel_type || 'RELATED_TO'}→ ${e.dst_name || '?'}`,
          detail: e.rel_type ?? '',
          reason: e.reason ?? '',
          stagedAt: e.staged_at ?? '',
          runId: null,
          confidence: e.confidence ?? null,
          purgeAt: purge(e.staged_at),
        }));

      // One list, newest first. Rows with an unreadable time sink to the end.
      const rows = [...entities, ...edges].sort(
        (a, b) => (parsePgTime(b.stagedAt) ?? 0) - (parsePgTime(a.stagedAt) ?? 0),
      );

      return {
        rows,
        entityTotal: Math.max(sum(data.counts), entities.length),
        edgeTotal: Math.max(sum(data.edge_counts), edges.length),
        note: data.note ?? null,
      };
    },
  });
}

export interface RestoreOutcome {
  status: string;
  /** Entities: the snapshot was grafted onto a re-extracted same name+type entity. */
  grafted: boolean;
  edgesRestored: number;
  edgesSkipped: number;
}

/**
 * Restore one staged row. Entities go in `staging_ids`, edges in
 * `edge_staging_ids` — the handler keeps the two id spaces apart.
 *
 * The route answers 200 with a per-id status, so a `not_found` or `error`
 * result is turned into a thrown error here rather than a silent success.
 * `already_restored` is not a failure: the row is back either way.
 */
export function useRestorePrune() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (row: Pick<StagedPrune, 'kind' | 'stagingId'>): Promise<RestoreOutcome> => {
      const body =
        row.kind === 'edge' ? { edge_staging_ids: [row.stagingId] } : { staging_ids: [row.stagingId] };
      const { data, error, response } = await client.POST('/api/v1/graph/prune/restore', { body });
      if (error || !data) {
        const status = response?.status;
        if (status === 403) throw new Error('Restoring needs the operator role.');
        throw new Error(`Restore failed${status ? ` (HTTP ${status})` : ''}`);
      }
      const r = (data.results ?? []).find((x) => x.staging_id === row.stagingId) ?? data.results?.[0];
      if (!r) throw new Error('Restore returned no result');
      if (r.status === 'not_found') {
        throw new Error('Not found — the row was already purged or never existed.');
      }
      if (r.status === 'error') throw new Error(r.error || 'Restore failed');
      return {
        status: r.status ?? 'restored',
        grafted: r.grafted_onto_existing ?? false,
        edgesRestored: r.edges_restored ?? 0,
        edgesSkipped: r.edges_skipped ?? 0,
      };
    },
    // Prefix ['graph'] covers the staged list AND the map: a restored entity
    // or edge is back in the graph.
    onSettled: () => qc.invalidateQueries({ queryKey: ['graph'] }),
  });
}
