// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { useQuery, useMetisClient } from '@metis/core';

export interface RunbookRef {
  name: string;
  title: string;
}

/**
 * The runbooks the gateway loaded at boot.
 *
 * Fetched, not linked. The gateway's own note on the route says why:
 * "Authenticated API, rendered in-app by the UI (a target=_blank href can
 * never carry the bearer, so these are NOT public pages)." This panel used to
 * link straight at `/docs/runbooks/<slug>` — a path the Rust gateway does not
 * serve at all, and which would 401 even if it did.
 *
 * The list is the gateway's, not a hard-coded one: it reflects the runbooks
 * that install actually has, so a trimmed OSS deployment does not advertise
 * pages it cannot serve.
 */
export function useRunbooks() {
  const client = useMetisClient();
  return useQuery<RunbookRef[]>({
    queryKey: ['runbooks'],
    queryFn: async () => {
      const { data, error } = await client.GET('/api/docs/runbooks');
      if (error) throw new Error('Could not load the runbook list');
      return (data?.runbooks ?? []).map((r) => ({
        name: r.name ?? '',
        title: r.title || r.name || 'Untitled',
      }));
    },
    // Loaded into gateway state at boot — it cannot change while we watch.
    staleTime: Infinity,
  });
}

/** One runbook's markdown. Enabled only once a runbook is selected. */
export function useRunbook(name: string | null) {
  const client = useMetisClient();
  return useQuery<string>({
    queryKey: ['runbook', name],
    enabled: !!name,
    staleTime: Infinity,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/docs/runbooks/{name}', {
        params: { path: { name: name! } },
      });
      if (error) throw new Error(`Could not load "${name}"`);
      return data?.markdown ?? '';
    },
  });
}

/**
 * The full OpenAPI document, fetched with credentials and opened as a blob.
 *
 * It was a plain link to `/static/openapi.json` until 2026-09-19, when that
 * path stopped being public: the file is the complete route map — admin,
 * security, posture, PKI — and it was readable by anything that could reach
 * the gateway. The routes all authenticate, so it was disclosure and not
 * access, but a free inventory of the surface for every node and tailnet
 * member.
 *
 * On demand, not on mount: it is ~460 kB and nobody opening the Docs tab is
 * necessarily after it.
 */
export function useFullSpec() {
  const client = useMetisClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    setPending(true);
    setError(null);
    try {
      const { data, error: err } = await client.GET('/api/docs/openapi');
      if (err || !data) throw new Error('could not load');
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
      );
      window.open(url, '_blank', 'noreferrer');
      // The tab has it; holding the object alive only leaks memory.
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch {
      setError('unavailable');
    } finally {
      setPending(false);
    }
  };
  return { load, pending, error };
}
