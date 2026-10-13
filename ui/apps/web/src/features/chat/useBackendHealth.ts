// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import { useBackends } from '@/features/backends/useBackends';

/** Backend kinds that can actually serve a chat completion. */
const INFERENCE = ['vllm', 'vllm-secondary', 'llamacpp', 'ollama'];

/** `ready` = serving. `loading` = container up, weights still loading. `down` = nothing to talk to. */
export type ServeState = 'ready' | 'loading' | 'down';

export interface ServingModel {
  model: string;
  backend: string;
  node: string;
}

export interface BackendHealth {
  state: ServeState;
  ready: boolean;
  /** Distinct models offered by the running inference backends, for the picker. */
  models: ServingModel[];
}

/**
 * Chat's view of whether a prompt can be sent right now.
 *
 * A registered backend only means the container is up — vLLM takes minutes to
 * load its weights, and a send during that window comes back 502. So the
 * registration list is not enough: we also probe `/v1/models`, which the
 * gateway proxies to the live backend, to tell "process up" from "model
 * serving". 502/503 is the loading gap, not a failure.
 *
 * Reuses the Backends tab's query key, so the two tabs share one 15s poll.
 */
export function useBackendHealth(): BackendHealth {
  const client = useMetisClient();
  const backends = useBackends();

  const inference = (backends.data ?? []).filter((b) => INFERENCE.includes(b.backend));

  const probe = useQuery<ServeState>({
    queryKey: ['inference', 'serve-probe'],
    enabled: inference.length > 0,
    refetchInterval: 15_000,
    queryFn: async () => {
      try {
        // 2.5s cap keeps the poll snappy; a slow probe means "not ready yet"
        // either way.
        const { response } = await client.GET('/v1/models', {
          signal: AbortSignal.timeout(2500),
        });
        if (response.ok) return 'ready';
        if (response.status === 502 || response.status === 503) return 'loading';
        return 'down';
      } catch {
        // Network/timeout, but registration succeeded — still warming up.
        return 'loading';
      }
    },
  });

  const state: ServeState =
    backends.isError || inference.length === 0 ? 'down' : (probe.data ?? 'loading');

  // One entry per distinct model; the first backend offering it wins the label.
  const models: ServingModel[] = [];
  for (const b of inference) {
    if (!b.model || b.model === '?') continue;
    if (models.some((m) => m.model === b.model)) continue;
    models.push({ model: b.model, backend: b.backend, node: b.nodeId === '?' ? '' : b.nodeId });
  }

  return { state, ready: state === 'ready', models };
}
