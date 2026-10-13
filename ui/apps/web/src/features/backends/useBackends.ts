// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

export interface Backend {
  backend: string;
  nodeId: string;
  model: string;
  load: number | null;
}

export interface CachedModel {
  name: string;
  backend: string;
  size: string;
  nodes: string[];
}

const BACKENDS_KEY = ['cluster', 'backends'];

/** Running backends across the cluster (GET /api/cluster/backends), polled 15s. */
export function useBackends() {
  const client = useMetisClient();
  return useQuery<Backend[]>({
    queryKey: BACKENDS_KEY,
    refetchInterval: 15_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/cluster/backends');
      if (error || !data) throw new Error('Backends API unavailable');
      return (data.backends ?? []).map((b) => ({
        backend: b.backend || b.backend_type || '?',
        nodeId: b.node_id || b.hostname || '?',
        model: b.model || '?',
        load: b.load ?? null,
      }));
    },
  });
}

/** Cached models across nodes (GET /api/models/cached), polled 30s. */
export function useCachedModels() {
  const client = useMetisClient();
  return useQuery<CachedModel[]>({
    queryKey: ['models', 'cached'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/models/cached');
      if (error || !data) throw new Error('Model cache API unavailable');
      return (data.models ?? []).map((m) => ({
        name: m.name || '?',
        backend: m.backend || '?',
        size: String(m.size ?? '?'),
        nodes: m.nodes ?? [],
      }));
    },
  });
}

/** Start a backend on the cluster (POST /api/cluster/backends/start), then refresh.
 *  node_id/model are optional — the gateway auto-selects a node when omitted. */
export function useStartBackend() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { backend: string; nodeId?: string; model?: string }) => {
      const { error } = await client.POST('/api/cluster/backends/start', {
        body: {
          backend: vars.backend,
          ...(vars.nodeId ? { node_id: vars.nodeId } : {}),
          ...(vars.model ? { model: vars.model } : {}),
        },
      });
      if (error) throw new Error('Start failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: BACKENDS_KEY }),
  });
}

/** Pre-cache a model on a node (POST /api/models/cache), then refresh the cache list. */
export function useCacheModel() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { model: string; nodeId?: string }) => {
      const { error } = await client.POST('/api/models/cache', {
        body: { model: vars.model, ...(vars.nodeId ? { node_id: vars.nodeId } : {}) },
      });
      if (error) throw new Error('Cache failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['models', 'cached'] }),
  });
}

/** Stop a running backend (POST /api/terminal/backends/stop), then refresh. */
export function useStopBackend() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { backend: string; nodeId: string }) => {
      const { error } = await client.POST('/api/terminal/backends/stop', {
        body: { backend: vars.backend, node_id: vars.nodeId },
      });
      if (error) throw new Error('Stop failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: BACKENDS_KEY }),
  });
}
