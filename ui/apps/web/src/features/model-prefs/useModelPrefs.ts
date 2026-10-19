// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import {
  errorMessage,
  type EmbeddingSpace,
  type ModelAlias,
  type ModelClass,
  type PoolNode,
} from './modelPrefs';

// The generated spec types these bodies as free-form objects and declares no
// path parameters, so the shapes are read defensively here and the path-param
// calls go through one loose view of the client.
type Obj = Record<string, unknown>;
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d);
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? (v as Obj[]) : []);

interface LooseResult {
  data?: Obj;
  error?: unknown;
}
interface LooseClient {
  GET(path: string): Promise<LooseResult>;
  PUT(path: string, init: unknown): Promise<LooseResult>;
  DELETE(path: string, init: unknown): Promise<LooseResult>;
}

const KEY = ['model-prefs'];

function poolNode(o: Obj): PoolNode {
  return {
    node: str(o.node, '?'),
    backend: str(o.backend, '?'),
    model: str(o.model),
    desiredState: str(o.desired_state),
    advertising: o.advertising === true,
  };
}

export interface ModelPrefsData {
  classes: ModelClass[];
  aliases: ModelAlias[];
  spaces: EmbeddingSpace[];
  unmatched: PoolNode[];
}

/** Model classes + aliases + embedding spaces (polled 15s). */
export function useModelPrefs() {
  const client = useLoose();
  return useQuery<ModelPrefsData>({
    queryKey: KEY,
    refetchInterval: 15_000,
    queryFn: async () => {
      const [c, e] = await Promise.all([
        client.GET('/api/cluster/model-classes'),
        client.GET('/api/cluster/embedding-spaces'),
      ]);
      if (c.error || !c.data) throw new Error(errorMessage(c.error, 'Model classes unavailable'));
      if (e.error || !e.data) throw new Error(errorMessage(e.error, 'Embedding spaces unavailable'));
      const cd = c.data as Obj;
      const ed = e.data as Obj;
      return {
        classes: arr(cd.classes).map((x) => ({
          name: str(x.name),
          declared: x.declared === true,
          dynamic: x.dynamic === true,
        })),
        aliases: arr(cd.aliases).map((x) => ({
          alias: str(x.alias),
          class: str(x.class),
          builtin: x.builtin === true,
          purpose: x.purpose === true,
        })),
        spaces: arr(ed.spaces).map((x) => ({
          space: str(x.space),
          model: str(x.model),
          dims: typeof x.dims === 'number' ? x.dims : null,
          isDefault: x.default === true,
          pool: arr(x.pool).map(poolNode),
          live: typeof x.live === 'number' ? x.live : 0,
        })),
        unmatched: arr(ed.unmatched).map(poolNode),
      };
    },
  });
}

function useLoose() {
  return useMetisClient() as unknown as LooseClient;
}

const pathOf = (k: string, v: string) => ({ params: { path: { [k]: v } } });

/** Point a purpose at a class or served model name. Resolves to the server's note, if any. */
export function useSetPreference() {
  const client = useLoose();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { alias: string; target: string }): Promise<string | null> => {
      const { data, error } = await client.PUT('/api/cluster/model-aliases/{alias}', {
        ...pathOf('alias', vars.alias),
        body: { class: vars.target },
      });
      if (error) throw new Error(errorMessage(error, 'Set preference failed'));
      return typeof data?.note === 'string' ? data.note : null;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Clear a purpose's preference (back to any live chat node). */
export function useClearPreference() {
  const client = useLoose();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (alias: string) => {
      const { error } = await client.DELETE('/api/cluster/model-aliases/{alias}', pathOf('alias', alias));
      if (error) throw new Error(errorMessage(error, 'Clear preference failed'));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Declare a new embedding space. */
export function useDeclareSpace() {
  const client = useLoose();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { space: string; body: { model: string; dims?: number } }) => {
      const { error } = await client.PUT('/api/cluster/embedding-spaces/{space}', {
        ...pathOf('space', vars.space),
        body: vars.body,
      });
      if (error) throw new Error(errorMessage(error, 'Declare space failed'));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Remove a non-default embedding space. */
export function useDeleteSpace() {
  const client = useLoose();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (space: string) => {
      const { error } = await client.DELETE('/api/cluster/embedding-spaces/{space}', pathOf('space', space));
      if (error) throw new Error(errorMessage(error, 'Delete space failed'));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
