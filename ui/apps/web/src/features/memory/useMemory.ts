// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

export interface ToolStat {
  name: string;
  calls: number;
  successful: number;
  successRate: number;
  avgMs: number;
}
export interface MemoryData {
  worker: { state: string; processed: number; embedded: number; failed: number; relationships: number };
  storage: { total: number; embedded: number; unembedded: number; users: number };
  conv: { conversations: number; messages: number; toolCalls: number; avgMessages: number };
  tools: ToolStat[];
}

const KEY = ['memory'];

/** Memory posture: embedding worker + storage coverage + conversation stats (15s). */
export function useMemory() {
  const client = useMetisClient();
  return useQuery<MemoryData>({
    queryKey: KEY,
    refetchInterval: 15_000,
    queryFn: async () => {
      const [w, s, o, t] = await Promise.all([
        client.GET('/api/memory/embed/status'),
        client.GET('/api/memory/storage-stats'),
        client.GET('/api/conversations/stats/overview'),
        client.GET('/api/conversations/stats/tools'),
      ]);
      if (w.error || s.error) throw new Error('Memory stats unavailable');
      const st = w.data?.stats ?? {};
      return {
        worker: {
          state: w.data?.state ?? 'not_initialized',
          processed: st.total_processed ?? 0,
          embedded: st.total_embedded ?? 0,
          failed: st.total_failed ?? 0,
          relationships: st.relationships_created ?? 0,
        },
        storage: {
          total: s.data?.total_records ?? 0,
          embedded: s.data?.embedded_records ?? 0,
          unembedded: s.data?.unembedded_records ?? 0,
          users: s.data?.unique_users ?? 0,
        },
        conv: {
          conversations: o.data?.total_conversations ?? 0,
          messages: o.data?.total_messages ?? 0,
          toolCalls: o.data?.total_tool_calls ?? 0,
          avgMessages: o.data?.avg_messages_per_conversation ?? 0,
        },
        tools: (t.data?.tools ?? []).map((x) => ({
          name: x.name ?? '?',
          calls: x.total_calls ?? 0,
          successful: x.successful ?? 0,
          successRate: x.success_rate ?? 0,
          avgMs: x.avg_execution_ms ?? 0,
        })),
      };
    },
  });
}

/** Start or stop the embedding worker. */
export function useEmbedControl() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (action: 'start' | 'stop') => {
      const res =
        action === 'start'
          ? await client.POST('/api/memory/embed/start', {})
          : await client.POST('/api/memory/embed/stop', {});
      if (res.error) throw new Error(`Embed ${action} failed`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
