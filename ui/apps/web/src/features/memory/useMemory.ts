// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { num } from '@/lib/num';
import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import { refusalMessage } from '../jobs/useJobs';

// Every count is `number | null`: null = the gateway did not send it (i195 E1).
export interface ToolStat {
  name: string;
  calls: number | null;
  successful: number | null;
  successRate: number | null;
  avgMs: number | null;
}
export interface MemoryData {
  worker: {
    state: string;
    processed: number | null;
    embedded: number | null;
    failed: number | null;
    relationships: number | null;
  };
  storage: { total: number | null; embedded: number | null; unembedded: number | null; users: number | null };
  conv: {
    conversations: number | null;
    messages: number | null;
    toolCalls: number | null;
    avgMessages: number | null;
  };
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
          processed: num(st.total_processed),
          embedded: num(st.total_embedded),
          failed: num(st.total_failed),
          relationships: num(st.relationships_created),
        },
        storage: {
          total: num(s.data?.total_records),
          embedded: num(s.data?.embedded_records),
          unembedded: num(s.data?.unembedded_records),
          users: num(s.data?.unique_users),
        },
        conv: {
          conversations: num(o.data?.total_conversations),
          messages: num(o.data?.total_messages),
          toolCalls: num(o.data?.total_tool_calls),
          avgMessages: num(o.data?.avg_messages_per_conversation),
        },
        tools: (t.data?.tools ?? []).map((x) => ({
          name: x.name ?? '?',
          calls: num(x.total_calls),
          successful: num(x.successful),
          successRate: num(x.success_rate),
          avgMs: num(x.avg_execution_ms),
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
      const refused: unknown = res.error;
      if (refused) throw new Error(refusalMessage(refused, `Embed ${action} failed`));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
