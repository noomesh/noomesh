// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import type { Proposal } from './types';

const KEY = ['cluster', 'proposals'];

/** Live proposals from POST /api/cluster/proposals, polled every 15s. The full
 *  list is fetched; the panel filters by status client-side. */
export function useProposals() {
  const client = useMetisClient();
  return useQuery<Proposal[]>({
    queryKey: KEY,
    refetchInterval: 15_000,
    queryFn: async () => {
      const res = await client.POST('/api/cluster/proposals', { body: { limit: 50 } });
      const status = res.response?.status;
      if (res.error || !res.data) {
        if (status === 403)
          throw new Error('Proposals require operator permission — your account is read-only.');
        throw new Error('Proposals are currently unavailable.');
      }
      return (res.data.proposals ?? []).map(
        (p): Proposal => ({
          id: p.id ?? '',
          host: p.host || '—',
          user: p.user_name || p.user || '—',
          role: p.role || '—',
          reason: p.reason ?? '',
          proposedBy: p.proposed_by || '—',
          createdAt: p.created_at ?? '',
          status: p.status ?? 'pending',
          executionLog: p.execution_log ?? undefined,
        }),
      );
    },
  });
}

/** Approve or reject a pending proposal, then refresh the list. */
export function useDecideProposal() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { id: string; decision: 'approve' | 'reject' }) => {
      const { error } = await client.POST('/api/cluster/proposals/decide', { body: vars });
      if (error) throw new Error('Decision failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
