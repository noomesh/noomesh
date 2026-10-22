// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient, useAuth } from '@metis/core';

/**
 * Prompt-skill promotion proposals: `GET /api/prompt-skills/proposals` and
 * `POST /api/prompt-skills/proposals/{id}/decide`. Operator and above; a
 * promotion is decided by a person (the gateway refuses an agent credential).
 * The contract types both bodies as open objects, so the rows are narrowed here.
 */

export type SkillStatus = 'pending' | 'promoted' | 'rejected' | 'superseded' | 'withdrawn';

export interface SkillProposal {
  id: number;
  name: string;
  contentSha: string;
  description: string;
  content: string;
  status: SkillStatus | string;
  proposedBy: string;
  proposedAt: string;
  decidedBy: string | null;
  decidedAt: string | null;
  reason: string | null;
}

export const KEY = ['prompt-skills', 'proposals'];

/** Narrow one open-object row; a row without an id or name is dropped. */
export function toProposal(r: Record<string, unknown>): SkillProposal | null {
  const s = (v: unknown) => (typeof v === 'string' ? v : '');
  const n = (v: unknown) => (typeof v === 'string' && v ? v : null);
  if (typeof r.id !== 'number' || !s(r.name)) return null;
  return {
    id: r.id,
    name: s(r.name),
    contentSha: s(r.content_sha),
    description: s(r.description),
    content: s(r.content),
    status: s(r.status) || 'pending',
    proposedBy: s(r.proposed_by),
    proposedAt: s(r.proposed_at),
    decidedBy: n(r.decided_by),
    decidedAt: n(r.decided_at),
    reason: n(r.reason),
  };
}

export function useSkillProposals() {
  const client = useMetisClient();
  const { isOperator } = useAuth();
  return useQuery<SkillProposal[]>({
    queryKey: KEY,
    enabled: isOperator,
    refetchInterval: 30_000,
    queryFn: async () => {
      const res = await client.GET('/api/prompt-skills/proposals', {});
      const status = res.response?.status;
      if (res.error || !res.data) {
        if (status === 403)
          throw new Error('Skill proposals need operator permission — your account is read-only.');
        throw new Error('Skill proposals are currently unavailable.');
      }
      const rows = (res.data as { proposals?: Record<string, unknown>[] }).proposals ?? [];
      return rows.map(toProposal).filter((p): p is SkillProposal => p !== null);
    },
  });
}

export type Decision = 'promote' | 'reject';

export interface DecideVars {
  id: number;
  decision: Decision;
  reason?: string;
}

/** Message for a failed decision: the gateway's own sentence when it sent one. */
export function decisionError(status: number | undefined, body: unknown): string {
  const b = body as { error?: string; detail?: string } | undefined;
  const text = b?.error ?? b?.detail;
  if (text) return text;
  if (status === 403) return 'Only a signed-in person with operator permission can decide a skill.';
  return 'The decision was not recorded.';
}

export function useDecideSkill() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: DecideVars) => {
      const reason = v.reason?.trim();
      const res = await client.POST('/api/prompt-skills/proposals/{id}/decide', {
        params: { path: { id: v.id } },
        body: { decision: v.decision, ...(reason ? { reason } : {}) },
      });
      // The contract documents no error body, so read it as the open object it is.
      const failed = res as { error?: unknown; response?: { status?: number } };
      if (failed.error) throw new Error(decisionError(failed.response?.status, failed.error));
      return res.data as { live?: unknown } | undefined;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
