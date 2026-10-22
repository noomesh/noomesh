// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  invalidate: vi.fn(),
  isOperator: { current: true },
  lastQuery: { current: null as null | Record<string, unknown> },
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get, POST: H.post }),
  useQueryClient: () => ({ invalidateQueries: H.invalidate }),
  useAuth: () => ({ isOperator: H.isOperator.current }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return {};
  },
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import { useSkillProposals, useDecideSkill, toProposal, decisionError } from './useSkillProposals';
import { trustMeta, promotedBefore } from './SkillProposalsPanel';

beforeEach(() => {
  H.get.mockReset();
  H.post.mockReset();
  H.invalidate.mockReset();
  H.isOperator.current = true;
});

const row = (o: Record<string, unknown> = {}) => ({
  id: 7, name: 'tidy', content_sha: 'abcdef012345', description: 'd', content: 'text',
  status: 'pending', proposed_by: 'sweep', proposed_at: '2026-10-19T00:00:00Z',
  decided_by: null, decided_at: null, reason: null, ...o,
});

describe('skill proposals query', () => {
  it('is not even enabled for a non-operator', () => {
    H.isOperator.current = false;
    useSkillProposals();
    expect(H.lastQuery.current?.enabled).toBe(false);
  });

  it('narrows rows and drops one with no id or name', async () => {
    H.get.mockResolvedValue({ data: { proposals: [row(), { name: 'x' }, row({ id: 8, name: '' })] } });
    useSkillProposals();
    const out = await (H.lastQuery.current!.queryFn as () => Promise<unknown[]>)();
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: 7, name: 'tidy', status: 'pending', decidedBy: null });
  });

  it('says operator permission on a 403 and never shows an empty list as success', async () => {
    H.get.mockResolvedValue({ error: {}, response: { status: 403 } });
    useSkillProposals();
    const q = H.lastQuery.current!.queryFn as () => Promise<unknown>;
    await expect(q()).rejects.toThrow(/operator permission/);
    H.get.mockResolvedValue({ error: {}, response: { status: 500 } });
    await expect(q()).rejects.toThrow(/unavailable/);
  });
});

describe('deciding', () => {
  it('posts the decision with a trimmed reason and omits an empty one', async () => {
    H.post.mockResolvedValue({ data: { live: true } });
    useDecideSkill();
    const run = H.lastMutation.current!.mutationFn as (v: unknown) => Promise<unknown>;
    await run({ id: 7, decision: 'promote', reason: '  looks fine ' });
    expect(H.post).toHaveBeenLastCalledWith('/api/prompt-skills/proposals/{id}/decide', {
      params: { path: { id: 7 } },
      body: { decision: 'promote', reason: 'looks fine' },
    });
    await run({ id: 7, decision: 'reject', reason: '   ' });
    expect(H.post.mock.calls.at(-1)![1].body).toEqual({ decision: 'reject' });
  });

  it('surfaces the gateway sentence when the decision is refused', async () => {
    H.post.mockResolvedValue({ error: { error: 'a prompt skill is promoted by a person' }, response: { status: 403 } });
    useDecideSkill();
    await expect((H.lastMutation.current!.mutationFn as (v: unknown) => Promise<unknown>)({ id: 1, decision: 'promote' }))
      .rejects.toThrow('a prompt skill is promoted by a person');
    expect(decisionError(403, undefined)).toMatch(/operator permission/);
  });
});

describe('presentation', () => {
  it('only promoted reads as in use', () => {
    expect(trustMeta('promoted').tone).toBe('good');
    expect(trustMeta('pending').tone).toBe('warn');
    expect(trustMeta('rejected').tone).toBe('bad');
  });
  it('diffs against the newest promoted text of the same skill only', () => {
    const a = toProposal(row({ id: 1, status: 'promoted', content_sha: 'aaaa', proposed_at: '2026-10-01' }))!;
    const b = toProposal(row({ id: 2, status: 'pending', content_sha: 'bbbb' }))!;
    const other = toProposal(row({ id: 3, name: 'other', status: 'promoted', content_sha: 'cccc' }))!;
    expect(promotedBefore([a, b, other], b)?.id).toBe(1);
    expect(promotedBefore([other, b], b)).toBeUndefined();
  });
});
