// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { beforeEach, describe, expect, it, vi } from 'vitest';
const H = vi.hoisted(() => ({
  username: 'alice',
  get: vi.fn(),
  mutations: [] as Record<string, unknown>[],
  cancelQueries: vi.fn(),
  removeQueries: vi.fn(),
  invalidateQueries: vi.fn(),
  query: { current: null as null | Record<string, unknown> },
}));
vi.mock('@metis/core', () => ({
  useAuth: () => ({ user: H.username ? { username: H.username } : null }),
  useMetisClient: () => ({ GET: H.get }),
  useQuery: (opts: Record<string, unknown>) => {
    H.query.current = opts;
    return {};
  },
  useMutation: (opts: Record<string, unknown>) => { H.mutations.push(opts); return opts; },
  useQueryClient: () => ({ cancelQueries: H.cancelQueries, removeQueries: H.removeQueries, invalidateQueries: H.invalidateQueries }),
}));
import { useConnections, useConnectionActions } from './useConnections';
beforeEach(() => {
  H.username = 'alice';
  H.get.mockReset();
  H.mutations = [];
  H.cancelQueries.mockReset().mockResolvedValue(undefined);
  H.removeQueries.mockReset();
  H.invalidateQueries.mockReset();
});
describe('private connection queries', () => {
  it('disconnect removes cached resource names only for the current user and account', async () => {
    useConnectionActions();
    const removed = H.mutations[2].onSuccess as (_data: unknown, id: string) => Promise<void>;
    await removed(undefined, 'account-a');
    const filter = { queryKey: ['connection-resources', 'alice', 'account-a'] };
    expect(H.cancelQueries).toHaveBeenCalledWith(filter);
    expect(H.removeQueries).toHaveBeenCalledExactlyOnceWith(filter);
    expect(H.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['connections', 'alice'] });
  });
  it('uses a different cache for each Noomesh user and disables signed-out reads', () => {
    useConnections();
    expect(H.query.current?.queryKey).toEqual(['connections', 'alice']);
    H.username = 'bob';
    useConnections();
    expect(H.query.current?.queryKey).toEqual(['connections', 'bob']);
    H.username = '';
    useConnections();
    expect(H.query.current?.enabled).toBe(false);
  });
  it('does not turn a server failure into an empty successful account list', async () => {
    H.get.mockResolvedValue({ error: { message: 'Storage failed' } });
    useConnections();
    await expect(
      (H.query.current!.queryFn as () => Promise<unknown>)(),
    ).rejects.toThrow('Unable to load');
  });
});
