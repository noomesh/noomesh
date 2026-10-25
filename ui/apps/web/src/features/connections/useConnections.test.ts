// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { beforeEach, describe, expect, it, vi } from 'vitest';
const H = vi.hoisted(() => ({
  username: 'alice',
  get: vi.fn(),
  query: { current: null as null | Record<string, unknown> },
}));
vi.mock('@metis/core', () => ({
  useAuth: () => ({ user: H.username ? { username: H.username } : null }),
  useMetisClient: () => ({ GET: H.get }),
  useQuery: (opts: Record<string, unknown>) => {
    H.query.current = opts;
    return {};
  },
  useMutation: () => ({}),
  useQueryClient: () => ({}),
}));
import { useConnections } from './useConnections';
beforeEach(() => {
  H.username = 'alice';
  H.get.mockReset();
});
describe('private connection queries', () => {
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
