// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  useMutation: () => ({}),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useSecurity, type SecurityData } from './useSecurity';

beforeEach(() => H.get.mockReset());

async function run(bodies: Record<string, unknown>): Promise<SecurityData> {
  H.get.mockImplementation((p: string) => Promise.resolve({ data: bodies[p] ?? {} }));
  useSecurity();
  return (H.lastQuery.current!.queryFn as () => Promise<SecurityData>)();
}

describe('useSecurity — unreported is null, never 0', () => {
  it('missing approval stats are null', async () => {
    const d = await run({});
    expect(d.stats).toEqual({ pending: null, approved: null, denied: null, total: null });
  });

  it('a cert with no readable expiry has null daysLeft and status unknown, not "expiring 0d"', async () => {
    const d = await run({
      '/api/security/pki/status': { status: 'ok', certs: { ca: { exists: true, subject: 'CN=ca' } } },
    });
    expect(d.pki.certs[0]).toMatchObject({ name: 'CA', daysLeft: null, status: 'unknown' });
  });

  it('a cert with an expiry still derives daysLeft and status', async () => {
    const soon = new Date(Date.now() + 10 * 86_400_000).toISOString();
    const d = await run({
      '/api/security/pki/status': { status: 'ok', certs: { gateway: { exists: true, not_after: soon } } },
    });
    expect(d.pki.certs[0]).toMatchObject({ daysLeft: 10, status: 'expiring' });
  });
});
