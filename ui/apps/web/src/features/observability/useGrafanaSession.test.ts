// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  post: vi.fn(),
  // Capture the options useMutation was built with so mutationFn can be driven
  // directly — no React, no query client (the useMintBootstrapToken pattern).
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ POST: H.post }),
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import { useGrafanaSession, sendTab, type TabHandle } from './useGrafanaSession';

const run = async () => {
  useGrafanaSession();
  const fn = H.lastMutation.current?.mutationFn as () => Promise<unknown>;
  return fn();
};

const OK = {
  url: 'https://grafana.example:3000/?auth_token=JWT',
  expires_at: '2026-09-28T12:15:00Z',
  role: 'operator',
};

describe('useGrafanaSession', () => {
  beforeEach(() => H.post.mockReset());

  it('mints on the monitoring route with no body — the gateway decides everything from the login', async () => {
    H.post.mockResolvedValue({ data: OK });
    await run();
    expect(H.post).toHaveBeenCalledWith('/api/monitoring/grafana-session', {});
    const [, opts] = H.post.mock.calls[0];
    expect(opts).not.toHaveProperty('body');
  });

  it("returns the gateway's URL untouched — the token is inside it and must not be rebuilt here", async () => {
    H.post.mockResolvedValue({ data: OK });
    await expect(run()).resolves.toEqual({
      url: 'https://grafana.example:3000/?auth_token=JWT',
      expiresAt: '2026-09-28T12:15:00Z',
      role: 'operator',
    });
  });

  it("surfaces the gateway's reason on failure (its 503 names the fix, its 403 names the account)", async () => {
    H.post.mockResolvedValue({ error: { error: 'Grafana SSO is not configured: NOO_GRAFANA_URL is empty' } });
    await expect(run()).rejects.toThrow('NOO_GRAFANA_URL is empty');
    H.post.mockResolvedValue({ error: { error: "account 'bob': account is disabled" } });
    await expect(run()).rejects.toThrow('account is disabled');
    H.post.mockResolvedValue({ error: {} });
    await expect(run()).rejects.toThrow('Could not open Grafana');
  });
});

describe('sendTab', () => {
  it('sends the tab opened on the click and cuts opener first', () => {
    const tab: TabHandle = { location: 'about:blank', opener: {} };
    const open = vi.fn();
    expect(sendTab(tab, 'https://g/?auth_token=T', open)).toBe(true);
    expect(tab.location).toBe('https://g/?auth_token=T');
    expect(tab.opener).toBeNull();
    expect(open).not.toHaveBeenCalled();
  });

  it('falls back to opening now, and reports a refused popup', () => {
    const open = vi.fn().mockReturnValue(null);
    expect(sendTab(null, 'https://g/?auth_token=T', open)).toBe(false);
    expect(open).toHaveBeenCalledWith('https://g/?auth_token=T');
    open.mockReturnValue({ location: '' });
    expect(sendTab(null, 'https://g/?auth_token=T', open)).toBe(true);
  });
});
