// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  // Capture the options the hooks were built with so queryFn / mutationFn
  // can be driven directly — no React, no query client.
  lastQuery: { current: null as null | Record<string, unknown> },
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get, POST: H.post }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import { useAddonUis, useOpenAddonUi, handoffUrl } from './useAddonUis';

const list = async () => {
  useAddonUis();
  return (H.lastQuery.current?.queryFn as () => Promise<unknown>)();
};
const openUi = async (addon: string) => {
  useOpenAddonUi();
  return (H.lastMutation.current?.mutationFn as (a: string) => Promise<unknown>)(addon);
};

describe('useAddonUis', () => {
  beforeEach(() => H.get.mockReset());

  it('reads the listing route and maps it', async () => {
    H.get.mockResolvedValue({
      data: {
        uis: [
          { addon: 'example-addon', title: 'Example', port: 8451, url_base: 'https://h.ts.net:8451', can_open: true },
          { addon: 'other', title: '', port: 8452, url_base: null, can_open: false },
        ],
      },
    });
    await expect(list()).resolves.toEqual([
      { addon: 'example-addon', title: 'Example', port: 8451, urlBase: 'https://h.ts.net:8451', canOpen: true },
      { addon: 'other', title: 'other', port: 8452, urlBase: null, canOpen: false },
    ]);
    expect(H.get).toHaveBeenCalledWith('/api/addons/ui');
    expect(H.lastQuery.current?.queryKey).toEqual(['addon-uis']);
  });

  it("surfaces the gateway's reason", async () => {
    H.get.mockResolvedValue({ error: { detail: 'nope' } });
    await expect(list()).rejects.toThrow('nope');
  });
});

describe('useOpenAddonUi', () => {
  beforeEach(() => H.post.mockReset());

  it('mints on the ui-session route for that add-on and returns the handoff URL untouched', async () => {
    H.post.mockResolvedValue({
      data: { code: 'C', port: 8451, path: '/__noo/session?code=C', url: 'https://h.ts.net:8451/__noo/session?code=C', expires_in: 30 },
    });
    await expect(openUi('example-addon')).resolves.toBe('https://h.ts.net:8451/__noo/session?code=C');
    expect(H.post).toHaveBeenCalledWith('/api/addons/{addon_id}/ui-session', {
      params: { path: { addon_id: 'example-addon' } },
    });
  });

  it("surfaces the gateway's refusal (403 role, 503 off)", async () => {
    H.post.mockResolvedValue({ error: { detail: 'the example-addon UI needs the operator role' } });
    await expect(openUi('example-addon')).rejects.toThrow('needs the operator role');
    H.post.mockResolvedValue({ error: {} });
    await expect(openUi('example-addon')).rejects.toThrow('Could not open example-addon');
  });
});

describe('handoffUrl', () => {
  it("prefers the gateway's URL and otherwise builds it on this host and the add-on's port", () => {
    expect(handoffUrl({ url: 'https://a:1/x', path: '/x', port: 1 }, { hostname: 'b' })).toBe('https://a:1/x');
    expect(handoffUrl({ url: null, path: '/__noo/session?code=C', port: 8451 }, { hostname: 'h.ts.net' })).toBe(
      'https://h.ts.net:8451/__noo/session?code=C',
    );
  });
});
