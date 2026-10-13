// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';
import { createAuthFetch } from './auth.ts';
import { memoryTokenStore } from './stores.ts';

// Node's `Request` (unlike the browser) requires absolute URLs, so tests use a
// base origin. In the app, baseUrl is '' and the browser resolves relative paths.
const BASE = 'https://gw.test';

function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const asReq = (input: RequestInfo | URL): Request =>
  input instanceof Request ? input : new Request(input);

describe('createAuthFetch', () => {
  it('injects the Bearer token', async () => {
    const store = memoryTokenStore('tok-1');
    const fetchImpl = vi.fn(async () => json(200, { ok: true }));
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await authFetch(`${BASE}/api/x`);

    const sent = fetchImpl.mock.calls[0]![0] as unknown as Request;
    expect(sent.headers.get('Authorization')).toBe('Bearer tok-1');
  });

  it('on 401, refreshes once and retries with the fresh token', async () => {
    const store = memoryTokenStore('stale');
    const auths: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const req = asReq(input);
      if (req.url.endsWith('/api/auth/refresh')) return json(200, { access_token: 'fresh' });
      auths.push(req.headers.get('Authorization') ?? '');
      return json(auths.length === 1 ? 401 : 200, { ok: true });
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(200);
    expect(auths).toEqual(['Bearer stale', 'Bearer fresh']);
    expect(await store.get()).toBe('fresh');
  });

  it('clears the token and calls onLogout when refresh fails (finding #5)', async () => {
    const store = memoryTokenStore('stale');
    const onLogout = vi.fn();
    const fetchImpl = vi.fn(async () => json(401)); // both the API call and refresh 401
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      onLogout,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(401);
    expect(onLogout).toHaveBeenCalledTimes(1);
    expect(await store.get()).toBeNull();
  });

  it('does not attempt a refresh when there is no token', async () => {
    const store = memoryTokenStore(null);
    let refreshes = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      if (asReq(input).url.endsWith('/api/auth/refresh')) refreshes++;
      return json(401);
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(401);
    expect(refreshes).toBe(0);
  });

  it('coalesces concurrent 401s into a single refresh', async () => {
    const store = memoryTokenStore('stale');
    let refreshes = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const req = asReq(input);
      if (req.url.endsWith('/api/auth/refresh')) {
        refreshes++;
        await new Promise((r) => setTimeout(r, 5));
        return json(200, { access_token: 'fresh' });
      }
      return json(req.headers.get('Authorization') === 'Bearer fresh' ? 200 : 401, {});
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const [a, b] = await Promise.all([authFetch(`${BASE}/api/a`), authFetch(`${BASE}/api/b`)]);

    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(refreshes).toBe(1);
  });
});
