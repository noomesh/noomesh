// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';
import { createAuthApi } from './authApi.ts';
import { memoryTokenStore } from './stores.ts';

function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('createAuthApi', () => {
  it('login posts form-urlencoded creds and stores the access token', async () => {
    const store = memoryTokenStore(null);
    const fetchImpl = vi.fn(async () => json(200, { access_token: 'abc' }));
    const api = createAuthApi({ tokenStore: store, fetchImpl: fetchImpl as unknown as typeof fetch });

    await api.login('rick', 'p@ss word');

    expect(await store.get()).toBe('abc');
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(url)).toContain('/auth/token');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(String(init.body)).toContain('username=rick');
    expect(String(init.body)).toContain('password=p%40ss%20word');
  });

  it('login throws with the server detail on failure and leaves no token', async () => {
    const store = memoryTokenStore(null);
    const fetchImpl = vi.fn(async () => json(401, { detail: 'bad creds' }));
    const api = createAuthApi({ tokenStore: store, fetchImpl: fetchImpl as unknown as typeof fetch });

    await expect(api.login('u', 'p')).rejects.toThrow('bad creds');
    expect(await store.get()).toBeNull();
  });

  it('fetchMe returns identity on 200, null on non-ok', async () => {
    const store = memoryTokenStore('tok');
    let ok = true;
    const fetchImpl = vi.fn(async () =>
      ok ? json(200, { username: 'rick', scopes: ['read'] }) : json(401),
    );
    const api = createAuthApi({ tokenStore: store, fetchImpl: fetchImpl as unknown as typeof fetch });

    expect(await api.fetchMe()).toEqual({ username: 'rick', scopes: ['read'] });
    ok = false;
    expect(await api.fetchMe()).toBeNull();
  });

  it('logout clears the token even if the request throws', async () => {
    const store = memoryTokenStore('tok');
    const fetchImpl = vi.fn(async () => {
      throw new Error('network down');
    });
    const api = createAuthApi({ tokenStore: store, fetchImpl: fetchImpl as unknown as typeof fetch });

    await api.logout();

    expect(await store.get()).toBeNull();
  });
});
