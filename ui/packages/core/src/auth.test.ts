// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { createElement, type ReactNode } from 'react';
import { describe, it, expect, vi } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import type { AuthApi, MeInfo } from '@metis/api';
import { AuthProvider, useAuth } from './auth.tsx';

function makeApi(overrides: Partial<AuthApi> = {}): AuthApi {
  return {
    login: vi.fn(async () => {}),
    logout: vi.fn(async () => {}),
    fetchMe: vi.fn(async () => null),
    ...overrides,
  };
}

// Wrapper without JSX so this stays a .ts file (no jsx-runtime config needed).
const wrap = (api: AuthApi) =>
  function Wrapper({ children }: { children: ReactNode }) {
    return createElement(AuthProvider, { authApi: api }, children);
  };

const render = (api: AuthApi) => renderHook(() => useAuth(), { wrapper: wrap(api) });

describe('AuthProvider', () => {
  it('loads identity on mount and derives isLoggedIn / isOperator', async () => {
    const me: MeInfo = { username: 'rick', scopes: ['read'] };
    const api = makeApi({ fetchMe: vi.fn(async () => me) });
    const { result } = render(api);

    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.user).toEqual(me);
    expect(result.current.isLoggedIn).toBe(true);
    expect(result.current.isOperator).toBe(false); // read-only
  });

  it('isOperator is true for write or admin scopes', async () => {
    const api = makeApi({ fetchMe: vi.fn(async () => ({ username: 'op', scopes: ['read', 'write'] })) });
    const { result } = render(api);
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.isOperator).toBe(true);
  });

  it('unauthenticated: ready becomes true with no user', async () => {
    const api = makeApi({ fetchMe: vi.fn(async () => null) });
    const { result } = render(api);
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.user).toBeNull();
    expect(result.current.isLoggedIn).toBe(false);
  });

  it('login succeeds and sets the user', async () => {
    const me: MeInfo = { username: 'rick', scopes: ['read'] };
    const api = makeApi({ fetchMe: vi.fn(async () => me) });
    const { result } = render(api);
    await waitFor(() => expect(result.current.ready).toBe(true));

    await act(async () => {
      await result.current.login('rick', 'pw');
    });

    expect(api.login).toHaveBeenCalledWith('rick', 'pw');
    expect(result.current.user).toEqual(me);
  });

  it('does NOT fail login when /auth/me hiccups transiently, then recovers (finding #6)', async () => {
    const me: MeInfo = { username: 'rick', scopes: ['read'] };
    let calls = 0;
    const api = makeApi({
      login: vi.fn(async () => {}), // credential grant succeeds
      fetchMe: vi.fn(async () => {
        calls += 1;
        if (calls === 1) return null; // initial mount: not logged in
        if (calls === 2) throw new Error('transient /auth/me error'); // first refresh in login
        return me; // retry succeeds
      }),
    });
    const { result } = render(api);
    await waitFor(() => expect(result.current.ready).toBe(true));

    await act(async () => {
      await result.current.login('rick', 'pw'); // must resolve, not throw
    });

    expect(result.current.user).toEqual(me);
    expect(calls).toBeGreaterThanOrEqual(3); // grant + failed refresh + successful retry
  });

  it('login throws (and leaves no user) when the credential grant fails', async () => {
    const api = makeApi({
      login: vi.fn(async () => {
        throw new Error('bad creds');
      }),
      fetchMe: vi.fn(async () => null),
    });
    const { result } = render(api);
    await waitFor(() => expect(result.current.ready).toBe(true));

    await expect(
      act(async () => {
        await result.current.login('u', 'p');
      }),
    ).rejects.toThrow('bad creds');
    expect(result.current.user).toBeNull();
  });

  it('logout clears the user', async () => {
    const api = makeApi({ fetchMe: vi.fn(async () => ({ username: 'rick', scopes: ['read'] })) });
    const { result } = render(api);
    await waitFor(() => expect(result.current.isLoggedIn).toBe(true));

    await act(async () => {
      await result.current.logout();
    });

    expect(api.logout).toHaveBeenCalled();
    expect(result.current.user).toBeNull();
  });

  it('a metis:logout window event clears the user (401-refresh-failed bridge)', async () => {
    const api = makeApi({ fetchMe: vi.fn(async () => ({ username: 'rick', scopes: ['read'] })) });
    const { result } = render(api);
    await waitFor(() => expect(result.current.isLoggedIn).toBe(true));

    act(() => {
      window.dispatchEvent(new Event('metis:logout'));
    });

    await waitFor(() => expect(result.current.user).toBeNull());
  });
});
