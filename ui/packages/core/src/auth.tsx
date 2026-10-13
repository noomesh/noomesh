// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import type { AuthApi, MeInfo } from '@metis/api';

interface AuthContextValue {
  user: MeInfo | null;
  /** false until the initial identity check completes (avoid a login flash). */
  ready: boolean;
  isLoggedIn: boolean;
  isOperator: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Session state on top of @metis/api's auth endpoints. Web and mobile share
 *  this; each passes an AuthApi built from its own token store. */
export function AuthProvider({ authApi, children }: { authApi: AuthApi; children: ReactNode }) {
  const [user, setUser] = useState<MeInfo | null>(null);
  const [ready, setReady] = useState(false);

  const refresh = useCallback(async () => {
    const me = await authApi.fetchMe();
    setUser(me);
    setReady(true);
  }, [authApi]);

  useEffect(() => {
    // A failed initial identity check (offline / gateway unreachable) must still
    // mark us ready — otherwise the app hangs on its splash forever instead of
    // falling through to the login screen.
    void refresh().catch(() => {
      setUser(null);
      setReady(true);
    });
  }, [refresh]);

  // The REST client dispatches this when a 401 refresh fails (web only).
  // React Native defines `window` but not window.addEventListener, so the
  // presence check must be on the method, not the object.
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return;
    const onLogout = () => setUser(null);
    window.addEventListener('metis:logout', onLogout);
    return () => window.removeEventListener('metis:logout', onLogout);
  }, []);

  const login = useCallback(
    async (u: string, p: string) => {
      // The credential grant is what "login" fails on. Once it succeeds we ARE
      // authenticated, so a transient /auth/me error shouldn't report the login
      // as failed — retry the identity load briefly before giving up.
      await authApi.login(u, p);
      for (let attempt = 0; ; attempt++) {
        try {
          await refresh();
          return;
        } catch (err) {
          if (attempt >= 2) throw err;
          await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
        }
      }
    },
    [authApi, refresh],
  );

  const logout = useCallback(async () => {
    await authApi.logout();
    setUser(null);
  }, [authApi]);

  const scopes = user?.scopes ?? [];
  const value: AuthContextValue = {
    user,
    ready,
    isLoggedIn: !!user,
    isOperator: scopes.includes('admin') || scopes.includes('write'),
    login,
    logout,
    refresh,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error('useAuth must be used within <AuthProvider>');
  return v;
}
