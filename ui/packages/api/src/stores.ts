// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — ready-made TokenStore adapters.
//
// Web uses localStorage (matches the legacy key `pai_token`). Mobile injects its
// own SecureStore-backed store. `memoryTokenStore` is handy for tests / SSR.

import type { TokenStore } from './auth.ts';

export function memoryTokenStore(initial: string | null = null): TokenStore {
  let token = initial;
  return {
    get: () => token,
    set: (v) => {
      token = v;
    },
  };
}

/** localStorage-backed store for the web app. Key defaults to the legacy name. */
export function webTokenStore(key = 'pai_token'): TokenStore {
  const available = typeof localStorage !== 'undefined';
  return {
    get: () => (available ? localStorage.getItem(key) : null),
    set: (v) => {
      if (!available) return;
      if (v == null) localStorage.removeItem(key);
      else localStorage.setItem(key, v);
    },
  };
}
