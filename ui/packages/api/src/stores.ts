// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — ready-made TokenStore adapters.
//
// Web keeps the access token in memory only (i515c): nothing a script on the
// page can read back from storage, and the httpOnly refresh cookie restores
// it after a reload. Mobile injects its own SecureStore-backed store.

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
