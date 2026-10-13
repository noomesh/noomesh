// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import * as SecureStore from 'expo-secure-store';
import type { TokenStore } from '@metis/api';

// expo-secure-store is async, but @metis/api's WebSocket getToken() is sync, so we
// keep an in-memory mirror: get() returns it synchronously; set() updates memory
// and persists to the keychain; hydrateToken() loads it once at startup.
const KEY = 'pai_token';
let cached: string | null = null;

export const secureTokenStore: TokenStore = {
  get: () => cached,
  set: async (value) => {
    cached = value;
    try {
      if (value == null) await SecureStore.deleteItemAsync(KEY);
      else await SecureStore.setItemAsync(KEY, value);
    } catch {
      /* keychain unavailable — in-memory value still works for this session */
    }
  },
};

/** Load the persisted token into the in-memory mirror. Call once before rendering the app. */
export async function hydrateToken(): Promise<void> {
  try {
    cached = await SecureStore.getItemAsync(KEY);
  } catch {
    cached = null;
  }
}
