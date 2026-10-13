// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import {
  createMetisClient,
  createAuthApi,
  createSocket,
  type SocketOptions,
} from '@metis/api';
import { GATEWAY_URL } from './config';
import { secureTokenStore } from './secureStore';
import { sessionEvents } from './sessionEvents';

// The same shared @metis/api client the web app uses — just pointed at the
// absolute gateway URL and backed by a SecureStore token store instead of
// localStorage. This is the whole "reuse the logic layer" thesis in one file.
export const tokenStore = secureTokenStore;

export const client = createMetisClient({
  baseUrl: GATEWAY_URL,
  tokenStore,
  onLogout: () => sessionEvents.emitExpire(),
});

export const authApi = createAuthApi({ baseUrl: GATEWAY_URL, tokenStore });

/** Open a gateway WebSocket (chat/collab) with the shared reconnecting socket. */
export function connect(path: string, opts: Omit<SocketOptions, 'baseUrl' | 'getToken'>) {
  return createSocket(path, {
    baseUrl: GATEWAY_URL,
    getToken: () => (tokenStore.get() as string | null) ?? '',
    ...opts,
  });
}
