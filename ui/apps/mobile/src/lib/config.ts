// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Gateway origin the companion talks to. Set EXPO_PUBLIC_GATEWAY_URL in .env.local
// (see .env.example). Unlike the web app there is no same-origin proxy, so this
// must be the absolute gateway URL.
export const GATEWAY_URL = process.env.EXPO_PUBLIC_GATEWAY_URL ?? '';

if (!GATEWAY_URL && __DEV__) {
  // eslint-disable-next-line no-console
  console.warn('[noomesh] EXPO_PUBLIC_GATEWAY_URL is not set — API calls will fail. See .env.example.');
}
