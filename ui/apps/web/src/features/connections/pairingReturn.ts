// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
import type { components } from '@metis/api';

export const PAIRING_PENDING = 'noomesh:pairing-oauth';
export const PAIRING_RESULT = 'noomesh:pairing-result';
export type PendingPairing = {
  session_id: string;
  completion_token: string;
  state: string;
  username: string;
  expires_at: number;
};

export function rememberPairing(session: components['schemas']['ConnectionOAuthSession'], username: string) {
  const authorization = new URL(session.authorization_url);
  if (authorization.protocol !== 'https:') throw new Error('Invalid sign-in destination.');
  sessionStorage.removeItem(PAIRING_RESULT);
  const pending: PendingPairing = {
    session_id: session.session_id, completion_token: session.completion_token,
    state: session.state, username,
    expires_at: Date.now() + Math.min(session.expires_in, 600) * 1000,
  };
  sessionStorage.setItem(PAIRING_PENDING, JSON.stringify(pending));
  return authorization.href;
}

/** Consume before sending anything: reloads cannot replay a completion. */
export function takePairingReturn(username: string) {
  const raw = sessionStorage.getItem(PAIRING_RESULT);
  const pendingRaw = sessionStorage.getItem(PAIRING_PENDING);
  if (!raw) {
    try {
      const pending = JSON.parse(pendingRaw || 'null');
      if (pending && (pending.username !== username || !(pending.expires_at > Date.now()))) sessionStorage.removeItem(PAIRING_PENDING);
    } catch { sessionStorage.removeItem(PAIRING_PENDING); }
    return null;
  }
  sessionStorage.removeItem(PAIRING_PENDING);
  sessionStorage.removeItem(PAIRING_RESULT);
  try {
    const pending: PendingPairing = JSON.parse(pendingRaw || 'null');
    const result: { state?: string; code?: string; error?: boolean } = JSON.parse(raw);
    if (!pending || pending.username !== username || !(pending.expires_at > Date.now()) ||
        pending.state !== result.state || typeof pending.session_id !== 'string' ||
        typeof pending.completion_token !== 'string') throw new Error();
    if (!result.error && (typeof result.code !== 'string' || !result.code || result.code.length > 8192)) throw new Error();
    return { pending, result };
  } catch {
    throw new Error('Sign-in expired or your Noomesh account changed. Start again from the terminal.');
  }
}
