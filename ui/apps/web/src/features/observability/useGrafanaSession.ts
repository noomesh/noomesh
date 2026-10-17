// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMutation, useMetisClient } from '@metis/core';

/** What the gateway minted: where to send the tab, and for how long. */
export interface GrafanaSession {
  /** Grafana's root with `?auth_token=<jwt>` — open it in a new tab. */
  url: string;
  expiresAt: string;
  /** The noomesh tier the token carries; Grafana maps it Viewer/Editor/Admin. */
  role: 'user' | 'operator' | 'admin';
}

/** The gateway's own words on failure: `{"error": "…"}`. Its 503 says
 * exactly what to fix (GRAFANA_ROOT_URL unset, the SSO key missing or
 * unreadable) and its 403 says why this login may not open Grafana, which a
 * generic "could not open" throws away. */
function gatewayMessage(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const e = error as { error?: unknown; detail?: unknown };
    if (typeof e.error === 'string' && e.error) return e.error;
    if (typeof e.detail === 'string' && e.detail) return e.detail;
  }
  return undefined;
}

/** A window opened SYNCHRONOUSLY on the click, so the popup blocker does not
 * eat a tab opened after an await. `null` when the browser refused. */
export type TabHandle = { location: string | { href: string }; opener?: unknown; close?: () => void } | null;

/**
 * Send an already-open tab to Grafana with the minted URL, or fall back to
 * opening one now (which a popup blocker may refuse — the caller shows the
 * URL then). `opener` is cut so the Grafana tab cannot reach back into the
 * console.
 */
export function sendTab(tab: TabHandle, url: string, open: (u: string) => TabHandle): boolean {
  if (tab) {
    tab.opener = null;
    tab.location = url;
    return true;
  }
  return open(url) !== null;
}

/**
 * Mint a Grafana session for the account at this browser and open it. The
 * gateway re-reads the account (a disabled one is refused) and its LIVE
 * tier becomes the Grafana role; the token lives 5 minutes by default, and
 * when the tab expires the fix is to click again.
 */
export function useGrafanaSession() {
  const client = useMetisClient();
  return useMutation<GrafanaSession, Error, void>({
    mutationFn: async () => {
      const { data, error } = await client.POST('/api/monitoring/grafana-session', {});
      if (error || !data) {
        throw new Error(gatewayMessage(error) ?? 'Could not open Grafana');
      }
      return { url: data.url, expiresAt: data.expires_at, role: data.role };
    },
  });
}
