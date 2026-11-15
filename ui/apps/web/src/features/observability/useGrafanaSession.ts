// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMutation, useMetisClient, useQuery } from '@metis/core';

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
 * unreadable), its 403 says why this login may not open Grafana, and its 409
 * says dashboards are off on this install by choice and names
 * `noo stack monitoring on` — all of which a generic "could not open" throws
 * away. */
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

/** `GET /api/monitoring/status`: which optional monitoring parts run. */
export interface MonitoringStatus {
  monitoring: 'full' | 'lean';
  grafana: boolean;
  log_search: boolean;
  traces: boolean;
  /** Present only when something is off; names `noo stack monitoring on`. */
  message?: string;
}

/**
 * The line shown INSTEAD of "Open Grafana" when dashboards are off by choice
 * (`cluster.monitoring: lean` and no Grafana running), else `null`. Only an
 * explicit `grafana: false` hides the button: no answer yet, an error, or an
 * older gateway without the route all keep the button, which is what the
 * console did before the declaration existed.
 */
export function grafanaOffLine(status: MonitoringStatus | undefined | null): string | null {
  if (!status || status.grafana !== false) return null;
  return 'Dashboards are off on this install: noo stack monitoring on';
}

/** Ask once a minute; a failure (an older gateway, a 403) is "unknown". */
export function useMonitoringStatus() {
  const client = useMetisClient();
  return useQuery<MonitoringStatus | null>({
    queryKey: ['monitoring-status'],
    queryFn: async () => {
      const { data, error } = await client.GET('/api/monitoring/status', {});
      if (error || !data) return null;
      return data as MonitoringStatus;
    },
    staleTime: 60_000,
    retry: false,
  });
}
