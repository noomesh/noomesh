// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMutation, useQuery, useMetisClient } from '@metis/core';

/** One add-on web UI, served by the gateway on an origin of its own
 * (`https://<host>:<port>`), so the add-on's scripts never share this
 * console's origin or its stored token. */
export interface AddonUi {
  addon: string;
  title: string;
  port: number;
  /** `https://<host>:<port>`, when the gateway could name the host. */
  urlBase: string | null;
  /** Whether this account's role may open it. */
  canOpen: boolean;
}

/** The gateway's own words on failure (`{"detail"}` or `{"error"}`). */
function gatewayMessage(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const e = error as { error?: unknown; detail?: unknown };
    if (typeof e.error === 'string' && e.error) return e.error;
    if (typeof e.detail === 'string' && e.detail) return e.detail;
  }
  return undefined;
}

/** `GET /api/addons/ui`: the add-on UIs this account may see. */
export function useAddonUis() {
  const client = useMetisClient();
  return useQuery<AddonUi[]>({
    queryKey: ['addon-uis'],
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/addons/ui');
      if (error || !data) throw new Error(gatewayMessage(error) ?? 'Add-on list unavailable');
      return (data.uis ?? []).map((u) => ({
        addon: u.addon,
        title: u.title || u.addon,
        port: u.port,
        urlBase: u.url_base ?? null,
        canOpen: u.can_open,
      }));
    },
  });
}

/**
 * Where to send the new tab. The gateway's `url` names the host it saw; when
 * it could not (a proxy that hid it), build the same URL from the host this
 * console is on — the add-on origin is that host on its own port.
 */
export function handoffUrl(
  answer: { url?: string | null; path: string; port: number },
  here: { hostname: string },
): string {
  if (answer.url) return answer.url;
  return `https://${here.hostname}:${answer.port}${answer.path}`;
}

/**
 * Open an add-on's UI: `POST /api/addons/{addon}/ui-session` mints a one-time
 * code (30 s, single use, bound to this browser by a cookie the same answer
 * sets) and the URL that redeems it on the add-on's origin. The caller opens
 * a tab on the click (popup blockers) and sends it there.
 */
export function useOpenAddonUi() {
  const client = useMetisClient();
  return useMutation<string, Error, string>({
    mutationFn: async (addon: string) => {
      const { data, error } = await client.POST('/api/addons/{addon_id}/ui-session', {
        params: { path: { addon_id: addon } },
      });
      if (error || !data) throw new Error(gatewayMessage(error) ?? `Could not open ${addon}`);
      const here = typeof window !== 'undefined' ? window.location : { hostname: 'localhost' };
      return handoffUrl({ url: data.url, path: data.path, port: data.port }, here);
    },
  });
}
