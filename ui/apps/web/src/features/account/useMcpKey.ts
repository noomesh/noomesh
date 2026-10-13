// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

/** Status of the caller's own MCP key. Never carries the key itself. */
export interface McpKeyStatus {
  active: boolean;
  consumer: string;
  createdAt: string;
  lastUsedAt: string | null;
  note: string;
  rpmLimit: number | null;
}

/** The one-time issue response. `key` exists ONLY here — see McpKeyDialog. */
export interface IssuedMcpKey {
  key: string;
  rpmLimit: number | null;
  /** How many previously-active keys this issue revoked (0 or 1). */
  replacedActive: number;
}

const KEY = ['mcp-key'];

/** Does the caller have an active MCP key, and when was it last used? */
export function useMcpKeyStatus() {
  const client = useMetisClient();
  return useQuery<McpKeyStatus>({
    queryKey: KEY,
    queryFn: async () => {
      const r = await client.GET('/api/security/service-keys/self');
      if (r.error) throw new Error('Could not read MCP key status');
      const d = (r.data ?? {}) as Record<string, unknown>;
      return {
        active: Boolean(d.active),
        consumer: String(d.consumer ?? ''),
        createdAt: String(d.created_at ?? ''),
        lastUsedAt: d.last_used_at ? String(d.last_used_at) : null,
        note: String(d.note ?? ''),
        rpmLimit: typeof d.rpm_limit === 'number' ? d.rpm_limit : null,
      };
    },
  });
}

/**
 * Mint (or rotate) the caller's MCP key.
 *
 * The response is the ONLY time the raw key exists anywhere the user can
 * reach — the gateway stores just its SHA-256. So the caller of this hook is
 * responsible for putting it on screen and keeping it there until dismissed;
 * do not log it, and do not stash it in the query cache, where a background
 * refetch could drop it while the user is still copying.
 */
export function useIssueMcpKey() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation<IssuedMcpKey, Error, { note?: string }>({
    mutationFn: async (vars) => {
      const r = await client.POST('/api/security/service-keys/self', {
        body: vars.note ? { note: vars.note } : {},
      });
      if (r.error) throw new Error('Could not issue an MCP key');
      const d = (r.data ?? {}) as Record<string, unknown>;
      const key = String(d.key ?? '');
      if (!key) throw new Error('Gateway returned no key');
      return {
        key,
        rpmLimit: typeof d.rpm_limit === 'number' ? d.rpm_limit : null,
        replacedActive: typeof d.replaced_active === 'number' ? d.replaced_active : 0,
      };
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Revoke the caller's own MCP key. */
export function useRevokeMcpKey() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation<number, Error, void>({
    mutationFn: async () => {
      const r = await client.POST('/api/security/service-keys/self/revoke');
      if (r.error) throw new Error('Could not revoke the key');
      const d = (r.data ?? {}) as Record<string, unknown>;
      return typeof d.revoked === 'number' ? d.revoked : 0;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
