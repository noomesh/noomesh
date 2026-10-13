// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

export interface AdminUser {
  username: string;
  scopes: string[];
  disabled: boolean;
  locked: boolean;
  lastLogin: string | null;
}
export interface Flag {
  key: string;
  label: string;
  help: string;
  value: boolean;
  category: string;
  source: string;
}
export interface AdminData {
  users: AdminUser[];
  flags: Flag[];
}

const KEY = ['admin'];

/** Users & scopes + behavioral flags (polled 30s). */
export function useAdmin() {
  const client = useMetisClient();
  return useQuery<AdminData>({
    queryKey: KEY,
    refetchInterval: 30_000,
    queryFn: async () => {
      const [u, f] = await Promise.all([
        client.GET('/api/users'),
        client.GET('/api/settings/flags'),
      ]);
      const uStatus = u.response?.status;
      if (u.error) {
        if (uStatus === 400 || uStatus === 403)
          throw new Error('Admin requires admin scope — your account lacks it.');
        throw new Error('Admin data unavailable');
      }
      return {
        users: (u.data?.users ?? []).map((x) => ({
          username: x.username ?? '?',
          scopes: x.scopes ?? [],
          disabled: x.disabled ?? false,
          locked: !!x.locked_until,
          lastLogin: x.last_login_at ?? null,
        })),
        flags: (f.data?.flags ?? []).map((x) => ({
          key: x.key ?? '',
          label: x.label || x.key || '?',
          help: x.help ?? '',
          value: x.value ?? false,
          category: x.category ?? 'general',
          source: x.source ?? '',
        })),
      };
    },
  });
}

/** Toggle a behavioral flag. */
export function useSetFlag() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { key: string; value: boolean }) => {
      const { error } = await client.POST('/api/settings/flags/set', { body: vars });
      if (error) throw new Error('Set flag failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
