// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import {
  useAuth,
  useMetisClient,
  useMutation,
  useQuery,
  useQueryClient,
} from '@metis/core';
import type { components } from '@metis/api';

export type Account = components['schemas']['ConnectionAccount'];
export type Source = components['schemas']['ConnectionSource'];
export type SourcePolicy = components['schemas']['ConnectionSourcePolicy'];
export type AccountDraft = components['schemas']['ConnectionAccountDraft'];
export type SourceDraft = components['schemas']['ConnectionSourceDraft'];
export type ConnectionsData = components['schemas']['ConnectionsResponse'];

export function useConnections() {
  const client = useMetisClient();
  const { user } = useAuth();
  return useQuery({
    queryKey: ['connections', user?.username],
    enabled: !!user,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/connections');
      if (error || !data)
        throw new Error('Unable to load your connections. Try again.');
      return data;
    },
  });
}

export function useConnectionActions() {
  const client = useMetisClient();
  const qc = useQueryClient();
  const { user } = useAuth();
  const refresh = () =>
    qc.invalidateQueries({ queryKey: ['connections', user?.username] });
  const addAccount = useMutation({
    mutationFn: async (body: AccountDraft) => {
      const { data, error } = await client.POST('/api/connections/accounts', {
        body,
      });
      if (error || !data) throw new Error('Unable to save the account draft.');
      return data;
    },
    onSuccess: refresh,
  });
  const addSource = useMutation({
    mutationFn: async (body: SourceDraft) => {
      const { data, error } = await client.POST('/api/connections/sources', {
        body,
      });
      if (error || !data) throw new Error('Unable to save the source draft.');
      return data;
    },
    onSuccess: refresh,
  });
  const removeAccount = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE('/api/connections/accounts/{id}', {
        params: { path: { id } },
      });
      if (error) throw new Error('Unable to remove the account draft.');
    },
    onSuccess: refresh,
  });
  const removeSource = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE('/api/connections/sources/{id}', {
        params: { path: { id } },
      });
      if (error) throw new Error('Unable to remove the source draft.');
    },
    onSuccess: refresh,
  });
  return { addAccount, addSource, removeAccount, removeSource };
}
