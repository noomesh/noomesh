// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

export interface Adapter {
  name: string;
  received: number;
  sent: number;
  errors: number;
}
export interface Recipient {
  id: string;
  channel: string;
  displayName: string;
  recipientId: string;
  notes: string;
  isDefault: boolean;
}
export interface ChannelsData {
  summary: { adapters: number; activeConvos: number; queueMode: string };
  adapters: Adapter[];
  recipients: Recipient[];
}

const KEY = ['channels'];

/** Channel adapter status + saved recipients (polled 30s). */
export function useChannels() {
  const client = useMetisClient();
  return useQuery<ChannelsData>({
    queryKey: KEY,
    refetchInterval: 30_000,
    queryFn: async () => {
      const [s, r] = await Promise.all([
        client.GET('/api/channels/status'),
        client.GET('/api/channels/saved-recipients'),
      ]);
      if (s.error) throw new Error('Channel status unavailable');
      const chMap = s.data?.channels ?? {};
      return {
        summary: {
          adapters: s.data?.channels_registered ?? Object.keys(chMap).length,
          activeConvos: s.data?.active_conversations ?? 0,
          queueMode: s.data?.queue_mode ?? '—',
        },
        adapters: Object.entries(chMap).map(([name, v]) => ({
          name,
          received: v?.stats?.received ?? 0,
          sent: v?.stats?.sent ?? 0,
          errors: v?.stats?.errors ?? 0,
        })),
        recipients: (r.data?.recipients ?? []).map((x) => ({
          id: x.id ?? '',
          channel: x.channel ?? '',
          displayName: x.display_name ?? '?',
          recipientId: x.recipient_id ?? '',
          notes: x.notes ?? '',
          isDefault: x.is_default ?? false,
        })),
      };
    },
  });
}

/** Add a saved recipient (POST /api/channels/saved-recipients). */
export function useAddRecipient() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      channel: string;
      recipientId: string;
      displayName?: string;
      notes?: string;
      isDefault?: boolean;
    }) => {
      const { error } = await client.POST('/api/channels/saved-recipients', {
        body: {
          channel: vars.channel,
          recipient_id: vars.recipientId,
          ...(vars.displayName ? { display_name: vars.displayName } : {}),
          ...(vars.notes ? { notes: vars.notes } : {}),
          ...(vars.isDefault ? { is_default: true } : {}),
        },
      });
      if (error) throw new Error('Add recipient failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Send a test message to verify a channel/recipient (POST /api/channels/test). */
export function useTestChannel() {
  const client = useMetisClient();
  return useMutation({
    mutationFn: async (vars: { channel: string; recipient: string; message?: string }) => {
      const { error } = await client.POST('/api/channels/test', {
        body: {
          channel: vars.channel,
          recipient: vars.recipient,
          ...(vars.message ? { message: vars.message } : {}),
        },
      });
      if (error) throw new Error('Test failed');
    },
  });
}

/** Delete a saved recipient. */
export function useDeleteRecipient() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE('/api/channels/saved-recipients/{recipient_db_id}', {
        params: { path: { recipient_db_id: id } },
      });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** google_chat → "Google Chat" */
export function prettyChannel(name: string): string {
  return name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
