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
import { useEffect, useRef, useState } from 'react';

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
      if (error) throw new Error('Unable to remove the account.');
    },
    onSuccess: async (_data, id: string) => {
      const queryKey = ['connection-resources', user?.username, id];
      await qc.cancelQueries({ queryKey });
      qc.removeQueries({ queryKey });
      await refresh();
    },
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

/** The callback page has no credentials or mutation authority. A random
 * channel delivers its code to this authenticated window; the completion
 * ticket stays in memory here and is never sent to Google or in a URL. */
export function useGoogleConnect() {
  const client = useMetisClient();
  const qc = useQueryClient();
  const { user } = useAuth();
  const [pending, setPending] = useState(false);
  const active = useRef(false);
  const dispose = useRef<(() => void) | null>(null);
  useEffect(
    () => () => {
      dispose.current?.();
    },
    [user?.username],
  );
  async function connect(
    services: ('google_drive' | 'gmail')[],
    accountId?: string,
  ): Promise<void> {
    if (active.current)
      throw new Error('Finish or cancel the current Google sign-in.');
    if (typeof BroadcastChannel === 'undefined')
      throw new Error(
        'Use a browser with BroadcastChannel support, or the noo auth connect google helper.',
      );
    // Open synchronously while the click still has browser activation.
    const popup = window.open(
      'about:blank',
      '_blank',
      'popup,width=560,height=760',
    );
    if (!popup)
      throw new Error('Allow pop-ups for Noomesh, then connect again.');
    active.current = true;
    setPending(true);
    let cancelled = false;
    dispose.current = () => {
      cancelled = true;
    };
    let session: components['schemas']['ConnectionOAuthSession'] | undefined;
    let channel: BroadcastChannel | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let settled = false;
    try {
      const { data, error } = await client.POST(
        '/api/connections/oauth/start',
        {
          body: {
            provider: 'google',
            client_kind: 'web',
            services,
            ...(accountId ? { account_id: accountId } : {}),
          },
        },
      );
      if (error || !data)
        throw new Error(
          'Google sign-in could not start. Check the installer configuration and try again.',
        );
      session = data;
      if (cancelled) throw new Error('Google sign-in cancelled.');
      const authorization = new URL(data.authorization_url);
      if (
        authorization.origin !== 'https://accounts.google.com' ||
        authorization.pathname !== '/o/oauth2/v2/auth'
      )
        throw new Error('Unexpected Google sign-in URL.');
      await new Promise<void>((resolve, reject) => {
        const finish = (error?: Error) => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve();
        };
        dispose.current = () => {
          cancelled = true;
          finish(new Error('Google sign-in cancelled.'));
        };
        timer = setTimeout(
          () => finish(new Error('Google sign-in expired. Connect again.')),
          Math.min(data.expires_in, 600) * 1000,
        );
        channel = new BroadcastChannel(`noomesh:oauth:${data.state}`);
        let completing = false;
        channel.onmessage = async (event: MessageEvent) => {
          const message = event.data;
          if (
            !message ||
            message.type !== 'noomesh:oauth-result' ||
            message.state !== data.state ||
            completing ||
            settled
          )
            return;
          if (message.error) {
            finish(
              new Error(
                'Google access was declined. Connect again when ready.',
              ),
            );
            return;
          }
          if (
            typeof message.code !== 'string' ||
            !message.code ||
            message.code.length > 8192
          )
            return;
          completing = true;
          try {
            const result = await client.POST(
              '/api/connections/oauth/complete',
              {
                body: {
                  session_id: data.session_id,
                  completion_token: data.completion_token,
                  state: data.state,
                  code: message.code,
                },
              },
            );
            if (result.error || !result.data)
              throw new Error(
                'Google could not finish connecting. Approve access and try again.',
              );
            await qc.invalidateQueries({
              queryKey: ['connections', user?.username],
            });
            finish();
          } catch (error) {
            finish(
              error instanceof Error
                ? error
                : new Error('Unable to finish Google sign-in.'),
            );
          }
        };
        popup.location.href = authorization.href;
      });
    } finally {
      if (timer) clearTimeout(timer);
      channel?.close();
      popup.close();
      dispose.current = null;
      active.current = false;
      setPending(false);
      if (session)
        void client
          .POST('/api/connections/oauth/cancel', {
            body: { session_id: session.session_id },
          })
          .catch(() => {});
    }
  }
  return { connect, pending, cancel: () => dispose.current?.() };
}

export function useConnectionResources(
  accountId: string | null,
  service: 'folders' | 'drives' | 'gmail',
  enabled: boolean,
) {
  const client = useMetisClient();
  const { user } = useAuth();
  const key = JSON.stringify([user?.username, accountId, service]);
  const [pagination, setPagination] = useState<{
    key: string;
    items: components['schemas']['ConnectionResources']['items'];
    page?: string;
  }>({ key, items: [] });
  const current = pagination.key === key ? pagination : { key, items: [] };
  const page = current.page;
  const query = useQuery({
    queryKey: [
      'connection-resources',
      user?.username,
      accountId,
      service,
      page,
    ],
    enabled: !!user && !!accountId && enabled,
    queryFn: async () => {
      const { data, error } = await client.GET(
        '/api/connections/accounts/{id}/resources',
        {
          params: {
            path: { id: accountId! },
            query: { service, ...(page ? { page } : {}) },
          },
        },
      );
      if (error || !data)
        throw new Error(
          'Unable to list Google content. Reconnect if access has expired or was not approved.',
        );
      return data;
    },
  });
  return {
    ...query,
    items: [...current.items, ...(query.data?.items ?? [])],
    more: () => {
      if (query.data?.next_page_token) {
        setPagination({
          key,
          items: [...current.items, ...query.data.items],
          page: query.data.next_page_token,
        });
      }
    },
  };
}
