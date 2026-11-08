// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from '@testing-library/react';
import type { ConnectionsData } from './useConnections';

const H = vi.hoisted(() => ({
  data: { current: null as unknown },
  addAccount: vi.fn(),
  addSource: vi.fn(),
  removeAccount: vi.fn(),
  syncSource: vi.fn(),
  refetch: vi.fn(),
  connect: vi.fn(),
  resources: [] as { id: string; name: string }[],
  failed: false,
}));
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/components/ConfirmDialog', () => ({
  useConfirm: () => vi.fn().mockResolvedValue(true),
}));
vi.mock('./useConnections', () => ({
  useConnections: () => ({
    data: H.data.current,
    isLoading: false,
    isError: H.failed,
    refetch: H.refetch,
  }),
  useGoogleConnect: () => ({
    connect: H.connect,
    pending: false,
    cancel: vi.fn(),
  }),
  useConnectionResources: () => ({
    items: H.resources,
    isLoading: false,
    isError: false,
  }),
  useConnectionActions: () => ({
    addAccount: { mutate: H.addAccount, isPending: false },
    addSource: { mutate: H.addSource, isPending: false },
    removeAccount: { mutate: H.removeAccount, isPending: false },
    removeSource: { mutate: vi.fn(), isPending: false },
    syncSource: { mutate: H.syncSource, isPending: false },
  }),
}));

import { ConnectionsPanel } from './ConnectionsPanel';

const a = '00000000-0000-4000-8000-000000000001';
const b = '00000000-0000-4000-8000-000000000002';
const data: ConnectionsData = {
  providers: [
    {
      id: 'google',
      name: 'Google',
      services: ['google_drive', 'gmail'],
      authorization_available: false,
      authorization_detail: 'Google sign-in is not available yet.',
    },
  ],
  accounts: [a, b].map((id, i) => ({
    id,
    label: i === 0 ? 'Work' : 'Personal',
    provider: 'google',
    status: 'needs_auth',
    email_hint: null,
    created_at: '2026-10-25T12:00:00Z',
  })),
  sources: [
    {
      id: 'source-a',
      account_id: a,
      name: 'Work mail',
      policy: { kind: 'gmail', exposure: 'selected_labels', label_ids: [] },
      status: 'draft',
      access: 'read_only',
      visibility: 'private',
      created_at: '2026-10-25T12:00:00Z',
    },
  ],
};

beforeEach(() => {
  H.data.current = data;
  H.failed = false;
  H.resources = [];
  vi.clearAllMocks();
  H.connect.mockResolvedValue(undefined);
});
afterEach(cleanup);

describe('Connections drafts', () => {
  it('starts sync only after the owner explicitly chooses it, and can pause', () => {
    H.data.current = { ...data,
      accounts: data.accounts.map(account => ({ ...account, status: 'connected' })),
      sources: data.sources.map(source => ({ ...source, sync_enabled: false })),
    };
    const rendered = render(<ConnectionsPanel />);
    expect(H.syncSource).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Start private sync' }));
    expect(H.syncSource).toHaveBeenCalledWith({ id: 'source-a', enabled: true }, expect.any(Object));
    H.data.current = { ...(H.data.current as ConnectionsData), sources: data.sources.map(source => ({ ...source, sync_enabled: true, sync_status: 'queued' })) };
    rendered.rerender(<ConnectionsPanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Pause sync' }));
    expect(H.syncSource).toHaveBeenLastCalledWith({ id: 'source-a', enabled: false }, expect.any(Object));
  });
  it('saves real label selections under the connected account and respects partial consent', () => {
    H.data.current = {
      ...data,
      accounts: data.accounts.map((account) =>
        account.id === a
          ? {
              ...account,
              status: 'connected',
              email: 'verified@example.test',
              granted_scopes: [
                'https://www.googleapis.com/auth/gmail.readonly',
              ],
            }
          : account,
      ),
    };
    H.resources = [{ id: 'Label_42', name: 'Team mail' }];
    render(<ConnectionsPanel />);
    const work = within(screen.getByRole('article', { name: 'Work' }));
    expect(work.getByText('Connected')).toBeTruthy();
    expect(work.getByText('verified@example.test')).toBeTruthy();
    fireEvent.click(work.getByRole('button', { name: 'Add source' }));
    expect(
      (work.getByRole('option', { name: 'Google Drive' }) as HTMLOptionElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(work.getByRole('checkbox', { name: 'Team mail' }));
    fireEvent.click(work.getByRole('button', { name: 'Save source settings' }));
    expect(H.addSource).toHaveBeenCalledWith(
      expect.objectContaining({
        account_id: a,
        policy: {
          kind: 'gmail',
          exposure: 'selected_labels',
          label_ids: ['Label_42'],
          lookback_days: 30,
        },
      }),
      expect.anything(),
    );
  });

  it('groups sources under their account and never claims a draft is connected', () => {
    render(<ConnectionsPanel />);
    expect(
      within(screen.getByRole('article', { name: 'Work' })).getByText(
        'Work mail',
      ),
    ).toBeTruthy();
    expect(
      within(screen.getByRole('article', { name: 'Personal' })).queryByText(
        'Work mail',
      ),
    ).toBeNull();
    expect(screen.getAllByText('Needs sign-in')).toHaveLength(2);
    for (const button of screen.getAllByRole('button', {
      name: 'Sign in with Google',
    }))
      expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Draft · Private · Read only')).toBeTruthy();
    expect(screen.getByText(/Choose labels after sign-in/)).toBeTruthy();
  });

  it('can prepare another account with an optional hint without asserting a Google identity', () => {
    render(<ConnectionsPanel />);
    fireEvent.click(
      screen.getByRole('button', { name: 'Prepare account draft' }),
    );
    fireEvent.change(screen.getByLabelText('Account name'), {
      target: { value: 'Another account' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save account draft' }));
    expect(H.addAccount.mock.calls[0][0]).toEqual({
      label: 'Another account',
      email_hint: null,
    });
  });

  it('attaches a read-only Gmail draft to the selected account with a small default history', () => {
    render(<ConnectionsPanel />);
    fireEvent.click(
      within(screen.getByRole('article', { name: 'Personal' })).getByRole(
        'button',
        { name: 'Add source' },
      ),
    );
    fireEvent.change(screen.getByLabelText('Service'), {
      target: { value: 'gmail' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save source settings' }),
    );
    expect(H.addSource.mock.calls[0][0]).toEqual({
      account_id: b,
      name: 'Gmail',
      policy: {
        kind: 'gmail',
        exposure: 'selected_labels',
        label_ids: [],
        lookback_days: 30,
      },
    });
  });

  it('keeps a one-drive draft distinct from all accessible files', () => {
    render(<ConnectionsPanel />);
    fireEvent.click(
      within(screen.getByRole('article', { name: 'Work' })).getByRole(
        'button',
        { name: 'Add source' },
      ),
    );
    fireEvent.change(screen.getByLabelText('Content to use'), {
      target: { value: 'drive' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save source settings' }),
    );
    expect(H.addSource.mock.calls[0][0].policy).toEqual({
      kind: 'google_drive',
      exposure: 'selected_drive',
      folder_ids: [],
    });
  });

  it('shows an actionable storage failure without an empty-account claim', () => {
    H.data.current = undefined;
    H.failed = true;
    render(<ConnectionsPanel />);
    expect(screen.getByRole('alert').textContent).toContain('Unable to load');
    expect(screen.queryByText(/Add your first/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(H.refetch).toHaveBeenCalledOnce();
  });
});
