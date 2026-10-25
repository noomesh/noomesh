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
  refetch: vi.fn(),
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
  useConnectionActions: () => ({
    addAccount: { mutate: H.addAccount, isPending: false },
    addSource: { mutate: H.addSource, isPending: false },
    removeAccount: { mutate: H.removeAccount, isPending: false },
    removeSource: { mutate: vi.fn(), isPending: false },
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
  vi.clearAllMocks();
});
afterEach(cleanup);

describe('Connections drafts', () => {
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
    fireEvent.click(screen.getByRole('button', { name: 'Add Google account' }));
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
    fireEvent.click(screen.getByRole('button', { name: 'Save source draft' }));
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
    fireEvent.click(screen.getByRole('button', { name: 'Save source draft' }));
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
