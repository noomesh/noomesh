// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';

const H = vi.hoisted(() => ({
  staged: { current: {} as Record<string, unknown> },
  mutate: vi.fn(),
  confirm: vi.fn(),
  isOperator: { current: true },
  toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}));

vi.mock('./usePrunes', async (importActual) => ({
  ...(await importActual<typeof import('./usePrunes')>()),
  useStagedPrunes: () => H.staged.current,
  useRestorePrune: () => ({ mutate: H.mutate, isPending: false, variables: undefined }),
}));
vi.mock('@metis/core', () => ({ useAuth: () => ({ isOperator: H.isOperator.current }) }));
vi.mock('@/components/ConfirmDialog', () => ({ useConfirm: () => H.confirm }));
vi.mock('sonner', () => ({ toast: H.toast }));

import { StagedPrunes } from './StagedPrunes';
import type { StagedPrune } from './usePrunes';

const ROW: StagedPrune = {
  kind: 'entity',
  stagingId: 's-1',
  label: 'Acme',
  detail: 'ORG',
  reason: 'orphan',
  stagedAt: '2026-09-20 06:00:00+00',
  runId: 'run1',
  edgeCount: 2,
  mentionCount: 5,
  purgeAt: Date.now() + 10 * 86_400_000 - 1000,
};
const loaded = (rows: StagedPrune[], note: string | null = null) => ({
  isLoading: false,
  isError: false,
  data: { rows, entityTotal: rows.length, edgeTotal: 0, note },
});

beforeEach(() => {
  H.isOperator.current = true;
  H.mutate.mockReset();
  H.confirm.mockReset();
});
afterEach(cleanup);

describe('StagedPrunes', () => {
  it('shows a loading state', () => {
    H.staged.current = { isLoading: true };
    render(<StagedPrunes />);
    expect(screen.getByText('Loading staged prunes…')).toBeTruthy();
  });

  it('shows the error plainly', () => {
    H.staged.current = { isLoading: false, isError: true, error: new Error('Prune staging API unavailable') };
    render(<StagedPrunes />);
    expect(screen.getByText('Prune staging API unavailable')).toBeTruthy();
  });

  it('explains the dry-run default when nothing is staged', () => {
    H.staged.current = loaded([], 'staging table not created yet — graph_prune has not run');
    render(<StagedPrunes />);
    const empty = screen.getByTestId('prunes-empty');
    expect(empty.textContent).toMatch(/Nothing is staged/);
    expect(empty.textContent).toMatch(/dry run/);
    expect(empty.textContent).toMatch(/has not run/);
  });

  it('lists a row with its reason and time left before purge', () => {
    H.staged.current = loaded([ROW]);
    render(<StagedPrunes />);
    expect(screen.getByText('Acme')).toBeTruthy();
    expect(screen.getByText('orphan')).toBeTruthy();
    expect(screen.getAllByText('10d left').length).toBeGreaterThan(0);
  });

  it('restores only after the confirmation is accepted', async () => {
    H.staged.current = loaded([ROW]);
    render(<StagedPrunes />);

    H.confirm.mockResolvedValueOnce(false);
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
    await waitFor(() => expect(H.confirm).toHaveBeenCalledTimes(1));
    expect(H.mutate).not.toHaveBeenCalled();

    H.confirm.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
    await waitFor(() => expect(H.mutate).toHaveBeenCalledTimes(1));
    expect(H.mutate.mock.calls[0]![0]).toMatchObject({ kind: 'entity', stagingId: 's-1' });
  });

  it('disables Restore below the operator role', () => {
    H.isOperator.current = false;
    H.staged.current = loaded([ROW]);
    render(<StagedPrunes />);
    const btn = screen.getByRole('button', { name: 'Restore' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.title).toMatch(/operator role/);
  });

  it('renders a dash, not 0, for counts the gateway did not send', () => {
    H.staged.current = loaded([{ ...ROW, edgeCount: null, mentionCount: null }]);
    (H.staged.current as { data: { entityTotal: number | null; edgeTotal: number | null } }).data.entityTotal = null;
    (H.staged.current as { data: { entityTotal: number | null; edgeTotal: number | null } }).data.edgeTotal = null;
    render(<StagedPrunes />);
    expect(screen.getByText(/— edges · — mentions/)).toBeTruthy();
    expect(screen.queryByText(/\b0 edges/)).toBeNull();
  });
});
