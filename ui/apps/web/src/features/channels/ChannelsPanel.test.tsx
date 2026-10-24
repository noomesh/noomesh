// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

const H = vi.hoisted(() => ({ data: { current: null as unknown } }));

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/components/ConfirmDialog', () => ({ useConfirm: () => vi.fn() }));
vi.mock('./useChannels', async (importActual) => ({
  ...(await importActual<typeof import('./useChannels')>()),
  useChannels: () => ({ data: H.data.current, isLoading: false, isError: false }),
  useAddRecipient: () => ({ mutate: vi.fn(), isPending: false }),
  useDeleteRecipient: () => ({ mutate: vi.fn(), isPending: false }),
  useTestChannel: () => ({ mutate: vi.fn(), isPending: false }),
}));

import { ChannelsPanel } from './ChannelsPanel';

afterEach(cleanup);

describe('ChannelsPanel — unmeasured traffic', () => {
  it('renders the gateway detail text, not zeros, when stats are null', () => {
    H.data.current = {
      summary: { adapters: 1, activeConvos: null, queueMode: 'x' },
      adapters: [{ name: 'telegram', received: null, sent: null, errors: null, statsDetail: 'not tracked — no counters exist' }],
      recipients: [],
    };
    render(<ChannelsPanel />);
    expect(screen.getByText('not tracked — no counters exist')).toBeTruthy();
    expect(screen.getByText(/— active/)).toBeTruthy();
    expect(screen.queryByText(/errors/)).toBeNull();
  });
});
