// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

const H = vi.hoisted(() => ({ data: { current: null as unknown } }));

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock('./useMemory', () => ({
  useMemory: () => ({ data: H.data.current, isLoading: false, isError: false }),
  useEmbedControl: () => ({ mutate: vi.fn(), isPending: false }),
}));

import { MemoryPanel } from './MemoryPanel';

afterEach(cleanup);

const tileValue = (label: string) =>
  screen.getByText(label).parentElement!.querySelector('.v')!.textContent;

describe('MemoryPanel — a number the gateway did not send is a dash', () => {
  it('renders dashes, not 0, when every count is null', () => {
    H.data.current = {
      worker: { state: 'running', processed: null, embedded: null, failed: null, relationships: null },
      storage: { total: null, embedded: null, unembedded: null, users: null },
      conv: { conversations: null, messages: null, toolCalls: null, avgMessages: null },
      tools: [{ name: 't', calls: null, successful: null, successRate: null, avgMs: null }],
    };
    render(<MemoryPanel />);
    expect(tileValue('Records')).toBe('—');
    expect(tileValue('Unembedded')).toBe('—');
    expect(tileValue('Messages')).toBe('—');
    expect(tileValue('Avg msgs')).toBe('—');
    expect(screen.getByText(/Storage · — embedded/)).toBeTruthy();
    expect(screen.getByText('— calls')).toBeTruthy();
  });

  it('still renders a reported zero as 0', () => {
    H.data.current = {
      worker: { state: 'running', processed: 0, embedded: 0, failed: 0, relationships: 0 },
      storage: { total: 0, embedded: 0, unembedded: 0, users: 0 },
      conv: { conversations: 0, messages: 0, toolCalls: 0, avgMessages: 0 },
      tools: [],
    };
    render(<MemoryPanel />);
    expect(tileValue('Records')).toBe('0');
    expect(tileValue('Avg msgs')).toBe('0.0');
  });
});
