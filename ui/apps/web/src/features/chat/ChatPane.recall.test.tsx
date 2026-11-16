// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

import { StatsFooter } from './ChatPane';

afterEach(cleanup);

// A turn answered without conversation memory says so in its detail line;
// a turn whose recall ran says nothing extra (the done frame's `recall`).
describe('StatsFooter recall line', () => {
  it('shows the skipped line with its reason', () => {
    render(
      <StatsFooter
        stats={{ elapsedSeconds: 3.1, recallSkipped: 'embedder not ready (timed out after 15 s)' }}
      />,
    );
    expect(screen.getByTestId('recall-skipped').textContent).toBe(
      'Memory recall skipped: embedder not ready (timed out after 15 s)',
    );
    expect(screen.getByText('3.1s')).toBeTruthy();
  });

  it('shows it even on a turn with no other accounting', () => {
    render(<StatsFooter stats={{ recallSkipped: 'embedder error: no embed target' }} />);
    expect(screen.getByTestId('recall-skipped').textContent).toBe(
      'Memory recall skipped: embedder error: no embed target',
    );
  });

  it('shows nothing about recall when it ran', () => {
    render(<StatsFooter stats={{ elapsedSeconds: 3.1 }} />);
    expect(screen.queryByTestId('recall-skipped')).toBeNull();
    expect(screen.queryByText(/Memory recall/)).toBeNull();
  });
});
