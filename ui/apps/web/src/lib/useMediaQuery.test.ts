// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useMediaQuery } from './useMediaQuery';

/** jsdom has no matchMedia — stub one whose matches can be flipped. */
function installMatchMedia(initial: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const mql = {
    matches: initial,
    addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.delete(fn),
  };
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => mql),
  );
  return {
    set(v: boolean) {
      mql.matches = v;
      for (const fn of listeners) fn({ matches: v } as MediaQueryListEvent);
    },
    listenerCount: () => listeners.size,
  };
}

beforeEach(() => vi.unstubAllGlobals());

describe('useMediaQuery', () => {
  it('reports the initial match', () => {
    installMatchMedia(true);
    const { result } = renderHook(() => useMediaQuery('(max-width: 860px)'));
    expect(result.current).toBe(true);
  });

  it('updates when the query starts matching', () => {
    const mm = installMatchMedia(false);
    const { result } = renderHook(() => useMediaQuery('(max-width: 860px)'));
    expect(result.current).toBe(false);

    act(() => mm.set(true));
    expect(result.current).toBe(true);
  });

  it('unsubscribes on unmount', () => {
    const mm = installMatchMedia(false);
    const { unmount } = renderHook(() => useMediaQuery('(max-width: 860px)'));
    expect(mm.listenerCount()).toBe(1);
    unmount();
    // A leaked listener would setState on an unmounted shell on every resize.
    expect(mm.listenerCount()).toBe(0);
  });
});
