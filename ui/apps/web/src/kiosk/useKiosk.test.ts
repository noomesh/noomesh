// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The hook's WIRING. The judgements it makes are pure functions in the
// store (`liveness`, `shouldRefreshData`) and are tested there; what is
// left here is what those functions are connected to, which is where this
// bug actually lived:
//
//  - the watchdog heartbeat was fed from the data clock, so it is now fed
//    from the contact clock, and
//  - nothing was connected to "the picture has gone stale" at all, so a
//    stream that stayed open and carried nothing never refetched. The
//    operator reclustered twice and the display showed neither result.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, cleanup } from '@testing-library/react';

type Cbs = {
  onOpen: () => void;
  onEvent: (e: { id: string | null; event: string; data: string }) => void;
  onKeepalive: () => void;
  onAuthFail: (status: number) => void;
};
const cbs: { current: Cbs | null } = { current: null };
let reconnects = 0;

vi.mock('@metis/api', () => ({
  createEventStream: (_path: string, opts: Cbs) => {
    cbs.current = opts;
    return { lastEventId: null, connected: true, setStallMs: () => {}, reconnectNow: () => { reconnects++; }, close: () => {} };
  },
}));

const { useKiosk } = await import('./useKiosk');
const { REFRESH_DATA_AFTER_MS } = await import('./store');
const { AUTH_RETRY_MS } = await import('./useKiosk');

/** Module-level so its identity is stable across renders (see mount). */
const SOURCES = ['scheduler'] as const;

const T0 = 1_700_000_000_000;

describe('useKiosk wiring', () => {
  let calls: string[];
  let heartbeats: number[];

  // Every dep is created ONCE and reused across renders. The hook's effect
  // keys on them, so an inline object here re-runs the effect on every
  // state update — which re-fetches, which updates state. The first draft
  // of this file did that and made 186,849 requests before the timeout,
  // with two of the four assertions passing off the flood.
  const mount = () => {
    calls = [];
    heartbeats = [];
    const client = {
      GET: (p: string) => {
        calls.push(p);
        return Promise.resolve({ data: { running: true, paused: false }, response: { ok: true } });
      },
    } as never;
    const deps = {
      client,
      sources: SOURCES,
      reload: () => {},
      publishHeartbeat: (at: number) => heartbeats.push(at),
    };
    renderHook(() => useKiosk(deps));
  };

  /** Jump the clock, then let exactly one 1s tick run. */
  const jump = async (ms: number) => {
    vi.setSystemTime(new Date(Date.now() + ms));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
  };

  /** Mount and let the connect snapshot settle. Called by each test, not
   *  from beforeEach: cleanup() has to run with the fake clock still
   *  installed, and interleaving the two in hooks hung the runner. */
  const start = async () => {
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(cbs.current).not.toBeNull();
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(T0));
    cbs.current = null;
    reconnects = 0;
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it('fetches the snapshot on connect', async () => {
    await start();
    expect(calls).toContain('/api/scheduler/status');
  });

  it('re-fetches when a healthy stream has carried nothing for the window', async () => {
    await start();
    const before = calls.length;
    // Keepalives right up to the edge: the connection is perfectly fine,
    // which is exactly why the old code sat there for hours.
    await jump(REFRESH_DATA_AFTER_MS - 2000);
    act(() => cbs.current!.onKeepalive());
    expect(calls.length).toBe(before);

    await jump(5000);
    act(() => cbs.current!.onKeepalive());
    await jump(0);
    expect(calls.length).toBeGreaterThan(before);
  });

  it('does not re-fetch while events keep arriving', async () => {
    await start();
    const before = calls.length;
    for (let i = 0; i < 3; i++) {
      await jump(REFRESH_DATA_AFTER_MS - 5000);
      act(() =>
        cbs.current!.onEvent({
          id: `e${i}`,
          event: 'node.state',
          data: JSON.stringify({ node_id: 'a', status: i % 2 ? 'online' : 'busy' }),
        }),
      );
    }
    await jump(1000);
    expect(calls.length).toBe(before);
  });

  it('publishes the watchdog heartbeat on a keepalive: it asks about the page, not the data', async () => {
    await start();
    const before = heartbeats.length;
    await jump(5000);
    act(() => cbs.current!.onKeepalive());
    expect(heartbeats.length).toBeGreaterThan(before);
    expect(heartbeats.at(-1)).toBe(Date.now());
  });

  // The display's proxy re-mints its own credential, so a refusal is
  // transient. The stream client gives up on 401/403 by design; the page
  // must come back for it, or the band reads "credential rejected" for
  // good while the polled tiles keep updating underneath.
  it('retries the stream after an auth failure, once per window', async () => {
    await start();
    act(() => cbs.current!.onAuthFail(401));
    act(() => cbs.current!.onAuthFail(401));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(AUTH_RETRY_MS - 1000);
    });
    expect(reconnects).toBe(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(reconnects).toBe(1);
  });
});
