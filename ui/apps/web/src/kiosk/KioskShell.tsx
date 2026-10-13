// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The shell: one store, one stream, several views. The views are pure
// renderers of shared state, so switching between them costs nothing —
// the stream stays open, the health view's transitions log survives, and
// "duration is the payload" keeps its durations. Only the graph canvas
// mounts and unmounts.
//
// Switching is navigation, not action: the credential is read-only whatever
// the display does, so a swipe can change what is shown and nothing else.
// Three ways, because the hardware varies — a tablet has touch, a laptop
// under `cage` has a trackpad and arrow keys, and a screen with no input at
// all can cycle on a timer:
//   - swipe left / right (touch, trackpad drag, mouse) — gesture.ts
//   - ← / → keys
//   - `?rotate=<seconds>` auto-cycles; a manual switch pauses it a while
// No target to hit, nothing a swipe can damage: safe to do blind.

import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import type { MetisClient } from '@metis/api';
import { useKiosk, useBurnInDrift } from './useKiosk';
import { SOURCES, GRAPH_SOURCES } from './store';
import { recognizeSwipe, type PointerSample } from './gesture';
import { Kiosk } from './Kiosk';
import { GraphKiosk } from './GraphKiosk';
import type { Quality } from './graph/quality';

export const VIEWS = ['health', 'graph'] as const;
export type ViewName = (typeof VIEWS)[number];
export const isView = (s: string | null): s is ViewName => VIEWS.includes(s as ViewName);

/** After a manual switch, auto-rotation waits this long before resuming. */
const ROTATE_PAUSE_MS = 5 * 60_000;

export interface KioskShellProps {
  client: MetisClient;
  /** Optional: the kiosk itself passes none — the local proxy holds the key. Kept for tests and for any embedding that does carry one. */
  getToken?: () => string | null;
  initial: ViewName;
  /** Seconds between automatic view changes; 0 = never. */
  rotateS: number;
  /** Seconds between graph re-fetches; 0 = never (the default, and the design). */
  pollS: number;
  /** `?quality=lean|full` pins the graph's drawing quality; unset = the page decides. */
  quality?: Quality;
}

export function KioskShell({ client, getToken, initial, rotateS, pollS, quality }: KioskShellProps) {
  // Every source: the health view's seven and the graph view's two. Cheap,
  // and it means a switch never has to wait for a snapshot.
  const poll = useMemo(() => (pollS > 0 ? { everyMs: pollS * 1000, sources: GRAPH_SOURCES } : undefined), [pollS]);
  const { state, now } = useKiosk({ client, getToken, sources: SOURCES, poll });
  useBurnInDrift();

  const [idx, setIdx] = useState(() => Math.max(0, VIEWS.indexOf(initial)));
  const [gen, setGen] = useState(0); // bumps to replay the entry fade
  const pausedUntil = useRef(0);

  const go = useCallback((dir: 1 | -1, manual: boolean) => {
    setIdx((i) => (i + dir + VIEWS.length) % VIEWS.length);
    setGen((g) => g + 1);
    if (manual) pausedUntil.current = Date.now() + ROTATE_PAUSE_MS;
  }, []);

  // Pointer swipe. Pointer events cover touch, pen, trackpad and mouse alike.
  const down = useRef<PointerSample | null>(null);
  const onPointerDown = (e: ReactPointerEvent) => {
    down.current = { x: e.clientX, y: e.clientY, t: performance.now() };
  };
  const onPointerUp = (e: ReactPointerEvent) => {
    const d = down.current;
    down.current = null;
    if (!d) return;
    const dir = recognizeSwipe(d, { x: e.clientX, y: e.clientY, t: performance.now() });
    if (dir !== 0) go(dir, true);
  };
  const onPointerCancel = () => {
    down.current = null;
  };

  // Keys.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight') go(1, true);
      else if (e.key === 'ArrowLeft') go(-1, true);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go]);

  // Auto-rotate, for a display with no input at all.
  useEffect(() => {
    if (!rotateS || rotateS <= 0) return;
    const id = setInterval(() => {
      if (Date.now() >= pausedUntil.current) go(1, false);
    }, rotateS * 1000);
    return () => clearInterval(id);
  }, [rotateS, go]);

  const view = VIEWS[idx]!;
  const pager = { count: VIEWS.length, index: idx };
  return (
    <div className="kiosk-shell" onPointerDown={onPointerDown} onPointerUp={onPointerUp} onPointerCancel={onPointerCancel}>
      <div key={gen} className="kiosk-view">
        {view === 'graph' ? (
          <GraphKiosk state={state} now={now} pager={pager} quality={quality} />
        ) : (
          <Kiosk state={state} now={now} pager={pager} />
        )}
      </div>
    </div>
  );
}
