// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// What the controller set for this display (i510 c1): `noo kiosk seats set
// <seat> quality|view|rotate|poll <value>`. The page reads it through its own
// proxy (`GET /api/kiosk/display`, kiosk-scoped, the seat comes from the
// token) and, when it differs from the URL it was started with, reloads onto
// the new URL. A reload, not a browser restart: nothing at the box changes
// and nothing there needs privilege. A key the controller never set keeps
// the box's own value (/etc/default/kiosk, via the launcher's URL).

export type Display = {
  quality?: string;
  view?: string;
  rotate?: number;
  poll?: number;
};

const KEYS = ['quality', 'view', 'rotate', 'poll'] as const;

/**
 * The search string the page should be on: the controller's value for each
 * key it set, the URL's own otherwise. `auto` quality and a 0 rotate or poll
 * drop the parameter (the page's own default). `null` when the page is
 * already there, so a reload can never loop.
 */
export function displaySearch(search: string, display: Display): string | null {
  const params = new URLSearchParams(search);
  for (const k of KEYS) {
    const v = display[k];
    if (v === undefined || v === null) continue;
    if (k === 'quality' && v === 'auto') params.delete(k);
    else if ((k === 'rotate' || k === 'poll') && Number(v) === 0) params.delete(k);
    else params.set(k, String(v));
  }
  const next = params.toString();
  return next === new URLSearchParams(search).toString() ? null : `?${next}`;
}

/**
 * Ask once at start, then every `everyMs`. A read that fails changes
 * nothing on screen (the band already shows a gateway that is away) and is
 * said in the console, not swallowed.
 */
export function watchDisplay(everyMs = 60_000): () => void {
  const check = async () => {
    try {
      const r = await fetch('/api/kiosk/display', { cache: 'no-store' });
      if (!r.ok) {
        console.warn(`kiosk display settings: ${r.status} ${r.statusText}`);
        return;
      }
      const body = (await r.json()) as { display?: Display };
      const next = displaySearch(location.search, body.display ?? {});
      if (next !== null) location.replace(location.pathname + next);
    } catch (e) {
      console.warn('kiosk display settings unreadable:', e);
    }
  };
  void check();
  const id = setInterval(() => void check(), everyMs);
  return () => clearInterval(id);
}
