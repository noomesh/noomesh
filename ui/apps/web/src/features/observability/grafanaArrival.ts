// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Arriving from a bookmark of Grafana.
 *
 * Grafana has no login of its own: sign-in is this console's "Open Grafana".
 * A browser that reaches Grafana's port with no session — a bookmark, a
 * typed URL, a session that expired — is sent by `tailscale serve` (its
 * `/login` → Grafana's `/logout` → `signout_redirect_url`) to
 * `<console>/#/observability?open=grafana`. The console's own login applies
 * first; then the Observe panel opens Grafana for the visitor.
 *
 * In the SAME tab, by navigation (`location.replace`): the visitor typed
 * Grafana's address into this tab, and a navigation is never a popup, so
 * the click-time popup logic of the button is not needed and not touched.
 * Nothing of the console's goes to Grafana's origin but the URL the gateway
 * minted for it.
 *
 * A Grafana that rejects every token would bounce the tab straight back
 * here; the second arrival inside {@link AUTO_OPEN_GAP_MS} does not reopen,
 * it says so and leaves the button.
 */

/** The hash `noo-cli` derives into `NOO_GRAFANA_CONSOLE_URL` (tailnet_serve.rs). */
export const OPEN_GRAFANA_HASH = '#/observability?open=grafana';

/** The panel a hash asks for, or null. Only `#/observability` is routed. */
export function arrivalPanel(hash: string): string | null {
  return /^#\/observability(?:\?|$)/.test(hash) ? 'observability' : null;
}

/** Whether a hash asks the Observe panel to open Grafana on arrival. */
export function arrivalAsksForGrafana(hash: string): boolean {
  const m = /^#\/observability\?(.*)$/.exec(hash);
  return !!m && new URLSearchParams(m[1]).get('open') === 'grafana';
}

/** A second automatic open sooner than this is a loop, not a bookmark. */
export const AUTO_OPEN_GAP_MS = 60_000;
export const AUTO_OPEN_KEY = 'noo.grafana.autoOpenedAt';

/** Whether to open automatically, given when this tab last did (or null). */
export function mayAutoOpen(lastAt: number | null, now: number): boolean {
  return lastAt === null || now < lastAt || now - lastAt >= AUTO_OPEN_GAP_MS;
}

type Store = Pick<Storage, 'getItem' | 'setItem'>;

/** When this tab last opened Grafana automatically; null when unknown
 * (storage blocked or empty — then the guard cannot hold, and one open is
 * still the right answer). */
export function lastAutoOpen(store: () => Store): number | null {
  try {
    const v = Number(store().getItem(AUTO_OPEN_KEY));
    return Number.isFinite(v) && v > 0 ? v : null;
  } catch {
    return null;
  }
}

export function recordAutoOpen(store: () => Store, now: number): void {
  try {
    store().setItem(AUTO_OPEN_KEY, String(now));
  } catch {
    /* storage blocked: the guard degrades to "always open once" */
  }
}

/** Drop the arrival hash so a reload does not open Grafana again. */
export function clearArrival(win: Pick<Window, 'location' | 'history'>): void {
  try {
    win.history.replaceState(win.history.state, '', win.location.pathname + win.location.search);
  } catch {
    /* no history API: a reload reopens Grafana, which is harmless */
  }
}
