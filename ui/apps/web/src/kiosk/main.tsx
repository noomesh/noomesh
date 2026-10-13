// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Kiosk entry — the second bundle (kiosk.html → here). Imports the transport
// from @metis/api and nothing from src/features or src/shell; see
// isolation.test.ts, which asserts that rather than trusting it.
//
// Auth is the console's inverse: no login overlay, no refresh — and, since
// 2026-09-06, NO CREDENTIAL IN THIS PAGE AT ALL.
//
// It used to hold one: the host launcher wrote a short-lived read-only token
// into localStorage over CDP (an earlier change.1) and re-minted it before
// expiry. That worked, and it put a bearer token in the DOM of a machine
// standing unattended in a corridor. "Locked in kiosk mode" means no window
// manager; it does not mean no USB port and no devtools.
//
// So the credential moved off the page and onto the device's filesystem.
// `noo kiosk serve` (pai-assistant, an earlier change mechanism 1) runs on this
// box, holds a service key 0600, serves THIS bundle, and proxies a fixed
// allow-list of reads to the gateway over the tailnet. The browser's only
// hop is 127.0.0.1 — it never learns the controller URL and carries nothing
// worth extracting.
//
// `baseUrl: ''` is unchanged and now means the local proxy rather than the
// gateway, which is why nothing else in this file had to move.
//
// A 401 still turns the liveness band red; it just means "the proxy's key is
// wrong or revoked" instead of "the launcher did not inject a token". The
// page still never asks anyone to log in, because nobody is there.

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createMetisClient } from '@metis/api';
import '@metis/tokens/tokens.css';
import './kiosk.css';
import { KioskShell, isView } from './KioskShell';
import { CONSOLE_BUILD } from './build';

// No token store, no bearer fetch, no `KIOSK_TOKEN_KEY`. All three are gone
// on purpose: the local proxy attaches the Authorization header, so anything
// here that could hold a credential is a credential this page can leak.
//
// Deleting `KIOSK_TOKEN_KEY` also retires the CDP injection step from the
// host launcher — the display is configured by a systemd unit and a key file,
// with nothing written into the browser.
const client = createMetisClient({ baseUrl: '' });

// The URL sets the starting view — so a display is
// configured by editing one string in its systemd unit, and the gateway
// needs one route, not one per view. From there, a swipe, the arrow keys,
// or `rotate` move between views (KioskShell).
//   /kiosk.html                       the health view
//   /kiosk.html?view=graph            the knowledge graph, entity level
//                                     (names only while the controller's
//                                     kiosk.graph_labels is on — `noo kiosk
//                                     labels on|off`; there is no page
//                                     parameter for it, so a display cannot
//                                     be configured into showing them)
//   /kiosk.html?rotate=180            cycle views every three minutes
//   /kiosk.html?view=graph&poll=10    re-fetch the graph every 10 s — a stopgap
//                                     until the gateway streams graph.delta
// Publish the build before anything else can fail: if the page throws while
// starting, "which console is this?" is the first question and the answer
// must already be there. Also keeps the literal in the bundle for the
// curl+grep check that needs no browser at all.
window.__nooKioskBuild = CONSOLE_BUILD;

declare global {
  interface Window {
    /** The stack tag this console was built from; `dev` outside a release. */
    __nooKioskBuild?: string;
  }
}

const params = new URLSearchParams(location.search);
const view = params.get('view');
// `?quality=lean|full` pins the graph's drawing quality. Unset, the page
// measures its own frames and degrades on a slow machine (graph/quality.ts).
const q = params.get('quality');
const quality = q === 'lean' || q === 'full' ? q : undefined;
const rotateS = Math.max(0, Number(params.get('rotate') ?? 0) || 0);
const pollS = Math.max(0, Number(params.get('poll') ?? 0) || 0);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <KioskShell client={client} initial={isView(view) ? view : 'health'} rotateS={rotateS} pollS={pollS} quality={quality} />
  </StrictMode>,
);
