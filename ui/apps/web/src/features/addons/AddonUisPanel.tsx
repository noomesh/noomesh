// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { sendTab, type TabHandle } from '@/features/observability/useGrafanaSession';
import { useAddonUis, useOpenAddonUi, type AddonUi } from './useAddonUis';

/**
 * Add-on web UIs. Each opens in a NEW TAB on the add-on's own origin (its own
 * port on this host): the add-on's scripts never run on this console's
 * origin, so they can never read what this console stores. The tab is
 * signed in by a one-time code the gateway mints for this browser.
 */
export function AddonUisPanel() {
  const { data, isLoading, isError, error } = useAddonUis();
  const open = useOpenAddonUi();
  const [notes, setNotes] = useState<Record<string, string>>({});

  async function onOpen(ui: AddonUi) {
    setNotes((n) => ({ ...n, [ui.addon]: '' }));
    // Before any await: a window.open after the POST resolves is what popup
    // blockers refuse.
    const tab: TabHandle =
      typeof window !== 'undefined' ? (window.open('', '_blank') as unknown as TabHandle) : null;
    try {
      const url = await open.mutateAsync(ui.addon);
      const sent = sendTab(tab, url, (u) => window.open(u, '_blank') as unknown as TabHandle);
      if (!sent) {
        setNotes((n) => ({ ...n, [ui.addon]: 'Your browser blocked the tab — allow pop-ups for this site and try again.' }));
      }
    } catch (e) {
      tab?.close?.();
      setNotes((n) => ({ ...n, [ui.addon]: (e as Error).message }));
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Add-ons</h2>
      </div>
      {isLoading && <div className="state">Loading add-ons…</div>}
      {isError && <div className="state err">{(error as Error)?.message ?? 'Failed to load'}</div>}
      {data &&
        (data.length ? (
          <ul className="addon-uis">
            {data.map((ui) => (
              <li key={ui.addon} className="addon-ui">
                <span className="addon-ui-title">{ui.title}</span>
                <span className="meta">
                  {ui.addon} · port {ui.port}
                </span>
                <Button
                  size="sm"
                  onClick={() => onOpen(ui)}
                  disabled={!ui.canOpen || (open.isPending && open.variables === ui.addon)}
                  title={
                    ui.canOpen
                      ? `Open ${ui.title} in a new tab, on its own origin`
                      : 'Your role may not open this add-on'
                  }
                >
                  {open.isPending && open.variables === ui.addon ? 'Opening…' : 'Open'}
                </Button>
                {notes[ui.addon] && <span className="state err">{notes[ui.addon]}</span>}
              </li>
            ))}
          </ul>
        ) : (
          <div className="state">No add-on with a web UI is enabled.</div>
        ))}
    </section>
  );
}
