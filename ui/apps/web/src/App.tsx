// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';
import { useIsMobile } from '@/lib/useMediaQuery';
import { ALL_TABS } from '@/shell/nav';
import { MobileBar } from '@/components/MobileBar';
import { Sidebar } from '@/components/Sidebar';
import { PanelPlaceholder } from '@/components/PanelPlaceholder';
import { LoginOverlay } from '@/components/LoginOverlay';
import { ChatPane } from '@/features/chat/ChatPane';
import { PANELS } from '@/shell/panels';
import { arrivalPanel } from '@/features/observability/grafanaArrival';
import { PairingPage } from '@/features/connections/PairingPage';

/**
 * Which of the two desktop columns are showing. One value rather than a
 * `panelHidden`/`chatHidden` pair, because that pair has a fourth state —
 * both hidden — that means an empty screen. This cannot express it.
 */
type Split = 'both' | 'chat' | 'panel';

export function App() {
  if (window.location.hash === '#/connect') return <PairingPage />;
  return <ConsoleApp />;
}

function ConsoleApp() {
  // `#/observability…` is where a bookmark of Grafana is sent (grafanaArrival.ts).
  const [active, setActive] = useState(
    () => (typeof window !== 'undefined' && arrivalPanel(window.location.hash)) || 'cluster',
  );
  const [split, setSplit] = useState<Split>('both');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const isMobile = useIsMobile();

  const hasPanel = active !== 'chat';
  const Panel = PANELS[active];
  const panelBody = Panel ? <Panel /> : <PanelPlaceholder tab={active} />;

  // On mobile the panel is a sheet over the chat, so "which sheet" and "which
  // tab" are the same question — no extra open/closed state to fall out of
  // sync. Closing the sheet is a return to the chat.
  const sheetOpen = isMobile && hasPanel;
  const closeSheet = () => setActive('chat');

  // Escape closes the drawer first, then the sheet — innermost layer wins.
  useEffect(() => {
    if (!isMobile || (!drawerOpen && !sheetOpen)) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (drawerOpen) setDrawerOpen(false);
      else closeSheet();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isMobile, drawerOpen, sheetOpen]);

  // Leaving mobile must not strand an open drawer over the desktop layout.
  useEffect(() => {
    if (!isMobile) setDrawerOpen(false);
  }, [isMobile]);

  const select = (id: string) => {
    setActive(id);
    setDrawerOpen(false);
  };

  if (isMobile) {
    return (
      <>
        <LoginOverlay />
        <div className="app mobile">
          <MobileBar active={active} onMenu={() => setDrawerOpen(true)} />

          {/* The chat is the screen; everything else arrives on top of it. */}
          <main className="main solo">
            <ChatPane panelHidden />
          </main>

          {sheetOpen && (
            <div className="sheet" role="dialog" aria-modal="true" aria-label={active}>
              <div className="sheet-head">
                <span className="sheet-title">{ALL_TABS[active]?.label ?? active}</span>
                <button
                  type="button"
                  className="sheet-close"
                  onClick={closeSheet}
                  aria-label="Back to chat"
                >
                  <svg viewBox="0 0 20 20" aria-hidden="true">
                    <path d="M6 6l8 8M14 6l-8 8" />
                  </svg>
                </button>
              </div>
              <div className="sheet-body">{panelBody}</div>
            </div>
          )}

          {drawerOpen && (
            <>
              <div className="scrim" onClick={() => setDrawerOpen(false)} aria-hidden="true" />
              <div className="drawer" role="dialog" aria-modal="true" aria-label="Navigation">
                <Sidebar active={active} onSelect={select} />
              </div>
            </>
          )}
        </div>
      </>
    );
  }

  // The Chat tab has no panel, so it is always chat-only regardless of what
  // the user last chose on another tab — and neither toggle is offered there.
  const effective: Split = hasPanel ? split : 'chat';
  const showPanel = effective !== 'chat';
  const chatCollapsed = effective === 'panel';

  return (
    <>
      <LoginOverlay />
      <div className="app">
        <Sidebar active={active} onSelect={setActive} />
        <main
          className={cn(
            'main',
            effective === 'chat' && 'solo',
            effective === 'panel' && 'railed',
          )}
        >
          {/* Always mounted: collapsing renders the rail from inside ChatPane,
              so the socket and the transcript survive being minimised. */}
          <ChatPane
            panelHidden={effective === 'chat'}
            collapsed={chatCollapsed}
            onTogglePanel={
              hasPanel ? () => setSplit((s) => (s === 'chat' ? 'both' : 'chat')) : undefined
            }
            onToggleChat={
              hasPanel ? () => setSplit((s) => (s === 'panel' ? 'both' : 'panel')) : undefined
            }
          />
          {showPanel && panelBody}
        </main>
      </div>
    </>
  );
}
