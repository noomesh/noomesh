// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { ALL_TABS } from '@/shell/nav';

/**
 * Mobile top bar: the only always-visible chrome once the sidebar is gone.
 * The hamburger opens the nav drawer; the title names the sheet you're in, or
 * the brand when you're on the chat.
 */
export function MobileBar({ active, onMenu }: { active: string; onMenu: () => void }) {
  const onChat = active === 'chat';

  return (
    <header className="mbar">
      <button
        type="button"
        className="mbar-menu"
        onClick={onMenu}
        aria-label="Open navigation"
        aria-haspopup="dialog"
      >
        <svg viewBox="0 0 20 20" aria-hidden="true">
          <path d="M3 5.5h14M3 10h14M3 14.5h14" />
        </svg>
      </button>
      <div className="mbar-title">
        {onChat ? (
          <>
            <span className="mbar-brand">Noomesh</span>
            <span className="mbar-sub">mesh online</span>
          </>
        ) : (
          <span className="mbar-brand">{ALL_TABS[active]?.label ?? active}</span>
        )}
      </div>
    </header>
  );
}
