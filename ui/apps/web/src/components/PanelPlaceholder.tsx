// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { ALL_TABS, ICONS } from '@/shell/nav';

/** Shown for a tab that still lives in the legacy app. Makes the full surface
 *  navigable now; each fills in as it's migrated (Phase 4). */
export function PanelPlaceholder({ tab }: { tab: string }) {
  const label = ALL_TABS[tab]?.label ?? tab;
  return (
    <section className="panel placeholder">
      <div className="box">
        <svg className="pico" viewBox="0 0 20 20">
          {ICONS[tab]}
        </svg>
        <h2>{label}</h2>
        <p>
          Not migrated yet. This view still lives in the current console and will be rebuilt here on the
          shared client and Slate components.
        </p>
        <a href="https://localhost:5173" target="_blank" rel="noreferrer">
          Open “{label}” in the current app ↗
        </a>
      </div>
    </section>
  );
}
