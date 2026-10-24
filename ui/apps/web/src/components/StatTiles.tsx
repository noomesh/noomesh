// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { cn } from '@/lib/utils';
import { DASH } from '@/lib/num';

export interface StatTile {
  label: string;
  /** null = the gateway did not send it: renders a dash, never 0. */
  value: string | number | null;
  hot?: boolean;
}

/** KPI tile row — the reusable replacement for the legacy stat-tiles.js. */
export function StatTiles({ tiles }: { tiles: StatTile[] }) {
  return (
    <div className="tiles">
      {tiles.map((t) => (
        <div key={t.label} className={cn('tile', t.hot && 'hot')}>
          <div className="v">{t.value ?? DASH}</div>
          <div className="k">{t.label}</div>
        </div>
      ))}
    </div>
  );
}
