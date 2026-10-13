// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { cn } from '@/lib/utils';

export interface StatTile {
  label: string;
  value: string | number;
  hot?: boolean;
}

/** KPI tile row — the reusable replacement for the legacy stat-tiles.js. */
export function StatTiles({ tiles }: { tiles: StatTile[] }) {
  return (
    <div className="tiles">
      {tiles.map((t) => (
        <div key={t.label} className={cn('tile', t.hot && 'hot')}>
          <div className="v">{t.value}</div>
          <div className="k">{t.label}</div>
        </div>
      ))}
    </div>
  );
}
