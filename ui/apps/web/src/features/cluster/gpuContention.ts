// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { relTime } from '@/lib/format';
import { DASH } from '@/lib/num';

/** The node agent's `gpu_contention` heartbeat report (internal/gpuyield),
 *  carried verbatim on the node record. Not in the typed contract yet, so it
 *  is read defensively. */
export interface GpuContention {
  state?: 'free' | 'shared' | 'yielded' | 'held' | string;
  foreign_mb?: number;
  total_mb?: number;
  free_mb?: number;
  method?: string;
  since?: string;
  paused_backends?: string[];
  reason?: string;
}

/** Read the report off a raw node object; undefined when absent or malformed. */
export function readGpuContention(raw: unknown): GpuContention | undefined {
  const v = (raw as { gpu_contention?: unknown } | null)?.gpu_contention;
  return v && typeof v === 'object' ? (v as GpuContention) : undefined;
}

const gb = (mb?: number) => (mb == null ? DASH : `${(mb / 1024).toFixed(1)} GB`);

/** The one line a node card shows, or null when there is nothing to say.
 *  Yielded/held is by design (the GPU was handed to other work), so it is
 *  worded as a state, not a fault. */
export function gpuContentionLine(gc?: GpuContention): string | null {
  if (!gc) return null;
  const paused = gc.paused_backends?.length ? gc.paused_backends.join(', ') : 'GPU backends';
  const since = gc.since ? ` since ${relTime(gc.since)} ago` : '';
  switch (gc.state) {
    case 'yielded':
      return `GPU in use by other work — ${paused} paused${since} (foreign ${gb(gc.foreign_mb)})`;
    case 'held':
      return `GPU held by operator${gc.reason ? ` (${gc.reason})` : ''} — ${paused} paused${since}`;
    case 'shared':
      return `GPU shared with other work (foreign ${gb(gc.foreign_mb)})`;
    default:
      return null;
  }
}
