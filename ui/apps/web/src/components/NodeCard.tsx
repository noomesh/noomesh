// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { cn } from '@/lib/utils';
import { dash } from '@/lib/num';
import type { ClusterNode } from '@/features/cluster/types';
import { gpuContentionLine } from '@/features/cluster/gpuContention';

const fmt = (n: number | undefined, digits = 1) => (n == null ? '—' : n.toFixed(digits));

/** One cluster node — componentized from the legacy cluster.js card. Renders the
 *  contract fields, degrading gracefully when optional telemetry is absent. */
export function NodeCard({ node }: { node: ClusterNode }) {
  const vram =
    node.vramUsed != null
      ? `${fmt(node.vramUsed)} / ${dash(node.vramTotal ?? null)} GB`
      : node.vramTotal
        ? `${node.vramTotal} GB`
        : '—';
  const cpu =
    node.cpuPct != null ? `${node.cpuPct}% · ${node.cpuCores ?? '?'}c` : `${node.cpuCores ?? '?'} cores`;
  const ram =
    node.ramUsed != null
      ? `${fmt(node.ramUsed, 0)} / ${dash(node.ramTotal ?? null)} GB`
      : node.ramTotal
        ? `${node.ramTotal} GB`
        : '—';
  const gpuLine = gpuContentionLine(node.gpuContention);
  const gpuPaused = node.gpuContention?.state === 'yielded' || node.gpuContention?.state === 'held';

  return (
    <div className={cn('node', node.status === 'offline' && 'off')}>
      <div className="node-top">
        <div>
          <div className="host">{node.hostname}</div>
          <div className="ip">{node.ip || '—'}</div>
        </div>
        <div className="tags">
          <span className="tier">T{dash(node.tier)}</span>
          <span className={cn('st', node.status)}>{node.status}</span>
        </div>
      </div>

      <div className="specs">
        <span>
          GPU <b>{node.gpu ?? 'No GPU'}</b>
        </span>
        <span>
          VRAM <b>{vram}</b>
        </span>
        <span>
          CPU <b>{cpu}</b>
        </span>
        <span>
          RAM <b>{ram}</b>
        </span>
      </div>

      {gpuLine && <div className={cn('gpu-contention', gpuPaused && 'paused')}>{gpuLine}</div>}

      <div className="node-foot">
        <span className="backends">
          {node.backends && node.backends.length ? (
            node.backends.map((b) => (
              <span key={b} className="chip">
                {b}
              </span>
            ))
          ) : (
            <em>no backends</em>
          )}
        </span>
        <span className="heart">♥ {node.heartbeat}</span>
      </div>

      {node.load != null && (
        <div className="meter">
          {node.load.toFixed(2)}
          <span className="track">
            <span
              className={cn('fill', node.load >= 0.8 && 'hot')}
              style={{ width: `${Math.round(node.load * 100)}%` }}
            />
          </span>
        </div>
      )}
    </div>
  );
}
