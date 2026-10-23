// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { StatTiles } from '@/components/StatTiles';
import { NodeCard } from '@/components/NodeCard';
import { useClusterNodes } from './useClusterNodes';
import { AddNode } from './AddNode';
import { dash } from '@/lib/num';

export function ClusterPanel() {
  const { data, isLoading, isError, error, isFetching } = useClusterNodes();

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Cluster</h2>
        <div className="panel-head-right">
          <span className="meta">
            {data ? `${data.stats.total} nodes` : '—'}
            {isFetching && ' · refreshing…'}
          </span>
          <AddNode />
        </div>
      </div>

      {isLoading && <div className="state">Loading cluster…</div>}
      {isError && <div className="state err">{(error as Error)?.message ?? 'Failed to load'}</div>}

      {data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Nodes', value: data.stats.total },
              { label: 'Online', value: data.stats.online },
              { label: 'Busy', value: data.stats.busy, hot: data.stats.busy > 0 },
              { label: 'VRAM GB', value: dash(data.stats.vramGb, (n) => n.toFixed(1)) },
            ]}
          />
          {data.nodes.length ? (
            data.nodes.map((n) => <NodeCard key={n.id} node={n} />)
          ) : (
            /* The first screen of a fresh install. "No nodes registered" alone
               is a dead end — say what to do next. */
            <div className="onboard">
              <p className="onboard-lead">No nodes yet.</p>
              <p>
                A node is any machine you want the mesh to use — this one included. Use{' '}
                <strong>+ Add node</strong> above: name the machine, and you get the two
                commands to run on it (install the noo CLI, then <code>noo enroll</code>) and
                the one to run here afterwards.
              </p>
              <p className="onboard-note">
                Until a node is enrolled and a backend is started, Chat has nothing to
                answer with.
              </p>
            </div>
          )}
        </>
      )}
    </section>
  );
}
