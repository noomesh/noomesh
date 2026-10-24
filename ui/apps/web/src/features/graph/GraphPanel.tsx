// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMemo, useState } from 'react';
import { cn } from '@/lib/utils';
import { StatTiles } from '@/components/StatTiles';
import { useGraph, type GraphFilters } from './useGraph';
import { StagedPrunes } from './StagedPrunes';
import { layoutGraph, radiusFor, colorFor, type LayoutNode } from '@/lib/graph/layout';
import { dash } from '@/lib/num';

const DEFAULTS: GraphFilters = { limit: 200, minDegree: 2, entityType: '' };

type View = 'map' | 'prunes';
const VIEWS: [View, string][] = [
  ['map', 'Map'],
  ['prunes', 'Staged prunes'],
];

export function GraphPanel() {
  const [filters, setFilters] = useState<GraphFilters>(DEFAULTS);
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<View>('map');
  const g = useGraph(filters);

  // The simulation is the expensive part — only rerun when the data actually
  // changes, not when a node is hovered or selected.
  const layout = useMemo(() => {
    if (!g.data) return null;
    return layoutGraph({ nodes: g.data.nodes, edges: g.data.edges });
  }, [g.data]);

  const maxTypeCount = g.data?.types[0]?.count ?? 1;
  const byId = useMemo(
    () => new Map((layout?.nodes ?? []).map((n) => [n.id, n])),
    [layout],
  );
  const sel: LayoutNode | undefined = selected ? byId.get(selected) : undefined;

  // Neighbours of the selection, for dimming everything else.
  const neighbours = useMemo(() => {
    if (!selected || !layout) return null;
    const set = new Set<string>([selected]);
    for (const e of layout.edges) {
      if (e.src === selected) set.add(e.dst);
      else if (e.dst === selected) set.add(e.src);
    }
    return set;
  }, [selected, layout]);

  const set = (patch: Partial<GraphFilters>) => {
    setSelected(null);
    setFilters((f) => ({ ...f, ...patch }));
  };

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Knowledge graph</h2>
        <div className="panel-head-right">
          {view === 'map' && (
            <span className="meta">{g.isFetching ? 'refreshing…' : 'entities & edges'}</span>
          )}
          <div className="seg" role="group" aria-label="Graph view">
            {VIEWS.map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={view === id ? 'on' : undefined}
                aria-pressed={view === id}
                onClick={() => setView(id)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {view === 'prunes' && <StagedPrunes />}

      {view === 'map' && g.isLoading && <div className="state">Loading graph…</div>}
      {view === 'map' && g.isError && <div className="state err">{(g.error as Error)?.message}</div>}

      {view === 'map' && g.data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Entities', value: g.data.nodeCount.toLocaleString() },
              { label: 'Edges', value: g.data.edgeCount.toLocaleString() },
              { label: 'Types', value: g.data.types.length },
              { label: 'Max degree', value: dash(g.data.maxDegree) },
            ]}
          />

          <div className="graph-controls">
            <label>
              <span className="ctl-label">Type</span>
              <select
                value={filters.entityType}
                onChange={(e) => set({ entityType: e.target.value })}
              >
                <option value="">All</option>
                {g.data.types.map((t) => (
                  <option key={t.type} value={t.type}>
                    {t.type} ({t.count})
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="ctl-label">Min degree</span>
              <select
                value={filters.minDegree}
                onChange={(e) => set({ minDegree: Number(e.target.value) })}
              >
                {[1, 2, 3, 5, 10].map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="ctl-label">Limit</span>
              <select value={filters.limit} onChange={(e) => set({ limit: Number(e.target.value) })}>
                {[50, 100, 200, 400].map((l) => (
                  <option key={l} value={l}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            {selected && (
              <button type="button" className="ctl-clear" onClick={() => setSelected(null)}>
                Clear selection
              </button>
            )}
          </div>

          {layout && layout.nodes.length > 0 ? (
            <div className="graph-map">
              <svg
                viewBox={`0 0 ${layout.width} ${layout.height}`}
                role="img"
                aria-label={`Knowledge graph: ${layout.nodes.length} entities, ${layout.edges.length} edges`}
              >
                <g className="graph-edges">
                  {layout.edges.map((e, i) => (
                    <line
                      key={`${e.src}-${e.dst}-${i}`}
                      x1={e.x1}
                      y1={e.y1}
                      x2={e.x2}
                      y2={e.y2}
                      className={cn(
                        neighbours && (e.src === selected || e.dst === selected) && 'lit',
                        neighbours && e.src !== selected && e.dst !== selected && 'dim',
                      )}
                    />
                  ))}
                </g>
                <g className="graph-nodes">
                  {layout.nodes.map((n) => {
                    const r = radiusFor(n.degree, g.data!.maxDegree);
                    const dimmed = neighbours ? !neighbours.has(n.id) : false;
                    return (
                      <g
                        key={n.id}
                        className={cn('gnode', dimmed && 'dim', n.id === selected && 'sel')}
                        onClick={() => setSelected((s) => (s === n.id ? null : n.id))}
                      >
                        <circle cx={n.x} cy={n.y} r={r} fill={colorFor(n.type)} />
                        <title>{`${n.name}${n.type ? ` · ${n.type}` : ''} · ${dash(n.degree)} edges`}</title>
                        {/* Only label what's readable — every label at 200 nodes is soup. */}
                        {(r > 9 || n.id === selected) && (
                          <text x={n.x} y={n.y - r - 4} textAnchor="middle">
                            {n.name.length > 22 ? `${n.name.slice(0, 21)}…` : n.name}
                          </text>
                        )}
                      </g>
                    );
                  })}
                </g>
              </svg>

              <div className="graph-foot">
                <div className="graph-legend">
                  {g.data.types.slice(0, 8).map((t) => (
                    <span key={t.type}>
                      <i style={{ background: colorFor(t.type) }} />
                      {t.type}
                    </span>
                  ))}
                </div>
                {g.data.truncated && (
                  <span className="graph-note">
                    showing {layout.nodes.length} of {g.data.nodeCount.toLocaleString()} — raise the
                    limit or the min degree
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div className="state">
              No entities match these filters — try a lower min degree.
            </div>
          )}

          {sel && (
            <div className="graph-sel">
              <span className="gs-name">{sel.name}</span>
              {sel.type && <span className="gs-type">{sel.type}</span>}
              <span className="gs-deg">{dash(sel.degree)} edges</span>
              <span className="gs-hint">
                {(neighbours?.size ?? 1) - 1} neighbour
                {(neighbours?.size ?? 1) - 1 === 1 ? '' : 's'} in view
              </span>
            </div>
          )}

          <h3 className="subhead">Entity types</h3>
          <div className="type-list">
            {g.data.types.map((t) => (
              <div className="type-row" key={t.type}>
                <span className="type-name">{t.type}</span>
                <span className="type-bar">
                  <span
                    className="type-fill"
                    style={{
                      width: `${Math.round((t.count / maxTypeCount) * 100)}%`,
                      background: colorFor(t.type),
                    }}
                  />
                </span>
                <span className="type-count">{t.count}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
