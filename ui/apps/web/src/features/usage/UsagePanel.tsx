// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { StatTiles } from '@/components/StatTiles';
import { dash } from '@/lib/num';
import {
  useUsage,
  recentMonths,
  compactOrDash,
  type UsageGroup,
} from './useUsage';

const GROUPS: { id: UsageGroup; label: string }[] = [
  { id: 'node', label: 'Node' },
  { id: 'model', label: 'Model' },
  { id: 'backend', label: 'Backend' },
  { id: 'source', label: 'Source' },
  { id: 'user', label: 'User' },
  { id: 'consumer', label: 'Consumer' },
];

const MONTHS = recentMonths(6);

/** `cloud` is a bucket, not a node — worth saying so rather than looking like a host. */
const rowNote = (group: string, key: string) => {
  if (group === 'node' && key === 'cloud') return 'cloud providers';
  if ((group === 'user' || group === 'consumer') && key === '(unattributed)')
    return 'no account or credential behind these calls';
  return undefined;
};

export function UsagePanel() {
  const [window, setWindow] = useState('month');
  const [group, setGroup] = useState<UsageGroup>('node');
  const u = useUsage(window, group);

  const max = u.data?.rows.find((r) => r.total !== null)?.total || 1;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Token usage</h2>
        <span className="meta">{u.isFetching ? 'refreshing…' : (u.data?.window ?? '')}</span>
      </div>

      <div className="usage-controls">
        <label>
          <span className="ctl-label">Window</span>
          <select
            value={window}
            onChange={(e) => setWindow(e.target.value)}
            title="Recent windows are per-completion rows; older months come from a monthly rollup."
          >
            <option value="month">This month</option>
            <option value="all">All time</option>
            {MONTHS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
        <div className="seg" role="group" aria-label="Group by">
          {GROUPS.map((g) => (
            <button
              key={g.id}
              type="button"
              className={g.id === group ? 'on' : undefined}
              title={`Break usage down by ${g.label.toLowerCase()}`}
              aria-pressed={g.id === group}
              onClick={() => setGroup(g.id)}
            >
              {g.label}
            </button>
          ))}
        </div>
      </div>

      {u.isLoading && <div className="state">Loading usage…</div>}
      {u.isError && <div className="state err">{(u.error as Error)?.message}</div>}

      {u.data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Total tokens', value: compactOrDash(u.data.total) },
              { label: 'Prompt', value: compactOrDash(u.data.promptTokens) },
              { label: 'Completion', value: compactOrDash(u.data.completionTokens) },
              { label: 'Requests', value: dash(u.data.requests) },
            ]}
          />

          <h3 className="subhead">By {u.data.group}</h3>

          {!u.data.rows.length && <div className="state">No usage recorded in this window.</div>}

          {u.data.rows.map((r) => {
            const note = rowNote(u.data.group, r.key);
            // Split bar: prompt vs completion, scaled against the biggest row.
            const promptPct = ((r.promptTokens ?? 0) / max) * 100;
            const completionPct = ((r.completionTokens ?? 0) / max) * 100;
            return (
              <div className="usage-row" key={r.key}>
                <div className="usage-id">
                  <span className="usage-key">{r.key}</span>
                  {note && <span className="usage-note">{note}</span>}
                </div>
                <div
                  className="usage-bar"
                  title={`${dash(r.promptTokens)} prompt + ${dash(r.completionTokens)} completion`}
                >
                  <span className="usage-fill prompt" style={{ width: `${promptPct}%` }} />
                  <span className="usage-fill completion" style={{ width: `${completionPct}%` }} />
                </div>
                <div className="usage-nums">
                  <span className="usage-total">{compactOrDash(r.total)}</span>
                  <span className="usage-reqs">{dash(r.requests)} req</span>
                </div>
              </div>
            );
          })}

          <div className="usage-legend">
            <span>
              <i className="prompt" /> prompt
            </span>
            <span>
              <i className="completion" /> completion
            </span>
          </div>
        </>
      )}
    </section>
  );
}
