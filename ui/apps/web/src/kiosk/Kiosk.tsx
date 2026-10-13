// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The screen. Answers one question — "is the mesh healthy right now, and if
// not, where should I go look?" — in six regions, by priority (an earlier change
// §5). Nobody acts on this screen; they act because of it, somewhere else.
//
// The layout is the proposal's first draft and is meant to be argued with.
// The rules it follows: duration is the payload; anything green 99.9% of the
// time is wallpaper; degrade visibly; never colour alone; no input.

import { LivenessBand, type Pager } from './Band';
import { fleet, pressure, work, exceptions, fmtDuration, fmtSince, type KioskState, type SourceKey } from './store';

/** The health view. A pure renderer: the store and the stream live in KioskShell. */
export function Kiosk({ state, now, pager }: { state: KioskState; now: number; pager?: Pager }) {
  return (
    <div className="kiosk">
      <LivenessBand state={state} now={now} pager={pager} />
      <Fleet state={state} now={now} />
      <Pressure state={state} now={now} />
      <Work state={state} now={now} />
      <Transitions state={state} now={now} />
      <Exceptions state={state} now={now} />
    </div>
  );
}

type P = { state: KioskState; now: number };

/** "cluster · 4m stale" in a region header when its source failed; nothing when fresh. */
function Freshness({ state, now, source }: P & { source: SourceKey }) {
  const s = state.sources[source];
  if (!s.error) return null;
  return <span className="meta">{s.at ? `${fmtDuration(now - s.at)} stale` : 'not loaded'}</span>;
}

function Fleet({ state, now }: P) {
  const nodes = fleet(state);
  const src = state.sources.cluster;
  return (
    <section className={`region fleet${src.error ? ' stale' : ''}`}>
      <h2>
        Fleet <Freshness state={state} now={now} source="cluster" />
      </h2>
      <div className="cells">
        {nodes.length === 0 && <div className="empty">{src.at ? 'no nodes' : src.error ? 'cluster unavailable' : '…'}</div>}
        {nodes.map((n) => {
          const model = Object.entries(n.running)
            .map(([b, m]) => `${b} · ${m}`)
            .join(' · ');
          return (
            <div key={n.id} className={`cell ${n.status}`}>
              <div className="host">{n.hostname}</div>
              <div className="state">
                <span className="word">{n.status}</span>
                <span className="for">{fmtSince(n.since, now)}</span>
              </div>
              <div className="model">{model || (n.status === 'offline' ? '' : 'nothing running')}</div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Pressure({ state, now }: P) {
  const gpus = pressure(state);
  const src = state.sources.gpus;
  return (
    <section className={`region pressure${src.error ? ' stale' : ''}`}>
      <h2>
        Pressure <Freshness state={state} now={now} source="gpus" />
      </h2>
      <div className="gpus">
        {gpus.length === 0 && <div className="empty">{src.at ? 'no GPUs reported' : '…'}</div>}
        {gpus.map((g) => {
          const who = g.hostname ?? g.nodeId ?? '';
          const vram =
            g.vramUsed != null && g.vramTotal
              ? `${(g.vramUsed / 1024).toFixed(0)} / ${(g.vramTotal / 1024).toFixed(0)} GB`
              : '—';
          return (
            <div key={g.key} className={`gpu${g.pinnedSince ? ' pinned' : ''}`}>
              <div className="who">
                {who ? `${who} · ` : ''}
                {g.name}
              </div>
              <div className="util">{g.util == null ? '—' : `${Math.round(g.util)}%`}</div>
              <div className="bar">
                <i style={{ width: `${Math.max(0, Math.min(100, g.util ?? 0))}%` }} />
              </div>
              <div className="sub">
                <span>
                  {vram}
                  {g.temp != null ? ` · ${Math.round(g.temp)}°` : ''}
                </span>
                <span className="pin">{g.pinnedSince ? `pinned ${fmtSince(g.pinnedSince, now)}` : fmtDuration(now - g.at) + ' ago'}</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Work({ state, now }: P) {
  const w = work(state, now);
  const stuck = w.oldestWaitingMs != null && w.oldestWaitingMs > 10 * 60_000;
  const srcErr = state.sources.jobs.error || state.sources.scheduler.error;
  const val = (v: number | null) => (v == null ? <span className="dim">—</span> : v);
  return (
    <section className={`region work${srcErr ? ' stale' : ''}`}>
      <h2>
        Work{' '}
        <span className="meta">
          scheduler {w.schedulerWord}
          {srcErr ? ' · stale' : ''}
        </span>
      </h2>
      <div className="stats">
        <div className="stat">
          <div className="v">{val(w.queueDepth)}</div>
          <div className="k">queued</div>
        </div>
        <div className="stat">
          <div className="v">{val(w.active)}</div>
          <div className="k">running</div>
        </div>
        <div className={`stat${stuck ? ' bad' : w.oldestWaitingMs != null && w.oldestWaitingMs > 60_000 ? ' hot' : ''}`}>
          <div className="v">{w.oldestWaitingMs == null ? <span className="dim">—</span> : fmtDuration(w.oldestWaitingMs)}</div>
          <div className="k">oldest waiting</div>
        </div>
      </div>
    </section>
  );
}

function Transitions({ state, now }: P) {
  return (
    <section className="region trans">
      <h2>Recent transitions</h2>
      {state.transitions.length === 0 ? (
        <div className="empty">{state.lastData ? 'nothing has changed since this display connected' : '…'}</div>
      ) : (
        <ol>
          {state.transitions.map((t) => (
            <li key={t.key} className={t.severity}>
              <span className="when">{fmtDuration(now - t.at)} ago</span>
              <span className="what">{t.text}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** Collapses to almost nothing when there is nothing abnormal — a region that is always populated is wallpaper. */
function Exceptions({ state, now }: P) {
  const ex = exceptions(state, now);
  return (
    <section className={`region exc${ex.length === 0 ? ' quiet' : ''}`}>
      <h2>Exceptions</h2>
      {ex.length === 0 ? (
        <div className="empty">none</div>
      ) : (
        <ul>
          {ex.map((e) => (
            <li key={e.key} className={e.severity}>
              {e.text}
              {e.since != null && <span className="for">{fmtDuration(now - e.since)}</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
