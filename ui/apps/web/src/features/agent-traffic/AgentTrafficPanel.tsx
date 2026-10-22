// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMemo, useState } from 'react';
import { useAuth } from '@metis/core';
import { relTime } from '@/lib/format';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  filterThreads,
  renderBody,
  usePresence,
  useThreadMessages,
  useThreads,
  type TrafficMessage,
} from './useAgentTraffic';

const REFRESH_MS = 10_000;

function Message({ m }: { m: TrafficMessage }) {
  const b = renderBody(m.body);
  const [open, setOpen] = useState(false);
  const closed = m.enc.endsWith(':closed');
  return (
    <div className="traffic-msg">
      <div className="traffic-msg-head">
        <span className="traffic-route">
          {m.from} <span aria-hidden>→</span> {m.to}
        </span>
        <span className="scope-chip">{m.kind || 'message'}</span>
        <StatusBadge tone={m.sigVerified ? 'good' : 'warn'}>
          {m.sigVerified ? 'signed' : 'unsigned'}
        </StatusBadge>
        <StatusBadge tone={closed ? 'bad' : 'good'}>{m.enc}</StatusBadge>
        <span className="traffic-ts" title={m.ts}>
          {new Date(m.ts).toLocaleString()} · {relTime(m.ts)} ago
        </span>
      </div>
      <pre className={b.isText ? 'traffic-body text' : 'traffic-body'} hidden={b.long && !open}>
        {b.text}
      </pre>
      {b.long && (
        <button type="button" className="traffic-more" onClick={() => setOpen((o) => !o)}>
          {open ? 'Collapse' : `Show all (${b.text.length.toLocaleString()} chars)`}
        </button>
      )}
    </div>
  );
}

export function AgentTrafficPanel() {
  const { isOperator } = useAuth();
  const [paused, setPaused] = useState(false);
  const [text, setText] = useState('');
  const [who, setWho] = useState('');
  const [picked, setPicked] = useState<string | null>(null);
  const ms = paused ? false : REFRESH_MS;

  const threads = useThreads(ms);
  const presence = usePresence(ms);
  const all = threads.data ?? [];
  const names = useMemo(() => [...new Set(all.flatMap((t) => t.participants))].sort(), [all]);
  const shown = useMemo(() => filterThreads(all, text, who), [all, text, who]);
  const selected = picked ?? shown[0]?.id ?? null;
  const msgs = useThreadMessages(selected, ms);
  const thread = all.find((t) => t.id === selected);

  if (!isOperator) {
    return (
      <section className="panel">
        <div className="panel-head">
          <h2>Agent traffic</h2>
        </div>
        <div className="state warn">Agent traffic is for operators only.</div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Agent traffic</h2>
        <span className="meta">operator</span>
        <div className="panel-head-right">
          <Button variant="outline" size="sm" aria-pressed={paused} onClick={() => setPaused((p) => !p)}>
            {paused ? 'Resume refresh' : 'Pause refresh'}
          </Button>
        </div>
      </div>

      <div className="traffic-live" aria-label="Live sessions">
        <span className="traffic-live-title">Live sessions</span>
        {presence.isError && <span className="state err">{(presence.error as Error).message}</span>}
        {presence.data && !presence.data.length && <span className="traffic-dim">none</span>}
        {(presence.data ?? []).map((s) => (
          <span className="scope-chip" key={s.connection} title={`${s.connection} · seen ${relTime(s.lastSeen)} ago`}>
            {s.displayName || s.connection}
            {s.consumer ? ` · ${s.consumer}` : ''}
          </span>
        ))}
      </div>

      <div className="traffic-split">
        <div className="traffic-threads">
          <Input
            placeholder="Filter threads…"
            aria-label="Filter threads"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <select aria-label="Filter by participant" value={who} onChange={(e) => setWho(e.target.value)}>
            <option value="">All participants</option>
            {names.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
          {threads.isLoading && <div className="state">Loading threads…</div>}
          {threads.isError && <div className="state err">{(threads.error as Error).message}</div>}
          {threads.data && !shown.length && <div className="state">No threads.</div>}
          {shown.map((t) => (
            <button
              type="button"
              key={t.id}
              className={t.id === selected ? 'traffic-thread on' : 'traffic-thread'}
              onClick={() => setPicked(t.id)}
            >
              <span className="traffic-thread-id">{t.id.slice(0, 12)}</span>
              <span className="traffic-thread-who">{t.participants.join(', ')}</span>
              <span className="traffic-thread-meta">
                {t.messages} msg · {relTime(t.last)} ago
              </span>
            </button>
          ))}
        </div>

        <div className="traffic-messages">
          {thread && (
            <h3 className="subhead">
              {thread.id} · {thread.messages} messages
            </h3>
          )}
          {!selected && <div className="state">Select a thread.</div>}
          {msgs.isLoading && selected && <div className="state">Loading messages…</div>}
          {msgs.isError && <div className="state err">{(msgs.error as Error).message}</div>}
          {(msgs.data ?? []).map((m) => (
            <Message key={m.id} m={m} />
          ))}
        </div>
      </div>
    </section>
  );
}
