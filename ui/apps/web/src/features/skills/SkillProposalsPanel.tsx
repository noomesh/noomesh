// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { useAuth } from '@metis/core';
import { toast } from 'sonner';
import { relTime } from '@/lib/format';
import { StatusBadge, type Tone } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useConfirm } from '@/components/ConfirmDialog';
import { lineDiff } from './diff';
import { useSkillProposals, useDecideSkill, type Decision, type SkillProposal } from './useSkillProposals';

const FILTERS: [string, string][] = [
  ['pending', 'Pending'],
  ['', 'All'],
  ['promoted', 'Promoted'],
  ['rejected', 'Rejected'],
  ['superseded', 'Superseded'],
  ['withdrawn', 'Withdrawn'],
];

/** Trust state as the person reads it: only a promoted text is injected. */
export function trustMeta(status: string): { label: string; tone: Tone } {
  switch (status) {
    case 'pending':
      return { label: 'Not trusted — awaiting review', tone: 'warn' };
    case 'promoted':
      return { label: 'Promoted — in use', tone: 'good' };
    case 'rejected':
      return { label: 'Rejected', tone: 'bad' };
    case 'superseded':
      return { label: 'Superseded by newer text', tone: 'neutral' };
    case 'withdrawn':
      return { label: 'Withdrawn', tone: 'neutral' };
    default:
      return { label: status || 'unknown', tone: 'neutral' };
  }
}

/** The text this proposal would replace: the newest promoted one of that skill. */
export function promotedBefore(all: SkillProposal[], p: SkillProposal): SkillProposal | undefined {
  return all
    .filter((o) => o.name === p.name && o.status === 'promoted' && o.contentSha !== p.contentSha)
    .sort((a, b) => b.proposedAt.localeCompare(a.proposedAt))[0];
}

function SkillText({ p, prior }: { p: SkillProposal; prior?: SkillProposal }) {
  const diff = prior ? lineDiff(prior.content, p.content) : null;
  return (
    <details>
      <summary>{diff ? `Changes since the promoted text (${prior!.contentSha.slice(0, 8)})` : 'Proposed text'}</summary>
      <pre className="skill-text">
        {diff
          ? diff.map((l, i) => (
              <span key={i} className={l.kind}>
                {l.kind === 'add' ? '+ ' : l.kind === 'del' ? '- ' : '  '}
                {l.text}
              </span>
            ))
          : p.content}
      </pre>
    </details>
  );
}

export function SkillProposalsPanel() {
  const { isOperator } = useAuth();
  const [filter, setFilter] = useState('pending');
  const [reasons, setReasons] = useState<Record<number, string>>({});
  const { data, isLoading, isError, error, isFetching } = useSkillProposals();
  const decide = useDecideSkill();
  const confirm = useConfirm();

  if (!isOperator) {
    return (
      <section className="panel">
        <div className="panel-head">
          <h2>Skill proposals</h2>
        </div>
        <div className="state">Promoting a skill needs operator permission.</div>
      </section>
    );
  }

  const rows = (data ?? []).filter((p) => !filter || p.status === filter);
  const pendingId = decide.isPending ? decide.variables?.id : undefined;

  async function onDecide(p: SkillProposal, decision: Decision) {
    const promote = decision === 'promote';
    const ok = await confirm({
      title: promote ? `Promote ${p.name}?` : `Reject ${p.name}?`,
      description: promote
        ? 'Its text will be injected into the assistant as instructions while this text stays unchanged.'
        : 'The text stays out of the assistant. A changed text is proposed again.',
      confirmText: promote ? 'Promote' : 'Reject',
      destructive: !promote,
    });
    if (!ok) return;
    decide.mutate(
      { id: p.id, decision, reason: reasons[p.id] },
      {
        onSuccess: (r) => {
          toast.success(promote ? 'Skill promoted' : 'Skill rejected', { description: p.name });
          if (typeof r?.live === 'string') toast.warning('Not live yet', { description: r.live });
        },
        onError: (e) => toast.error('Decision failed', { description: (e as Error).message }),
      },
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Skill proposals</h2>
        <div className="panel-head-right">
          {isFetching && <span className="meta">refreshing…</span>}
          <select
            className="filter-select"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            aria-label="Filter skill proposals by status"
          >
            {FILTERS.map(([v, l]) => (
              <option key={v || 'all'} value={v}>
                {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && <div className="state">Loading skill proposals…</div>}
      {isError && <div className="state err">{(error as Error)?.message ?? 'Failed to load'}</div>}

      {data &&
        (rows.length ? (
          rows.map((p) => {
            const meta = trustMeta(p.status);
            const busy = pendingId === p.id;
            return (
              <div key={p.id} className="proposal">
                <div className="proposal-top">
                  <StatusBadge tone={meta.tone}>{meta.label}</StatusBadge>
                  <span className="host">{p.name}</span>
                </div>
                <div className="proposal-meta">
                  by {p.proposedBy || '—'}
                  {p.proposedAt ? ` · ${relTime(p.proposedAt)} ago` : ''} · {p.contentSha.slice(0, 8)}
                  {p.decidedBy ? ` · decided by ${p.decidedBy}` : ''}
                </div>
                {p.description && <div className="proposal-reason">{p.description}</div>}
                {p.reason && <div className="proposal-reason">Reason: {p.reason}</div>}
                <SkillText p={p} prior={promotedBefore(data, p)} />
                {p.status === 'pending' && (
                  <>
                    <input
                      className="skill-reason"
                      placeholder="Reason (optional)"
                      aria-label={`Reason for deciding ${p.name}`}
                      value={reasons[p.id] ?? ''}
                      onChange={(e) => setReasons((r) => ({ ...r, [p.id]: e.target.value }))}
                    />
                    <div className="proposal-actions">
                      <Button size="sm" disabled={busy} onClick={() => onDecide(p, 'promote')}>
                        {busy && decide.variables?.decision === 'promote' ? 'Promoting…' : 'Promote'}
                      </Button>
                      <Button size="sm" variant="outline" disabled={busy} onClick={() => onDecide(p, 'reject')}>
                        {busy && decide.variables?.decision === 'reject' ? 'Rejecting…' : 'Reject'}
                      </Button>
                    </div>
                  </>
                )}
              </div>
            );
          })
        ) : (
          <div className="state">No matching skill proposals.</div>
        ))}
    </section>
  );
}
