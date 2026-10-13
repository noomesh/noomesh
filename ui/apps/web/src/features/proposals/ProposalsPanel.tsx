// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { relTime } from '@/lib/format';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useConfirm } from '@/components/ConfirmDialog';
import { useProposals, useDecideProposal } from './useProposals';
import { statusMeta, type Proposal } from './types';

const FILTERS: [string, string][] = [
  ['pending', 'Pending'],
  ['', 'All'],
  ['needs_bootstrap', 'Needs bootstrap'],
  ['approved', 'Approved'],
  ['enrolled', 'Enrolled'],
  ['rejected', 'Rejected'],
  ['failed', 'Failed'],
];

export function ProposalsPanel() {
  const [filter, setFilter] = useState('pending');
  const { data, isLoading, isError, error, isFetching } = useProposals();
  const decide = useDecideProposal();
  const confirm = useConfirm();

  const rows = (data ?? []).filter((p) => !filter || p.status === filter);
  const pendingId = decide.isPending ? decide.variables?.id : undefined;

  async function onDecide(p: Proposal, decision: 'approve' | 'reject') {
    const ok = await confirm({
      title: decision === 'approve' ? `Approve ${p.host}?` : `Reject ${p.host}?`,
      description:
        decision === 'approve'
          ? 'The cluster executor will enroll this host.'
          : 'The proposal will be dismissed.',
      confirmText: decision === 'approve' ? 'Approve' : 'Reject',
      destructive: decision === 'reject',
    });
    if (!ok) return;
    decide.mutate(
      { id: p.id, decision },
      {
        onSuccess: () =>
          toast.success(`Proposal ${decision === 'approve' ? 'approved' : 'rejected'}`, {
            description: p.host,
          }),
        onError: (e) => toast.error('Action failed', { description: (e as Error).message }),
      },
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Proposals</h2>
        <div className="panel-head-right">
          {isFetching && <span className="meta">refreshing…</span>}
          <select
            className="filter-select"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            aria-label="Filter proposals by status"
          >
            {FILTERS.map(([v, l]) => (
              <option key={v || 'all'} value={v}>
                {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && <div className="state">Loading proposals…</div>}
      {isError && <div className="state err">{(error as Error)?.message ?? 'Failed to load'}</div>}

      {data &&
        (rows.length ? (
          rows.map((p) => {
            const meta = statusMeta(p.status);
            const busy = pendingId === p.id;
            return (
              <div key={p.id} className="proposal">
                <div className="proposal-top">
                  <StatusBadge tone={meta.tone}>{meta.label}</StatusBadge>
                  <span className="host">{p.host}</span>
                </div>
                <div className="proposal-meta">
                  {p.role} · {p.user} · via {p.proposedBy}
                  {p.createdAt ? ` · ${relTime(p.createdAt)} ago` : ''}
                </div>
                {p.reason && <div className="proposal-reason">{p.reason}</div>}
                {p.status === 'pending' && (
                  <div className="proposal-actions">
                    <Button size="sm" disabled={busy} onClick={() => onDecide(p, 'approve')}>
                      {busy && decide.variables?.decision === 'approve' ? 'Approving…' : 'Approve'}
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => onDecide(p, 'reject')}>
                      {busy && decide.variables?.decision === 'reject' ? 'Rejecting…' : 'Reject'}
                    </Button>
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="state">No matching proposals.</div>
        ))}
    </section>
  );
}
