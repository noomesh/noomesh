// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { relTime } from '@/lib/format';
import { StatTiles } from '@/components/StatTiles';
import { StatusBadge, type Tone } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useConfirm } from '@/components/ConfirmDialog';
import { useSecurity, useApprovalDecision, type PendingApproval, type Cert } from './useSecurity';

const certTone = (s: string): Tone =>
  s === 'expired' || s === 'missing' ? 'bad' : s === 'expiring' ? 'warn' : 'good';
const approvalTone = (r: string): Tone => (r === 'high' ? 'bad' : r === 'medium' ? 'warn' : 'neutral');

const VIOLATION_TYPES: [string, string][] = [
  ['violations', 'Rate-limit'],
  ['path_traversal', 'Path traversal'],
  ['xss', 'Cross-site scripting'],
  ['sql_injection', 'SQL injection'],
  ['shell_meta', 'Shell metacharacters'],
  ['blocked_file', 'Blocked file access'],
];

export function SecurityPanel() {
  const sec = useSecurity();
  const decide = useApprovalDecision();
  const confirm = useConfirm();
  const deciding = decide.isPending ? decide.variables : undefined;

  async function onDecide(p: PendingApproval, decision: 'approve' | 'deny') {
    const ok = await confirm({
      title: `${decision === 'approve' ? 'Approve' : 'Deny'} ${p.tool}?`,
      description:
        decision === 'approve'
          ? `Lets the ${p.tool} request run (risk: ${p.riskLevel}).`
          : `Blocks the ${p.tool} request.`,
      confirmText: decision === 'approve' ? 'Approve' : 'Deny',
      destructive: decision === 'deny',
    });
    if (!ok) return;
    decide.mutate(
      { id: p.id, decision },
      {
        onSuccess: () => toast.success(`Request ${decision === 'approve' ? 'approved' : 'denied'}`, { description: p.tool }),
        onError: (e) => toast.error('Action failed', { description: (e as Error).message }),
      },
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Security</h2>
        <span className="meta">{sec.isFetching ? 'refreshing…' : 'last 24h'}</span>
      </div>

      {sec.isLoading && <div className="state">Loading security posture…</div>}
      {sec.isError && <div className="state err">{(sec.error as Error)?.message}</div>}

      {sec.data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Risk', value: sec.data.riskLevel, hot: sec.data.riskLevel !== 'LOW' && sec.data.riskLevel !== 'UNKNOWN' },
              { label: 'Violations', value: sec.data.violations.total ?? 0 },
              { label: 'Pending', value: sec.data.stats.pending, hot: sec.data.stats.pending > 0 },
              { label: 'Certs expiring', value: sec.data.pki.summary.expiring, hot: sec.data.pki.summary.expiring > 0 },
            ]}
          />

          <h3 className="subhead">Pending approvals</h3>
          {sec.data.pending.length ? (
            sec.data.pending.map((p) => {
              const busy = deciding?.id === p.id;
              return (
                <div className="approval-row" key={p.id}>
                  <div className="approval-main">
                    <div className="approval-line1">
                      <StatusBadge tone={approvalTone(p.riskLevel)}>{p.riskLevel}</StatusBadge>
                      <span className="approval-tool">{p.tool}</span>
                    </div>
                    <div className="approval-meta">
                      {p.id}
                      {p.createdAt ? ` · ${relTime(p.createdAt)} ago` : ''}
                    </div>
                  </div>
                  <div className="approval-actions">
                    <Button
                      size="sm"
                      disabled={busy}
                      onClick={() => onDecide(p, 'approve')}
                      title={`Let ${p.tool} run. This cannot be undone once it executes.`}
                    >
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => onDecide(p, 'deny')}
                      title={`Block ${p.tool}. The agent is told and carries on without it.`}
                    >
                      Deny
                    </Button>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="state">No requests awaiting approval.</div>
          )}

          <h3 className="subhead">Certificates</h3>
          {sec.data.pki.configured ? (
            <div className="cache-list">
              {sec.data.pki.certs.map((c: Cert) => (
                <div className="cert-row" key={c.name}>
                  <div className="cert-id">
                    <span className="cert-name">{c.name}</span>
                    <span className="cert-role">{c.role}</span>
                  </div>
                  <div className="cert-right">
                    <span className={`cert-days ${c.daysLeft < 0 ? 'bad' : c.daysLeft <= 30 ? 'warn' : ''}`}>
                      {c.daysLeft}d
                    </span>
                    <StatusBadge tone={certTone(c.status)}>{c.status}</StatusBadge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="state">PKI not configured.</div>
          )}

          {/* Ranked, and zeros are dimmed. Six categories all reading "0" in
              the same weight as a real hit is the same failure as showing only
              a total: the eye has nothing to catch on. */}
          <h3 className="subhead">Violations · last 24h</h3>
          <div className="cache-list">
            {[...VIOLATION_TYPES]
              .sort((a, b) => (sec.data!.violations[b[0]] ?? 0) - (sec.data!.violations[a[0]] ?? 0))
              .map(([key, label]) => {
                const n = sec.data!.violations[key] ?? 0;
                return (
                  <div className={cn('cache-row', n === 0 && 'quiet')} key={key}>
                    <span className="cache-name">{label}</span>
                    <span className={cn('cache-meta', n > 0 && 'vio-hit')}>{n.toLocaleString()}</span>
                  </div>
                );
              })}
          </div>
        </>
      )}
    </section>
  );
}
