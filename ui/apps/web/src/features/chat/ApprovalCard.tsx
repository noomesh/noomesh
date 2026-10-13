// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { useApprovalDecision } from '@/features/security/useSecurity';
import type { ApprovalRun } from './useCoordinator';

/**
 * The in-conversation ask: a tool call is blocked waiting on a human.
 *
 * This is the surface that matters. The Security tab lists the same requests
 * out of band, but the operator is *here*, watching a turn — and before this
 * existed the React console dropped the frame entirely, so the agent appeared
 * to hang and the request expired unseen.
 *
 * Decisions go through the same mutation the Security tab uses, so whichever
 * surface you act on, the other one's queue is invalidated.
 */
export function ApprovalCard({ approval }: { approval: ApprovalRun }) {
  const decide = useApprovalDecision();
  const [left, setLeft] = useState(() => Math.max(0, approval.deadline - Date.now()));

  const settled = approval.status !== 'pending';
  const expired = !settled && left <= 0;

  // Count down only while it can still be acted on.
  useEffect(() => {
    if (settled) return;
    const t = setInterval(() => setLeft(Math.max(0, approval.deadline - Date.now())), 1000);
    return () => clearInterval(t);
  }, [approval.deadline, settled]);

  function onDecide(decision: 'approve' | 'deny') {
    decide.mutate(
      { id: approval.id, decision },
      {
        onSuccess: () =>
          toast.success(decision === 'approve' ? 'Approved' : 'Denied', { description: approval.tool }),
        // The gateway's approval_outcome frame is the authority on what
        // actually happened; this only reports that the call itself failed.
        onError: (e) =>
          toast.error('Could not send the decision', {
            description: `${(e as Error).message} — try the Security tab.`,
          }),
      },
    );
  }

  const secs = Math.round(left / 1000);
  const countdown = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;

  return (
    <div className={cn('approval-card', settled && 'settled', expired && 'expired')}>
      <div className="ac-head">
        <span className="ac-lock" aria-hidden="true">
          <svg viewBox="0 0 20 20">
            <rect x="5" y="9" width="10" height="8" rx="1" />
            <path d="M7 9V7a3 3 0 0 1 6 0v2" />
          </svg>
        </span>
        <span className="ac-title">Approval needed</span>
        <span className="ac-tool">{approval.tool}</span>
        {!settled &&
          (expired ? (
            <span className="ac-left expired">expired — it did not run</span>
          ) : (
            <span className="ac-left">{countdown} left</span>
          ))}
      </div>

      {/* What is actually being approved. Without it this card asks the
          operator to authorise `pai_execute_command` with no idea which
          command — a gate that cannot tell you what it is gating manufactures
          confidence rather than providing oversight. */}
      {approval.args && <div className="ac-args">{approval.args}</div>}

      {settled ? (
        <div className={cn('ac-verdict', approval.status === 'denied' && 'blocked')}>
          {approval.outcome ?? (approval.status === 'denied' ? 'Blocked — it did not run.' : 'Approved — it ran.')}
        </div>
      ) : expired ? null : (
        <div className="ac-actions">
          <Button
            size="sm"
            disabled={decide.isPending}
            onClick={() => onDecide('approve')}
            title={`Let ${approval.tool} run. This cannot be undone once it executes.`}
          >
            Approve
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={decide.isPending}
            onClick={() => onDecide('deny')}
            title={`Block ${approval.tool}. The agent is told and carries on without it.`}
          >
            Deny
          </Button>
        </div>
      )}
    </div>
  );
}
