// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { Tone } from '@/components/StatusBadge';

export interface Proposal {
  id: string;
  host: string;
  user: string;
  role: string;
  reason: string;
  proposedBy: string;
  createdAt: string;
  status: string;
  executionLog?: string;
}

/** Map a proposal status to a display label + semantic tone. */
export function statusMeta(status: string): { label: string; tone: Tone } {
  switch (status) {
    case 'pending':
      return { label: 'Pending', tone: 'warn' };
    case 'needs_bootstrap':
      return { label: 'Bootstrap', tone: 'warn' };
    case 'approved':
      return { label: 'Approved', tone: 'good' };
    case 'enrolled':
      return { label: 'Enrolled', tone: 'good' };
    case 'rejected':
      return { label: 'Rejected', tone: 'bad' };
    case 'failed':
      return { label: 'Failed', tone: 'bad' };
    default:
      return { label: status || 'unknown', tone: 'neutral' };
  }
}
