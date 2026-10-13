// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { Tone } from '@/components/StatusBadge';

export interface Job {
  id: string;
  type: string;
  status: string;
  priority: number | null;
  nodeId: string | null;
  createdAt: string;
}

export function jobStatusMeta(status: string): { label: string; tone: Tone } {
  switch (status) {
    case 'running':
      return { label: 'Running', tone: 'neutral' };
    case 'queued':
      return { label: 'Queued', tone: 'warn' };
    case 'completed':
      return { label: 'Completed', tone: 'good' };
    case 'failed':
      return { label: 'Failed', tone: 'bad' };
    case 'cancelled':
      return { label: 'Cancelled', tone: 'neutral' };
    default:
      return { label: status || 'unknown', tone: 'neutral' };
  }
}
