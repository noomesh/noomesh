// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export type Tone = 'good' | 'warn' | 'bad' | 'neutral';

/** Small semantic status pill (good/warn/bad/neutral) — shared across tabs. */
export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={cn('status-badge', tone)}>{children}</span>;
}
