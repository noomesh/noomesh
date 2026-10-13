// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Slate palette (dark) — mirrors packages/tokens so the companion matches the web console.
export const theme = {
  bg: '#0e1116',
  card: '#161b22',
  cardAlt: '#1b222b',
  border: '#232a33',
  text: '#e6edf3',
  dim: '#8b949e',
  faint: '#6b7480',
  accent: '#5f8fd0',
  accentText: '#0e1116',
  good: '#5aa66e',
  warn: '#e0a24a',
  bad: '#c9524b',
} as const;

export const toneColor = (tone: 'good' | 'warn' | 'bad' | 'neutral') =>
  tone === 'good' ? theme.good : tone === 'warn' ? theme.warn : tone === 'bad' ? theme.bad : theme.dim;
