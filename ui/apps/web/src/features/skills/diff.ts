// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

export type DiffLine = { kind: 'same' | 'add' | 'del'; text: string };

/**
 * Line diff of `before` -> `after` (longest common subsequence). Skill texts are
 * a few hundred lines at most, so the quadratic table is fine; past the cap the
 * caller shows the full text instead (null), never a wrong diff.
 */
export function lineDiff(before: string, after: string, cap = 2000): DiffLine[] | null {
  const a = before.split('\n');
  const b = after.split('\n');
  if (a.length > cap || b.length > cap) return null;
  const t: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      t[i][j] = a[i] === b[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) out.push({ kind: 'same', text: a[i++] }), j++;
    else if (t[i + 1][j] >= t[i][j + 1]) out.push({ kind: 'del', text: a[i++] });
    else out.push({ kind: 'add', text: b[j++] });
  }
  while (i < a.length) out.push({ kind: 'del', text: a[i++] });
  while (j < b.length) out.push({ kind: 'add', text: b[j++] });
  return out;
}
