// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { lineDiff } from './diff';

describe('lineDiff', () => {
  it('marks added and removed lines and keeps the rest', () => {
    const d = lineDiff('a\nb\nc', 'a\nc\nd')!;
    expect(d).toEqual([
      { kind: 'same', text: 'a' },
      { kind: 'del', text: 'b' },
      { kind: 'same', text: 'c' },
      { kind: 'add', text: 'd' },
    ]);
  });
  it('identical text is all same', () => {
    expect(lineDiff('x\ny', 'x\ny')!.every((l) => l.kind === 'same')).toBe(true);
  });
  it('refuses past the cap instead of guessing', () => {
    expect(lineDiff('a\nb\nc', 'a', 2)).toBeNull();
  });
});
