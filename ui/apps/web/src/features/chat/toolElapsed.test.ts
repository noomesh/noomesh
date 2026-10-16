// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { formatElapsed } from './toolElapsed';

describe('formatElapsed', () => {
  it('shows a fast call in milliseconds, not 0.0s', () => {
    expect(formatElapsed(22)).toBe('22ms');
    expect(formatElapsed(0)).toBe('0ms');
  });
  it('keeps seconds for a call of a second or more', () => {
    expect(formatElapsed(1000)).toBe('1.0s');
    expect(formatElapsed(7712)).toBe('7.7s');
  });
});
