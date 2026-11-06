// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, expect, it } from 'vitest';
import { displaySearch } from './display';

describe('displaySearch (i510 c1)', () => {
  it('applies what the controller set over the URL the box started with', () => {
    expect(displaySearch('?view=health&quality=lean', { quality: 'full', view: 'graph' })).toBe('?view=graph&quality=full');
    expect(displaySearch('?view=health', { rotate: 30 })).toBe('?view=health&rotate=30');
  });

  it('auto quality and a zero rotate or poll drop the parameter', () => {
    expect(displaySearch('?view=graph&quality=lean&poll=10', { quality: 'auto', poll: 0 })).toBe('?view=graph');
  });

  it('is null when the page is already there, so it never reloads in a loop', () => {
    expect(displaySearch('?view=graph&quality=lean', { view: 'graph', quality: 'lean' })).toBeNull();
    expect(displaySearch('?view=health', {})).toBeNull();
    expect(displaySearch('?view=health', { quality: 'auto' })).toBeNull();
  });
});
