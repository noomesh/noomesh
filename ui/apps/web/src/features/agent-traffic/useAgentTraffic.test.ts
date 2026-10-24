// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { filterThreads, parseMessages, parseThreads, renderBody } from './useAgentTraffic';

const threads = parseThreads({
  threads: [
    { thread_id: 'abc123', messages: 3, started: 'a', last: 'b', senders: ['alice/s1'], recipients: ['bob', 'alice/s1'] },
    { thread_id: 'zzz999', messages: 1, started: 'a', last: 'b', senders: ['node7'], recipients: ['bob'] },
  ],
});

describe('agent traffic', () => {
  it('merges senders and recipients into sorted unique participants', () => {
    expect(threads[0].participants).toEqual(['alice/s1', 'bob']);
    expect(threads[0].messages).toBe(3);
  });

  it('filters by text and by exact participant', () => {
    expect(filterThreads(threads, 'ZZZ', '').map((t) => t.id)).toEqual(['zzz999']);
    expect(filterThreads(threads, '', 'alice/s1').map((t) => t.id)).toEqual(['abc123']);
    expect(filterThreads(threads, 'node', 'bob').map((t) => t.id)).toEqual(['zzz999']);
  });

  it('orders messages oldest first', () => {
    const m = parseMessages({
      messages: [
        { id: 'b', ts: '2026-01-02T00:00:00Z', sig_verified: true, from_id: { node: 'n1' } },
        { id: 'a', ts: '2026-01-01T00:00:00Z' },
      ],
    });
    expect(m.map((x) => x.id)).toEqual(['a', 'b']);
    expect(m[1].sigVerified).toBe(true);
    expect(m[1].fromNode).toBe('n1');
  });

  it('renders body.text, else pretty JSON, collapsing long bodies', () => {
    expect(renderBody({ text: 'hi' })).toEqual({ text: 'hi', isText: true, long: false });
    expect(renderBody({ a: 1 }).text).toBe('{\n  "a": 1\n}');
    expect(renderBody({ text: 'x'.repeat(700) }).long).toBe(true);
  });
});
