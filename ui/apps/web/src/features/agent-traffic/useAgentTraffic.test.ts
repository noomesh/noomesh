// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import {
  PREVIEW_CHARS,
  PREVIEW_LINES,
  filterThreads,
  parseMessages,
  parseThreads,
  previewOf,
  recipientLabel,
  renderBody,
} from './useAgentTraffic';

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

  it('renders body.text, else pretty JSON, collapsing long bodies to a preview', () => {
    expect(renderBody({ text: 'hi' })).toEqual({ text: 'hi', isText: true, long: false, preview: 'hi' });
    expect(renderBody({ a: 1 }).text).toBe('{\n  "a": 1\n}');
    const long = renderBody({ text: 'x'.repeat(700) });
    expect(long.long).toBe(true);
    expect(long.preview).toBe(`${'x'.repeat(PREVIEW_CHARS)}…`);
  });

  it('previews the first lines of a long body, and nothing is cut from a short one', () => {
    const lines = Array.from({ length: PREVIEW_LINES + 3 }, (_, i) => `line ${i}`).join('\n');
    expect(previewOf(lines)).toBe(`${lines.split('\n').slice(0, PREVIEW_LINES).join('\n')}…`);
    expect(previewOf('short\nbody')).toBe('short\nbody');
  });

  it('never counts the thread address as a participant', () => {
    const t = parseThreads({
      threads: [{ thread_id: 't', messages: 2, started: 'a', last: 'b', senders: ['rbwolf/op'], recipients: ['thread', 'rbwolf/codex'] }],
    });
    expect(t[0].participants).toEqual(['rbwolf/codex', 'rbwolf/op']);
    expect(recipientLabel('thread')).toEqual({ text: 'the thread', isThread: true });
    expect(recipientLabel('rbwolf/codex')).toEqual({ text: 'rbwolf/codex', isThread: false });
  });
});
