// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { summariseArgs } from './useCoordinator';

/**
 * The approval card's whole claim to being oversight rather than theatre is
 * that it shows the call it is gating. These pin the shapes the gateway
 * actually sends on `tool_call` (agent_loop.rs emits `arguments` verbatim from
 * the model, so anything JSON-shaped can arrive).
 */
describe('summariseArgs', () => {
  it('renders an object as readable key=value pairs', () => {
    expect(summariseArgs({ command: 'systemctl restart pai', timeout: 30 })).toBe(
      'command=systemctl restart pai  timeout=30',
    );
  });

  it('parses arguments that arrive as a JSON string', () => {
    // Some backends hand tool arguments back serialised rather than as an object.
    expect(summariseArgs('{"path":"/etc/hosts"}')).toBe('path=/etc/hosts');
  });

  it('keeps an unparseable string rather than dropping it', () => {
    // Showing something imperfect beats a card that gates an unnamed action.
    expect(summariseArgs('{not json')).toBe('{not json');
  });

  it('masks credential-shaped keys', () => {
    expect(summariseArgs({ url: 'https://x.dev', api_key: 'sk-live-abc123' })).toBe(
      'url=https://x.dev  api_key=•••',
    );
  });

  it('masks on the key, not the value — a token nested in a command still shows', () => {
    // Honest limit: the gateway sends arguments unredacted and the operator
    // needs to read the command, so only the obvious cases are masked here.
    // Server-side redaction is the fix for the out-of-band queue.
    expect(summariseArgs({ command: 'curl -H "Authorization: Bearer sk-1"' })).toContain('sk-1');
  });

  it('flattens newlines so a multi-line script cannot blow out the card', () => {
    expect(summariseArgs({ script: 'set -e\nrm -rf /tmp/x' })).toBe('script=set -e rm -rf /tmp/x');
  });

  it('clips very long arguments and marks the truncation', () => {
    const out = summariseArgs({ command: 'x'.repeat(500) })!;
    expect(out.length).toBeLessThanOrEqual(240);
    expect(out.endsWith('…')).toBe(true);
  });

  it('returns undefined when there is nothing to show, so the card omits the row', () => {
    expect(summariseArgs(undefined)).toBeUndefined();
    expect(summariseArgs(null)).toBeUndefined();
    expect(summariseArgs({})).toBeUndefined();
    expect(summariseArgs('   ')).toBeUndefined();
    expect(summariseArgs({ a: '', b: null })).toBeUndefined();
  });
});
