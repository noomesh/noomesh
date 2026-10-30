// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { resolve } from 'node:path';
import { PAIRING_PENDING, PAIRING_RESULT, rememberPairing, takePairingReturn } from './pairingReturn';

const session = { session_id: 'owned-session', completion_token: 'private-ticket', state: 'random-state', authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth?state=random-state', expires_in: 600 };
beforeEach(() => { sessionStorage.clear(); });
function result(overrides = {}) {
  sessionStorage.setItem(PAIRING_RESULT, JSON.stringify({ state: session.state, code: 'one-time-code', ...overrides }));
}
describe('phone authorization return', () => {
  it('keeps the ticket out of the provider URL and consumes a return once', () => {
    expect(rememberPairing(session, 'alice')).not.toContain('private-ticket');
    result();
    expect(takePairingReturn('alice')?.result.code).toBe('one-time-code');
    expect(sessionStorage.getItem(PAIRING_PENDING)).toBeNull();
    expect(takePairingReturn('alice')).toBeNull();
  });
  it('rejects a changed owner, mismatched state, or expired request', () => {
    for (const scenario of ['owner','state','expiry']) {
      rememberPairing({ ...session, expires_in: scenario === 'expiry' ? -1 : 600 }, 'alice');
      result(scenario === 'state' ? { state: 'unrelated' } : {});
      expect(() => takePairingReturn(scenario === 'owner' ? 'bob' : 'alice')).toThrow('expired');
      expect(sessionStorage.length).toBe(0);
    }
  });
  it('handles declined access and rejects oversized codes and insecure destinations', () => {
    rememberPairing(session, 'alice'); result({ error: true, code: null });
    expect(takePairingReturn('alice')?.result.error).toBe(true);
    rememberPairing(session, 'alice'); result({ code: 'x'.repeat(8193) });
    expect(() => takePairingReturn('alice')).toThrow();
    expect(() => rememberPairing({ ...session, authorization_url: 'http://untrusted.test' }, 'alice')).toThrow();
  });
  it('removes abandoned tickets on account changes and expiry', () => {
    rememberPairing(session, 'alice');
    expect(takePairingReturn('bob')).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });
});

describe('the served callback script', () => {
  const html = readFileSync(resolve(process.cwd(), '../../../gateway-rust/src/integrations/callback.html'), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1];
  it('returns a phone flow to the pairing page and strips the callback query', () => {
    rememberPairing(session, 'alice');
    let destination = ''; let stripped = false;
    runInNewContext(script, {
      URLSearchParams, sessionStorage, Date,
      history: { replaceState: () => { stripped = true; } },
      location: { search: '?state=random-state&code=one-time-code', pathname: '/api/connections/oauth/callback', replace: (path: string) => { destination = path; } },
    });
    expect(stripped).toBe(true);
    expect(destination).toBe('/#/connect');
    expect(takePairingReturn('alice')?.result.code).toBe('one-time-code');
  });
  it('keeps the existing desktop-console popup callback working', () => {
    let message: unknown;
    class Channel { postMessage(value: unknown) { message = value; } close() {} }
    const status = { textContent: '' };
    runInNewContext(script, {
      URLSearchParams, sessionStorage, Date, BroadcastChannel: Channel,
      history: { replaceState() {} }, document: { getElementById: () => status },
      location: { search: '?state=popup-state&code=one-time-code', pathname: '/api/connections/oauth/callback' },
    });
    expect(message).toEqual({ type: 'noomesh:oauth-result', state: 'popup-state', code: 'one-time-code', error: null });
    expect(status.textContent).toContain('Return to the Noomesh window');
  });
});
