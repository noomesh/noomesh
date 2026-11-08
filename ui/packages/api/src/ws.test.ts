// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createSocket, wsUrl } from './ws.ts';

// Minimal fake WebSocket the factory can drive. Records instances so tests can
// assert how many sockets were created (the reconnect-dedup bug, finding #2).
class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  url: string;
  readyState = FakeWebSocket.CONNECTING;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: unknown) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  sent: string[] = [];

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code: 1000, reason: '' });
  }
  // test helpers
  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.({});
  }
  serverClose(code: number, reason = '') {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason });
  }
  message(data: unknown) {
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) });
  }
}

// The ticket mint (POST /api/ws-ticket): records each call, answers with a
// ticket named after the bearer it was sent, so a URL shows which token bought it.
type Mint = { url: string; auth: string | null; body: string };
let mints: Mint[] = [];
let mintStatus = 200;
const fetchImpl = (async (url: string, init: RequestInit) => {
  const auth = new Headers(init.headers).get('Authorization');
  mints.push({ url, auth, body: String(init.body) });
  const ticket = `tik-${(auth ?? '').replace('Bearer ', '')}`;
  return new Response(JSON.stringify({ ticket }), { status: mintStatus });
}) as unknown as typeof fetch;

const opts = () => ({ baseUrl: 'https://gw.test', getToken: () => 'tok', reconnectMs: 1000, fetchImpl });
/** Let the ticket fetch (and any refresh) resolve. */
const flush = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  FakeWebSocket.instances = [];
  mints = [];
  mintStatus = 200;
  (globalThis as { WebSocket?: unknown }).WebSocket = FakeWebSocket;
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

const only = () => FakeWebSocket.instances[FakeWebSocket.instances.length - 1]!;

describe('createSocket', () => {
  // i515c: the access token never rides the socket URL. Each connect mints a
  // single-use ticket with the bearer, and the URL carries only the ticket.
  it('mints a ticket with the bearer and connects with ?ticket=, never ?token=', async () => {
    createSocket('/ws/coordinator', opts());
    await flush();
    expect(mints).toEqual([{ url: 'https://gw.test/api/ws-ticket', auth: 'Bearer tok', body: '{"socket":"/ws/coordinator"}' }]);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(only().url).toBe('wss://gw.test/ws/coordinator?ticket=tik-tok');
    expect(only().url).not.toContain('token=');
  });

  it('wsUrl carries a ticket and nothing else', () => {
    expect(wsUrl('/ws/collab', 'a b', { baseUrl: 'http://gw.test:8080', getToken: () => 'secret' })).toBe('ws://gw.test:8080/ws/collab?ticket=a%20b');
  });

  it('a refused ticket is an auth failure: refresh once, then stop', async () => {
    mintStatus = 401;
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => 'fresh');
    createSocket('/ws/coordinator', { ...opts(), refreshToken, onAuthFail });
    await flush();
    await flush();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it('reconnects after a non-auth close', async () => {
    createSocket('/ws/x', opts());
    await flush();
    only().open();
    only().serverClose(1006); // abnormal close
    expect(FakeWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('does NOT reconnect on an auth close (1008/4401) and fires onAuthFail (finding #7)', async () => {
    const onAuthFail = vi.fn();
    createSocket('/ws/x', { ...opts(), onAuthFail });
    await flush();
    only().open();
    only().serverClose(4401);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('reconnectNow() does not spawn duplicate concurrent sockets (finding #2)', async () => {
    const sock = createSocket('/ws/x', opts());
    await flush();
    only().open();
    sock.reconnectNow();
    await flush();
    // exactly one fresh socket — the old one's handlers were detached so its
    // async onclose can't also schedule a reconnect.
    expect(FakeWebSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('send() returns false when not OPEN, true when OPEN (finding #1 root)', async () => {
    const sock = createSocket('/ws/x', opts());
    expect(sock.send({ a: 1 })).toBe(false);
    await flush();
    only().open();
    expect(sock.send({ a: 1 })).toBe(true);
    expect(only().sent).toEqual([JSON.stringify({ a: 1 })]);
  });

  it('close() prevents any reconnect', async () => {
    const sock = createSocket('/ws/x', opts());
    await flush();
    only().open();
    sock.close();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('close() before the ticket arrives opens no socket', async () => {
    const sock = createSocket('/ws/x', opts());
    sock.close();
    await flush();
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it('parses JSON frames before handing them to onMessage', async () => {
    const onMessage = vi.fn();
    createSocket('/ws/x', { ...opts(), onMessage });
    await flush();
    only().open();
    only().message({ type: 'content', text: 'hi' });
    expect(onMessage).toHaveBeenCalledWith({ type: 'content', text: 'hi' }, expect.anything());
  });

  // 2026-09-18: a 4401 (token expired, logged out, bad token) refreshes once
  // and reconnects; a failed refresh — or a second 4401 before the socket
  // opens — stops the socket.
  it('refreshes once on 4401 and reconnects with a ticket bought by the new token', async () => {
    let tok = 'stale';
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => {
      tok = 'fresh';
      return tok;
    });
    createSocket('/ws/coordinator', { ...opts(), getToken: () => tok, refreshToken, onAuthFail });
    await flush();
    only().serverClose(4401, 'Token expired');
    await flush();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(only().url).toContain('ticket=tik-fresh');
    expect(onAuthFail).not.toHaveBeenCalled();
  });

  it('a failed refresh ends the socket instead of looping', async () => {
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => null);
    createSocket('/ws/coordinator', { ...opts(), refreshToken, onAuthFail });
    await flush();
    only().serverClose(4401, 'Logged out');
    await flush();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('does not refresh twice without the socket opening in between', async () => {
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => 'fresh');
    createSocket('/ws/coordinator', { ...opts(), refreshToken, onAuthFail });
    await flush();
    only().serverClose(4401);
    await flush();
    expect(FakeWebSocket.instances).toHaveLength(2);
    only().serverClose(4401); // the fresh token was refused too
    await flush();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
  });

  it('a socket that opened may refresh again on a later 4401', async () => {
    const refreshToken = vi.fn(async () => 'fresh');
    createSocket('/ws/coordinator', { ...opts(), refreshToken });
    await flush();
    only().open();
    only().serverClose(4401, 'Token expired');
    await flush();
    only().open();
    only().serverClose(4401, 'Token expired');
    await flush();
    expect(refreshToken).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(3);
  });
});
