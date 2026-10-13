// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createSocket } from './ws.ts';

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

const opts = () => ({ baseUrl: 'https://gw.test', getToken: () => 'tok', reconnectMs: 1000 });

beforeEach(() => {
  FakeWebSocket.instances = [];
  (globalThis as { WebSocket?: unknown }).WebSocket = FakeWebSocket;
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

const only = () => FakeWebSocket.instances[FakeWebSocket.instances.length - 1]!;

describe('createSocket', () => {
  it('connects immediately with a token in the URL', () => {
    createSocket('/ws/coordinator', opts());
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(only().url).toContain('wss://gw.test/ws/coordinator?token=tok');
  });

  it('reconnects after a non-auth close', () => {
    createSocket('/ws/x', opts());
    only().open();
    only().serverClose(1006); // abnormal close
    expect(FakeWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('does NOT reconnect on an auth close (1008/4401) and fires onAuthFail (finding #7)', () => {
    const onAuthFail = vi.fn();
    createSocket('/ws/x', { ...opts(), onAuthFail });
    only().open();
    only().serverClose(4401);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(10_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('reconnectNow() does not spawn duplicate concurrent sockets (finding #2)', () => {
    const sock = createSocket('/ws/x', opts());
    only().open();
    sock.reconnectNow();
    // exactly one fresh socket — the old one's handlers were detached so its
    // async onclose can't also schedule a reconnect.
    expect(FakeWebSocket.instances).toHaveLength(2);
    vi.advanceTimersByTime(10_000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('send() returns false when not OPEN, true when OPEN (finding #1 root)', () => {
    const sock = createSocket('/ws/x', opts());
    expect(sock.send({ a: 1 })).toBe(false);
    only().open();
    expect(sock.send({ a: 1 })).toBe(true);
    expect(only().sent).toEqual([JSON.stringify({ a: 1 })]);
  });

  it('close() prevents any reconnect', () => {
    const sock = createSocket('/ws/x', opts());
    only().open();
    sock.close();
    vi.advanceTimersByTime(10_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('parses JSON frames before handing them to onMessage', () => {
    const onMessage = vi.fn();
    createSocket('/ws/x', { ...opts(), onMessage });
    only().open();
    only().message({ type: 'content', text: 'hi' });
    expect(onMessage).toHaveBeenCalledWith({ type: 'content', text: 'hi' }, expect.anything());
  });

  // 2026-09-18: a 4401 (token expired, logged out, bad token) refreshes once
  // and reconnects; a failed refresh — or a second 4401 before the socket
  // opens — stops the socket. Before this the gateway's HTTP 401 on the
  // handshake reached the browser as 1006 and a lapsed tab retried forever.
  it('refreshes once on 4401 and reconnects with the new token', async () => {
    let tok = 'stale';
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => {
      tok = 'fresh';
      return tok;
    });
    createSocket('/ws/coordinator', { ...opts(), getToken: () => tok, refreshToken, onAuthFail });
    only().serverClose(4401, 'Token expired');
    await Promise.resolve();
    await Promise.resolve();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(only().url).toContain('token=fresh');
    expect(onAuthFail).not.toHaveBeenCalled();
  });

  it('a failed refresh ends the socket instead of looping', async () => {
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => null);
    createSocket('/ws/coordinator', { ...opts(), refreshToken, onAuthFail });
    only().serverClose(4401, 'Logged out');
    await Promise.resolve();
    await Promise.resolve();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('does not refresh twice without the socket opening in between', async () => {
    const onAuthFail = vi.fn();
    const refreshToken = vi.fn(async () => 'fresh');
    createSocket('/ws/coordinator', { ...opts(), refreshToken, onAuthFail });
    only().serverClose(4401);
    await Promise.resolve();
    await Promise.resolve();
    expect(FakeWebSocket.instances).toHaveLength(2);
    only().serverClose(4401); // the fresh token was refused too
    await Promise.resolve();
    await Promise.resolve();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(onAuthFail).toHaveBeenCalledTimes(1);
  });

  it('a socket that opened may refresh again on a later 4401', async () => {
    const refreshToken = vi.fn(async () => 'fresh');
    createSocket('/ws/coordinator', { ...opts(), refreshToken });
    only().open();
    only().serverClose(4401, 'Token expired');
    await Promise.resolve();
    await Promise.resolve();
    only().open();
    only().serverClose(4401, 'Token expired');
    await Promise.resolve();
    await Promise.resolve();
    expect(refreshToken).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(3);
  });
});
