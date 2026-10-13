// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createEventStream, type StreamEvent } from './sse.ts';

// A fake fetch that hands back a Response whose body is a stream the test can
// push into and close. Records every request so headers can be asserted.
interface Conn {
  url: string;
  headers: Record<string, string>;
  push(text: string): void;
  end(): void;
  signal: AbortSignal | null;
}
let conns: Conn[] = [];
let nextStatus = 200;
let networkError = false;

const fakeFetch: typeof fetch = async (input, init) => {
  if (networkError) throw new TypeError('network down');
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      ctrl = c;
    },
  });
  const enc = new TextEncoder();
  const h = init?.headers as Record<string, string>;
  const conn: Conn = {
    url: String(input),
    headers: { ...h },
    push: (t) => ctrl.enqueue(enc.encode(t)),
    end: () => ctrl.close(),
    signal: init?.signal ?? null,
  };
  // The abort must surface to the reader as a rejected read(), like a real
  // fetch body — otherwise a superseded loop never exits.
  init?.signal?.addEventListener('abort', () => {
    try {
      ctrl.error(new DOMException('aborted', 'AbortError'));
    } catch {
      /* already closed */
    }
  });
  conns.push(conn);
  const status = nextStatus;
  nextStatus = 200;
  // Response refuses a body on some statuses; 401/403 don't need one.
  return new Response(status === 401 || status === 403 ? null : body, { status });
};

const last = () => conns[conns.length - 1]!;
// Let the reader drain what was pushed. setImmediate is real even under the
// fake timers below (only setTimeout/clearTimeout are faked).
const settle = () => new Promise<void>((r) => setImmediate(r));

const opts = (extra: Partial<Parameters<typeof createEventStream>[1]> = {}) => ({
  baseUrl: 'https://gw.test',
  getToken: () => 'tok',
  fetchImpl: fakeFetch,
  reconnectMs: 1000,
  ...extra,
});

beforeEach(() => {
  conns = [];
  nextStatus = 200;
  networkError = false;
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe('createEventStream', () => {
  it('GETs the path with Accept and a bearer header — never a token in the URL', async () => {
    createEventStream('/api/events/stream', opts());
    await settle();
    expect(conns).toHaveLength(1);
    expect(last().url).toBe('https://gw.test/api/events/stream');
    expect(last().headers.Accept).toBe('text/event-stream');
    expect(last().headers.Authorization).toBe('Bearer tok');
    expect(last().url).not.toContain('tok');
  });

  it('parses id / event / data and dispatches on the blank line', async () => {
    const onEvent = vi.fn<(ev: StreamEvent) => void>();
    createEventStream('/s', opts({ onEvent }));
    await settle();
    last().push('id: 7\nevent: node.state\ndata: {"a":1}\n\n');
    await settle();
    expect(onEvent).toHaveBeenCalledWith({ id: '7', event: 'node.state', data: '{"a":1}' });
  });

  it('joins multi-line data with newline and defaults event to "message"', async () => {
    const onEvent = vi.fn<(ev: StreamEvent) => void>();
    createEventStream('/s', opts({ onEvent }));
    await settle();
    last().push('data: one\ndata: two\n\n');
    await settle();
    expect(onEvent).toHaveBeenCalledWith({ id: null, event: 'message', data: 'one\ntwo' });
  });

  it('handles a frame split across chunks and CRLF line endings', async () => {
    const onEvent = vi.fn<(ev: StreamEvent) => void>();
    createEventStream('/s', opts({ onEvent }));
    await settle();
    last().push('event: gpu.sa');
    await settle();
    last().push('mple\r\ndata: {"u":9');
    await settle();
    last().push('1}\r\n\r\n');
    await settle();
    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onEvent).toHaveBeenCalledWith({ id: null, event: 'gpu.sample', data: '{"u":91}' });
  });

  it('treats a comment line as a keepalive and does not dispatch it', async () => {
    const onEvent = vi.fn();
    const onKeepalive = vi.fn();
    createEventStream('/s', opts({ onEvent, onKeepalive }));
    await settle();
    last().push(': keepalive\n\n');
    await settle();
    expect(onKeepalive).toHaveBeenCalledTimes(1);
    expect(onEvent).not.toHaveBeenCalled();
  });

  it('drops an event with no data lines', async () => {
    const onEvent = vi.fn();
    createEventStream('/s', opts({ onEvent }));
    await settle();
    last().push('event: hello\n\n');
    await settle();
    expect(onEvent).not.toHaveBeenCalled();
  });

  it('reconnects with Last-Event-ID after the stream ends', async () => {
    const onError = vi.fn();
    const s = createEventStream('/s', opts({ onError }));
    await settle();
    last().push('id: 41\ndata: x\n\n');
    await settle();
    expect(s.lastEventId).toBe('41');
    last().end();
    await settle();
    expect(onError).toHaveBeenCalledWith(null);
    expect(conns).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(2);
    expect(last().headers['Last-Event-ID']).toBe('41');
  });

  it('backs off exponentially across consecutive failed opens, and resets once one succeeds', async () => {
    nextStatus = 503;
    createEventStream('/s', opts());
    await settle();
    expect(conns).toHaveLength(1);
    // 1st retry after 1s
    nextStatus = 503;
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(2);
    // 2nd retry after 2s, not 1s
    await vi.advanceTimersByTimeAsync(1000);
    expect(conns).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(3);
    // that one opened cleanly (200) → the counter resets, so a later close retries at 1s again
    last().end();
    await settle();
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(4);
  });

  it('honours a retry: field as the new base backoff', async () => {
    createEventStream('/s', opts());
    await settle();
    last().push('retry: 250\n');
    await settle();
    last().end();
    await settle();
    await vi.advanceTimersByTimeAsync(250);
    await settle();
    expect(conns).toHaveLength(2);
  });

  it('surfaces 401/403 as onAuthFail and does NOT reconnect', async () => {
    const onAuthFail = vi.fn();
    const onError = vi.fn();
    nextStatus = 401;
    createEventStream('/s', opts({ onAuthFail, onError }));
    await settle();
    expect(onAuthFail).toHaveBeenCalledWith(401);
    expect(onError).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(conns).toHaveLength(1);
  });

  it('surfaces other non-2xx as onError(status) and reconnects', async () => {
    const onError = vi.fn();
    nextStatus = 503;
    createEventStream('/s', opts({ onError }));
    await settle();
    expect(onError).toHaveBeenCalledWith(503);
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(2);
  });

  it('surfaces a network error as onError(null) and reconnects', async () => {
    const onError = vi.fn();
    networkError = true;
    createEventStream('/s', opts({ onError }));
    await settle();
    expect(onError).toHaveBeenCalledWith(null);
    networkError = false;
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(1);
  });

  it('reconnectNow() aborts the old connection and opens exactly one new one', async () => {
    const s = createEventStream('/s', opts());
    await settle();
    const first = last();
    s.reconnectNow();
    await settle();
    expect(first.signal?.aborted).toBe(true);
    expect(conns).toHaveLength(2);
    // the aborted loop must not schedule its own reconnect
    await vi.advanceTimersByTimeAsync(10_000);
    expect(conns).toHaveLength(2);
  });

  it('close() aborts and prevents any reconnect', async () => {
    const s = createEventStream('/s', opts());
    await settle();
    s.close();
    await settle();
    expect(last().signal?.aborted).toBe(true);
    expect(s.connected).toBe(false);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(conns).toHaveLength(1);
  });

  it('a stalled connection — open but silent past stallMs — is aborted and reconnected', async () => {
    const onStall = vi.fn();
    const onError = vi.fn();
    createEventStream('/s', opts({ stallMs: 5000, onStall, onError }));
    await settle();
    const first = last();
    // bytes reset the clock: 4s quiet, a keepalive, 4s quiet → still fine
    await vi.advanceTimersByTimeAsync(4000);
    first.push(': keepalive\n\n');
    await settle();
    await vi.advanceTimersByTimeAsync(4000);
    expect(onStall).not.toHaveBeenCalled();
    expect(first.signal?.aborted).toBe(false);
    // 5s of silence from the last byte → stall
    await vi.advanceTimersByTimeAsync(1001);
    await settle();
    expect(onStall).toHaveBeenCalledTimes(1);
    expect(first.signal?.aborted).toBe(true);
    expect(onError).toHaveBeenCalledWith(null);
    // and it comes back, at the base delay (the open had succeeded)
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(conns).toHaveLength(2);
  });

  it('setStallMs re-arms a live connection with the new timeout', async () => {
    const onStall = vi.fn();
    const s = createEventStream('/s', opts({ stallMs: 0, onStall }));
    await settle();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(onStall).not.toHaveBeenCalled(); // disabled
    s.setStallMs(2000);
    await vi.advanceTimersByTimeAsync(2001);
    await settle();
    expect(onStall).toHaveBeenCalledTimes(1);
  });

  it('close() disarms the stall clock', async () => {
    const onStall = vi.fn();
    const s = createEventStream('/s', opts({ stallMs: 1000, onStall }));
    await settle();
    s.close();
    await vi.advanceTimersByTimeAsync(5000);
    expect(onStall).not.toHaveBeenCalled();
  });

  it('reports connected only while a 2xx body is open', async () => {
    const s = createEventStream('/s', opts());
    expect(s.connected).toBe(false);
    await settle();
    expect(s.connected).toBe(true);
    last().end();
    await settle();
    expect(s.connected).toBe(false);
  });
});
