// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';
import { createMetisClient } from './client.ts';
import { awaitOperation, isOperationHandle, OperationError, type OperationHandle } from './ops.ts';

function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const handle: OperationHandle = {
  op_id: '0f9c1d2e-0000-4000-8000-000000000001',
  type: 'graph.navigate',
  status: 'running',
  poll: '/api/v1/ops/0f9c1d2e-0000-4000-8000-000000000001',
  poll_interval_ms: 1000,
};

function clientFor(replies: Array<Response | (() => Response)>) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (input: Request | string | URL) => {
    calls.push(typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url);
    const next = replies.shift();
    if (!next) throw new Error('unexpected extra request');
    return typeof next === 'function' ? next() : next;
  });
  return { client: createMetisClient({ baseUrl: 'http://gw', fetchImpl: fetchImpl as unknown as typeof fetch }), calls };
}

describe('isOperationHandle', () => {
  it('tells a 202 handle from a 200 result', () => {
    expect(isOperationHandle(handle)).toBe(true);
    expect(isOperationHandle({ clusters: 3 })).toBe(false);
    expect(isOperationHandle({ op_id: 'x', poll: '/p', status: 'succeeded' })).toBe(false);
    expect(isOperationHandle(null)).toBe(false);
    expect(isOperationHandle('running')).toBe(false);
  });
});

describe('awaitOperation', () => {
  it('long-polls until the op succeeds and returns the route result', async () => {
    const { client, calls } = clientFor([
      json(200, { status: 'running', progress: { stage: 'a' } }),
      json(200, { status: 'succeeded', result: { message: 'ingested' } }),
    ]);
    const seen: unknown[] = [];
    const out = await awaitOperation<{ message: string }>(client, handle, { onProgress: (o) => seen.push(o.progress) });
    expect(out).toEqual({ message: 'ingested' });
    expect(seen).toEqual([{ stage: 'a' }]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toContain(`/api/v1/ops/${handle.op_id}`);
    expect(calls[0]).toMatch(/wait=\d+/);
  });

  it('rejects with the op for a failure, a cancel and an expiry', async () => {
    for (const status of ['failed', 'cancelled', 'expired'] as const) {
      const { client } = clientFor([json(200, { op_id: handle.op_id, type: handle.type, status, error: 'boom' })]);
      const err = await awaitOperation(client, handle).catch((e) => e);
      expect(err).toBeInstanceOf(OperationError);
      expect((err as OperationError).op.status).toBe(status);
    }
  });

  it('gives up when out of time without cancelling, and never reports success', async () => {
    const { client, calls } = clientFor([]);
    await expect(awaitOperation(client, handle, { timeoutMs: 0 })).rejects.toThrow(/still running/);
    expect(calls).toHaveLength(0);
  });

  it('reports an unreadable op as an error, not as running forever', async () => {
    const { client } = clientFor([json(404, { error: 'no such operation' })]);
    await expect(awaitOperation(client, handle)).rejects.toThrow(/could not read operation/);
  });
});
