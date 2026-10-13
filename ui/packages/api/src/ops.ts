// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — asynchronous operations (gateway `routes/ops.rs`).
//
// The long routes (recluster, extract-relations, consolidate, ingest, and the
// slower graph walks) are OPERATION-BACKED: they start an operation and wait a
// bounded time for it, so a call answers either
//   200 — the result, in the route's own shape (it finished in time), or
//   202 — an OperationHandle (it did not).
// A caller must handle both. `isOperationHandle` tells them apart and
// `awaitOperation` follows a handle to the end with long-polls
// (`GET /api/v1/ops/{id}?wait=`, a handful of requests, not a busy loop).

import type { MetisClient } from './client.ts';

/** What an operation-backed route answers 202 with. */
export interface OperationHandle {
  op_id: string;
  type: string;
  status: 'queued' | 'running';
  poll: string;
  poll_interval_ms: number;
  joined?: boolean;
}

export type OperationStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'expired';

/** One operation as `GET /api/v1/ops/{id}` shows it. */
export interface Operation<T = unknown> {
  op_id: string;
  type: string;
  status: OperationStatus;
  progress?: Record<string, unknown>;
  result?: T | null;
  result_status?: number | null;
  error?: string | null;
  cancel?: { gateway_aborted: boolean; worker_stopped: boolean; note: string };
  retry_safe?: boolean;
}

/** An operation that did not succeed. `status` is the terminal state; `result` is the worker's body when it sent one. */
export class OperationError extends Error {
  readonly op: Operation;
  constructor(op: Operation) {
    super(op.error ?? `operation ${op.op_id} ${op.status}`);
    this.name = 'OperationError';
    this.op = op;
  }
}

/** Whether a response body is an operation handle (a 202 from an operation-backed route). */
export function isOperationHandle(v: unknown): v is OperationHandle {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.op_id === 'string' &&
    typeof o.poll === 'string' &&
    (o.status === 'queued' || o.status === 'running')
  );
}

export interface AwaitOptions {
  /** Give up after this long (default 5 minutes). The operation itself is NOT cancelled. */
  timeoutMs?: number;
  /** Seconds each long-poll asks the gateway to hold for (default 20; the gateway caps it at 25). */
  waitSecs?: number;
  signal?: AbortSignal;
  /** Called with every non-terminal view (progress). */
  onProgress?: (op: Operation) => void;
}

/**
 * Follow `handle` to its end and return the route's result.
 * Rejects with {@link OperationError} if it failed, was cancelled or expired,
 * and with a plain Error if `timeoutMs` ran out first (the op is still running).
 */
export async function awaitOperation<T = unknown>(
  client: MetisClient,
  handle: OperationHandle,
  opts: AwaitOptions = {},
): Promise<T> {
  const deadline = Date.now() + (opts.timeoutMs ?? 5 * 60_000);
  const waitCap = Math.min(opts.waitSecs ?? 20, 25);
  for (;;) {
    const remainingSecs = Math.ceil((deadline - Date.now()) / 1000);
    if (remainingSecs <= 0) {
      throw new Error(`operation ${handle.op_id} is still running; it was not cancelled`);
    }
    const { data, error } = await client.GET('/api/v1/ops/{id}', {
      params: { path: { id: handle.op_id }, query: { wait: Math.max(1, Math.min(waitCap, remainingSecs)) } },
      signal: opts.signal,
    });
    if (error || !data) {
      throw new Error(`could not read operation ${handle.op_id}`);
    }
    const op = data as unknown as Operation<T>;
    if (op.status === 'succeeded') return op.result as T;
    if (op.status === 'failed' || op.status === 'cancelled' || op.status === 'expired') {
      throw new OperationError(op);
    }
    opts.onProgress?.(op);
  }
}
