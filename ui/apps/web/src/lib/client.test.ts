// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

// A plain delegate, not vi.fn(): vitest 5 reports an error thrown by a vi.fn as a test failure even when the code under test catches it.
const H = vi.hoisted(() => {
  const h = { impl: (async () => new Response('{}')) as (r: Request) => Promise<Response>, fetch: (r: Request) => h.impl(r) };
  return h;
});

vi.mock('@metis/api', () => ({
  createMetisClient: () => ({}),
  createAuthApi: () => ({}),
  createAuthFetch: () => H.fetch,
  createTokenRefresher: () => async () => null,
  webTokenStore: () => ({}),
}));

import { apiGet, apiErrorMessage, ApiError } from './client';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

beforeEach(() => {
  H.impl = async () => new Response('{}');
});

describe('apiGet — a failure is never "no data"', () => {
  it('resolves the body on 200', async () => {
    H.impl = async () => (json(200, { a: 1 }));
    expect(await apiGet('http://localhost/x')).toEqual({ a: 1 });
  });

  it('throws ApiError with status + refusal body on 503 redis_reconnecting', async () => {
    const body = { error: 'redis_reconnecting', detail: 'Redis not connected: retry shortly.', retry_after_secs: 5 };
    H.impl = async () => (json(503, body));
    const err = await apiGet('http://localhost/x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(503);
    expect(err.body).toEqual(body);
    expect(apiErrorMessage(err, 'fallback')).toBe('Redis not connected: retry shortly. Retry in 5s.');
  });

  it('throws on 403 with a non-JSON body and uses the fallback sentence', async () => {
    H.impl = async () => (new Response('nope', { status: 403 }));
    const err = await apiGet('http://localhost/x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(apiErrorMessage(err, 'Threads API unavailable')).toBe('Threads API unavailable');
  });

  it('throws status 0 on a network error', async () => {
    H.impl = async () => {
      throw new Error('offline');
    };
    const err = await apiGet('http://localhost/x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
  });
});
