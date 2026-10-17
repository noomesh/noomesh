// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, expect, it } from 'vitest';
import { gpuContentionLine, readGpuContention } from './gpuContention';

describe('gpuContentionLine', () => {
  it('says the GPU is in use by other work and which backend is paused', () => {
    const line = gpuContentionLine({
      state: 'yielded',
      foreign_mb: 11468,
      paused_backends: ['vllm'],
      since: new Date(Date.now() - 5 * 60_000).toISOString(),
    });
    expect(line).toBe('GPU in use by other work — vllm paused since 5m ago (foreign 11.2 GB)');
  });
  it('names an operator hold and its reason', () => {
    expect(gpuContentionLine({ state: 'held', reason: 'voice', paused_backends: ['vllm'] })).toBe(
      'GPU held by operator (voice) — vllm paused',
    );
  });
  it('is silent when the GPU is free or unreported', () => {
    expect(gpuContentionLine({ state: 'free' })).toBeNull();
    expect(gpuContentionLine(undefined)).toBeNull();
  });
  it('reads the raw node defensively', () => {
    expect(readGpuContention({ gpu_contention: { state: 'free' } })?.state).toBe('free');
    expect(readGpuContention({})).toBeUndefined();
    expect(readGpuContention({ gpu_contention: 'x' })).toBeUndefined();
  });
});
