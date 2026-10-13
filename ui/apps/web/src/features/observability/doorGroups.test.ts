// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { doorBackendName, groupBackendDoors } from './doorGroups';
import type { Container } from './useObservability';

function c(name: string, node: string, status = 'running', cpu = 1, memUsed = 100): Container {
  return { name, node, status, cpu, memUsed, memLimit: 3788, memPct: 0 };
}

describe('doorBackendName — the source naming rule', () => {
  it('maps <p>-stunnel-<x> to <p>-<x>', () => {
    expect(doorBackendName('noo-stunnel-ollama')).toBe('noo-ollama');
    expect(doorBackendName('noo-stunnel-tei-gpu')).toBe('noo-tei-gpu');
    expect(doorBackendName('noo-stunnel-ollama-embed')).toBe('noo-ollama-embed');
    expect(doorBackendName('lab-stunnel-reranker')).toBe('lab-reranker');
  });
  it('is null for anything that is not a door', () => {
    expect(doorBackendName('noo-ollama')).toBeNull();
    expect(doorBackendName('noo-vllm')).toBeNull();
  });
});

describe('groupBackendDoors — one row per backend', () => {
  // What the operator saw on host9, host2 and host8: the door listed as a
  // second ollama, sometimes ahead of the backend itself.
  const fleet = [
    c('noo-stunnel-ollama', 'host9', 'running', 7.5, 2),
    c('noo-ollama', 'host9', 'running', 7.6, 1946),
    c('noo-ollama', 'host2'),
    c('noo-stunnel-ollama', 'host2'),
    c('noo-stunnel-ollama', 'host8'),
    c('noo-ollama', 'host8'),
    c('noo-vllm', 'host8'),
  ];

  it('folds each door into its backend: one noo-ollama per node, each with a door', () => {
    const rows = groupBackendDoors(fleet);
    expect(rows.map((r) => `${r.node}/${r.name}`)).toEqual([
      'host9/noo-ollama',
      'host2/noo-ollama',
      'host8/noo-ollama',
      'host8/noo-vllm',
    ]);
    for (const r of rows.filter((r) => r.name === 'noo-ollama')) {
      expect(r.door?.name).toBe('noo-stunnel-ollama');
      expect(r.door?.node).toBe(r.node);
      expect(r.doorState).toBe('running');
      expect(r.doorWarning).toBeNull();
      expect(r.orphanDoor).toBe(false);
    }
    // The row keeps the backend's own metrics, not the door's.
    const host9 = rows.find((r) => r.node === 'host9')!;
    expect(host9.cpu).toBe(7.6);
    expect(host9.memUsed).toBe(1946);
  });

  it('gives vLLM (native TLS) no door badge and no warning', () => {
    const vllm = groupBackendDoors(fleet).find((r) => r.name === 'noo-vllm')!;
    expect(vllm.door).toBeNull();
    expect(vllm.doorState).toBeNull();
    expect(vllm.doorWarning).toBeNull();
  });

  it('never pairs a door with a backend on another node', () => {
    const rows = groupBackendDoors([c('noo-ollama', 'host9'), c('noo-stunnel-ollama', 'host2')]);
    expect(rows).toHaveLength(2);
    expect(rows[0].doorState).toBe('missing');
    expect(rows[1].orphanDoor).toBe(true);
  });

  it('still shows a door that has no backend, flagged as a leftover', () => {
    const rows = groupBackendDoors([c('noo-ollama', 'host9'), c('noo-stunnel-ollama', 'host9'), c('noo-stunnel-reranker', 'host2')]);
    expect(rows).toHaveLength(2);
    const orphan = rows.find((r) => r.name === 'noo-stunnel-reranker')!;
    expect(orphan.node).toBe('host2');
    expect(orphan.orphanDoor).toBe(true);
    expect(orphan.doorWarning).toMatch(/leftover/);
  });

  it('warns when a running backend has no door', () => {
    const [r] = groupBackendDoors([c('noo-ollama', 'host9')]);
    expect(r.doorState).toBe('missing');
    expect(r.doorWarning).toMatch(/no mTLS door/);
  });

  it('warns when the door is not running while the backend runs', () => {
    const [r] = groupBackendDoors([c('noo-ollama', 'host9'), c('noo-stunnel-ollama', 'host9', 'exited')]);
    expect(r.doorState).toBe('down');
    expect(r.doorWarning).toMatch(/exited/);
  });

  it('does not warn about a door when the backend itself is stopped', () => {
    const [r] = groupBackendDoors([c('noo-tei-gpu', 'host3', 'exited')]);
    expect(r.doorState).toBe('missing');
    expect(r.doorWarning).toBeNull();
  });
});
