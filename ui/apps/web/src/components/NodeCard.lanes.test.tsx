// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { NodeCard } from './NodeCard';
import type { ClusterNode } from '@/features/cluster/types';
import { readLanes } from '@/features/cluster/lanes';

afterEach(cleanup);

const node = (lanes: unknown): ClusterNode => ({
  id: 'host3',
  hostname: 'host3',
  ip: '100.64.0.3',
  tier: 1,
  status: 'online',
  backends: ['ollama', 'vllm'],
  heartbeat: '5s',
  lanes: readLanes({ lanes }),
});

describe('NodeCard lanes', () => {
  it('shows one line per chat lane that is not routed', () => {
    render(
      <NodeCard
        node={node([
          { backend: 'ollama', model: 'gemma4:12b', role: 'chat', state: 'serving', reason: '' },
          { backend: 'vllm', model: 'org/new-model', role: 'chat', state: 'loading', reason: 'warming' },
        ])}
      />,
    );
    const lines = screen.getAllByTestId('lane-state');
    expect(lines.map((l) => l.textContent)).toEqual(['vllm org/new-model: loading (warming)']);
  });

  it('shows nothing when every lane routes or the agent sends none', () => {
    render(<NodeCard node={node([{ backend: 'ollama', model: 'm', role: 'chat', state: 'serving', reason: '' }])} />);
    expect(screen.queryAllByTestId('lane-state')).toHaveLength(0);
    cleanup();
    render(<NodeCard node={node(undefined)} />);
    expect(screen.queryAllByTestId('lane-state')).toHaveLength(0);
  });
});
