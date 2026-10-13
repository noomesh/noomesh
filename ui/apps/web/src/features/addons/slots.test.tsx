// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';

vi.mock('@/features/observability/useObservability', () => ({
  useObservability: () => ({ data: { addons: [{ id: 'evolve', label: 'Evolve', state: 'disabled' }] } }),
}));
const P = vi.hoisted(() => ({ pieces: {} as Record<string, { title: string; description: string; steps: string[] }> }));
vi.mock('./useConsolePieces', () => ({ useConsolePieces: () => P.pieces }));
vi.mock('@/features/brain-map/useBrainStatus', () => ({ useBrainStatus: () => ({ data: undefined }) }));

import { SLOTS } from './slots';
import { WORKFLOW_SLOT_NODES } from '@/features/workflow/svg';
import { BRAIN_SLOT_NODES } from '@/features/brain-map/svg';
import { WorkflowPanel } from '@/features/workflow/WorkflowPanel';

// No node in either diagram belongs to the Intelligent tier yet; the registry
// reserves the ids so the add-on's piece has somewhere to land.
const RESERVED_UNPLACED = ['trellion_intel:graph-nav', 'trellion_intel:temporal'];

describe('slot registry', () => {
  it('every slot id is referenced by exactly one node across both diagrams', () => {
    const refs = [...Object.values(WORKFLOW_SLOT_NODES), ...Object.values(BRAIN_SLOT_NODES)].map((n) => n.slotId);
    for (const s of SLOTS) {
      const n = refs.filter((r) => r === s.slotId).length;
      expect(n, s.slotId).toBe(RESERVED_UNPLACED.includes(s.slotId) ? 0 : 1);
    }
    for (const r of refs) expect(SLOTS.some((s) => s.slotId === r), r).toBe(true);
  });

  it('ids follow <addonId>:<lane>', () => {
    for (const s of SLOTS) expect(s.slotId.startsWith(`${s.addonId}:`)).toBe(true);
  });
});

describe('slot rendering', () => {
  afterEach(cleanup);
  const open = (nodeId: string) => {
    const g = document.querySelector(`[data-id="${nodeId}"]`);
    expect(g).not.toBeNull();
    fireEvent.click(g!);
  };

  it('with no piece shows the placeholder and the not-installed state', () => {
    render(<WorkflowPanel />);
    open('ga-evolve');
    expect(screen.getByText('Provided by the Evolve add-on.')).toBeTruthy();
    expect(screen.getByText(/not installed/)).toBeTruthy();
  });

  it('with a piece shows the add-on description', () => {
    P.pieces = { 'evolve:ga-evolve': { title: 'Evolve', description: 'fake description from the piece', steps: ['first step', 'second step'] } };
    render(<WorkflowPanel />);
    open('ga-evolve');
    expect(screen.getByText('fake description from the piece')).toBeTruthy();
    expect(screen.getByText('second step')).toBeTruthy();
    P.pieces = {};
  });
});
