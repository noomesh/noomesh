// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { phaseFromFrame, phaseLabel, type TurnPhase } from './phase';

const T0 = 1_000_000;

describe('phaseLabel', () => {
  it('says a turn is queued when every slot is busy, with who is ahead and the wait', () => {
    const p: TurnPhase = { kind: 'routed', since: T0, node: 'mcmini', slotsBusy: 2, slotsTotal: 2, queuedAhead: 1 };
    expect(phaseLabel(p, T0 + 4_200)).toBe('queued on mcmini (2/2 busy, 1 ahead) · 4s');
  });

  it('says sending when a slot is free, or when the agent reports no slots', () => {
    expect(phaseLabel({ kind: 'routed', since: T0, node: 'awolf', slotsBusy: 1, slotsTotal: 2 }, T0)).toBe(
      'sending to awolf · 0s',
    );
    expect(phaseLabel({ kind: 'routed', since: T0, node: 'awolf', slotsBusy: null, slotsTotal: null }, T0)).toBe(
      'sending to awolf · 0s',
    );
  });

  it('names the node a retry moved from, and why', () => {
    const p: TurnPhase = {
      kind: 'routed',
      since: T0,
      node: 'host8',
      attempt: 2,
      previousNode: 'host3',
      previousReason: 'connect refused',
    };
    expect(phaseLabel(p, T0 + 1_000)).toBe('sending to host8 (moved from host3: connect refused) · 1s');
  });

  it('reads the prompt with its token count, then thinks, each timed from its own start', () => {
    expect(phaseLabel({ kind: 'prompt', since: T0, node: 'awolf', inputTokens: 1834 }, T0 + 2_000)).toBe(
      'reading your prompt (1,834 tokens) on awolf · 2s',
    );
    expect(phaseLabel({ kind: 'thinking', since: T0, node: 'awolf' }, T0 + 12_900)).toBe('thinking… 12s');
  });

  it('never shows a negative timer', () => {
    expect(phaseLabel({ kind: 'thinking', since: T0 }, T0 - 5_000)).toBe('thinking… 0s');
  });
});

describe('phaseFromFrame', () => {
  it('maps routed and prompt frames, keeps the node into prompt, ignores unknown phases', () => {
    const routed = phaseFromFrame({ phase: 'routed', node: 'mcmini', slots_busy: 2, slots_total: 2 }, undefined, T0);
    expect(routed).toMatchObject({ kind: 'routed', node: 'mcmini', since: T0, slotsBusy: 2 });
    expect(phaseFromFrame({ phase: 'prompt', input_tokens: 10 }, routed!, T0 + 1)).toMatchObject({
      kind: 'prompt',
      node: 'mcmini',
      inputTokens: 10,
    });
    expect(phaseFromFrame({ phase: 'routed' }, undefined, T0)).toBeNull();
  });

  it('keeps the clock across repeated routed frames for the same node and attempt (harness turns send several)', () => {
    const gw = phaseFromFrame({ phase: 'routed', node: 'mcmini', slots_busy: null, slots_total: null }, undefined, T0)!;
    const queued = phaseFromFrame(
      { phase: 'routed', node: 'mcmini', slots_busy: 2, slots_total: 2, queued_ahead: 2 },
      gw,
      T0 + 3_000,
    )!;
    expect(queued.since).toBe(T0);
    expect(phaseLabel(queued, T0 + 9_000)).toBe('queued on mcmini (2/2 busy, 2 ahead) · 9s');
    // Another node, or a retry, starts a new clock.
    expect(phaseFromFrame({ phase: 'routed', node: 'awolf' }, queued, T0 + 10_000)!.since).toBe(T0 + 10_000);
    expect(
      phaseFromFrame({ phase: 'routed', node: 'mcmini', attempt: 2, previous_node: 'mcmini' }, queued, T0 + 11_000)!.since,
    ).toBe(T0 + 11_000);
    expect(phaseFromFrame({ phase: 'compiling' }, undefined, T0)).toBeNull();
  });
});
