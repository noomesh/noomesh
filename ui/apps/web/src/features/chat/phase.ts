// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * What an in-flight turn is doing before its first answer token, so the
 * bubble never sits on a bare cursor (operator, 2026-11-01: a turn showed
 * "answering on mcmini ▍" with nothing else while it queued).
 *
 * The gateway sends `phase` frames (`routed`, `prompt`); `thinking` and the
 * first token are read off frames the console already gets. Every phase is
 * timed from when the console RECEIVED it (`since`, browser clock): the
 * frame's own `at_ms` is the gateway's clock and the two need not agree.
 */
export type TurnPhase =
  | {
      kind: 'routed';
      since: number;
      node: string;
      model?: string;
      slotsBusy?: number | null;
      slotsTotal?: number | null;
      queuedAhead?: number | null;
      attempt?: number;
      previousNode?: string;
      previousReason?: string;
    }
  | { kind: 'prompt'; since: number; node?: string; inputTokens?: number | null }
  | { kind: 'thinking'; since: number; node?: string };

/** The fields of a `phase` frame (gateway, agreed with harness 2026-11-01). */
export interface PhaseFrame {
  phase?: string;
  node?: string;
  model?: string;
  slots_busy?: number | null;
  slots_total?: number | null;
  queued_ahead?: number | null;
  attempt?: number;
  previous_node?: string;
  previous_reason?: string;
  input_tokens?: number | null;
}

/** The phase a `phase` frame moves the turn to, or null for one we do not know. */
export function phaseFromFrame(f: PhaseFrame, prev: TurnPhase | undefined, now: number): TurnPhase | null {
  if (f.phase === 'routed' && f.node) {
    // A harness turn sends routed more than once for the same attempt (the
    // gateway at dispatch, the node's loop, the agent's queue): the line keeps
    // its clock, so "queued … · 9s" is the whole wait, not the last frame's.
    const same = prev?.kind === 'routed' && prev.node === f.node && (prev.attempt ?? 1) === (f.attempt ?? 1);
    return {
      kind: 'routed',
      since: same ? prev.since : now,
      node: f.node,
      model: f.model,
      slotsBusy: f.slots_busy,
      slotsTotal: f.slots_total,
      queuedAhead: f.queued_ahead,
      attempt: f.attempt,
      previousNode: f.previous_node,
      previousReason: f.previous_reason,
    };
  }
  if (f.phase === 'prompt') {
    return { kind: 'prompt', since: now, node: prev && 'node' in prev ? prev.node : undefined, inputTokens: f.input_tokens };
  }
  return null;
}

const secs = (since: number, now: number) => `${Math.max(0, Math.floor((now - since) / 1000))}s`;

/** The line the bubble shows for a phase at `now` (both browser clock, ms). */
export function phaseLabel(p: TurnPhase, now: number): string {
  const t = secs(p.since, now);
  switch (p.kind) {
    case 'routed': {
      const moved =
        p.attempt && p.attempt > 1 && p.previousNode
          ? ` (moved from ${p.previousNode}${p.previousReason ? `: ${p.previousReason}` : ''})`
          : '';
      const full =
        p.slotsBusy != null && p.slotsTotal != null && p.slotsTotal > 0 && p.slotsBusy >= p.slotsTotal;
      if (full) {
        const ahead = p.queuedAhead ? `, ${p.queuedAhead} ahead` : '';
        return `queued on ${p.node} (${p.slotsBusy}/${p.slotsTotal} busy${ahead})${moved} · ${t}`;
      }
      return `sending to ${p.node}${moved} · ${t}`;
    }
    case 'prompt': {
      const n = p.inputTokens != null ? ` (${p.inputTokens.toLocaleString('en-US')} tokens)` : '';
      return `reading your prompt${n}${p.node ? ` on ${p.node}` : ''} · ${t}`;
    }
    case 'thinking':
      return `thinking… ${t}`;
  }
}
